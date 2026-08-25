import pytest
import boto3
import io
import zipfile
from moto import mock_aws
from drift_engine.remediation import (
    get_environment_tag,
    confirm_action,
    remediate_ec2_instance_type,
    remediate_security_group,
    remediate_s3_bucket,
    remediate_rds_instance,
    remediate_lambda_function,
    remediate_iam_role,
    process_remediation
)
from drift_engine.models import DriftResult, DriftType

REGION = "ap-south-1"

def test_get_environment_tag():
    assert get_environment_tag({"Environment": "Dev"}) == "dev"
    assert get_environment_tag([{"Key": "Environment", "Value": "Staging"}]) == "staging"
    assert get_environment_tag([{"Key": "Environment", "Value": None}]) == "unknown"
    assert get_environment_tag({}) == "unknown"
    assert get_environment_tag(None) == "unknown"

def test_confirm_action_auto_approves_dev_staging():
    assert confirm_action("test action", "dev", False) is True
    assert confirm_action("test action", "staging", True) is True

def test_confirm_action_auto_approve_flag():
    assert confirm_action("test action", "production", False, auto_approve=True) is True

def test_confirm_action_manual(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert confirm_action("test action", "production", False) is True

    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert confirm_action("test action", "production", False) is False

def test_confirm_action_eof_fails_closed(monkeypatch):
    def raise_eof(prompt):
        raise EOFError("EOF on input")
    monkeypatch.setattr("builtins.input", raise_eof)
    assert confirm_action("test action", "production", False) is False

@mock_aws
def test_remediate_ec2_instance_type_success():
    ec2 = boto3.client("ec2", region_name=REGION)
    res = ec2.run_instances(
        ImageId="ami-0c2af51e265bd5e0e",
        InstanceType="t3.small",
        MinCount=1,
        MaxCount=1
    )
    instance_id = res["Instances"][0]["InstanceId"]

    # Remediate back to t3.micro in dev (auto-approves)
    remediate_ec2_instance_type(REGION, instance_id, "t3.micro", "dev")

    desc = ec2.describe_instances(InstanceIds=[instance_id])
    assert desc["Reservations"][0]["Instances"][0]["InstanceType"] == "t3.micro"

@mock_aws
def test_remediate_ec2_instance_type_not_found():
    remediate_ec2_instance_type(REGION, "i-nonexistent", "t3.micro", "dev")

@mock_aws
def test_remediate_security_group_ingress_and_egress():
    ec2 = boto3.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(GroupName="test-sg-rem", Description="Test SG")
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpProtocol="tcp",
        FromPort=22,
        ToPort=22,
        CidrIp="0.0.0.0/0"
    )
    ec2.authorize_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
    )

    diff_data = {
        "ingress": {
            "terraform": [{"from_port": 80, "to_port": 80, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}],
            "live": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]
        },
        "egress": {
            "terraform": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}],
            "live": [{"from_port": 8080, "to_port": 8080, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]
        },
        "description": {
            "terraform": "Terraform description",
            "live": "Live description"
        }
    }

    remediate_security_group(REGION, sg_id, diff_data, "dev")
    sg_info = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    ingress_ports = [p["FromPort"] for p in sg_info.get("IpPermissions", []) if "FromPort" in p]
    assert 80 in ingress_ports
    assert 22 not in ingress_ports

@mock_aws
def test_remediate_s3_bucket_tags_and_bucket_name():
    s3 = boto3.client("s3", region_name=REGION)
    bucket_name = "remediate-s3-test-bucket"
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={"LocationConstraint": REGION}
    )

    diff_data = {
        "tags": {
            "terraform": {"Environment": "Dev", "ManagedBy": "Terraform"},
            "live": {}
        },
        "bucket": {
            "terraform": "expected-bucket-name",
            "live": bucket_name
        }
    }

    remediate_s3_bucket(bucket_name, diff_data, "dev")
    tags = s3.get_bucket_tagging(Bucket=bucket_name)["TagSet"]
    tag_dict = {t["Key"]: t["Value"] for t in tags}
    assert tag_dict["ManagedBy"] == "Terraform"

@mock_aws
def test_remediate_rds_instance():
    rds = boto3.client("rds", region_name=REGION)
    db_id = "test-rds-remediate"
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        AllocatedStorage=20,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="SecurePassword123!"
    )

    diff_data = {
        "instance_class": {"terraform": "db.t3.small", "live": "db.t3.micro"},
        "allocated_storage": {"terraform": 40, "live": 20}
    }

    remediate_rds_instance(REGION, db_id, diff_data, "dev", apply_immediately=False)

@mock_aws
def test_remediate_lambda_function():
    iam = boto3.client("iam", region_name=REGION)
    role_res = iam.create_role(
        RoleName="lambda-rem-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
    )
    role_arn = role_res["Role"]["Arn"]

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("index.py", "def handler(e, c): return 'ok'")
    zip_bytes = zip_buffer.getvalue()

    lambda_client = boto3.client("lambda", region_name=REGION)
    fn_name = "test-lambda-rem"
    lambda_client.create_function(
        FunctionName=fn_name,
        Runtime="python3.9",
        Role=role_arn,
        Handler="index.old_handler",
        Code={"ZipFile": zip_bytes},
        Timeout=10,
        MemorySize=128
    )

    diff_data = {
        "runtime": {"terraform": "python3.10", "live": "python3.9"},
        "handler": {"terraform": "index.handler", "live": "index.old_handler"},
        "memory_size": {"terraform": 256, "live": 128},
        "timeout": {"terraform": 30, "live": 10}
    }

    remediate_lambda_function(REGION, fn_name, diff_data, "dev")
    fn_info = lambda_client.get_function_configuration(FunctionName=fn_name)
    assert fn_info["Runtime"] == "python3.10"
    assert fn_info["Handler"] == "index.handler"
    assert fn_info["MemorySize"] == 256
    assert fn_info["Timeout"] == 30

@mock_aws
def test_remediate_iam_role():
    iam = boto3.client("iam", region_name=REGION)
    role_name = "test-iam-rem-role"
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
    )

    policy_res1 = iam.create_policy(
        PolicyName="ReadOnlyPolicy",
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
    )
    policy_read = policy_res1["Policy"]["Arn"]

    policy_res2 = iam.create_policy(
        PolicyName="AdminPolicy",
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
    )
    policy_admin = policy_res2["Policy"]["Arn"]
    
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_admin)

    diff_data = {
        "attached_policies": {
            "terraform": [policy_read],
            "live": [policy_admin]
        }
    }

    remediate_iam_role(role_name, diff_data, "dev")
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    arns = [p["PolicyArn"] for p in attached]
    assert policy_read in arns
    assert policy_admin not in arns

@mock_aws
def test_process_remediation_dispatch(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    results = [
        DriftResult(
            resource_type="aws_s3_bucket",
            resource_id="test-bucket",
            drift_type=DriftType.UNMANAGED,
            resource_name="test-bucket",
            live_attributes={"tags": {"Environment": "Dev"}}
        ),
        DriftResult(
            resource_type="aws_instance",
            resource_id="i-nonexistent",
            drift_type=DriftType.MODIFIED,
            resource_name="test-ec2",
            diff={"instance_type": {"terraform": "t3.micro", "live": "t3.small"}},
            live_attributes={"tags": {"Environment": "Dev"}}
        ),
        DriftResult(
            resource_type="aws_security_group",
            resource_id="sg-nonexistent",
            drift_type=DriftType.MODIFIED,
            resource_name="test-sg",
            diff={"description": {"terraform": "A", "live": "B"}},
            live_attributes={"tags": {"Environment": "Dev"}}
        ),
        DriftResult(
            resource_type="aws_db_instance",
            resource_id="db-nonexistent",
            drift_type=DriftType.MODIFIED,
            resource_name="test-db",
            diff={"instance_class": {"terraform": "db.t3.micro", "live": "db.t3.small"}},
            live_attributes={"tags": {"Environment": "Dev"}}
        ),
        DriftResult(
            resource_type="aws_lambda_function",
            resource_id="fn-nonexistent",
            drift_type=DriftType.MODIFIED,
            resource_name="test-fn",
            diff={"timeout": {"terraform": 15, "live": 3}},
            live_attributes={"tags": {"Environment": "Dev"}}
        ),
        DriftResult(
            resource_type="aws_iam_role",
            resource_id="role-nonexistent",
            drift_type=DriftType.MODIFIED,
            resource_name="test-role",
            diff={"attached_policies": {"terraform": [], "live": []}},
            live_attributes={"tags": {"Environment": "Dev"}}
        )
    ]
    process_remediation(results)
