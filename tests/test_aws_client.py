import pytest
import boto3
import zipfile
import io
from moto import mock_aws
from drift_engine.aws_client import (
    fetch_live_ec2_instances,
    fetch_live_s3_buckets,
    fetch_live_security_groups,
    fetch_live_rds_instances,
    fetch_live_lambda_functions,
    fetch_live_iam_roles,
    get_resource_cost
)

REGION = "ap-south-1"

@mock_aws
def test_fetch_live_ec2_instances():
    ec2 = boto3.client("ec2", region_name=REGION)
    res = ec2.run_instances(
        ImageId="ami-0c2af51e265bd5e0e",
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": "Test-EC2"}]
        }]
    )
    instance_id = res["Instances"][0]["InstanceId"]

    live = fetch_live_ec2_instances(REGION)
    assert live is not None
    assert instance_id in live
    assert live[instance_id]["name"] == "Test-EC2"
    assert live[instance_id]["attributes"]["instance_type"] == "t3.micro"

@mock_aws
def test_fetch_live_s3_buckets():
    s3 = boto3.client("s3", region_name=REGION)
    bucket_name = "test-s3-driftwatch-bucket"
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={"LocationConstraint": REGION}
    )
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "Env", "Value": "Dev"}]}
    )

    live = fetch_live_s3_buckets(REGION)
    assert live is not None
    assert bucket_name in live
    assert live[bucket_name]["attributes"]["tags"] == {"Env": "Dev"}

@mock_aws
def test_fetch_live_security_groups():
    ec2 = boto3.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(
        GroupName="test-sg",
        Description="DriftWatch test security group"
    )
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpProtocol="tcp",
        FromPort=80,
        ToPort=80,
        CidrIp="0.0.0.0/0"
    )

    live = fetch_live_security_groups(REGION)
    assert live is not None
    assert sg_id in live
    assert live[sg_id]["attributes"]["name"] == "test-sg"
    assert len(live[sg_id]["attributes"]["ingress"]) >= 1

@mock_aws
def test_fetch_live_rds_instances_matches_db_instance_identifier():
    rds = boto3.client("rds", region_name=REGION)
    db_identifier = "driftwatch-test-db"
    rds.create_db_instance(
        DBInstanceIdentifier=db_identifier,
        AllocatedStorage=20,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="SecurePassword123!"
    )

    live = fetch_live_rds_instances(REGION)
    assert live is not None
    assert db_identifier in live
    assert live[db_identifier]["type"] == "aws_db_instance"
    assert live[db_identifier]["attributes"]["id"] == db_identifier
    assert live[db_identifier]["attributes"]["identifier"] == db_identifier
    assert live[db_identifier]["attributes"]["instance_class"] == "db.t3.micro"

@mock_aws
def test_fetch_live_lambda_functions():
    iam = boto3.client("iam", region_name=REGION)
    role_res = iam.create_role(
        RoleName="lambda-test-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
    )
    role_arn = role_res["Role"]["Arn"]

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("index.py", "def handler(event, context): return 'ok'")
    zip_bytes = zip_buffer.getvalue()

    lambda_client = boto3.client("lambda", region_name=REGION)
    fn_name = "test-drift-lambda"
    lambda_client.create_function(
        FunctionName=fn_name,
        Runtime="python3.10",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes}
    )

    live = fetch_live_lambda_functions(REGION)
    assert live is not None
    assert fn_name in live
    assert live[fn_name]["attributes"]["runtime"] == "python3.10"
    assert live[fn_name]["attributes"]["handler"] == "index.handler"

@mock_aws
def test_fetch_live_iam_roles():
    iam = boto3.client("iam", region_name=REGION)
    role_name = "custom-app-role"
    iam.create_role(
        RoleName=role_name,
        Path="/app/",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
    )

    live = fetch_live_iam_roles(REGION)
    assert live is not None
    assert role_name in live
    assert live[role_name]["attributes"]["path"] == "/app/"

def test_get_resource_cost_graceful_fallback():
    """M8: get_resource_cost should return None (not raise) when the resource is not found or CE fails."""
    cost = get_resource_cost("non-existent-res")
    assert cost is None  # None signals "unavailable" — callers display "cost: unavailable"
