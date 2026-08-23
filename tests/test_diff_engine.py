import os
import json
import pytest
import boto3
from moto import mock_aws
from drift_engine.core import compare_attributes, normalize_sg_rules, get_severity, detect_drift
from drift_engine.models import DriftType
from drift_engine.tf_parser import load_terraform_state

def test_ignored_or_empty_attributes_do_not_trigger_drift():
    tf = {"id": "i-123", "private_ip": "10.0.0.5"}
    live = {"id": "i-123", "private_ip": "10.0.0.9"}
    diff = compare_attributes(tf, live, "aws_instance")
    assert diff == {}

def test_ec2_instance_type_change_detected():
    tf = {"id": "i-123", "instance_type": "t3.micro", "ami": "ami-123"}
    live = {"id": "i-123", "instance_type": "t3.small", "ami": "ami-123"}
    diff = compare_attributes(tf, live, "aws_instance")
    assert "instance_type" in diff
    assert diff["instance_type"]["terraform"] == "t3.micro"
    assert diff["instance_type"]["live"] == "t3.small"

def test_security_group_rule_normalization_and_diff():
    rule1 = [{"from_port": 80, "to_port": 80, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]
    rule2 = [{"from_port": 80, "to_port": 80, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0", "10.0.0.0/16"]}]
    
    tf = {"id": "sg-1", "ingress": rule1}
    live = {"id": "sg-1", "ingress": rule2}
    diff = compare_attributes(tf, live, "aws_security_group")
    assert "ingress" in diff

    norm1 = normalize_sg_rules([{"from_port": 80, "to_port": 80, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/16", "0.0.0.0/0"]}])
    norm2 = normalize_sg_rules([{"from_port": 80, "to_port": 80, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0", "10.0.0.0/16"]}])
    assert norm1 == norm2
    assert normalize_sg_rules("invalid") == []

def test_iam_role_diff_detected():
    tf = {"id": "role-1", "attached_policies": ["arn:aws:iam::aws:policy/ReadOnlyAccess"], "path": "/"}
    live = {"id": "role-1", "attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"], "path": "/"}
    diff = compare_attributes(tf, live, "aws_iam_role")
    assert "attached_policies" in diff
    assert diff["attached_policies"]["terraform"] == ["arn:aws:iam::aws:policy/ReadOnlyAccess"]

def test_rds_instance_diff_detected():
    tf = {"id": "db-1", "instance_class": "db.t3.micro", "allocated_storage": 20}
    live = {"id": "db-1", "instance_class": "db.t3.large", "allocated_storage": 50}
    diff = compare_attributes(tf, live, "aws_db_instance")
    assert "instance_class" in diff
    assert "allocated_storage" in diff

def test_s3_bucket_diff_detected():
    tf = {"id": "my-bucket", "bucket": "my-bucket", "tags": {"Env": "prod"}}
    live = {"id": "my-bucket", "bucket": "my-bucket", "tags": {"Env": "dev"}}
    diff = compare_attributes(tf, live, "aws_s3_bucket")
    assert "tags" in diff

def test_lambda_diff_detected():
    tf = {"id": "fn-1", "runtime": "python3.10", "handler": "index.handler"}
    live = {"id": "fn-1", "runtime": "python3.12", "handler": "index.handler"}
    diff = compare_attributes(tf, live, "aws_lambda_function")
    assert "runtime" in diff

def test_data_driven_severity_scoring():
    # SG ingress change -> CRITICAL
    sg_diff_crit = {"ingress": {"terraform": [], "live": []}}
    assert get_severity("aws_security_group", DriftType.MODIFIED, sg_diff_crit) == "CRITICAL"

    # SG description change only -> LOW
    sg_diff_low = {"description": {"terraform": "A", "live": "B"}}
    assert get_severity("aws_security_group", DriftType.MODIFIED, sg_diff_low) == "LOW"

    # EC2 instance_type change -> HIGH
    ec2_diff_high = {"instance_type": {"terraform": "t3.micro", "live": "t3.large"}}
    assert get_severity("aws_instance", DriftType.MODIFIED, ec2_diff_high) == "HIGH"

    # EC2 ami change -> MEDIUM
    ec2_diff_med = {"ami": {"terraform": "ami-1", "live": "ami-2"}}
    assert get_severity("aws_instance", DriftType.MODIFIED, ec2_diff_med) == "MEDIUM"

    # EC2 tags change -> LOW
    ec2_diff_low = {"tags": {"terraform": {}, "live": {}}}
    assert get_severity("aws_instance", DriftType.MODIFIED, ec2_diff_low) == "LOW"

    # IAM role attached_policies -> CRITICAL
    iam_diff = {"attached_policies": {"terraform": [], "live": []}}
    assert get_severity("aws_iam_role", DriftType.MODIFIED, iam_diff) == "CRITICAL"

    # RDS instance_class -> HIGH, allocated_storage -> MEDIUM
    rds_diff_high = {"instance_class": {"terraform": "db.t3.micro", "live": "db.t3.medium"}}
    assert get_severity("aws_db_instance", DriftType.MODIFIED, rds_diff_high) == "HIGH"

    rds_diff_med = {"allocated_storage": {"terraform": 20, "live": 40}}
    assert get_severity("aws_db_instance", DriftType.MODIFIED, rds_diff_med) == "MEDIUM"

    # Missing & Unmanaged severities
    assert get_severity("aws_security_group", DriftType.MISSING) == "CRITICAL"
    assert get_severity("aws_instance", DriftType.MISSING) == "HIGH"
    assert get_severity("aws_security_group", DriftType.UNMANAGED) == "CRITICAL"
    assert get_severity("aws_instance", DriftType.UNMANAGED) == "HIGH"
    assert get_severity("aws_s3_bucket", DriftType.MODIFIED, None) == "MEDIUM"

def test_load_terraform_state_parser(tmp_path):
    state_content = {
        "resources": [
            {
                "type": "aws_instance",
                "instances": [
                    {
                        "attributes": {
                            "id": "i-0123456789abcdef0",
                            "instance_type": "t3.micro",
                            "ami": "ami-0c2af51e265bd5e0e",
                            "tags": {"Name": "TestInstance"}
                        }
                    }
                ]
            },
            {
                "type": "aws_db_instance",
                "instances": [
                    {
                        "attributes": {
                            "id": "driftwatch-test-db",
                            "identifier": "driftwatch-test-db",
                            "allocated_storage": 20,
                            "engine": "mysql",
                            "instance_class": "db.t3.micro"
                        }
                    }
                ]
            },
            {
                "type": "aws_iam_role_policy_attachment",
                "instances": [
                    {
                        "attributes": {
                            "role": "test_role",
                            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"
                        }
                    }
                ]
            }
        ]
    }
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(state_content))

    resources = load_terraform_state(str(state_file))
    assert "i-0123456789abcdef0" in resources
    assert resources["i-0123456789abcdef0"]["name"] == "TestInstance"
    assert "driftwatch-test-db" in resources
    assert "test_role" in resources

def test_load_terraform_state_missing_or_corrupt(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_terraform_state("non_existent_file.tfstate")
    corrupt_file = tmp_path / "corrupt.tfstate"
    corrupt_file.write_text("invalid json")
    with pytest.raises(ValueError):
        load_terraform_state(str(corrupt_file))

@mock_aws
def test_detect_drift_full_flow(tmp_path):
    region = "ap-south-1"
    ec2 = boto3.client("ec2", region_name=region)
    res = ec2.run_instances(ImageId="ami-0c2af51e265bd5e0e", InstanceType="t3.small", MinCount=1, MaxCount=1)
    inst_id = res["Instances"][0]["InstanceId"]

    # State expects t3.micro
    state_content = {
        "resources": [
            {
                "type": "aws_instance",
                "instances": [
                    {
                        "attributes": {
                            "id": inst_id,
                            "instance_type": "t3.micro",
                            "ami": "ami-0c2af51e265bd5e0e"
                        }
                    }
                ]
            },
            {
                "type": "aws_s3_bucket",
                "instances": [
                    {
                        "attributes": {
                            "id": "deleted-bucket",
                            "bucket": "deleted-bucket"
                        }
                    }
                ]
            }
        ]
    }
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(state_content))

    results, total_scanned = detect_drift(str(state_file), region)
    assert total_scanned >= 2
    types = {r.resource_id: r.drift_type for r in results}
    assert inst_id in types
    assert types[inst_id] == DriftType.MODIFIED
    assert "deleted-bucket" in types
    assert types["deleted-bucket"] == DriftType.MISSING