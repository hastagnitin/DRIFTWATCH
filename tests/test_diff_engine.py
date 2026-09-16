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
    sg_diff_crit = {"ingress": {"terraform": [], "live": []}}
    assert get_severity("aws_security_group", DriftType.MODIFIED, sg_diff_crit) == "CRITICAL"

    sg_diff_low = {"description": {"terraform": "A", "live": "B"}}
    assert get_severity("aws_security_group", DriftType.MODIFIED, sg_diff_low) == "LOW"

    ec2_diff_high = {"instance_type": {"terraform": "t3.micro", "live": "t3.large"}}
    assert get_severity("aws_instance", DriftType.MODIFIED, ec2_diff_high) == "HIGH"

    ec2_diff_med = {"ami": {"terraform": "ami-1", "live": "ami-2"}}
    assert get_severity("aws_instance", DriftType.MODIFIED, ec2_diff_med) == "MEDIUM"

    ec2_diff_low = {"tags": {"terraform": {}, "live": {}}}
    assert get_severity("aws_instance", DriftType.MODIFIED, ec2_diff_low) == "LOW"

    iam_diff = {"attached_policies": {"terraform": [], "live": []}}
    assert get_severity("aws_iam_role", DriftType.MODIFIED, iam_diff) == "CRITICAL"

    rds_diff_high = {"instance_class": {"terraform": "db.t3.micro", "live": "db.t3.medium"}}
    assert get_severity("aws_db_instance", DriftType.MODIFIED, rds_diff_high) == "HIGH"

    rds_diff_med = {"allocated_storage": {"terraform": 20, "live": 40}}
    assert get_severity("aws_db_instance", DriftType.MODIFIED, rds_diff_med) == "MEDIUM"

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
def test_detect_drift_raises_on_aws_auth_failure(tmp_path, monkeypatch):
    state_content = {"resources": []}
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(state_content))

    monkeypatch.setattr("drift_engine.core.fetch_live_ec2_instances", lambda reg, profile=None: None)

    with pytest.raises(RuntimeError, match="Failed to fetch live AWS resources"):
        detect_drift(str(state_file), "ap-south-1")


@mock_aws
def test_detect_drift_raises_when_multiple_fetches_fail(tmp_path, monkeypatch):
    state_content = {"resources": []}
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(state_content))

    monkeypatch.setattr("drift_engine.core.fetch_live_ec2_instances", lambda reg, profile=None: None)
    monkeypatch.setattr("drift_engine.core.fetch_live_rds_instances", lambda reg, profile=None: None)

    with pytest.raises(RuntimeError) as exc_info:
        detect_drift(str(state_file), "ap-south-1")

    error_msg = str(exc_info.value)
    assert "aws_instance" in error_msg
    assert "aws_db_instance" in error_msg


@mock_aws
def test_detect_drift_full_flow(tmp_path):
    region = "ap-south-1"
    ec2 = boto3.client("ec2", region_name=region)
    res = ec2.run_instances(ImageId="ami-0c2af51e265bd5e0e", InstanceType="t3.small", MinCount=1, MaxCount=1)
    inst_id = res["Instances"][0]["InstanceId"]

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


def test_drift_engine_package_exports():
    """L3: Verify drift_engine/__init__.py exports the core API symbols."""
    import drift_engine
    assert hasattr(drift_engine, "detect_drift")
    assert hasattr(drift_engine, "get_severity")
    assert hasattr(drift_engine, "DriftResult")
    assert hasattr(drift_engine, "DriftType")
    assert hasattr(drift_engine, "MONITORED_ATTRIBUTES")
    assert hasattr(drift_engine, "ATTRIBUTE_SEVERITY")


def test_driftwatch_engine_namespaced_alias():
    """L3: Verify driftwatch exports the engine module under driftwatch.engine."""
    import driftwatch
    assert hasattr(driftwatch, "engine")
    assert driftwatch.engine is not None
    assert hasattr(driftwatch.engine, "detect_drift")
    assert hasattr(driftwatch.engine, "get_severity")


@mock_aws
def test_load_terraform_state_from_s3_success():
    region = "ap-south-1"
    s3 = boto3.client("s3", region_name=region)
    bucket = "my-tfstate-bucket"
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})

    state_content = {
        "resources": [
            {
                "type": "aws_instance",
                "instances": [
                    {
                        "attributes": {
                            "id": "i-remote-1",
                            "instance_type": "t3.micro"
                        }
                    }
                ]
            }
        ]
    }
    s3.put_object(Bucket=bucket, Key="env/prod/terraform.tfstate", Body=json.dumps(state_content))

    parsed = load_terraform_state(f"s3://{bucket}/env/prod/terraform.tfstate")
    assert "i-remote-1" in parsed
    assert parsed["i-remote-1"]["type"] == "aws_instance"


@mock_aws
def test_load_terraform_state_from_s3_not_found():
    with pytest.raises(FileNotFoundError):
        load_terraform_state("s3://nonexistent-bucket/state.tfstate")


@mock_aws
def test_load_terraform_state_from_s3_corrupt():
    region = "ap-south-1"
    s3 = boto3.client("s3", region_name=region)
    bucket = "corrupt-tf-bucket"
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_object(Bucket=bucket, Key="state.tfstate", Body=b"not-json-content")

    with pytest.raises(ValueError, match="corrupted or invalid JSON"):
        load_terraform_state(f"s3://{bucket}/state.tfstate")


def test_load_terraform_state_from_s3_invalid_uri():
    with pytest.raises(ValueError, match="Invalid S3 state URI"):
        load_terraform_state("s3://onlybucket")


def test_cost_explorer_caching(monkeypatch):
    from drift_engine.aws_client import get_resource_cost, clear_cost_cache, _cost_cache

    clear_cost_cache()
    api_call_count = 0

    class MockCE:
        def get_cost_and_usage(self, **kwargs):
            nonlocal api_call_count
            api_call_count += 1
            return {"ResultsByTime": [{"Total": {"UnblendedCost": {"Amount": "42.50"}}}]}

    monkeypatch.setattr("drift_engine.aws_client.get_boto3_client", lambda s, profile=None, region=None: MockCE())

    c1 = get_resource_cost("i-test-cache-1")
    assert c1 == 42.50
    assert api_call_count == 1

    c2 = get_resource_cost("i-test-cache-1")
    assert c2 == 42.50
    assert api_call_count == 1

    clear_cost_cache()
    assert len(_cost_cache) == 0


@mock_aws
def test_detect_drift_partial_failure_with_allow_partial(tmp_path, monkeypatch):
    region = "ap-south-1"
    state_content = {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "instances": [{"attributes": {"id": "bucket-1", "bucket": "bucket-1"}}]
            },
            {
                "type": "aws_db_instance",
                "instances": [{"attributes": {"id": "db-1", "identifier": "db-1"}}]
            }
        ]
    }
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(state_content))

    monkeypatch.setattr("drift_engine.core.fetch_live_rds_instances", lambda reg, profile=None: None)
    monkeypatch.setattr("drift_engine.core.fetch_live_s3_buckets", lambda reg, profile=None: {"bucket-1": {"type": "aws_s3_bucket", "name": "bucket-1", "attributes": {"id": "bucket-1", "bucket": "bucket-1"}}})
    monkeypatch.setattr("drift_engine.core.fetch_live_ec2_instances", lambda reg, profile=None: {})
    monkeypatch.setattr("drift_engine.core.fetch_live_security_groups", lambda reg, profile=None: {})
    monkeypatch.setattr("drift_engine.core.fetch_live_lambda_functions", lambda reg, profile=None: {})
    monkeypatch.setattr("drift_engine.core.fetch_live_iam_roles", lambda reg, profile=None: {})

    with pytest.raises(RuntimeError, match="aws_db_instance"):
        detect_drift(str(state_file), region, allow_partial=False)

    scan_result = detect_drift(str(state_file), region, allow_partial=True)
    results, total_scanned = scan_result
    assert scan_result.failed_services == ["aws_db_instance"]
    assert len(results) == 0