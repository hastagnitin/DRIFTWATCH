import os
import json
import pytest
import boto3
from moto import mock_aws
from typer.testing import CliRunner
from driftwatch.cli import app
from drift_engine.models import DriftResult, DriftType

runner = CliRunner()

def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "DriftWatch CLI" in result.stdout

def test_cli_scan_no_region_error(monkeypatch):
    monkeypatch.setattr("driftwatch.cli._resolve_region", lambda r, profile=None: None)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0
    assert "No AWS region found" in result.stdout

def test_cli_scan_success_no_drift(tmp_path, monkeypatch):
    empty_state = {"resources": []}
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(empty_state))
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: ([], 0))

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file)])
    assert result.exit_code == 0
    assert "No drift detected" in result.stdout

@mock_aws
def test_cli_scan_zero_drift_with_matching_state(tmp_path):
    region = "ap-south-1"
    s3 = boto3.client("s3", region_name=region)
    s3.create_bucket(Bucket="driftwatch-clean-bucket", CreateBucketConfiguration={"LocationConstraint": region})
    
    ec2 = boto3.client("ec2", region_name=region)
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    default_sg = sgs[0]
    sg_id = default_sg["GroupId"]

    state_content = {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "instances": [
                    {
                        "attributes": {
                            "id": "driftwatch-clean-bucket",
                            "bucket": "driftwatch-clean-bucket",
                            "tags": {}
                        }
                    }
                ]
            },
            {
                "type": "aws_security_group",
                "instances": [
                    {
                        "attributes": {
                            "id": sg_id,
                            "name": default_sg.get("GroupName", "default"),
                            "description": default_sg.get("Description", "default VPC security group"),
                            "tags": {},
                            "ingress": [],
                            "egress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "protocol": "-1", "to_port": 0}]
                        }
                    }
                ]
            }
        ]
    }
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps(state_content))

    result = runner.invoke(app, ["scan", "--region", region, "--state", str(state_file)])
    assert result.exit_code == 0
    assert "No drift detected" in result.stdout

def test_cli_scan_with_unmanaged_ec2_and_cost(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_instance",
            resource_id="i-untracked-1",
            drift_type=DriftType.UNMANAGED,
            resource_name="manual-ec2",
            live_attributes={"instance_type": "t3.medium"}
        )
    ]
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    monkeypatch.setattr("driftwatch.cli.get_resource_cost", lambda rid, profile=None: 25.50)
    monkeypatch.setattr("driftwatch.cli.get_drift_explanation", lambda rt, rid, diff, dt: "Untracked compute cost.")
    monkeypatch.setattr("driftwatch.cli.process_alerts", lambda res: None)
    monkeypatch.setattr("driftwatch.cli.save_drift_to_db", lambda res: None)

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file)])
    assert result.exit_code == 0
    assert "Cost: +$25.50/month" in result.stdout

def test_cli_scan_with_gate_failure(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_security_group",
            resource_id="sg-12345",
            drift_type=DriftType.MODIFIED,
            resource_name="test-sg",
            diff={"ingress": {"terraform": [], "live": []}}
        )
    ]

    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    monkeypatch.setattr("driftwatch.cli.process_alerts", lambda res: None)
    monkeypatch.setattr("driftwatch.cli.save_drift_to_db", lambda res: None)
    monkeypatch.setattr("driftwatch.cli.get_drift_explanation", lambda rt, rid, diff, dt: "")

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file), "--fail-on", "CRITICAL"])
    assert result.exit_code == 1
    assert "BUILD FAILED" in result.stdout

def test_cli_explain_command(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_instance",
            resource_id="i-0123456789abcdef0",
            drift_type=DriftType.MODIFIED,
            resource_name="web-1",
            diff={"instance_type": {"terraform": "t3.micro", "live": "t3.large"}}
        )
    ]

    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    monkeypatch.setattr("driftwatch.cli.get_drift_explanation", lambda rt, rid, diff, dt: "Mock AI analysis.")

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["explain", "i-0123456789abcdef0", "--region", "ap-south-1", "--state", str(state_file)])
    assert result.exit_code == 0
    assert "Mock AI analysis" in result.stdout
    assert "terraform apply" in result.stdout

def test_cli_explain_missing_region(monkeypatch):
    monkeypatch.setattr("driftwatch.cli._resolve_region", lambda r, profile=None: None)
    result = runner.invoke(app, ["explain", "i-123"])
    assert result.exit_code != 0
    assert "No AWS region found" in result.stdout

def test_cli_explain_resource_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: ([], 0))
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["explain", "non-existent-id", "--region", "ap-south-1", "--state", str(state_file)])
    assert result.exit_code == 1
    assert "No current drift found" in result.stdout

def test_cli_remediate_dry_run(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_security_group",
            resource_id="sg-12345",
            drift_type=DriftType.MODIFIED,
            resource_name="test-sg",
            diff={"description": {"terraform": "A", "live": "B"}}
        )
    ]

    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["remediate", "sg-12345", "--region", "ap-south-1", "--state", str(state_file), "--dry-run"])
    assert result.exit_code == 0
    assert "DRY RUN" in result.stdout

def test_cli_remediate_apply_mode(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_s3_bucket",
            resource_id="b-1",
            drift_type=DriftType.MODIFIED,
            resource_name="b-1",
            diff={"tags": {"terraform": {}, "live": {}}}
        )
    ]

    called = []
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    monkeypatch.setattr("driftwatch.cli.process_remediation", lambda res, auto_approve=False: called.append((res, auto_approve)))

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["remediate", "b-1", "--region", "ap-south-1", "--state", str(state_file), "--apply"])
    assert result.exit_code == 0
    assert len(called) == 1
    assert called[0][1] is False

def test_cli_remediate_apply_yes_flag(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_s3_bucket",
            resource_id="b-1",
            drift_type=DriftType.MODIFIED,
            resource_name="b-1",
            diff={"tags": {"terraform": {}, "live": {}}}
        )
    ]

    called = []
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    monkeypatch.setattr("driftwatch.cli.process_remediation", lambda res, auto_approve=False: called.append((res, auto_approve)))

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["remediate", "b-1", "--region", "ap-south-1", "--state", str(state_file), "--apply", "--yes"])
    assert result.exit_code == 0
    assert len(called) == 1
    assert called[0][1] is True

@mock_aws
def test_cli_remediate_apply_non_interactive_eof(tmp_path, monkeypatch):
    region = "ap-south-1"
    ec2 = boto3.client("ec2", region_name=region)
    res = ec2.run_instances(ImageId="ami-0c2af51e265bd5e0e", InstanceType="t3.small", MinCount=1, MaxCount=1)
    inst_id = res["Instances"][0]["InstanceId"]

    mock_results = [
        DriftResult(
            resource_type="aws_instance",
            resource_id=inst_id,
            drift_type=DriftType.MODIFIED,
            resource_name="prod-ec2",
            diff={"instance_type": {"terraform": "t3.micro", "live": "t3.small"}},
            live_attributes={"tags": {"Environment": "production"}}
        )
    ]

    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    def raise_eof(prompt):
        raise EOFError("EOF from stdin")
    monkeypatch.setattr("builtins.input", raise_eof)

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["remediate", inst_id, "--region", region, "--state", str(state_file), "--apply"])
    assert result.exit_code == 0
    assert "Non-interactive shell detected" in result.stdout
    assert "Skipped remediation" in result.stdout

def test_cli_remediate_missing_region(monkeypatch):
    monkeypatch.setattr("driftwatch.cli._resolve_region", lambda r, profile=None: None)
    result = runner.invoke(app, ["remediate", "b-1"])
    assert result.exit_code != 0
    assert "No AWS region found" in result.stdout

def test_cli_remediate_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: ([], 0))
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["remediate", "non-existent-b", "--region", "ap-south-1", "--state", str(state_file)])
    assert result.exit_code == 1
    assert "No current drift found" in result.stdout

def test_cli_scan_missing_state_file_fails(monkeypatch):
    monkeypatch.setattr("driftwatch.cli._resolve_region", lambda r, profile=None: "ap-south-1")
    result = runner.invoke(app, ["scan", "--state", "non_existent_path.tfstate"])
    assert result.exit_code != 0
    assert "Error during execution" in result.stdout or "not found" in result.stdout

def test_cli_scan_corrupt_state_file_fails(tmp_path, monkeypatch):
    corrupt_state = tmp_path / "corrupt.tfstate"
    corrupt_state.write_text("invalid json state")
    monkeypatch.setattr("driftwatch.cli._resolve_region", lambda r, profile=None: "ap-south-1")
    result = runner.invoke(app, ["scan", "--state", str(corrupt_state)])
    assert result.exit_code != 0
    assert "Error during execution" in result.stdout or "corrupted" in result.stdout

def test_cli_scan_aws_fetch_failure_fails(tmp_path, monkeypatch):
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps({"resources": []}))
    monkeypatch.setattr("driftwatch.cli._resolve_region", lambda r, profile=None: "ap-south-1")
    monkeypatch.setattr("drift_engine.core.fetch_live_ec2_instances", lambda reg, profile=None: None)
    result = runner.invoke(app, ["scan", "--state", str(state_file), "--region", "ap-south-1"])
    assert result.exit_code != 0
    assert "Failed to fetch live AWS resources" in result.stdout

def test_cli_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "driftwatch-cli" in result.stdout

def test_cli_h_help_shorthand():
    result = runner.invoke(app, ["-h"])
    assert result.exit_code == 0
    assert "DriftWatch CLI" in result.stdout

def test_cli_scan_json_output(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_instance",
            resource_id="i-abc",
            drift_type=DriftType.UNMANAGED,
            resource_name="manual-ec2",
            live_attributes={"instance_type": "t3.micro"}
        )
    ]
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    monkeypatch.setattr("driftwatch.cli.get_resource_cost", lambda rid, profile=None: 12.50)
    monkeypatch.setattr("driftwatch.cli.get_drift_explanation", lambda rt, rid, diff, dt: "AI insight.")
    monkeypatch.setattr("driftwatch.cli.process_alerts", lambda res: None)
    monkeypatch.setattr("driftwatch.cli.save_drift_to_db", lambda res: None)

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file), "--output", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["drift_count"] == 1
    assert data["results"][0]["resource_id"] == "i-abc"
    assert data["results"][0]["cost_estimate"] == 12.50

def test_cli_scan_json_flag(monkeypatch, tmp_path):
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: ([], 0))
    monkeypatch.setattr("driftwatch.cli.process_alerts", lambda res: None)
    monkeypatch.setattr("driftwatch.cli.save_drift_to_db", lambda res: None)

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["drift_count"] == 0

def test_cli_remediate_all_flag(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(resource_type="aws_s3_bucket", resource_id="b-1", drift_type=DriftType.MODIFIED,
                    resource_name="b-1", diff={"tags": {"terraform": {}, "live": {}}}),
        DriftResult(resource_type="aws_s3_bucket", resource_id="b-2", drift_type=DriftType.MODIFIED,
                    resource_name="b-2", diff={"tags": {"terraform": {}, "live": {}}}),
    ]
    called = []
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 2))
    monkeypatch.setattr("driftwatch.cli.process_remediation", lambda res, auto_approve=False: called.append(res))

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["remediate", "--all", "--region", "ap-south-1", "--state", str(state_file), "--apply", "--yes"])
    assert result.exit_code == 0
    # All resources were passed to process_remediation
    assert len(called) == 1
    assert len(called[0]) == 2

def test_cli_remediate_no_target_errors(monkeypatch):
    result = runner.invoke(app, ["remediate", "--region", "ap-south-1"])
    assert result.exit_code != 0
    assert "Must specify a resource_id" in result.stdout

def test_cli_scan_profile_option(monkeypatch, tmp_path):
    """Test that --profile is forwarded to detect_drift"""
    captured = []
    def fake_detect(state, reg, profile=None):
        captured.append(profile)
        return [], 0
    monkeypatch.setattr("driftwatch.cli.detect_drift", fake_detect)

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file), "--profile", "staging"])
    assert result.exit_code == 0
    assert captured[0] == "staging"

def test_cli_explain_from_scan(monkeypatch, tmp_path):
    """Test --from-scan loads results from JSON without making AWS calls"""
    scan_data = {
        "region": "ap-south-1",
        "total_scanned": 1,
        "results": [
            {
                "resource_type": "aws_instance",
                "resource_id": "i-from-file",
                "resource_name": "my-ec2",
                "drift_type": "MODIFIED",
                "severity": "HIGH",
                "diff": {"instance_type": {"terraform": "t3.micro", "live": "t3.large"}},
                "live_attributes": {},
                "tf_attributes": {},
                "ai_analysis": ""
            }
        ]
    }
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(scan_data))
    monkeypatch.setattr("driftwatch.cli.get_drift_explanation", lambda rt, rid, diff, dt: "Loaded from file.")

    result = runner.invoke(app, ["explain", "i-from-file", "--from-scan", str(scan_file)])
    assert result.exit_code == 0
    assert "Loaded from file" in result.stdout
