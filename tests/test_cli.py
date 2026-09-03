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
    monkeypatch.setattr("driftwatch.cli.process_remediation", lambda res, auto_approve=False, profile=None: called.append((res, auto_approve)))

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
    monkeypatch.setattr("driftwatch.cli.process_remediation", lambda res, auto_approve=False, profile=None: called.append((res, auto_approve)))

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
    monkeypatch.setattr("driftwatch.cli.process_remediation", lambda res, auto_approve=False, profile=None: called.append(res))

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["remediate", "--all", "--region", "ap-south-1", "--state", str(state_file), "--apply", "--yes"])
    assert result.exit_code == 0
  
    assert len(called) == 1
    assert len(called[0]) == 2

def test_cli_remediate_no_target_errors(monkeypatch):
    result = runner.invoke(app, ["remediate", "--region", "ap-south-1"])
    assert result.exit_code != 0
    assert "Must specify a resource_id" in result.stdout

def test_cli_scan_profile_option(monkeypatch, tmp_path):
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

def test_cli_scan_legitimately_empty_state_exits_zero(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "driftwatch.cli.detect_drift",
        lambda state, reg, profile=None: ([], 0),
    )
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file)])
    assert result.exit_code == 0, f"Expected exit 0 for clean scan, got {result.exit_code}. Output:\n{result.stdout}"
    assert "No drift detected" in result.stdout

def test_cli_scan_exits_nonzero_when_detect_drift_raises(monkeypatch, tmp_path):
    def _raise_auth_error(state, reg, profile=None):
        raise RuntimeError("Failed to fetch live AWS resources for: aws_instance, aws_iam_role")

    monkeypatch.setattr("driftwatch.cli.detect_drift", _raise_auth_error)
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file)])
    assert result.exit_code != 0
    assert "Error" in result.stdout or "Failed" in result.stdout

def test_cli_scan_json_exits_nonzero_on_scan_failure(monkeypatch, tmp_path):
    def _raise(*a, **kw):
        raise RuntimeError("Failed to fetch live AWS resources for: aws_s3_bucket")

    monkeypatch.setattr("driftwatch.cli.detect_drift", _raise)
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file), "--output", "json"])
    assert result.exit_code != 0

def test_cli_scan_fail_on_gate_does_not_fire_when_scan_errors(monkeypatch, tmp_path):
    def _raise(*a, **kw):
        raise RuntimeError("Failed to fetch live AWS resources for: aws_instance")

    monkeypatch.setattr("driftwatch.cli.detect_drift", _raise)
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file), "--fail-on", "CRITICAL"])
    assert result.exit_code != 0
    assert "BUILD FAILED" not in result.stdout

def test_cli_scan_invalid_fail_on_value(tmp_path):
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file), "--fail-on", "INVALID_SEV_XYZ"])
    assert result.exit_code != 0
    output_text = result.output or result.stdout
    assert "Invalid value for '--fail-on'" in output_text or "invalid" in output_text.lower()

def test_cli_scan_fail_on_case_insensitive(monkeypatch, tmp_path):
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: ([], 0))
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file), "--fail-on", "critical"])
    assert result.exit_code == 0
    assert "No drift detected" in result.stdout

def test_cli_remediate_from_scan(monkeypatch, tmp_path):
    scan_data = {
        "region": "ap-south-1",
        "total_scanned": 1,
        "results": [
            {
                "resource_type": "aws_s3_bucket",
                "resource_id": "b-from-scan",
                "resource_name": "b-from-scan",
                "drift_type": "MODIFIED",
                "severity": "LOW",
                "diff": {"tags": {"terraform": {"Env": "prod"}, "live": {"Env": "dev"}}},
                "live_attributes": {},
                "tf_attributes": {},
                "ai_analysis": ""
            }
        ]
    }
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(scan_data))

    called = []
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("detect_drift should not be called")))
    monkeypatch.setattr("driftwatch.cli.process_remediation", lambda res, auto_approve=False, profile=None: called.append(res))

    result = runner.invoke(app, ["remediate", "b-from-scan", "--from-scan", str(scan_file), "--apply", "--yes"])
    assert result.exit_code == 0
    assert len(called) == 1
    assert called[0][0].resource_id == "b-from-scan"

def test_cli_scan_with_unmanaged_ec2_and_cost_unavailable(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_instance",
            resource_id="i-untracked-no-ce",
            drift_type=DriftType.UNMANAGED,
            resource_name="manual-ec2",
            live_attributes={"instance_type": "t3.medium"}
        )
    ]
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    monkeypatch.setattr("driftwatch.cli.get_resource_cost", lambda rid, profile=None: None)
    monkeypatch.setattr("driftwatch.cli.get_drift_explanation", lambda rt, rid, diff, dt: "")
    monkeypatch.setattr("driftwatch.cli.process_alerts", lambda res: None)
    monkeypatch.setattr("driftwatch.cli.save_drift_to_db", lambda res: None)

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file)])
    assert result.exit_code == 0
    assert "Cost: unavailable" in result.stdout
    assert "$0.00" not in result.stdout


# --- C1 regression: ALL six AWS fetch functions return None ---
def test_cli_scan_all_aws_fetches_fail_exits_nonzero(tmp_path, monkeypatch):
    """C1: When every AWS resource type fails to fetch, scan must exit non-zero
    and NOT print 'No drift detected'."""
    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text(json.dumps({"resources": []}))
    monkeypatch.setattr("driftwatch.cli._resolve_region", lambda r, profile=None: "ap-south-1")
    monkeypatch.setattr("drift_engine.core.fetch_live_ec2_instances", lambda reg, profile=None: None)
    monkeypatch.setattr("drift_engine.core.fetch_live_s3_buckets", lambda reg, profile=None: None)
    monkeypatch.setattr("drift_engine.core.fetch_live_security_groups", lambda reg, profile=None: None)
    monkeypatch.setattr("drift_engine.core.fetch_live_rds_instances", lambda reg, profile=None: None)
    monkeypatch.setattr("drift_engine.core.fetch_live_lambda_functions", lambda reg, profile=None: None)
    monkeypatch.setattr("drift_engine.core.fetch_live_iam_roles", lambda reg, profile=None: None)

    result = runner.invoke(app, ["scan", "--state", str(state_file), "--region", "ap-south-1"])
    assert result.exit_code != 0, f"Expected non-zero exit when all AWS fetches fail, got {result.exit_code}"
    assert "No drift detected" not in result.stdout
    assert "Failed to fetch live AWS resources" in result.stdout


# --- M1 regression: --version output matches importlib.metadata ---
def test_cli_version_matches_package_metadata():
    """M1: --version must print the version from package metadata, not a hardcoded string."""
    import importlib.metadata
    try:
        expected = importlib.metadata.version("driftwatch-cli")
    except Exception:
        pytest.skip("driftwatch-cli not installed as a package in this environment")
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert expected in result.stdout


# --- M4 regression: --profile is threaded into process_remediation ---
def test_cli_remediate_profile_passed_to_remediation(monkeypatch, tmp_path):
    """M4: When --profile is passed to remediate, it must be forwarded to process_remediation."""
    mock_results = [
        DriftResult(
            resource_type="aws_s3_bucket",
            resource_id="b-prof",
            drift_type=DriftType.MODIFIED,
            resource_name="b-prof",
            diff={"tags": {"terraform": {}, "live": {}}}
        )
    ]
    captured_kwargs = []
    def fake_remediation(res, auto_approve=False, profile=None):
        captured_kwargs.append({"auto_approve": auto_approve, "profile": profile})
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    monkeypatch.setattr("driftwatch.cli.process_remediation", fake_remediation)

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, [
        "remediate", "b-prof", "--region", "ap-south-1", "--state", str(state_file),
        "--apply", "--yes", "--profile", "staging"
    ])
    assert result.exit_code == 0
    assert len(captured_kwargs) == 1
    assert captured_kwargs[0]["profile"] == "staging"


# --- M6 regression: --from-scan must NOT call any fetch_live function ---
def test_cli_explain_from_scan_does_not_call_fetch_live(monkeypatch, tmp_path):
    """M6: When --from-scan is used, no live AWS fetching should occur."""
    scan_data = {
        "region": "ap-south-1",
        "total_scanned": 1,
        "results": [
            {
                "resource_type": "aws_instance",
                "resource_id": "i-cached",
                "resource_name": "cached-ec2",
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
    monkeypatch.setattr("driftwatch.cli.get_drift_explanation", lambda rt, rid, diff, dt: "Cached analysis.")

    # Plant bombs: if any fetch_live is called, the test explodes
    def _boom(*a, **kw):
        raise AssertionError("fetch_live_* should not be called when --from-scan is used")
    monkeypatch.setattr("driftwatch.cli.detect_drift", _boom)

    result = runner.invoke(app, ["explain", "i-cached", "--from-scan", str(scan_file)])
    assert result.exit_code == 0
    assert "Cached analysis" in result.stdout


def test_cli_remediate_from_scan_does_not_call_fetch_live(monkeypatch, tmp_path):
    """M6: When --from-scan is used with remediate, no live AWS fetching should occur."""
    scan_data = {
        "region": "ap-south-1",
        "total_scanned": 1,
        "results": [
            {
                "resource_type": "aws_s3_bucket",
                "resource_id": "b-cached",
                "resource_name": "b-cached",
                "drift_type": "MODIFIED",
                "severity": "LOW",
                "diff": {"tags": {"terraform": {"Env": "prod"}, "live": {"Env": "dev"}}},
                "live_attributes": {},
                "tf_attributes": {},
                "ai_analysis": ""
            }
        ]
    }
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(scan_data))

    called = []
    def _boom(*a, **kw):
        raise AssertionError("detect_drift should not be called when --from-scan is used")
    monkeypatch.setattr("driftwatch.cli.detect_drift", _boom)
    monkeypatch.setattr("driftwatch.cli.process_remediation", lambda res, auto_approve=False, profile=None: called.append(res))

    result = runner.invoke(app, ["remediate", "b-cached", "--from-scan", str(scan_file), "--apply", "--yes"])
    assert result.exit_code == 0
    assert len(called) == 1


# --- M7 regression: batch remediation with 3 resources ---
def test_cli_remediate_all_flag_three_resources(monkeypatch, tmp_path):
    """M7: --all against 3 drifted resources calls process_remediation once with all 3."""
    mock_results = [
        DriftResult(resource_type="aws_s3_bucket", resource_id="b-1", drift_type=DriftType.MODIFIED,
                    resource_name="b-1", diff={"tags": {"terraform": {}, "live": {}}}),
        DriftResult(resource_type="aws_s3_bucket", resource_id="b-2", drift_type=DriftType.MODIFIED,
                    resource_name="b-2", diff={"tags": {"terraform": {}, "live": {}}}),
        DriftResult(resource_type="aws_s3_bucket", resource_id="b-3", drift_type=DriftType.MODIFIED,
                    resource_name="b-3", diff={"tags": {"terraform": {}, "live": {}}}),
    ]
    called = []
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 3))
    monkeypatch.setattr("driftwatch.cli.process_remediation", lambda res, auto_approve=False, profile=None: called.append(res))

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["remediate", "--all", "--region", "ap-south-1", "--state", str(state_file), "--apply", "--yes"])
    assert result.exit_code == 0
    assert len(called) == 1, f"process_remediation should be called once, was called {len(called)} times"
    assert len(called[0]) == 3, f"Expected 3 resources in batch, got {len(called[0])}"


# --- M8 regression: cost unavailable for MODIFIED resources ---
def test_cli_scan_modified_resource_cost_unavailable(monkeypatch, tmp_path):
    """M8: When Cost Explorer fails for a MODIFIED EC2/RDS/Lambda, output should say
    'unavailable' not '$0.00' or just omit cost."""
    mock_results = [
        DriftResult(
            resource_type="aws_instance",
            resource_id="i-modified-no-ce",
            drift_type=DriftType.MODIFIED,
            resource_name="modified-ec2",
            diff={"instance_type": {"terraform": "t3.micro", "live": "t3.large"}}
        )
    ]
    monkeypatch.setattr("driftwatch.cli.detect_drift", lambda state, reg, profile=None: (mock_results, 1))
    monkeypatch.setattr("driftwatch.cli.get_resource_cost", lambda rid, profile=None: None)
    monkeypatch.setattr("driftwatch.cli.get_drift_explanation", lambda rt, rid, diff, dt: "")
    monkeypatch.setattr("driftwatch.cli.process_alerts", lambda res: None)
    monkeypatch.setattr("driftwatch.cli.save_drift_to_db", lambda res: None)

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--region", "ap-south-1", "--state", str(state_file)])
    assert result.exit_code == 0
    assert "unavailable" in result.stdout.lower()
    assert "$0.00" not in result.stdout


