import json
import sys
import os
import subprocess
import tempfile
import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock

import driftwatch.cli as cli
from drift_engine.core import compare_attributes, normalize_sg_rules, detect_drift
from drift_engine.tf_parser import load_terraform_state
from drift_engine.models import DriftResult, DriftType
from drift_engine.explain import get_drift_explanation

runner = CliRunner()

# 1. Clean scans with every --fail-on threshold (F7)
@pytest.mark.parametrize("threshold", ["LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "medium", "high", "critical"])
@pytest.mark.parametrize("output_format", ["text", "json"])
def test_clean_scan_passes_all_fail_on_gates(monkeypatch, tmp_path, threshold, output_format):
    state_file = tmp_path / "empty_state.json"
    state_file.write_text('{"version": 4, "resources": []}')
    monkeypatch.setattr(cli, "_run_scan", lambda *args, **kwargs: ([], 0))

    args = ["scan", "--region", "us-east-1", "--state", str(state_file), "--fail-on", threshold]
    if output_format == "json":
        args.extend(["--output", "json"])

    result = runner.invoke(cli.app, args)
    assert result.exit_code == 0
    if output_format == "json":
        data = json.loads(result.stdout)
        assert data["drift_count"] == 0
        assert data["highest_severity"] == "NONE"


# 2. IPv6, prefix list, and security group reference changes (F2)
def test_ipv6_security_group_change_is_detected():
    tf = {
        "ingress": [{
            "from_port": 443, "to_port": 443, "protocol": "tcp",
            "cidr_blocks": [], "ipv6_cidr_blocks": [],
        }]
    }
    live = {
        "ingress": [{
            "from_port": 443, "to_port": 443, "protocol": "tcp",
            "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"],
        }]
    }
    diff = compare_attributes(tf, live, "aws_security_group")
    assert "ingress" in diff

def test_prefix_list_and_sg_reference_changes_detected():
    tf = {
        "egress": [{
            "from_port": 80, "to_port": 80, "protocol": "tcp",
            "prefix_list_ids": ["pl-12345"], "security_groups": ["sg-source1"]
        }]
    }
    live = {
        "egress": [{
            "from_port": 80, "to_port": 80, "protocol": "tcp",
            "prefix_list_ids": ["pl-99999"], "security_groups": ["sg-source1"]
        }]
    }
    diff = compare_attributes(tf, live, "aws_security_group")
    assert "egress" in diff


# 3. Saved-scan region forwarding into remediation (F1)
def test_remediate_from_scan_passes_saved_region(monkeypatch, tmp_path):
    saved = tmp_path / "scan.json"
    saved.write_text(
        '{"region":"eu-west-1","results":[{"resource_type":"aws_instance",'
        '"resource_id":"i-example","resource_name":"example",'
        '"drift_type":"MODIFIED","diff":{"instance_type":'
        '{"terraform":"t3.small","live":"t3.micro"}}}]}'
    )
    calls = []
    monkeypatch.setattr(cli, "process_remediation", lambda results, **kwargs: calls.append(kwargs))
    result = runner.invoke(
        cli.app,
        ["remediate", "i-example", "--from-scan", str(saved), "--apply", "--yes"],
    )
    assert result.exit_code == 0
    assert calls[0]["region"] == "eu-west-1"


# 4. Resource ID collisions across types (F5)
def test_resource_id_collision_across_types(tmp_path):
    state_content = {
        "version": 4,
        "resources": [
            {
                "type": "aws_instance",
                "instances": [{"attributes": {"id": "shared-id", "tags": {"Name": "MyInstance"}}}]
            },
            {
                "type": "aws_s3_bucket",
                "instances": [{"attributes": {"id": "shared-id", "bucket": "shared-id"}}]
            }
        ]
    }
    state_file = tmp_path / "collision.json"
    state_file.write_text(json.dumps(state_content))

    resources = load_terraform_state(str(state_file))
    assert len(resources) == 2
    assert ("aws_instance", "shared-id") in resources
    assert ("aws_s3_bucket", "shared-id") in resources
    assert resources[("aws_instance", "shared-id")]["name"] == "MyInstance"
    assert resources[("aws_s3_bucket", "shared-id")]["attributes"]["bucket"] == "shared-id"


# 5. IAM trust and inline policy monitoring (F3)
def test_iam_trust_policy_drift_detected():
    tf = {
        "assume_role_policy": '{"Version":"2012-10-17","Statement":[{"Action":"sts:AssumeRole","Principal":{"Service":"ec2.amazonaws.com"}}]}',
        "inline_policies": {"policy1": '{"Statement":[]}'}
    }
    live = {
        "assume_role_policy": '{"Version":"2012-10-17","Statement":[{"Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}]}',
        "inline_policies": {"policy1": '{"Statement":[]}'}
    }
    diff = compare_attributes(tf, live, "aws_iam_role")
    assert "assume_role_policy" in diff

def test_iam_inline_policy_drift_detected():
    tf = {
        "inline_policies": {"admin": '{"Effect":"Allow"}'}
    }
    live = {
        "inline_policies": {"admin": '{"Effect":"Deny"}'}
    }
    diff = compare_attributes(tf, live, "aws_iam_role")
    assert "inline_policies" in diff


# 6. JSON stdout purity with integrations enabled (F8)
def test_json_stdout_purity_with_integrations_enabled(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_instance",
            resource_id="i-test-pure",
            drift_type=DriftType.MODIFIED,
            resource_name="test-server",
            diff={"instance_type": {"terraform": "t3.micro", "live": "t3.large"}}
        )
    ]
    monkeypatch.setattr(cli, "_run_scan", lambda *args, **kwargs: (mock_results, 1))

    # Enable mock integrations that print to stdout/stderr
    monkeypatch.setattr(cli, "process_alerts", lambda res: print("SLACK NOTIFICATION SENT TO STDOUT"))
    monkeypatch.setattr(cli, "save_drift_to_db", lambda res: print("DB LOG SAVED TO STDOUT"))

    state_file = tmp_path / "state.json"
    state_file.write_text('{"version":4,"resources":[]}')

    result = runner.invoke(
        cli.app,
        ["scan", "--region", "us-east-1", "--state", str(state_file), "--output", "json"]
    )
    assert result.exit_code == 0
    # stdout MUST be valid JSON and parseable with no leading/trailing non-JSON text
    data = json.loads(result.stdout)
    assert data["drift_count"] == 1
    assert data["results"][0]["resource_id"] == "i-test-pure"


# 7. Sensitive JSON redaction (F4)
def test_sensitive_json_redaction(monkeypatch, tmp_path):
    mock_results = [
        DriftResult(
            resource_type="aws_db_instance",
            resource_id="db-secret-test",
            drift_type=DriftType.MODIFIED,
            resource_name="prod-db",
            diff={"master_password": {"terraform": "super_secret_123", "live": "old_pass"}},
            live_attributes={"master_password": "live_plaintext_password", "allocated_storage": 20},
            tf_attributes={"master_password": "tf_plaintext_password", "allocated_storage": 20}
        )
    ]
    monkeypatch.setattr(cli, "_run_scan", lambda *args, **kwargs: (mock_results, 1))
    monkeypatch.setattr(cli, "get_drift_explanation", lambda *args, **kwargs: "Mocked explanation")

    state_file = tmp_path / "state.json"
    state_file.write_text('{"version":4,"resources":[]}')

    # Default scan --output json should redact sensitive diff and omit raw attribute maps
    result = runner.invoke(
        cli.app,
        ["scan", "--region", "us-east-1", "--state", str(state_file), "--output", "json"]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    res = data["results"][0]

    # Diff should have sensitive values redacted
    assert res["diff"]["master_password"] == "[REDACTED]"
    # Raw attribute maps should be omitted by default
    assert res["live_attributes"] == {}
    assert res["tf_attributes"] == {}

    # With --include-raw, attribute maps are included but sensitive values are redacted
    result_raw = runner.invoke(
        cli.app,
        ["scan", "--region", "us-east-1", "--state", str(state_file), "--output", "json", "--include-raw"]
    )
    assert result_raw.exit_code == 0
    data_raw = json.loads(result_raw.stdout)
    res_raw = data_raw["results"][0]
    assert res_raw["live_attributes"]["master_password"] == "[REDACTED]"
    assert res_raw["live_attributes"]["allocated_storage"] == 20


# 8. Provider retry/backoff on rate limits (F19)
def test_groq_retry_on_429_rate_limit(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-mock-key")

    attempts = 0

    class Mock429Response:
        status_code = 429
        headers = {"Retry-After": "0.01"}
        def raise_for_status(self):
            import requests
            raise requests.exceptions.HTTPError(response=self)
        def json(self):
            return {"error": {"message": "Rate limited"}}

    class Mock200Response:
        status_code = 200
        headers = {}
        def raise_for_status(self): pass
        def json(self):
            return {
                "choices": [{
                    "message": {"content": "Analysis succeeded after retry."}
                }]
            }

    def mock_post(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return Mock429Response()
        return Mock200Response()

    monkeypatch.setattr("requests.post", mock_post)
    monkeypatch.setattr("time.sleep", lambda s: None)

    explanation = get_drift_explanation("aws_instance", "i-test", {"instance_type": {}}, "MODIFIED")
    assert "Analysis succeeded after retry" in explanation
    assert attempts == 2


# 9. Split vs combined CIDRs normalization (F17)
def test_split_vs_combined_cidrs_merge():
    # Split representation: two rules with different CIDR blocks
    split_rules = [
        {"from_port": 80, "to_port": 80, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]},
        {"from_port": 80, "to_port": 80, "protocol": "tcp", "cidr_blocks": ["192.168.0.0/16"]}
    ]
    # Combined representation: one rule with both CIDR blocks
    combined_rules = [
        {"from_port": 80, "to_port": 80, "protocol": "tcp", "cidr_blocks": ["192.168.0.0/16", "10.0.0.0/8"]}
    ]

    norm_split = normalize_sg_rules(split_rules)
    norm_combined = normalize_sg_rules(combined_rules)

    assert norm_split == norm_combined
    diff = compare_attributes({"ingress": split_rules}, {"ingress": combined_rules}, "aws_security_group")
    assert "ingress" not in diff


# 10. Importability from built wheel (F12)
def test_drift_engine_importable_from_installed_package():
    import drift_engine
    assert hasattr(drift_engine, "detect_drift")
    assert hasattr(drift_engine, "get_severity")
    assert hasattr(drift_engine, "DriftResult")
    assert hasattr(drift_engine, "DriftType")
