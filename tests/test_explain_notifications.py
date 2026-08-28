import sys
import pytest
from drift_engine.explain import get_deterministic_remediation_suggestion, get_drift_explanation
from drift_engine.notifications import (
    _format_drift_results,
    send_slack_alert,
    send_telegram_alert,
    send_email_alert,
    process_alerts
)
from drift_engine.database import save_drift_to_db
from drift_engine.models import DriftResult, DriftType

def test_deterministic_remediation_suggestions():
    
    unmanaged_cmd = get_deterministic_remediation_suggestion("aws_s3_bucket", "extra-bucket-123", {}, "UNMANAGED")
    assert "terraform import aws_s3_bucket.extra_bucket_123 extra-bucket-123" in unmanaged_cmd

   
    missing_cmd = get_deterministic_remediation_suggestion("aws_instance", "web-server-1", {}, "MISSING")
    assert "terraform apply -target=aws_instance.web_server_1" in missing_cmd

    
    diff_data = {"instance_type": {"terraform": "t3.micro", "live": "t3.large"}}
    modified_cmd = get_deterministic_remediation_suggestion("aws_instance", "web-server-1", diff_data, "MODIFIED")
    assert "terraform apply -target=aws_instance.web_server_1" in modified_cmd
    assert "t3.micro" in modified_cmd

def test_explain_without_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    explanation = get_drift_explanation("aws_instance", "i-123", {}, "MODIFIED")
    assert "AI explanation unavailable" in explanation

def test_explain_with_mock_groq_api(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-mock-key")

    class MockResponse:
        def raise_for_status(self): pass
        def json(self):
            return {
                "choices": [{
                    "message": {"content": "Potential security risk: Unmanaged port 22 exposes host."}
                }]
            }

    monkeypatch.setattr("requests.post", lambda url, json, headers, timeout: MockResponse())
    explanation = get_drift_explanation("aws_security_group", "sg-123", {"ingress": {}}, "MODIFIED")
    assert "Potential security risk" in explanation

def test_notifications_formatting():
    results = [
        DriftResult(
            resource_type="aws_instance",
            resource_id="i-123",
            drift_type=DriftType.MODIFIED,
            resource_name="web-1",
            diff={"instance_type": {"terraform": "t3.micro", "live": "t3.large"}},
            ai_analysis="Instance type drift detected."
        )
    ]
    lines = _format_drift_results(results, include_ai=True)
    formatted = "\n".join(lines)
    assert "[MODIFIED] aws_instance: web-1 (i-123)" in formatted
    assert "Expected 't3.micro', Found 't3.large'" in formatted
    assert "AI Analysis: Instance type drift detected." in formatted

def test_send_slack_alert_mock(monkeypatch):
    posted = []
    class MockResponse:
        def raise_for_status(self): pass

    monkeypatch.setattr("requests.post", lambda url, json, timeout: posted.append((url, json)) or MockResponse())
    results = [DriftResult(resource_type="aws_s3_bucket", resource_id="b-1", drift_type=DriftType.MISSING, resource_name="b-1")]
    send_slack_alert("https://hooks.slack.com/services/test", results)
    assert len(posted) == 1
    assert "DriftWatch Alert" in posted[0][1]["text"]

def test_send_telegram_alert_mock(monkeypatch):
    posted = []
    class MockResponse:
        def raise_for_status(self): pass

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "12345:mock-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654")
    monkeypatch.setattr("requests.post", lambda url, json, timeout: posted.append((url, json)) or MockResponse())
    
    send_telegram_alert("Test telegram alert")
    assert len(posted) == 1
    assert posted[0][1]["chat_id"] == "987654"

def test_send_email_alert_mock(monkeypatch):
    class MockSMTP:
        def __init__(self, host, port, timeout): pass
        def starttls(self): pass
        def login(self, u, p): pass
        def send_message(self, msg): pass
        def quit(self): pass

    monkeypatch.setattr("smtplib.SMTP", MockSMTP)
    results = [DriftResult(resource_type="aws_s3_bucket", resource_id="b-1", drift_type=DriftType.MISSING, resource_name="b-1")]
    send_email_alert("smtp.test.com", 587, "from@test.com", "pass", "to@test.com", results)

def test_process_alerts_all_channels(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "bot-tok")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "chat-id")
    monkeypatch.setenv("SENDER_EMAIL", "sender@test.com")
    monkeypatch.setenv("SENDER_PASSWORD", "pwd")
    monkeypatch.setenv("RECIPIENT_EMAIL", "rec@test.com")

    class MockResponse:
        def raise_for_status(self): pass

    class MockSMTP:
        def __init__(self, host, port, timeout): pass
        def starttls(self): pass
        def login(self, u, p): pass
        def send_message(self, msg): pass
        def quit(self): pass

    monkeypatch.setattr("requests.post", lambda url, json, timeout: MockResponse())
    monkeypatch.setattr("smtplib.SMTP", MockSMTP)

    results = [DriftResult(resource_type="aws_s3_bucket", resource_id="b-1", drift_type=DriftType.MISSING, resource_name="b-1")]
    process_alerts(results)
    process_alerts([])

def test_database_save_with_mock_psycopg2(monkeypatch):
    import types
    class MockCursor:
        def execute(self, query, params=None): pass
        def close(self): pass

    class MockConn:
        def cursor(self): return MockCursor()
        def commit(self): pass
        def close(self): pass

    mock_psycopg2 = types.ModuleType("psycopg2")
    mock_psycopg2.connect = lambda **kwargs: MockConn()
    monkeypatch.setitem(sys.modules, "psycopg2", mock_psycopg2)

    monkeypatch.setenv("DB_USER", "postgres")
    monkeypatch.setenv("DB_PASSWORD", "postgres")

    results = [
        DriftResult(
            resource_type="aws_s3_bucket",
            resource_id="b-1",
            drift_type=DriftType.MISSING,
            resource_name="b-1",
            diff={"tags": {"terraform": "A", "live": "B"}}
        )
    ]
    save_drift_to_db(results)
    save_drift_to_db([])

def test_database_save_skipped_without_creds(monkeypatch):
    monkeypatch.delenv("DB_USER", raising=False)
    monkeypatch.delenv("DB_PASSWORD", raising=False)
    results = [DriftResult(resource_type="aws_s3_bucket", resource_id="b-1", drift_type=DriftType.MISSING, resource_name="b-1")]
    save_drift_to_db(results)



    results = [DriftResult(resource_type="aws_s3_bucket", resource_id="b-1", drift_type=DriftType.MISSING, resource_name="b-1")]
    save_drift_to_db(results)
    captured = capsys.readouterr()
    assert "pip install driftwatch-cli[postgres]" in captured.out

