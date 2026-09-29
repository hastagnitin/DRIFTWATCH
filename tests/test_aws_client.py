import pytest
import boto3
import zipfile
import io
from datetime import datetime
from moto import mock_aws
from drift_engine.aws_client import (
    get_boto3_session,
    get_boto3_client,
    fetch_live_ec2_instances,
    fetch_live_s3_buckets,
    fetch_live_security_groups,
    fetch_live_rds_instances,
    fetch_live_lambda_functions,
    fetch_live_iam_roles,
    get_resource_cost,
    get_resource_cost_status,
    get_resource_cost_details,
    clear_cost_cache,
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

def test_get_resource_cost_graceful_fallback(monkeypatch):
    """Hermetic test: When Cost Explorer raises an error, get_resource_cost returns None."""
    clear_cost_cache()

    class ErrorCE:
        def get_cost_and_usage(self, **kwargs):
            raise Exception("CE Service Unavailable")

    monkeypatch.setattr("drift_engine.aws_client.get_boto3_client", lambda s, profile=None, region=None: ErrorCE())
    cost = get_resource_cost("non-existent-res")
    assert cost is None
    assert get_resource_cost_status("non-existent-res") == "unavailable"


def test_get_resource_cost_sums_multiple_periods(monkeypatch):
    """P2.3: Verify that get_resource_cost sums across ALL returned periods in the 30-day window."""
    clear_cost_cache()

    class MultiPeriodCE:
        def get_cost_and_usage(self, **kwargs):
            return {
                "ResultsByTime": [
                    {
                        "TimePeriod": {"Start": "2026-08-30", "End": "2026-09-01"},
                        "Total": {"UnblendedCost": {"Amount": "14.25", "Unit": "USD"}}
                    },
                    {
                        "TimePeriod": {"Start": "2026-09-01", "End": "2026-09-29"},
                        "Total": {"UnblendedCost": {"Amount": "25.75", "Unit": "USD"}}
                    }
                ]
            }

    monkeypatch.setattr("drift_engine.aws_client.get_boto3_client", lambda s, profile=None, region=None: MultiPeriodCE())

    cost = get_resource_cost("i-multi-period")
    assert cost == 40.00
    assert get_resource_cost_status("i-multi-period") == "available"

    details = get_resource_cost_details("i-multi-period")
    assert details["cost"] == 40.00
    assert details["status"] == "available"
    assert details["periods_counted"] == 2


def test_get_resource_cost_pagination(monkeypatch):
    """P2.3: Verify that get_resource_cost handles pagination via NextPageToken."""
    clear_cost_cache()
    calls = []

    class PaginatedCE:
        def get_cost_and_usage(self, **kwargs):
            calls.append(kwargs)
            if "NextPageToken" not in kwargs:
                return {
                    "NextPageToken": "page-2-token",
                    "ResultsByTime": [
                        {"Total": {"UnblendedCost": {"Amount": "10.00"}}}
                    ]
                }
            return {
                "ResultsByTime": [
                    {"Total": {"UnblendedCost": {"Amount": "15.50"}}}
                ]
            }

    monkeypatch.setattr("drift_engine.aws_client.get_boto3_client", lambda s, profile=None, region=None: PaginatedCE())

    cost = get_resource_cost("i-paginated")
    assert cost == 25.50
    assert len(calls) == 2
    assert calls[1].get("NextPageToken") == "page-2-token"


def test_get_resource_cost_distinguishes_no_data(monkeypatch):
    """P2.3: Distinguish 'no cost data' (empty ResultsByTime) from 'query unavailable'."""
    clear_cost_cache()

    class EmptyCE:
        def get_cost_and_usage(self, **kwargs):
            return {"ResultsByTime": []}

    monkeypatch.setattr("drift_engine.aws_client.get_boto3_client", lambda s, profile=None, region=None: EmptyCE())

    cost = get_resource_cost("i-no-data")
    assert cost is None
    assert get_resource_cost_status("i-no-data") == "no_data"

    details = get_resource_cost_details("i-no-data")
    assert details["cost"] is None
    assert details["status"] == "no_data"
    assert details["periods_counted"] == 0
    assert details["error"] is None


def test_get_resource_cost_query_unavailable_logs_stderr(monkeypatch, capsys):
    """P2.3: Query error logs to stderr and marks status as 'unavailable'."""
    clear_cost_cache()

    class FailingCE:
        def get_cost_and_usage(self, **kwargs):
            raise RuntimeError("AccessDeniedException: not authorized to call ce:GetCostAndUsage")

    monkeypatch.setattr("drift_engine.aws_client.get_boto3_client", lambda s, profile=None, region=None: FailingCE())

    cost = get_resource_cost("i-fail-perm")
    assert cost is None
    assert get_resource_cost_status("i-fail-perm") == "unavailable"

    captured = capsys.readouterr()
    assert "Failed to fetch cost for i-fail-perm" in captured.err
    assert "AccessDeniedException" in captured.err

    details = get_resource_cost_details("i-fail-perm")
    assert details["status"] == "unavailable"
    assert "AccessDeniedException" in details["error"]


def test_get_resource_cost_utc_date_range(monkeypatch):
    """P2.3: Date range passed to CE must span exactly 30 days in YYYY-MM-DD."""
    clear_cost_cache()
    captured_kwargs = {}

    class InspectingCE:
        def get_cost_and_usage(self, **kwargs):
            captured_kwargs.update(kwargs)
            return {"ResultsByTime": []}

    monkeypatch.setattr("drift_engine.aws_client.get_boto3_client", lambda s, profile=None, region=None: InspectingCE())

    get_resource_cost("i-date-check")
    time_period = captured_kwargs.get("TimePeriod", {})
    start = datetime.strptime(time_period["Start"], "%Y-%m-%d")
    end = datetime.strptime(time_period["End"], "%Y-%m-%d")
    assert (end - start).days == 30


def test_get_boto3_session_with_profile(monkeypatch):
    captured = []
    _real_session = boto3.Session

    def _spy_session(**kwargs):
        captured.append(kwargs)
        return _real_session(**{k: v for k, v in kwargs.items() if k != "profile_name"})

    monkeypatch.setattr("boto3.Session", _spy_session)
    session = get_boto3_session(profile="my-prod-profile", region="us-east-1")
    assert len(captured) >= 1
    assert captured[0].get("profile_name") == "my-prod-profile"
    assert captured[0].get("region_name") == "us-east-1"
