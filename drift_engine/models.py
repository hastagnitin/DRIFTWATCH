from dataclasses import dataclass, field
from enum import Enum

class DriftType(Enum):
    MISSING = "MISSING"
    MODIFIED = "MODIFIED"
    UNMANAGED = "UNMANAGED"

@dataclass
class DriftResult:
    resource_type: str
    resource_id: str
    drift_type: DriftType
    resource_name: str
    tf_attributes: dict = field(default_factory=dict)
    live_attributes: dict = field(default_factory=dict)
    diff: dict = field(default_factory=dict)
    ai_analysis: str = ""

IGNORED_ATTRIBUTES = {
    "aws_instance": {
        "private_ip", "public_ip", "network_interface_id",
        "instance_state", "private_dns", "public_dns", "tags_all"
    },
    "aws_security_group": {"owner_id"},
    "aws_s3_bucket": {
        "arn", "bucket_domain_name", "bucket_regional_domain_name",
        "hosted_zone_id", "region", "request_payer", "tags_all"
    },
    "aws_db_instance": {"engine_version"}
}

MONITORED_ATTRIBUTES = {
    "aws_instance": {"instance_type", "ami"},
    "aws_security_group": {"ingress", "egress", "description"},
    "aws_s3_bucket": {"bucket"},
    "aws_db_instance": {"instance_class", "engine", "allocated_storage"},
    "aws_lambda_function": {"runtime", "handler"},
    "aws_iam_role": {"attached_policies"}
}

MONITORED_RESOURCES = list(MONITORED_ATTRIBUTES.keys())