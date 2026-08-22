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

MONITORED_ATTRIBUTES = {
    "aws_instance": {"instance_type", "ami", "tags", "vpc_security_group_ids"},
    "aws_security_group": {"ingress", "egress", "description"},
    "aws_s3_bucket": {"bucket", "tags"},
    "aws_db_instance": {"instance_class", "engine", "allocated_storage", "engine_version", "multi_az"},
    "aws_lambda_function": {"runtime", "handler", "memory_size", "timeout", "role"},
    "aws_iam_role": {"attached_policies", "path"}
}

MONITORED_RESOURCES = list(MONITORED_ATTRIBUTES.keys())

ATTRIBUTE_SEVERITY = {
    "aws_security_group": {
        "ingress": "CRITICAL",
        "egress": "CRITICAL",
        "description": "LOW"
    },
    "aws_instance": {
        "instance_type": "HIGH",
        "ami": "MEDIUM",
        "vpc_security_group_ids": "HIGH",
        "tags": "LOW"
    },
    "aws_iam_role": {
        "attached_policies": "CRITICAL",
        "path": "LOW"
    },
    "aws_db_instance": {
        "instance_class": "HIGH",
        "allocated_storage": "MEDIUM",
        "engine": "HIGH",
        "engine_version": "MEDIUM",
        "multi_az": "HIGH"
    },
    "aws_s3_bucket": {
        "bucket": "HIGH",
        "tags": "LOW"
    },
    "aws_lambda_function": {
        "runtime": "HIGH",
        "handler": "HIGH",
        "memory_size": "MEDIUM",
        "timeout": "MEDIUM",
        "role": "HIGH"
    }
}