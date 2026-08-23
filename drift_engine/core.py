import os
import sys
from drift_engine.models import (
    DriftResult,
    DriftType,
    MONITORED_ATTRIBUTES,
    ATTRIBUTE_SEVERITY
)
from drift_engine.tf_parser import load_terraform_state
from drift_engine.aws_client import (
    fetch_live_ec2_instances,
    fetch_live_s3_buckets,
    fetch_live_security_groups,
    fetch_live_rds_instances,
    fetch_live_lambda_functions,
    fetch_live_iam_roles
)

SEVERITY_LEVELS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def normalize_sg_rules(rules) -> list:
    normalized = []
    if not isinstance(rules, list):
        return normalized
        
    for rule in rules:
        if isinstance(rule, dict):
            cidrs = rule.get('cidr_blocks') or []
            if isinstance(cidrs, list):
                cidrs = tuple(sorted(cidrs))
            else:
                cidrs = tuple()
                
            normalized.append({
                'from_port': rule.get('from_port'),
                'to_port': rule.get('to_port'),
                'protocol': rule.get('protocol'),
                'cidr_blocks': cidrs
            })
            
    final_rules = []
    for t in {tuple(sorted(d.items())) for d in normalized}:
        rule_dict = dict(t)
        rule_dict['cidr_blocks'] = list(rule_dict['cidr_blocks'])
        final_rules.append(rule_dict)
        
    return final_rules

def compare_attributes(tf, live, r_type) -> dict:
    monitored = MONITORED_ATTRIBUTES.get(r_type, set())
    diff = {}
    
    for key in monitored:
        tf_val = tf.get(key)
        live_val = live.get(key)
        
        if (tf_val in [None, "", [], {}]) and (live_val in [None, "", [], {}]):
            continue
            
        if r_type == "aws_security_group" and key in ["ingress", "egress"]:
            tf_norm = normalize_sg_rules(tf_val)
            live_norm = normalize_sg_rules(live_val)
            if tf_norm != live_norm:
                diff[key] = {"terraform": tf_norm, "live": live_norm}
        elif tf_val != live_val:
            diff[key] = {"terraform": tf_val, "live": live_val}
            
    return diff

def detect_drift(tf_state_path: str, region: str, profile: str = None):
    tf_resources = load_terraform_state(tf_state_path)

    failed_types = set()

    live_ec2 = fetch_live_ec2_instances(region, profile=profile)
    if live_ec2 is None:
        failed_types.add("aws_instance")
        live_ec2 = {}

    live_s3 = fetch_live_s3_buckets(region, profile=profile)
    if live_s3 is None:
        failed_types.add("aws_s3_bucket")
        live_s3 = {}

    live_sg = fetch_live_security_groups(region, profile=profile)
    if live_sg is None:
        failed_types.add("aws_security_group")
        live_sg = {}

    live_rds = fetch_live_rds_instances(region, profile=profile)
    if live_rds is None:
        failed_types.add("aws_db_instance")
        live_rds = {}

    live_lambda = fetch_live_lambda_functions(region, profile=profile)
    if live_lambda is None:
        failed_types.add("aws_lambda_function")
        live_lambda = {}

    live_iam = fetch_live_iam_roles(region, profile=profile)
    if live_iam is None:
        failed_types.add("aws_iam_role")
        live_iam = {}

    if failed_types:
        raise RuntimeError(f"Failed to fetch live AWS resources for: {', '.join(sorted(failed_types))}")
        
    live_resources = {**live_ec2, **live_s3, **live_sg, **live_rds, **live_lambda, **live_iam}
    
    results = []
    all_ids = set(tf_resources) | set(live_resources)
    total_scanned = len(all_ids)
    
    for rid in all_ids:
        in_tf = rid in tf_resources
        in_live = rid in live_resources
        
        res_name = "Unknown"
        if in_tf:
            res_name = tf_resources[rid]["name"]
        elif in_live:
            res_name = live_resources[rid]["name"]
            
        if in_tf and not in_live:
            if tf_resources[rid]["type"] in failed_types:
                continue
            results.append(DriftResult(
                resource_type=tf_resources[rid]["type"],
                resource_id=rid,
                drift_type=DriftType.MISSING,
                resource_name=res_name,
                tf_attributes=tf_resources[rid]["attributes"]
            ))
        elif in_live and not in_tf:
            results.append(DriftResult(
                resource_type=live_resources[rid]["type"],
                resource_id=rid,
                drift_type=DriftType.UNMANAGED,
                resource_name=res_name,
                live_attributes=live_resources[rid]["attributes"]
            ))
        else:
            diff = compare_attributes(
                tf_resources[rid]["attributes"],
                live_resources[rid]["attributes"],
                tf_resources[rid]["type"]
            )
            if diff:
                results.append(DriftResult(
                    resource_type=tf_resources[rid]["type"],
                    resource_id=rid,
                    drift_type=DriftType.MODIFIED,
                    resource_name=res_name,
                    tf_attributes=tf_resources[rid]["attributes"],
                    live_attributes=live_resources[rid]["attributes"],
                    diff=diff
                ))
                
    return results, total_scanned

def get_severity(r_type: str, d_type: DriftType, diff: dict = None) -> str:
    if d_type == DriftType.MISSING or d_type == DriftType.UNMANAGED:
        if r_type in ["aws_security_group", "aws_iam_role"]:
            return "CRITICAL"
        return "HIGH"
        
    if diff:
        type_severity_map = ATTRIBUTE_SEVERITY.get(r_type, {})
        highest_sev = "LOW"
        for attr in diff.keys():
            attr_sev = type_severity_map.get(attr, "MEDIUM")
            if SEVERITY_LEVELS.get(attr_sev, 1) > SEVERITY_LEVELS.get(highest_sev, 0):
                highest_sev = attr_sev
        return highest_sev

    if r_type in ["aws_security_group", "aws_iam_role"]:
        return "CRITICAL"
    if r_type == "aws_instance":
        return "HIGH"
    return "MEDIUM"

if __name__ == "__main__":
    state_file = os.environ.get("TF_STATE_PATH", "terraform/terraform.tfstate")
    scan_region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    print(f"Executing DriftWatch Engine on {state_file} ({scan_region})...")
    drift_items, scanned = detect_drift(state_file, scan_region)
    print(f"Scanned {scanned} resources. Found {len(drift_items)} drift items.")
    for item in drift_items:
        sev = get_severity(item.resource_type, item.drift_type, item.diff)
        print(f" - [{item.drift_type.value}] {item.resource_type} ({item.resource_id}): Severity={sev}")