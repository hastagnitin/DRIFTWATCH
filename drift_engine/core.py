import os
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
    """Normalize security group rules for comparison.

    F2: Handles IPv6 CIDRs, prefix list IDs, and security group references
    in addition to IPv4 CIDRs.
    F17: Merges rules with same protocol/port by unioning source ranges.
    """
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

            ipv6_cidrs = rule.get('ipv6_cidr_blocks') or []
            if isinstance(ipv6_cidrs, list):
                ipv6_cidrs = tuple(sorted(ipv6_cidrs))
            else:
                ipv6_cidrs = tuple()

            prefix_ids = rule.get('prefix_list_ids') or []
            if isinstance(prefix_ids, list):
                prefix_ids = tuple(sorted(prefix_ids))
            else:
                prefix_ids = tuple()

            sg_refs = rule.get('security_groups') or []
            if isinstance(sg_refs, list):
                sg_refs = tuple(sorted(sg_refs))
            else:
                sg_refs = tuple()

            normalized.append({
                'from_port': rule.get('from_port'),
                'to_port': rule.get('to_port'),
                'protocol': rule.get('protocol'),
                'cidr_blocks': cidrs,
                'ipv6_cidr_blocks': ipv6_cidrs,
                'prefix_list_ids': prefix_ids,
                'security_groups': sg_refs
            })

    # F17: Merge rules with the same protocol/port by unioning source ranges
    merged = {}
    for rule in normalized:
        key = (rule['from_port'], rule['to_port'], rule['protocol'])
        if key in merged:
            existing = merged[key]
            existing['cidr_blocks'] = tuple(sorted(set(existing['cidr_blocks']) | set(rule['cidr_blocks'])))
            existing['ipv6_cidr_blocks'] = tuple(sorted(set(existing['ipv6_cidr_blocks']) | set(rule['ipv6_cidr_blocks'])))
            existing['prefix_list_ids'] = tuple(sorted(set(existing['prefix_list_ids']) | set(rule['prefix_list_ids'])))
            existing['security_groups'] = tuple(sorted(set(existing['security_groups']) | set(rule['security_groups'])))
        else:
            merged[key] = rule.copy()

    # Deduplicate and convert tuples back to lists for comparison
    final_rules = []
    for rule in merged.values():
        rule_copy = rule.copy()
        rule_copy['cidr_blocks'] = list(rule_copy['cidr_blocks'])
        rule_copy['ipv6_cidr_blocks'] = list(rule_copy['ipv6_cidr_blocks'])
        rule_copy['prefix_list_ids'] = list(rule_copy['prefix_list_ids'])
        rule_copy['security_groups'] = list(rule_copy['security_groups'])
        final_rules.append(rule_copy)

    # Sort by port/protocol for deterministic comparison
    final_rules.sort(key=lambda r: (r.get('from_port') or 0, r.get('to_port') or 0, r.get('protocol') or ''))
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


def _rekey_live(live_dict):
    """Re-key a live resource dict from {id: resource} to {(type, id): resource}.

    F5: Prevents collisions when different resource types share the same ID.
    """
    if not live_dict:
        return {}
    return {(v["type"], k): v for k, v in live_dict.items()}


class DriftScanResult(tuple):
    def __new__(cls, results, total_scanned, failed_services=None):
        return super().__new__(cls, (results, total_scanned))

    def __init__(self, results, total_scanned, failed_services=None):
        self.results = results
        self.total_scanned = total_scanned
        self.failed_services = failed_services or []

def detect_drift(tf_state_path: str, region: str, profile: str = None, allow_partial: bool = False):
    tf_resources = load_terraform_state(tf_state_path, profile=profile)

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

    ALL_SERVICE_TYPES = {"aws_instance", "aws_s3_bucket", "aws_security_group", "aws_db_instance", "aws_lambda_function", "aws_iam_role"}

    if failed_types:
        if failed_types >= ALL_SERVICE_TYPES:
            raise RuntimeError(f"Failed to fetch live AWS resources for all services: {', '.join(sorted(failed_types))}")
        if not allow_partial:
            raise RuntimeError(f"Failed to fetch live AWS resources for: {', '.join(sorted(failed_types))}. Pass --allow-partial to scan healthy services anyway.")

    # F5: Re-key live resources by (type, id) to prevent cross-type collisions
    live_resources = {
        **_rekey_live(live_ec2),
        **_rekey_live(live_s3),
        **_rekey_live(live_sg),
        **_rekey_live(live_rds),
        **_rekey_live(live_lambda),
        **_rekey_live(live_iam),
    }

    # Ensure all TF resources are keyed by (type, id)
    canonical_tf = {}
    for k, v in tf_resources.items():
        if isinstance(k, tuple) and len(k) == 2:
            canonical_tf[k] = v
        elif isinstance(k, str):
            r_type = v.get("type", "unknown") if isinstance(v, dict) else "unknown"
            canonical_tf[(r_type, k)] = v

    results = []
    all_keys = set(canonical_tf) | set(live_resources)
    total_scanned = len(all_keys)

    for composite_key in all_keys:
        r_type_key, rid = composite_key
        in_tf = composite_key in canonical_tf
        in_live = composite_key in live_resources

        res_name = "Unknown"
        if in_tf:
            res_name = canonical_tf[composite_key]["name"]
        elif in_live:
            res_name = live_resources[composite_key]["name"]

        if in_tf and not in_live:
            if canonical_tf[composite_key]["type"] in failed_types:
                continue
            results.append(DriftResult(
                resource_type=canonical_tf[composite_key]["type"],
                resource_id=rid,
                drift_type=DriftType.MISSING,
                resource_name=res_name,
                tf_attributes=canonical_tf[composite_key]["attributes"]
            ))
        elif in_live and not in_tf:
            results.append(DriftResult(
                resource_type=live_resources[composite_key]["type"],
                resource_id=rid,
                drift_type=DriftType.UNMANAGED,
                resource_name=res_name,
                live_attributes=live_resources[composite_key]["attributes"]
            ))
        else:
            diff = compare_attributes(
                canonical_tf[composite_key]["attributes"],
                live_resources[composite_key]["attributes"],
                canonical_tf[composite_key]["type"]
            )
            if diff:
                results.append(DriftResult(
                    resource_type=canonical_tf[composite_key]["type"],
                    resource_id=rid,
                    drift_type=DriftType.MODIFIED,
                    resource_name=res_name,
                    tf_attributes=canonical_tf[composite_key]["attributes"],
                    live_attributes=live_resources[composite_key]["attributes"],
                    diff=diff
                ))

    return DriftScanResult(results, total_scanned, failed_services=sorted(failed_types))


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
