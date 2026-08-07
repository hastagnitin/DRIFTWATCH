import os
from datetime import datetime
from models import DriftResult, DriftType, MONITORED_RESOURCES, MONITORED_ATTRIBUTES, IGNORED_ATTRIBUTES
from tf_parser import load_terraform_state
from aws_client import (
    fetch_live_ec2_instances, fetch_live_s3_buckets,
    fetch_live_security_groups, fetch_live_rds_instances,
    fetch_live_lambda_functions, fetch_live_iam_roles
)
from notifications import process_alerts, send_telegram_alert
from database import save_drift_to_db
from remediation import process_remediation

def process_drift_results(resource_id, drift_status):
    if drift_status in ["MODIFIED", "UNMANAGED"]:
        alert_msg = f"DRIFT ALERT\nResource: {resource_id}\nType: {drift_status}\nAction Required!"
        send_telegram_alert(alert_msg)

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

def detect_drift(tf_state_path: str, region: str) -> list[DriftResult]:
    tf_resources = load_terraform_state(tf_state_path)
    
    if not tf_resources:
        return []
        
    live_ec2 = fetch_live_ec2_instances(region)
    live_s3 = fetch_live_s3_buckets(region)
    live_sg = fetch_live_security_groups(region)
    live_rds = fetch_live_rds_instances(region)
    live_lambda = fetch_live_lambda_functions(region)
    live_iam = fetch_live_iam_roles(region)
    
    live_resources = {**live_ec2, **live_s3, **live_sg, **live_rds, **live_lambda, **live_iam}
    
    results = []
    all_ids = set(tf_resources) | set(live_resources)
    
    for rid in all_ids:
        in_tf = rid in tf_resources
        in_live = rid in live_resources
        
        res_name = "Unknown"
        if in_tf:
            res_name = tf_resources[rid]["name"]
        elif in_live:
            res_name = live_resources[rid]["name"]
            
        if in_tf and not in_live:
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
                
    return results

def main():
    tf_state_path = os.environ.get("TF_STATE_PATH", "terraform/terraform.tfstate")
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    
    try:
        results = detect_drift(tf_state_path, region)
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")
        total_drift = len(results)
        
        print("\n=== DRIFTWATCH SCAN REPORT ===")
        print(f"Scan time: {current_time}")
        print("-" * 50)
        
        if not results:
            print("✅ No drift detected. Infrastructure matches IaC.")
        else:
            for r in results:
                print(f"\n[{r.drift_type.value}] {r.resource_type}: {r.resource_name} ({r.resource_id})")
                if r.diff:
                    for attr, vals in r.diff.items():
                        print(f"  Attribute: {attr}")
                        print(f"  Terraform: {vals['terraform']}")
                        print(f"  Live AWS:  {vals['live']}")
            
            print("-" * 50)
            print(f"Total drift found: {total_drift} resources\n")
            
            process_alerts(results)
            save_drift_to_db(results)
            process_remediation(results)
                        
    except Exception as e:
        print(f"Error during execution: {e}")

if __name__ == "__main__":
    main()