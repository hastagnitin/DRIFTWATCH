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
from explain import get_drift_explanation

def process_drift_results(resource_id, drift_status, ai_explanation=""):
    if drift_status in ["MODIFIED", "UNMANAGED"]:
        alert_msg = f"DRIFT ALERT\nResource: {resource_id}\nType: {drift_status}\nAction Required!\n\nAI Analysis:\n{ai_explanation}"
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

def detect_drift(tf_state_path: str, region: str):
    tf_resources = load_terraform_state(tf_state_path)
    
    if not tf_resources:
        return [], 0
        
    live_ec2 = fetch_live_ec2_instances(region)
    live_s3 = fetch_live_s3_buckets(region)
    live_sg = fetch_live_security_groups(region)
    live_rds = fetch_live_rds_instances(region)
    live_lambda = fetch_live_lambda_functions(region)
    live_iam = fetch_live_iam_roles(region)
    
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

def get_severity(r_type, d_type):
    if r_type in ["aws_security_group", "aws_iam_role"]:
        return "CRITICAL"
    if d_type == DriftType.MISSING or r_type == "aws_instance":
        return "HIGH"
    return "MEDIUM"

def get_genuine_cost(instance_type):
    prices = {
        "t2.micro": 0,
        "t3.micro": 850,
        "t3.small": 1700,
        "t3.large": 2847,
        "t3.medium": 3400
    }
    return prices.get(instance_type, 0)

def main():
    tf_state_path = os.environ.get("TF_STATE_PATH", "terraform/terraform.tfstate")
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    
    try:
        results, total_scanned = detect_drift(tf_state_path, region)
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")
        total_drift = len(results)
        
        print("\n=== DRIFTWATCH SCAN REPORT ===")
        print(f"Scan time: {current_time} | Resources scanned: {total_scanned}\n")
        
        if not results:
            print("No drift detected. Infrastructure matches IaC.")
        else:
            crit_count = 0
            high_count = 0
            
            for r in results:
                severity = get_severity(r.resource_type, r.drift_type)
                
                if severity == "CRITICAL":
                    crit_count += 1
                elif severity == "HIGH":
                    high_count += 1
                    
                print(f"[{r.drift_type.value}] {r.resource_type}: {r.resource_id}")
                
                ai_text = ""
                
                if r.drift_type == DriftType.UNMANAGED and r.resource_type == "aws_instance":
                    inst_type = r.live_attributes.get("instance_type", "unknown")
                    cost = "{:,}".format(get_genuine_cost(inst_type))
                    print(f"  Type: {inst_type} (created manually in console)")
                    print(f"  Severity: {severity} | Cost: +Rs.{cost}/month (untracked)")
                    
                    ai_text = get_drift_explanation(r.resource_type, r.resource_id, r.live_attributes)
                    
                elif r.diff:
                    for attr, vals in r.diff.items():
                        print(f"  Attribute: {attr}")
                        print(f"  Terraform: {vals['terraform']}")
                        print(f"  Live AWS:  {vals['live']}")
                    print(f"  Severity: {severity}")
                    
                    ai_text = get_drift_explanation(r.resource_type, r.resource_id, r.diff)
                else:
                    print(f"  Severity: {severity}")
                    ai_text = get_drift_explanation(r.resource_type, r.resource_id, {"status": "missing"})

                if ai_text:
                    print(f"  AI Analysis: {ai_text}\n")
                else:
                    print("\n")
                    
                process_drift_results(r.resource_id, r.drift_type.value, ai_text)
            
            print(f"Total drift found: {total_drift} resources  |  CRITICAL: {crit_count}  HIGH: {high_count}\n")
            
            process_alerts(results)
            save_drift_to_db(results)
            process_remediation(results)
                        
    except Exception as e:
        print(f"Error during execution: {e}")

if __name__ == "__main__":
    main()