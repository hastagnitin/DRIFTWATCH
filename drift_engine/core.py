import boto3
import json
import os
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
    tf_attributes: dict = field(default_factory=dict)
    live_attributes: dict = field(default_factory=dict)
    diff: dict = field(default_factory=dict)

IGNORED_ATTRIBUTES = {
    "aws_instance": {
        "private_ip", "public_ip", "network_interface_id",
        "instance_state", "private_dns", "public_dns",
    },
    "aws_security_group": {"owner_id"},
}

def load_terraform_state(state_path: str) -> dict:
    with open(state_path) as f:
        state = json.load(f)
    
    resources = {}
    for resource in state.get("resources", []):
        r_type = resource["type"]
        for instance in resource.get("instances", []):
            attrs = instance.get("attributes", {})
            resource_id = attrs.get("id")
            if resource_id:
                resources[resource_id] = {"type": r_type, "attributes": attrs}
    return resources

def fetch_live_ec2_instances(region: str) -> dict:
    ec2 = boto3.client("ec2", region_name=region)
    live = {}
    paginator = ec2.get_paginator("describe_instances")
    
    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                if instance["State"]["Name"] == "terminated":
                    continue
                
                live[instance["InstanceId"]] = {
                    "type": "aws_instance",
                    "attributes": {
                        "id": instance["InstanceId"],
                        "instance_type": instance["InstanceType"],
                        "ami": instance["ImageId"],
                    },
                }
    return live

def compare_attributes(tf_attrs: dict, live_attrs: dict, r_type: str) -> dict:
    ignored = IGNORED_ATTRIBUTES.get(r_type, set())
    diff = {}
    
    for key in set(tf_attrs) | set(live_attrs):
        if key in ignored:
            continue
            
        tf_val = tf_attrs.get(key)
        live_val = live_attrs.get(key)
        
        if tf_val != live_val and key in live_attrs:
            diff[key] = {"terraform": tf_val, "live": live_val}
            
    return diff

def detect_drift(tf_state_path: str, region: str) -> list[DriftResult]:
    tf_resources = load_terraform_state(tf_state_path)
    live_resources = fetch_live_ec2_instances(region)
    
    results = []
    all_ids = set(tf_resources) | set(live_resources)
    
    for rid in all_ids:
        in_tf = rid in tf_resources
        in_live = rid in live_resources
        
        if in_tf and not in_live:
            results.append(DriftResult(
                resource_type=tf_resources[rid]["type"],
                resource_id=rid,
                drift_type=DriftType.MISSING,
                tf_attributes=tf_resources[rid]["attributes"]
            ))
        elif in_live and not in_tf:
            results.append(DriftResult(
                resource_type=live_resources[rid]["type"],
                resource_id=rid,
                drift_type=DriftType.UNMANAGED,
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
                    tf_attributes=tf_resources[rid]["attributes"],
                    live_attributes=live_resources[rid]["attributes"],
                    diff=diff
                ))
                
    return results

def main():
    print("--------------------------------------------------")
    print("DriftWatch Engine Started")
    print("--------------------------------------------------")
    
    tf_state_path = "/root/driftwatch/terraform/terraform.tfstate"
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    
    try:
        results = detect_drift(tf_state_path, region)
        
        if not results:
            print("No drift detected. Infrastructure matches IaC.")
        else:
            for r in results:
                print(f"[{r.drift_type.value}] {r.resource_type}: {r.resource_id}")
                if r.diff:
                    for attr, vals in r.diff.items():
                        print(f"  - {attr}: Expected '{vals['terraform']}', Found '{vals['live']}'")
                        
    except Exception as e:
        print(f"Error during execution: {e}")

if __name__ == "__main__":
    main()