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
    resource_name: str
    tf_attributes: dict = field(default_factory=dict)
    live_attributes: dict = field(default_factory=dict)
    diff: dict = field(default_factory=dict)

IGNORED_ATTRIBUTES = {
    "aws_instance": {
        "private_ip", "public_ip", "network_interface_id",
        "instance_state", "private_dns", "public_dns",
        "tags_all"
    },
    "aws_security_group": {"owner_id"},
    "aws_s3_bucket": {
        "arn", "bucket_domain_name", "bucket_regional_domain_name",
        "hosted_zone_id", "region", "request_payer",
        "tags_all"
    }
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
            
            tags = attrs.get("tags", {})
            name = tags.get("Name") if tags else "Unknown"
            
            if resource_id:
                resources[resource_id] = {
                    "type": r_type, 
                    "name": name, 
                    "attributes": attrs
                }
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
                
                tags_list = instance.get("Tags", [])
                tags_dict = {t["Key"]: t["Value"] for t in tags_list}
                name = tags_dict.get("Name", "Unknown")
                
                live[instance["InstanceId"]] = {
                    "type": "aws_instance",
                    "name": name,
                    "attributes": {
                        "id": instance["InstanceId"],
                        "instance_type": instance["InstanceType"],
                        "ami": instance["ImageId"],
                        "tags": tags_dict,
                    },
                }
    return live

def fetch_live_s3_buckets(region: str) -> dict:
    s3 = boto3.client("s3", region_name=region)
    live = {}
    
    try:
        response = s3.list_buckets()
        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]
            
            try:
                tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
                tags_list = tags_response.get("TagSet", [])
                tags_dict = {t["Key"]: t["Value"] for t in tags_list}
                name = tags_dict.get("Name", bucket_name)
            except Exception:
                tags_dict = {}
                name = bucket_name

            live[bucket_name] = {
                "type": "aws_s3_bucket",
                "name": name,
                "attributes": {
                    "id": bucket_name,
                    "bucket": bucket_name,
                    "tags": tags_dict,
                },
            }
    except Exception as e:
        print(f"Error fetching S3 buckets: {e}")
        
    return live

def fetch_live_security_groups(region: str) -> dict:
    ec2 = boto3.client("ec2", region_name=region)
    live = {}
    paginator = ec2.get_paginator("describe_security_groups")
    
    try:
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]
                
                tags_list = sg.get("Tags", [])
                tags_dict = {t["Key"]: t["Value"] for t in tags_list}
                name_tag = tags_dict.get("Name", sg_name)
                
                live[sg_id] = {
                    "type": "aws_security_group",
                    "name": name_tag,
                    "attributes": {
                        "id": sg_id,
                        "name": sg_name,
                        "description": sg.get("Description", ""),
                        "tags": tags_dict,
                    },
                }
    except Exception as e:
        print(f"Error fetching Security Groups: {e}")
        
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
    
    live_ec2 = fetch_live_ec2_instances(region)
    live_s3 = fetch_live_s3_buckets(region)
    live_sg = fetch_live_security_groups(region)
    
    live_resources = {**live_ec2, **live_s3, **live_sg}
    
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
    print("--------------------------------------------------")
    print("DriftWatch Engine Started")
    print("--------------------------------------------------")
    
    tf_state_path = "/root/driftwatch/terraform/terraform.tfstate"
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    
    try:
        results = detect_drift(tf_state_path, region)
        
        if not results:
            print("✅ No drift detected. Infrastructure matches IaC.")
        else:
            for r in results:
                print(f"[{r.drift_type.value}] {r.resource_type}: {r.resource_name} ({r.resource_id})")
                if r.diff:
                    for attr, vals in r.diff.items():
                        print(f"  ⚠️ {attr}: Expected '{vals['terraform']}', Found '{vals['live']}'")
                        
    except Exception as e:
        print(f"Error during execution: {e}")

if __name__ == "__main__":
    main()