from remediation import process_remediation
import boto3
import json
import os
import urllib.request
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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
    "aws_security_group": {
        "owner_id", "ingress", "egress"
    },
    "aws_s3_bucket": {
        "arn", "bucket_domain_name", "bucket_regional_domain_name",
        "hosted_zone_id", "region", "request_payer",
        "tags_all"
    },
    "aws_db_instance": {
        "engine_version"
    }
}

def load_terraform_state(state_path: str) -> dict:
    with open(state_path) as f:
        state = json.load(f)
    
    resources = {}
    for resource in state.get("resources", []):
        r_type = resource["type"]
        
        if r_type in ["archive_file", "aws_iam_role_policy_attachment"]:
            continue
            
        for instance in resource.get("instances", []):
            attrs = instance.get("attributes", {})
            resource_id = attrs.get("id")
            
            tags = attrs.get("tags", {})
            if tags and tags.get("Name"):
                name = tags.get("Name")
            elif r_type == "aws_lambda_function":
                name = attrs.get("function_name", "Unknown")
            elif r_type == "aws_db_instance":
                name = attrs.get("identifier", "Unknown")
            elif r_type == "aws_iam_role":
                name = attrs.get("name", "Unknown")
            else:
                name = "Unknown"
            
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
                
                ingress_rules = []
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        ingress_rules.append({
                            "from_port": perm.get("FromPort", 0),
                            "to_port": perm.get("ToPort", 0),
                            "protocol": perm.get("IpProtocol", "-1"),
                            "cidr_blocks": [ip_range.get("CidrIp")]
                        })
                
                egress_rules = []
                for perm in sg.get("IpPermissionsEgress", []):
                    for ip_range in perm.get("IpRanges", []):
                        egress_rules.append({
                            "from_port": perm.get("FromPort", 0),
                            "to_port": perm.get("ToPort", 0),
                            "protocol": perm.get("IpProtocol", "-1"),
                            "cidr_blocks": [ip_range.get("CidrIp")]
                        })
                
                live[sg_id] = {
                    "type": "aws_security_group",
                    "name": name_tag,
                    "attributes": {
                        "id": sg_id,
                        "name": sg_name,
                        "description": sg.get("Description", ""),
                        "tags": tags_dict,
                        "ingress": ingress_rules,
                        "egress": egress_rules,
                    },
                }
    except Exception as e:
        print(f"Error fetching Security Groups: {e}")
        
    return live

def fetch_live_rds_instances(region: str = "ap-south-1") -> dict:
    rds = boto3.client("rds", region_name=region)
    live = {}
    paginator = rds.get_paginator("describe_db_instances")
    
    try:
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db.get("DbiResourceId") 
                db_name = db["DBInstanceIdentifier"]
                
                if not db_id:
                    continue
                
                live[db_id] = {
                    "type": "aws_db_instance",
                    "name": db_name,
                    "attributes": {
                        "id": db_id,
                        "allocated_storage": db.get("AllocatedStorage"),
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "instance_class": db.get("DBInstanceClass"),
                        "multi_az": db.get("MultiAZ"),
                    },
                }
    except Exception as e:
        print(f"Error fetching RDS instances: {e}")
        
    return live

def fetch_live_lambda_functions(region: str = "ap-south-1") -> dict:
    lambda_client = boto3.client("lambda", region_name=region)
    live = {}
    paginator = lambda_client.get_paginator("list_functions")
    
    try:
        for page in paginator.paginate():
            for func in page["Functions"]:
                func_name = func["FunctionName"]
                
                live[func_name] = {
                    "type": "aws_lambda_function",
                    "name": func_name,
                    "attributes": {
                        "id": func_name,
                        "function_name": func_name,
                        "runtime": func.get("Runtime"),
                        "handler": func.get("Handler"),
                        "memory_size": func.get("MemorySize"),
                        "timeout": func.get("Timeout"),
                        "role": func.get("Role"),
                    },
                }
    except Exception as e:
        print(f"Error fetching Lambda functions: {e}")
        
    return live

def fetch_live_iam_roles(region: str = "ap-south-1") -> dict:
    iam = boto3.client("iam", region_name=region)
    live = {}
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                
                if role_name.startswith("AWSServiceRoleFor") or role.get("Path", "").startswith("/aws-service-role/"):
                    continue
                    
                live[role_name] = {
                    "type": "aws_iam_role",
                    "name": role_name,
                    "attributes": {
                        "id": role_name,
                        "name": role_name,
                        "arn": role["Arn"]
                    }
                }
    except Exception as e:
        print(f"Error fetching IAM roles: {e}")
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

def send_slack_alert(webhook_url: str, drift_results: list):
    if not webhook_url:
        return

    message_lines = ["*DriftWatch Alert: Infrastructure Drift Detected!*"]
    for r in drift_results:
        line = f"• [{r.drift_type.value}] {r.resource_type}: {r.resource_name} ({r.resource_id})"
        message_lines.append(line)
        if r.diff:
            for attr, vals in r.diff.items():
                message_lines.append(f"    - {attr}: Expected '{vals['terraform']}', Found '{vals['live']}'")

    payload = {"text": "\n".join(message_lines)}
    req = urllib.request.Request(
        webhook_url, 
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        urllib.request.urlopen(req)
        print("✅ Slack alert sent successfully.")
    except Exception as e:
        print(f"❌ Failed to send Slack alert: {e}")

def send_email_alert(smtp_server: str, smtp_port: int, sender_email: str, sender_password: str, recipient_email: str, drift_results: list):
    if not all([smtp_server, sender_email, sender_password, recipient_email]):
        return

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = "DriftWatch Alert: Infrastructure Drift Detected"

    body_lines = ["DriftWatch has detected changes in your infrastructure:\n"]
    for r in drift_results:
        line = f"[{r.drift_type.value}] {r.resource_type}: {r.resource_name} ({r.resource_id})"
        body_lines.append(line)
        if r.diff:
            for attr, vals in r.diff.items():
                body_lines.append(f"    - {attr}: Expected '{vals['terraform']}', Found '{vals['live']}'")

    msg.attach(MIMEText("\n".join(body_lines), 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        print("✅ Email alert sent successfully.")
    except Exception as e:
        print(f"❌ Failed to send Email alert: {e}")

def process_alerts(drift_results: list):
    if not drift_results:
        return
        
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    sender_email = os.environ.get("SENDER_EMAIL")
    sender_password = os.environ.get("SENDER_PASSWORD")
    recipient_email = os.environ.get("RECIPIENT_EMAIL")

    if slack_webhook:
        send_slack_alert(slack_webhook, drift_results)
    
    if sender_email and sender_password and recipient_email:
        send_email_alert(smtp_server, smtp_port, sender_email, sender_password, recipient_email, drift_results)

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
            
            process_alerts(results)
            process_remediation(results)
                        
    except Exception as e:
        print(f"Error during execution: {e}")

if __name__ == "__main__":
    main()