import os
import sys
import boto3
from datetime import datetime, timedelta

def get_boto3_session(profile: str = None, region: str = None) -> boto3.Session:
    actual_profile = profile or os.environ.get("AWS_PROFILE")
    actual_region = region or os.environ.get("AWS_DEFAULT_REGION")
    if actual_profile:
        return boto3.Session(profile_name=actual_profile, region_name=actual_region)
    return boto3.Session(region_name=actual_region)

def get_boto3_client(service_name: str, profile: str = None, region: str = None):
    session = get_boto3_session(profile=profile, region=region)
    return session.client(service_name, region_name=region or session.region_name)

def fetch_live_ec2_instances(region: str, profile: str = None) -> dict:
    ec2 = get_boto3_client("ec2", profile=profile, region=region)
    live = {}
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    if instance.get("State", {}).get("Name") == "terminated":
                        continue
                    
                    tags_list = instance.get("Tags", [])
                    tags_dict = {t["Key"]: t["Value"] for t in tags_list if "Key" in t and "Value" in t}
                    name = tags_dict.get("Name", "Unknown")
                    
                    sg_ids = []
                    for sg in instance.get("SecurityGroups", []):
                        if "GroupId" in sg:
                            sg_ids.append(sg.get("GroupId"))
                    sg_ids.sort()
                    
                    instance_id = instance["InstanceId"]
                    live[instance_id] = {
                        "type": "aws_instance",
                        "name": name,
                        "attributes": {
                            "id": instance_id,
                            "instance_type": instance.get("InstanceType"),
                            "ami": instance.get("ImageId"),
                            "tags": tags_dict,
                            "vpc_security_group_ids": sg_ids
                        },
                    }
    except Exception as e:
        print(f"Failed to fetch aws_instance: {e}", file=sys.stderr)
        return None
    return live

def fetch_live_s3_buckets(region: str, profile: str = None) -> dict:
    s3 = get_boto3_client("s3", profile=profile, region=region)
    live = {}
    try:
        response = s3.list_buckets()
        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]
            try:
                tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
                tags_list = tags_response.get("TagSet", [])
                tags_dict = {t["Key"]: t["Value"] for t in tags_list if "Key" in t and "Value" in t}
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
        print(f"Failed to fetch aws_s3_bucket: {e}", file=sys.stderr)
        return None
    return live

def fetch_live_security_groups(region: str, profile: str = None) -> dict:
    ec2 = get_boto3_client("ec2", profile=profile, region=region)
    live = {}
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")
                
                tags_list = sg.get("Tags", [])
                tags_dict = {t["Key"]: t["Value"] for t in tags_list if "Key" in t and "Value" in t}
                name_tag = tags_dict.get("Name", sg_name)
                
                ingress_rules = []
                for perm in sg.get("IpPermissions", []):
                    cidrs = [ip.get("CidrIp") for ip in perm.get("IpRanges", []) if ip.get("CidrIp")]
                    if cidrs:
                        ingress_rules.append({
                            "from_port": perm.get("FromPort", 0),
                            "to_port": perm.get("ToPort", 0),
                            "protocol": perm.get("IpProtocol", "-1"),
                            "cidr_blocks": cidrs
                        })
                
                egress_rules = []
                for perm in sg.get("IpPermissionsEgress", []):
                    cidrs = [ip.get("CidrIp") for ip in perm.get("IpRanges", []) if ip.get("CidrIp")]
                    if cidrs:
                        egress_rules.append({
                            "from_port": perm.get("FromPort", 0),
                            "to_port": perm.get("ToPort", 0),
                            "protocol": perm.get("IpProtocol", "-1"),
                            "cidr_blocks": cidrs
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
        print(f"Failed to fetch aws_security_group: {e}", file=sys.stderr)
        return None
    return live

def fetch_live_rds_instances(region: str, profile: str = None) -> dict:
    rds = get_boto3_client("rds", profile=profile, region=region)
    live = {}
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                db_id = db.get("DBInstanceIdentifier")
                if not db_id:
                    continue
                live[db_id] = {
                    "type": "aws_db_instance",
                    "name": db_id,
                    "attributes": {
                        "id": db_id,
                        "identifier": db_id,
                        "allocated_storage": db.get("AllocatedStorage"),
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "instance_class": db.get("DBInstanceClass"),
                        "multi_az": db.get("MultiAZ"),
                    },
                }
    except Exception as e:
        print(f"Failed to fetch aws_db_instance: {e}", file=sys.stderr)
        return None
    return live

def fetch_live_lambda_functions(region: str, profile: str = None) -> dict:
    lambda_client = get_boto3_client("lambda", profile=profile, region=region)
    live = {}
    try:
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page.get("Functions", []):
                func_name = func.get("FunctionName")
                if not func_name:
                    continue
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
        print(f"Failed to fetch aws_lambda_function: {e}", file=sys.stderr)
        return None
    return live

def fetch_live_iam_roles(region: str, profile: str = None) -> dict:
    iam = get_boto3_client("iam", profile=profile, region=region)
    live = {}
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role.get("RoleName")
                if not role_name:
                    continue
                if role_name.startswith("AWSServiceRoleFor") or role.get("Path", "").startswith("/aws-service-role/"):
                    continue
                
                try:
                    policies = iam.list_attached_role_policies(RoleName=role_name)
                    attached_policies = sorted(
                        p["PolicyArn"] for p in policies.get("AttachedPolicies", []) if "PolicyArn" in p
                    )
                except Exception:
                    attached_policies = []
                
                live[role_name] = {
                    "type": "aws_iam_role",
                    "name": role_name,
                    "attributes": {
                        "id": role_name,
                        "name": role_name,
                        "path": role.get("Path", "/"),
                        "arn": role.get("Arn", ""),
                        "attached_policies": attached_policies
                    }
                }
    except Exception as e:
        print(f"Failed to fetch aws_iam_role: {e}", file=sys.stderr)
        return None
    return live

def get_resource_cost(resource_id: str, profile: str = None) -> float | None:
    try:
        client = get_boto3_client("ce", profile=profile, region="us-east-1")
        
        end_date = datetime.today().strftime("%Y-%m-%d")
        start_date = (datetime.today() - timedelta(days=30)).strftime("%Y-%m-%d")
        
        response = client.get_cost_and_usage(
            TimePeriod={"Start": start_date, "End": end_date},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            Filter={
                "Dimensions": {
                    "Key": "RESOURCE_ID",
                    "Values": [resource_id]
                }
            }
        )
        
        results_by_time = response.get("ResultsByTime", [])
        if not results_by_time:
            return None
        usd_cost = float(results_by_time[0]["Total"]["UnblendedCost"]["Amount"])
        return usd_cost
    except Exception:
        return None