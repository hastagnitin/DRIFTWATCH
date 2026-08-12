import boto3

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
                
                sg_ids = []
                for sg in instance.get("SecurityGroups", []):
                    sg_ids.append(sg.get("GroupId"))
                sg_ids.sort()
                
                live[instance["InstanceId"]] = {
                    "type": "aws_instance",
                    "name": name,
                    "attributes": {
                        "id": instance["InstanceId"],
                        "instance_type": instance["InstanceType"],
                        "ami": instance["ImageId"],
                        "tags": tags_dict,
                        "vpc_security_group_ids": sg_ids
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

from datetime import datetime, timedelta
import boto3

def get_resource_cost(resource_id: str) -> float:
    try:
        client = boto3.client("ce", region_name="us-east-1")
        
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
        
        usd_cost = float(response["ResultsByTime"][0]["Total"]["UnblendedCost"]["Amount"])
        inr_cost = round(usd_cost * 83.5, 2)
        return inr_cost
    except Exception:
        return 0.0
