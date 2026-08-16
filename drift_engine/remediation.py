import boto3
import os

def get_environment_tag(tags):
    if not tags:
        return 'unknown'
    if isinstance(tags, dict):
        value = tags.get('Environment')
        return value.lower() if value else 'unknown'
    for tag in tags:
        if isinstance(tag, dict) and tag.get('Key') == 'Environment':
            return tag.get('Value').lower()
    return 'unknown'

def confirm_action(action_desc: str, env: str = 'unknown', is_disruptive: bool = False) -> bool:
    if env in ['dev', 'staging']:
        print(f"[*] [{env.upper()}] Auto-approving: {action_desc}")
        return True

    print(f"[!] [{env.upper()}] Protection Active. Manual action required.")
    if is_disruptive:
        print("[!] WARNING: This is a disruptive action -> Downtime risk!")

    while True:
        choice = input(f"⚠️ {action_desc}. Proceed? (y/n): ").strip().lower()
        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False
        print("Invalid input. Please enter 'y' or 'n'.")

def remediate_ec2_instance_type(region: str, instance_id: str, expected_type: str, env: str):
    if not confirm_action(f"Change EC2 {instance_id} instance type to {expected_type}", env, True):
        print(f"⏭️  Skipped remediation for EC2 {instance_id}")
        return

    ec2 = boto3.client('ec2', region_name=region)
    print(f"Stopping instance {instance_id} for remediation...")
    ec2.stop_instances(InstanceIds=[instance_id])
    waiter = ec2.get_waiter('instance_stopped')
    waiter.wait(InstanceIds=[instance_id])
    print(f"Modifying instance type to {expected_type}...")
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        InstanceType={'Value': expected_type}
    )
    print(f"Restarting instance {instance_id}...")
    ec2.start_instances(InstanceIds=[instance_id])
    print(f"✅ [REMEDIATED] Successfully remediated {instance_id} back to {expected_type}")

def remediate_security_group(region: str, sg_id: str, diff_data: dict, env: str):
    ec2 = boto3.client('ec2', region_name=region)
    
    # 1. INGRESS RULES
    if "ingress" in diff_data:
        expected_ingress = diff_data["ingress"].get("terraform", [])
        live_ingress = diff_data["ingress"].get("live", [])
        
        print(f"Checking Security Group {sg_id} for Ingress drift...")
        for live_rule in live_ingress:
            if live_rule not in expected_ingress:
                if confirm_action(f"Revoke unauthorized Inbound rule (Port {live_rule.get('from_port')}) in {sg_id}", env, False):
                    try:
                        ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[{
                            'IpProtocol': live_rule['protocol'], 'FromPort': live_rule['from_port'], 'ToPort': live_rule['to_port'],
                            'IpRanges': [{'CidrIp': c} for c in live_rule.get('cidr_blocks', []) if c]
                        }])
                        print(f"✅ [REMEDIATED] Removed unauthorized Inbound Rule from {sg_id}")
                    except Exception as e:
                        print(f"❌ Failed to revoke Inbound rule: {e}")

        for exp_rule in expected_ingress:
            if exp_rule not in live_ingress:
                if confirm_action(f"Restore missing IaC Inbound rule (Port {exp_rule.get('from_port')}) in {sg_id}", env, False):
                    try:
                        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
                            'IpProtocol': exp_rule['protocol'], 'FromPort': exp_rule['from_port'], 'ToPort': exp_rule['to_port'],
                            'IpRanges': [{'CidrIp': c} for c in exp_rule.get('cidr_blocks', []) if c]
                        }])
                        print(f"✅ [REMEDIATED] Restored missing Inbound Rule to {sg_id}")
                    except Exception as e:
                        print(f"❌ Failed to restore Inbound rule: {e}")

    # 2. EGRESS RULES
    if "egress" in diff_data:
        expected_egress = diff_data["egress"].get("terraform", [])
        live_egress = diff_data["egress"].get("live", [])
        
        print(f"Checking Security Group {sg_id} for Egress drift...")
        for live_rule in live_egress:
            if live_rule not in expected_egress:
                if confirm_action(f"Revoke unauthorized Outbound rule (Port {live_rule.get('from_port')}) in {sg_id}", env, False):
                    try:
                        ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=[{
                            'IpProtocol': live_rule['protocol'], 'FromPort': live_rule['from_port'], 'ToPort': live_rule['to_port'],
                            'IpRanges': [{'CidrIp': c} for c in live_rule.get('cidr_blocks', []) if c]
                        }])
                        print(f"✅ [REMEDIATED] Removed unauthorized Outbound Rule from {sg_id}")
                    except Exception as e:
                        print(f"❌ Failed to revoke Outbound rule: {e}")

        for exp_rule in expected_egress:
            if exp_rule not in live_egress:
                if confirm_action(f"Restore missing IaC Outbound rule (Port {exp_rule.get('from_port')}) in {sg_id}", env, False):
                    try:
                        ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=[{
                            'IpProtocol': exp_rule['protocol'], 'FromPort': exp_rule['from_port'], 'ToPort': exp_rule['to_port'],
                            'IpRanges': [{'CidrIp': c} for c in exp_rule.get('cidr_blocks', []) if c]
                        }])
                        print(f"✅ [REMEDIATED] Restored missing Outbound Rule to {sg_id}")
                    except Exception as e:
                        print(f"❌ Failed to restore Outbound rule: {e}")

    # 3. DESCRIPTION
    if "description" in diff_data:
        print(f"⚠️  Description drift detected for {sg_id}. SG descriptions cannot be updated dynamically. Please recreate via Terraform.")

def remediate_s3_bucket(bucket_name: str, diff_data: dict, env: str):
    s3 = boto3.client('s3')
    
    if "tags" in diff_data:
        expected_tags = diff_data["tags"].get("terraform", {})
        if confirm_action(f"Restore IaC tags for S3 Bucket '{bucket_name}'", env, False):
            try:
                tag_set = [{'Key': k, 'Value': v} for k, v in expected_tags.items()]
                s3.put_bucket_tagging(Bucket=bucket_name, Tagging={'TagSet': tag_set})
                print(f"✅ [REMEDIATED] Successfully restored tags for {bucket_name}")
            except Exception as e:
                print(f"❌ Failed to restore S3 tags: {e}")
                
    if "bucket" in diff_data:
        print(f"⚠️  Bucket name drift detected for {bucket_name}. S3 buckets cannot be renamed. Please recreate via Terraform.")

def remediate_rds_instance(region: str, db_id: str, diff_data: dict, env: str):
    rds = boto3.client('rds', region_name=region)
    updates = {}
    
    if "instance_class" in diff_data:
        updates['DBInstanceClass'] = diff_data["instance_class"]["terraform"]
    if "allocated_storage" in diff_data:
        updates['AllocatedStorage'] = diff_data["allocated_storage"]["terraform"]
        
    if updates:
        if confirm_action(f"Modify RDS {db_id} with new configs: {updates}", env, True):
            try:
                updates['ApplyImmediately'] = True
                rds.modify_db_instance(DBInstanceIdentifier=db_id, **updates)
                print(f"✅ [REMEDIATED] Initiated RDS modification for {db_id}. This may take several minutes.")
            except Exception as e:
                print(f"❌ Failed to remediate RDS {db_id}: {e}")

def remediate_lambda_function(region: str, func_name: str, diff_data: dict, env: str):
    lam = boto3.client('lambda', region_name=region)
    updates = {}
    
    if "runtime" in diff_data: updates['Runtime'] = diff_data["runtime"]["terraform"]
    if "handler" in diff_data: updates['Handler'] = diff_data["handler"]["terraform"]
    if "memory_size" in diff_data: updates['MemorySize'] = diff_data["memory_size"]["terraform"]
    if "timeout" in diff_data: updates['Timeout'] = diff_data["timeout"]["terraform"]
    
    if updates:
        if confirm_action(f"Modify Lambda {func_name} with {updates}", env, False):
            try:
                lam.update_function_configuration(FunctionName=func_name, **updates)
                print(f"✅ [REMEDIATED] Successfully modified Lambda {func_name}")
            except Exception as e:
                print(f"❌ Failed to remediate Lambda {func_name}: {e}")

def remediate_iam_role(role_name: str, diff_data: dict, env: str):
    iam = boto3.client('iam')
    expected_policies = diff_data.get("attached_policies", {}).get("terraform", [])
    live_policies = diff_data.get("attached_policies", {}).get("live", [])

    print(f"Checking IAM Role {role_name} for unauthorized policies...")
    for live_policy in live_policies:
        if live_policy not in expected_policies:
            if confirm_action(f"Detach unauthorized policy '{live_policy}' from Role '{role_name}'", env, False):
                try:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=live_policy)
                    print(f"✅ [REMEDIATED] Successfully detached {live_policy} from {role_name}")
                except Exception as e:
                    print(f"❌ Failed to detach policy from {role_name}: {e}")

    for exp_policy in expected_policies:
        if exp_policy not in live_policies:
            if confirm_action(f"Attach missing IaC policy '{exp_policy}' to Role '{role_name}'", env, False):
                try:
                    iam.attach_role_policy(RoleName=role_name, PolicyArn=exp_policy)
                    print(f"✅ [REMEDIATED] Successfully attached {exp_policy} to {role_name}")
                except Exception as e:
                    print(f"❌ Failed to attach policy to {role_name}: {e}")

def process_remediation(drift_results: list):
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    for result in drift_results:
        attrs = result.live_attributes or result.tf_attributes or {}
        tags = attrs.get('tags', {})
        env = get_environment_tag(tags)

        if result.drift_type.value == "MODIFIED":
            print(f"\n--- Drift Detected: {result.resource_type} ({result.resource_id}) ---")
            
            if result.resource_type == "aws_instance" and "instance_type" in result.diff:
                expected_type = result.diff["instance_type"]["terraform"]
                remediate_ec2_instance_type(region, result.resource_id, expected_type, env)
            
            elif result.resource_type == "aws_security_group":
                remediate_security_group(region, result.resource_id, result.diff, env)

            elif result.resource_type == "aws_s3_bucket":
                remediate_s3_bucket(result.resource_id, result.diff, env)
                
            elif result.resource_type == "aws_db_instance":
                remediate_rds_instance(region, result.resource_id, result.diff, env)
                
            elif result.resource_type == "aws_lambda_function":
                remediate_lambda_function(region, result.resource_id, result.diff, env)

            elif result.resource_type == "aws_iam_role":
                remediate_iam_role(result.resource_id, result.diff, env)
                
        elif result.drift_type.value in ["MISSING", "UNMANAGED"]:
            print(f"\n--- {result.drift_type.value} Resource Detected: {result.resource_type} ({result.resource_id}) ---")
            print(f"⚠️  Auto-remediation for {result.drift_type.value} resources is not executed directly. Please review the AI Analysis in the scan report for the exact `terraform import` or creation commands required to fix this.")