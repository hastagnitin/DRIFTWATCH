import os
import boto3
from drift_engine.aws_client import get_boto3_client

def _get_client(service_name: str, region: str = None, profile: str = None):
    if profile:
        return get_boto3_client(service_name, profile=profile, region=region)
    return boto3.client(service_name, region_name=region)

def get_environment_tag(tags):
    if not tags:
        return 'unknown'
    if isinstance(tags, dict):
        value = tags.get('Environment')
        return value.lower() if value else 'unknown'
    for tag in tags:
        if isinstance(tag, dict) and tag.get('Key') == 'Environment':
            val = tag.get('Value')
            return val.lower() if val else 'unknown'
    return 'unknown'

def confirm_action(action_desc: str, env: str = 'unknown', is_disruptive: bool = False, auto_approve: bool = False) -> bool:
    if auto_approve:
        print(f"[*] Auto-approving (--yes/--force): {action_desc}")
        return True

    if env in ['dev', 'staging']:
        print(f"[*] [{env.upper()}] Auto-approving: {action_desc}")
        return True

    print(f"[!] [{env.upper()}] Protection Active. Manual action required.")
    if is_disruptive:
        print("[!] WARNING: This is a disruptive action -> Downtime risk!")

    while True:
        try:
            choice = input(f"⚠️ {action_desc}. Proceed? (y/n): ").strip().lower()
        except EOFError:
            print(f"\n[!] Non-interactive shell detected (EOF on stdin). Skipping action: {action_desc}")
            return False
        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False
        print("Invalid input. Please enter 'y' or 'n'.")

def remediate_ec2_instance_type(region: str, instance_id: str, expected_type: str, env: str, auto_approve: bool = False, profile: str = None):
    ec2 = _get_client('ec2', region=region, profile=profile)
    try:
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = desc.get('Reservations', [])
        if not reservations or not reservations[0].get('Instances'):
            print(f"❌ EC2 instance {instance_id} not found.")
            return
        instance_info = reservations[0]['Instances'][0]
        
        if instance_info.get('RootDeviceType') != 'ebs':
            print(f"❌ Cannot modify instance {instance_id}: Root device is not EBS-backed (found: {instance_info.get('RootDeviceType')}).")
            return
            
        if instance_info.get('InstanceLifecycle') == 'spot':
            print(f"❌ Cannot modify instance {instance_id}: Spot instances do not support instance type modification.")
            return

        state = instance_info.get('State', {}).get('Name')
        if state not in ['running', 'stopped']:
            print(f"❌ Cannot modify instance {instance_id}: Instance state is '{state}'. Must be 'running' or 'stopped'.")
            return
    except Exception as e:
        print(f"❌ Pre-flight check failed for EC2 {instance_id}: {e}")
        return

    if not confirm_action(f"Change EC2 {instance_id} instance type to {expected_type}", env, True, auto_approve=auto_approve):
        print(f"⏭️  Skipped remediation for EC2 {instance_id}")
        return

    was_running = (state == 'running')
    stopped = False
    try:
        if was_running:
            print(f"Stopping instance {instance_id} for remediation...")
            ec2.stop_instances(InstanceIds=[instance_id])
            waiter = ec2.get_waiter('instance_stopped')
            waiter.wait(InstanceIds=[instance_id])
            stopped = True
            
        print(f"Modifying instance type to {expected_type}...")
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            InstanceType={'Value': expected_type}
        )
        
        if was_running:
            print(f"Restarting instance {instance_id}...")
            ec2.start_instances(InstanceIds=[instance_id])
            stopped = False
            
        print(f"✅ [REMEDIATED] Successfully remediated {instance_id} back to {expected_type}")
    except Exception as e:
        print(f"❌ Failed to remediate EC2 {instance_id}: {e}")
        if stopped:
            try:
                print(f"Attempting to restart EC2 {instance_id} after failed remediation...")
                ec2.start_instances(InstanceIds=[instance_id])
            except Exception as restart_error:
                print(f"❌ Failed to restart EC2 {instance_id}: {restart_error}")

def remediate_security_group(region: str, sg_id: str, diff_data: dict, env: str, auto_approve: bool = False, profile: str = None):
    ec2 = _get_client('ec2', region=region, profile=profile)
    
    if "ingress" in diff_data:
        expected_ingress = diff_data["ingress"].get("terraform", [])
        live_ingress = diff_data["ingress"].get("live", [])
        
        print(f"Checking Security Group {sg_id} for Ingress drift...")
        for live_rule in live_ingress:
            if live_rule not in expected_ingress:
                from_p = live_rule.get('from_port')
                to_p = live_rule.get('to_port')
                is_ssh = (from_p == 22 or to_p == 22 or (isinstance(from_p, int) and isinstance(to_p, int) and from_p <= 22 <= to_p))
                if is_ssh:
                    print("⚠️ CAUTION: Rule being revoked includes SSH (Port 22). Active connections may be terminated.")
                if confirm_action(f"Revoke unauthorized Inbound rule (Port {from_p}) in {sg_id}", env, is_ssh, auto_approve=auto_approve):
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
                if confirm_action(f"Restore missing IaC Inbound rule (Port {exp_rule.get('from_port')}) in {sg_id}", env, False, auto_approve=auto_approve):
                    try:
                        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
                            'IpProtocol': exp_rule['protocol'], 'FromPort': exp_rule['from_port'], 'ToPort': exp_rule['to_port'],
                            'IpRanges': [{'CidrIp': c} for c in exp_rule.get('cidr_blocks', []) if c]
                        }])
                        print(f"✅ [REMEDIATED] Restored missing Inbound Rule to {sg_id}")
                    except Exception as e:
                        print(f"❌ Failed to restore Inbound rule: {e}")

    if "egress" in diff_data:
        expected_egress = diff_data["egress"].get("terraform", [])
        live_egress = diff_data["egress"].get("live", [])
        
        print(f"Checking Security Group {sg_id} for Egress drift...")
        for live_rule in live_egress:
            if live_rule not in expected_egress:
                if confirm_action(f"Revoke unauthorized Outbound rule (Port {live_rule.get('from_port')}) in {sg_id}", env, False, auto_approve=auto_approve):
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
                if confirm_action(f"Restore missing IaC Outbound rule (Port {exp_rule.get('from_port')}) in {sg_id}", env, False, auto_approve=auto_approve):
                    try:
                        ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=[{
                            'IpProtocol': exp_rule['protocol'], 'FromPort': exp_rule['from_port'], 'ToPort': exp_rule['to_port'],
                            'IpRanges': [{'CidrIp': c} for c in exp_rule.get('cidr_blocks', []) if c]
                        }])
                        print(f"✅ [REMEDIATED] Restored missing Outbound Rule to {sg_id}")
                    except Exception as e:
                        print(f"❌ Failed to restore Outbound rule: {e}")

    if "description" in diff_data:
        print(f"⚠️  Description drift detected for {sg_id}. SG descriptions cannot be updated dynamically in AWS EC2 API. Please update via Terraform.")

def remediate_s3_bucket(bucket_name: str, diff_data: dict, env: str, region: str = None, auto_approve: bool = False, profile: str = None):
    actual_region = region or os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    s3 = _get_client('s3', region=actual_region, profile=profile)
    
    if "tags" in diff_data:
        expected_tags = diff_data["tags"].get("terraform", {})
        if confirm_action(f"Restore IaC tags for S3 Bucket '{bucket_name}'", env, False, auto_approve=auto_approve):
            try:
                tag_set = [{'Key': k, 'Value': v} for k, v in expected_tags.items()]
                s3.put_bucket_tagging(Bucket=bucket_name, Tagging={'TagSet': tag_set})
                print(f"✅ [REMEDIATED] Successfully restored tags for {bucket_name}")
            except Exception as e:
                print(f"❌ Failed to restore S3 tags: {e}")
                
    if "bucket" in diff_data:
        print(f"⚠️  Bucket name drift detected for {bucket_name}. S3 buckets cannot be renamed. Please recreate via Terraform.")

def remediate_rds_instance(region: str, db_id: str, diff_data: dict, env: str, apply_immediately: bool = False, auto_approve: bool = False, profile: str = None):
    rds = _get_client('rds', region=region, profile=profile)
    updates = {}
    
    if "instance_class" in diff_data:
        updates['DBInstanceClass'] = diff_data["instance_class"]["terraform"]
    if "allocated_storage" in diff_data:
        updates['AllocatedStorage'] = diff_data["allocated_storage"]["terraform"]
        
    if updates:
        mode_desc = "immediately (may force reboot)" if apply_immediately else "during next maintenance window"
        if confirm_action(f"Modify RDS {db_id} ({mode_desc}) with configs: {updates}", env, apply_immediately, auto_approve=auto_approve):
            try:
                updates['ApplyImmediately'] = apply_immediately
                rds.modify_db_instance(DBInstanceIdentifier=db_id, **updates)
                print(f"✅ [REMEDIATED] Initiated RDS modification for {db_id} (ApplyImmediately={apply_immediately}).")
            except Exception as e:
                print(f"❌ Failed to remediate RDS {db_id}: {e}")

def remediate_lambda_function(region: str, func_name: str, diff_data: dict, env: str, auto_approve: bool = False, profile: str = None):
    lam = _get_client('lambda', region=region, profile=profile)
    updates = {}
    
    if "runtime" in diff_data:
        updates['Runtime'] = diff_data["runtime"]["terraform"]
    if "handler" in diff_data:
        updates['Handler'] = diff_data["handler"]["terraform"]
    if "memory_size" in diff_data:
        updates['MemorySize'] = diff_data["memory_size"]["terraform"]
    if "timeout" in diff_data:
        updates['Timeout'] = diff_data["timeout"]["terraform"]
    
    if updates:
        if confirm_action(f"Modify Lambda {func_name} with {updates}", env, False, auto_approve=auto_approve):
            try:
                lam.update_function_configuration(FunctionName=func_name, **updates)
                print(f"✅ [REMEDIATED] Successfully modified Lambda {func_name}")
            except Exception as e:
                print(f"❌ Failed to remediate Lambda {func_name}: {e}")

def remediate_iam_role(role_name: str, diff_data: dict, env: str, region: str = None, auto_approve: bool = False, profile: str = None):
    actual_region = region or os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    iam = _get_client('iam', region=actual_region, profile=profile)
    expected_policies = diff_data.get("attached_policies", {}).get("terraform", [])
    live_policies = diff_data.get("attached_policies", {}).get("live", [])

    print(f"Checking IAM Role {role_name} for unauthorized policies...")
    for live_policy in live_policies:
        if live_policy not in expected_policies:
            if confirm_action(f"Detach unauthorized policy '{live_policy}' from Role '{role_name}'", env, False, auto_approve=auto_approve):
                try:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=live_policy)
                    print(f"✅ [REMEDIATED] Successfully detached {live_policy} from {role_name}")
                except Exception as e:
                    print(f"❌ Failed to detach policy from {role_name}: {e}")

    for exp_policy in expected_policies:
        if exp_policy not in live_policies:
            if confirm_action(f"Attach missing IaC policy '{exp_policy}' to Role '{role_name}'", env, False, auto_approve=auto_approve):
                try:
                    iam.attach_role_policy(RoleName=role_name, PolicyArn=exp_policy)
                    print(f"✅ [REMEDIATED] Successfully attached {exp_policy} to {role_name}")
                except Exception as e:
                    print(f"❌ Failed to attach policy to {role_name}: {e}")

def process_remediation(drift_results: list, auto_approve: bool = False, profile: str = None):
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    for result in drift_results:
        attrs = result.live_attributes or result.tf_attributes or {}
        tags = attrs.get('tags', {})
        env = get_environment_tag(tags)

        if result.drift_type.value == "MODIFIED":
            print(f"\n--- Drift Detected: {result.resource_type} ({result.resource_id}) ---")
            
            if result.resource_type == "aws_instance" and "instance_type" in result.diff:
                expected_type = result.diff["instance_type"]["terraform"]
                remediate_ec2_instance_type(region, result.resource_id, expected_type, env, auto_approve=auto_approve, profile=profile)
            
            elif result.resource_type == "aws_security_group":
                remediate_security_group(region, result.resource_id, result.diff, env, auto_approve=auto_approve, profile=profile)

            elif result.resource_type == "aws_s3_bucket":
                remediate_s3_bucket(result.resource_id, result.diff, env, region=region, auto_approve=auto_approve, profile=profile)
                
            elif result.resource_type == "aws_db_instance":
                remediate_rds_instance(region, result.resource_id, result.diff, env, apply_immediately=False, auto_approve=auto_approve, profile=profile)
                
            elif result.resource_type == "aws_lambda_function":
                remediate_lambda_function(region, result.resource_id, result.diff, env, auto_approve=auto_approve, profile=profile)

            elif result.resource_type == "aws_iam_role":
                remediate_iam_role(result.resource_id, result.diff, env, region=region, auto_approve=auto_approve, profile=profile)
                
        elif result.drift_type.value in ["MISSING", "UNMANAGED"]:
            print(f"\n--- {result.drift_type.value} Resource Detected: {result.resource_type} ({result.resource_id}) ---")
            print(f"⚠️  Auto-remediation for {result.drift_type.value} resources is not executed directly. Please review the suggested Terraform template/import commands to reconcile.")