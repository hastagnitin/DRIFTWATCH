import boto3
import os

def get_environment_tag(tags):
    if not tags:
        return 'unknown'
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
    expected_ingress = diff_data.get("ingress", {}).get("terraform", [])
    live_ingress = diff_data.get("ingress", {}).get("live", [])
    
    print(f"Checking Security Group {sg_id} for unauthorized rules...")
    for live_rule in live_ingress:
        is_authorized = False
        for exp_rule in expected_ingress:
            if (live_rule.get('from_port') == exp_rule.get('from_port') and
                live_rule.get('to_port') == exp_rule.get('to_port') and
                live_rule.get('protocol') == exp_rule.get('protocol')):
                is_authorized = True
                break
                
        if not is_authorized:
            if confirm_action(f"Revoke unauthorized rule (Port {live_rule.get('from_port')}) in {sg_id}", env, False):
                print(f"Revoking unauthorized rule: {live_rule}")
                try:
                    ec2.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[{
                            'IpProtocol': live_rule['protocol'],
                            'FromPort': live_rule['from_port'],
                            'ToPort': live_rule['to_port'],
                            'IpRanges': [{'CidrIp': cidr} for cidr in live_rule.get('cidr_blocks', []) if cidr]
                        }]
                    )
                    print(f"✅ [REMEDIATED] Successfully removed unauthorized Inbound Rule from {sg_id}")
                except Exception as e:
                    print(f"❌ Failed to revoke rule in {sg_id}: {e}")
            else:
                print(f"⏭️  Skipped revoking rule for Port {live_rule.get('from_port')}")

    print(f"Checking Security Group {sg_id} for missing IaC rules...")
    for exp_rule in expected_ingress:
        is_missing = True
        for live_rule in live_ingress:
            if (live_rule.get('from_port') == exp_rule.get('from_port') and
                live_rule.get('to_port') == exp_rule.get('to_port') and
                live_rule.get('protocol') == exp_rule.get('protocol')):
                is_missing = False
                break
        
        if is_missing:
            if confirm_action(f"Restore missing IaC rule (Port {exp_rule.get('from_port')}) in {sg_id}", env, False):
                print(f"Restoring missing IaC rule: Port {exp_rule.get('from_port')}")
                try:
                    ec2.authorize_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[{
                            'IpProtocol': exp_rule['protocol'],
                            'FromPort': exp_rule['from_port'],
                            'ToPort': exp_rule['to_port'],
                            'IpRanges': [{'CidrIp': cidr} for cidr in exp_rule.get('cidr_blocks', []) if cidr]
                        }]
                    )
                    print(f"✅ [REMEDIATED] Successfully restored missing IaC Inbound Rule to {sg_id}")
                except Exception as e:
                    print(f"❌ Failed to restore rule in {sg_id}: {e}")
            else:
                print(f"⏭️  Skipped restoring rule for Port {exp_rule.get('from_port')}")
                
    print(f"Completed remediation check for Security Group {sg_id}")

def remediate_s3_bucket(bucket_name: str, env: str):
    if not confirm_action(f"Enforce strict Public Access Block on S3 Bucket '{bucket_name}'", env, False):
        print(f"⏭️  Skipped remediation for S3 bucket {bucket_name}")
        return

    s3 = boto3.client('s3')
    print(f"Remediating S3 Bucket {bucket_name} by enforcing public access block...")
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(f"✅ [REMEDIATED] Successfully blocked public access for {bucket_name}")
    except Exception as e:
        print(f"❌ Failed to remediate S3 bucket {bucket_name}: {e}")

def remediate_iam_role(role_name: str, diff_data: dict, env: str):
    iam = boto3.client('iam')
    expected_policies = diff_data.get("attached_policies", {}).get("terraform", [])
    live_policies = diff_data.get("attached_policies", {}).get("live", [])

    print(f"Checking IAM Role {role_name} for unauthorized policies...")
    for live_policy in live_policies:
        if live_policy not in expected_policies:
            if confirm_action(f"Detach unauthorized policy '{live_policy}' from Role '{role_name}'", env, False):
                print(f"Detaching unauthorized policy: {live_policy}")
                try:
                    iam.detach_role_policy(
                        RoleName=role_name,
                        PolicyArn=live_policy
                    )
                    print(f"✅ [REMEDIATED] Successfully detached {live_policy} from {role_name}")
                except Exception as e:
                    print(f"❌ Failed to detach policy from {role_name}: {e}")
            else:
                print(f"⏭️  Skipped detaching policy {live_policy}")

def process_remediation(drift_results: list):
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    for result in drift_results:
        tags = getattr(result, 'tags', [])
        if not tags and hasattr(result, 'live_state'):
            tags = result.live_state.get('Tags', [])
        env = get_environment_tag(tags)

        if result.drift_type.value == "MODIFIED":
            if result.resource_type == "aws_instance" and "instance_type" in result.diff:
                expected_type = result.diff["instance_type"]["terraform"]
                print(f"\n--- Drift Detected: EC2 Instance ({result.resource_id}) ---")
                try:
                    remediate_ec2_instance_type(region, result.resource_id, expected_type, env)
                except Exception as e:
                    print(f"Remediation failed for {result.resource_id}: {e}")
            
            elif result.resource_type == "aws_security_group" and "ingress" in result.diff:
                print(f"\n--- Drift Detected: Security Group ({result.resource_id}) ---")
                try:
                    remediate_security_group(region, result.resource_id, result.diff, env)
                except Exception as e:   
                    print(f"Remediation failed for {result.resource_id}: {e}")

            elif result.resource_type == "aws_s3_bucket":
                print(f"\n--- Drift Detected: S3 Bucket ({result.resource_id}) ---")
                try:
                    remediate_s3_bucket(result.resource_id, env)
                except Exception as e:
                    print(f"Remediation failed for {result.resource_id}: {e}")

            elif result.resource_type == "aws_iam_role" and "attached_policies" in result.diff:
                print(f"\n--- Drift Detected: IAM Role ({result.resource_id}) ---")
                try:
                    remediate_iam_role(result.resource_id, result.diff, env)
                except Exception as e:
                    print(f"Remediation failed for {result.resource_id}: {e}")