import boto3
import os

def remediate_ec2_instance_type(region: str, instance_id: str, expected_type: str):
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

def remediate_security_group(region: str, sg_id: str, diff_data: dict):
    ec2 = boto3.client('ec2', region_name=region)
    expected_ingress = diff_data.get("ingress", {}).get("terraform", [])
    live_ingress = diff_data.get("ingress", {}).get("live", [])
    
    print(f"Remediating Security Group {sg_id}...")
    for rule in live_ingress:
        if rule not in expected_ingress:
            print(f"Revoking unauthorized rule: {rule}")
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': rule['protocol'],
                        'FromPort': rule['from_port'],
                        'ToPort': rule['to_port'],
                        'IpRanges': [{'CidrIp': cidr} for cidr in rule['cidr_blocks'] if cidr]
                    }]
                )

                print(f"✅ [REMEDIATED] Successfully removed unauthorized Inbound Rule from {sg_id} (Port {rule['from_port']} to {rule['to_port']})")
            except Exception as e:
                print(f"❌ Failed to revoke rule in {sg_id}: {e}")
    print(f"Successfully completed remediation check for Security Group {sg_id}")

def process_remediation(drift_results: list):
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    for result in drift_results:
        if result.drift_type.value == "MODIFIED":
            if result.resource_type == "aws_instance" and "instance_type" in result.diff:
                expected_type = result.diff["instance_type"]["terraform"]
                print(f"Auto-remediation triggered for EC2: {result.resource_id}")
                try:
                    remediate_ec2_instance_type(region, result.resource_id, expected_type)
                except Exception as e:
                    print(f"Remediation failed for {result.resource_id}: {e}")
            
            elif result.resource_type == "aws_security_group" and "ingress" in result.diff:
                print(f"Auto-remediation triggered for Security Group: {result.resource_id}")
                try:
                    remediate_security_group(region, result.resource_id, result.diff)
                except Exception as e:   
                    print(f"Remediation failed for {result.resource_id}: {e}")