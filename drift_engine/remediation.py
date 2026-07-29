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
    
    print(f"✅ Successfully remediated {instance_id} back to {expected_type}")

def process_remediation(drift_results: list):
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    
    for result in drift_results:
        # Changed this line to check .value directly. No need to import DriftType!
        if result.resource_type == "aws_instance" and result.drift_type.value == "MODIFIED":
            if "instance_type" in result.diff:
                expected_type = result.diff["instance_type"]["terraform"]
                print(f"⚠️ Auto-remediation triggered for {result.resource_id}")
                try:
                    remediate_ec2_instance_type(region, result.resource_id, expected_type)
                except Exception as e:
                    print(f"❌ Remediation failed for {result.resource_id}: {e}")