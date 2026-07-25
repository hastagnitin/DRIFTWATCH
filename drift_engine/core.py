import json
import boto3
import os

def check_drift():
    state_file_path = os.path.join(os.path.dirname(__file__), "..", "terraform", "terraform.tfstate")
    
    try:
        with open(state_file_path, "r") as f:
            tf_state = json.load(f)
    except FileNotFoundError:
        print("Error: terraform.tfstate not found. Ensure 'terraform apply' has been run.")
        return

    try:
        attributes = tf_state['resources'][0]['instances'][0]['attributes']
        instance_id = attributes['id']
        expected_type = attributes['instance_type']
        print(f"Expected State: Instance ID -> {instance_id}, Type -> {expected_type}")
    except (KeyError, IndexError):
        print("Error: Failed to parse Terraform state file.")
        return

    print("Fetching actual details from AWS...")
    ec2_client = boto3.client('ec2', region_name='ap-south-1') 
    
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        actual_type = response['Reservations'][0]['Instances'][0]['InstanceType']
        print(f"Actual State: Type -> {actual_type}")
    except Exception as e:
        print(f"Error connecting to AWS: {e}")
        return

    print("-" * 30)
    if expected_type != actual_type:
        print("DRIFT DETECTED: Manual change identified.")
        print(f"Expected Type: {expected_type}")
        print(f"Actual Type:   {actual_type}")
    else:
        print("No drift detected. Infrastructure is in sync.")
    print("-" * 30)

if __name__ == "__main__":
    print("DriftWatch Engine Started")
    print("-" * 30)
    check_drift()