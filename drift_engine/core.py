import boto3
import os
import requests
import smtplib
import json
from email.mime.text import MIMEText

def load_terraform_state(state_path: str):
    with open(state_path) as f:
        state = json.load(f)
    resources = {}
    for resource in state.get("resources", []):
        r_type = resource["type"]
        for instance in resource.get("instances", []):
            attrs = instance.get("attributes", {})
            resource_id = attrs.get("id")
            if resource_id:
                resources[resource_id] = {"type": r_type, "attributes": attrs}
    return resources

def send_slack_alert(message):
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("Slack Webhook URL is not set!")
        return
    payload = {"text": message}
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200:
            print("Slack alert sent successfully!")
        else:
            print(f"Failed to send Slack alert. Status code: {response.status_code}")
    except Exception as e:
        print(f"Slack Notification Error: {e}")

def send_gmail_alert(subject, body):
    gmail_user = os.environ.get("GMAIL_USER")
    gmail_pass = os.environ.get("GMAIL_PASS")
    if not gmail_user or not gmail_pass:
        print("Gmail credentials are not set! Skipping email.")
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = gmail_user
    msg['To'] = gmail_user
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(gmail_user, gmail_pass)
        server.send_message(msg)
        server.quit()
        print("Gmail alert sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

def main():
    print("--------------------------------------------------")
    print("DriftWatch Engine Started")
    print("--------------------------------------------------")
    
    tf_state_path = "/root/driftwatch/terraform/terraform.tfstate"
    
    try:
        tf_resources = load_terraform_state(tf_state_path)
    except FileNotFoundError:
        print(f"Error: Terraform state file not found at {tf_state_path}")
        return
    except Exception as e:
        print(f"Error loading state file: {e}")
        return

    ec2_instances_in_tf = {k: v for k, v in tf_resources.items() if v['type'] == 'aws_instance'}

    if not ec2_instances_in_tf:
        print("No EC2 instances found in Terraform state.")
        return

    try:
        region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
        ec2_client = boto3.client('ec2', region_name=region)
    except Exception as e:
        print(f"AWS Client Initialization Error: {e}")
        return

    for instance_id, data in ec2_instances_in_tf.items():
        expected_type = data['attributes'].get('instance_type')
        print(f"Expected State (From TF): Instance ID -> {instance_id}, Type -> {expected_type}")
        print("Fetching actual details from AWS...")
        
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            actual_type = response['Reservations'][0]['Instances'][0]['InstanceType']
            print(f"Actual State (From AWS): Type -> {actual_type}")
            print("--------------------------------------------------")

            if expected_type != actual_type:
                alert_msg = (
                    f"⚠️ *DRIFT DETECTED: Manual change identified!*\n"
                    f"Resource: EC2 Instance (`{instance_id}`)\n"
                    f"Expected Type (Terraform): `{expected_type}`\n"
                    f"Actual Type (AWS Live): `{actual_type}`"
                )
                print(alert_msg)
                send_slack_alert(alert_msg)
                send_gmail_alert("DriftWatch Alert: EC2 Drift Detected", alert_msg)
            else:
                print(f"✅ No drift detected for {instance_id}. Infrastructure matches IaC.")

        except Exception as e:
            print(f"AWS Data Fetch Error for {instance_id}: {e}")

if __name__ == "__main__":
    main()