import boto3
import requests
import json
import os
INSTANCE_ID = 'i-057f05151b227214d'
EXPECTED_TYPE = 't3.micro'
WEBHOOK_URL = 'SLACK_WEBHOOK_URL'

def send_slack_alert(message):
    slack_data = {"text": f"🚨 *DriftWatch Alert* 🚨\n{message}"}
    requests.post(
        WEBHOOK_URL, 
        data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )

def check_drift():
    print("DriftWatch Engine Started")
    print("------------------------------------------------")
    print(f"Expected State: Instance ID -> {INSTANCE_ID}, Type -> {EXPECTED_TYPE}")
    print("Fetching actual details from AWS...")
    
    try:
        ec2 = boto3.client('ec2', region_name='ap-south-1')
        response = ec2.describe_instances(InstanceIds=[INSTANCE_ID])
        actual_type = response['Reservations'][0]['Instances'][0]['InstanceType']
        
        print(f"Actual State: Type -> {actual_type}")
        print("------------------------------------------------")
        
        if actual_type == EXPECTED_TYPE:
            print("No drift detected. Infrastructure is in sync.")
            print("------------------------------------------------")
        else:
            print("DRIFT DETECTED: Manual change identified.")
            print(f"Expected Type: {EXPECTED_TYPE}")
            print(f"Actual Type:   {actual_type}")
            print("------------------------------------------------")
            
            alert_msg = f"Drift Detected on Instance `{INSTANCE_ID}`!\n*Expected Type:* `{EXPECTED_TYPE}`\n*Actual Type:* `{actual_type}`"
            send_slack_alert(alert_msg)
            
    except Exception as e:
        print(f"Error: {str(e)}")
        send_slack_alert(f"AWS Check Failed: {str(e)}")

if __name__ == "__main__":
    check_drift()
