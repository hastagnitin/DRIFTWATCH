import boto3
import requests
import json
import os
import smtplib
from email.mime.text import MIMEText

INSTANCE_ID = 'i-057f05151b227214d'
EXPECTED_TYPE = 't3.micro'

WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')
GMAIL_USER = os.getenv('GMAIL_USER')
GMAIL_PASS = os.getenv('GMAIL_PASS')

def send_slack_alert(message):
    slack_data = {"text": f"🚨 *DriftWatch Alert* 🚨\n{message}"}
    if WEBHOOK_URL:
        requests.post(WEBHOOK_URL, data=json.dumps(slack_data))

def send_email_alert(message):
    if not GMAIL_USER or not GMAIL_PASS:
        print("Gmail credentials are not set!")
        return
        
    msg = MIMEText(message)
    msg['Subject'] = '🚨 DriftWatch Alert: AWS EC2 Deviation Detected'
    msg['From'] = GMAIL_USER
    msg['To'] = GMAIL_USER
    
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_USER, GMAIL_PASS)
            server.send_message(msg)
            print("Gmail alert sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")

def check_drift():
    print("DriftWatch Engine Started")
    print("--------------------------------------------------")
    print(f"Expected State: Instance ID -> {INSTANCE_ID}, Type -> {EXPECTED_TYPE}")
    print("Fetching actual details from AWS...")
    
    try:
        ec2 = boto3.client('ec2')
        response = ec2.describe_instances(InstanceIds=[INSTANCE_ID])
        current_type = response['Reservations'][0]['Instances'][0]['InstanceType']
        
        print(f"Actual State: Type -> {current_type}")
        print("--------------------------------------------------")
        
        if current_type != EXPECTED_TYPE:
            print("DRIFT DETECTED: Manual change identified.")
            print(f"Expected Type: {EXPECTED_TYPE}")
            print(f"Actual Type:   {current_type}")
            print("--------------------------------------------------")
            
            alert_message = f"Instance type drifted! Expected {EXPECTED_TYPE}, got {current_type}."
            send_slack_alert(alert_message)
            send_email_alert(alert_message)
    except Exception as e:
        print(f"AWS Data Fetch Error: {e}")

if __name__ == "__main__":
    check_drift()