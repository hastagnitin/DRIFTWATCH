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