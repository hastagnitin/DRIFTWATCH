#!/bin/bash



export AWS_DEFAULT_REGION="ap-south-1"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SENDER_EMAIL="your_email@gmail.com"
export SENDER_PASSWORD="your_app_password_here"
export RECIPIENT_EMAIL="recipient_email@gmail.com"

cd /root/driftwatch

echo "Starting DriftWatch Check at $(date)" | tee -a drift.log
python3 drift_engine/core.py 2>&1 | tee -a drift.log
echo "Finished Check" | tee -a drift.log