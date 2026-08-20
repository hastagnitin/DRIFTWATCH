import os
import json
import urllib.request
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _format_drift_results(drift_results: list, include_ai: bool = True) -> list:
    lines = []
    for result in drift_results:
        lines.append(
            f"[{result.drift_type.value}] {result.resource_type}: "
            f"{result.resource_name} ({result.resource_id})"
        )
        if result.diff:
            for attr, values in result.diff.items():
                lines.append(
                    f"    - {attr}: Expected '{values['terraform']}', "
                    f"Found '{values['live']}'"
                )
        if include_ai and getattr(result, "ai_analysis", ""):
            lines.append(f"    - AI Analysis: {result.ai_analysis}")
        lines.append("")
    return lines

def send_telegram_alert(message: str):
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    
    if not bot_token or not chat_id:
        print("Telegram credentials missing in environment variables.")
        return
        
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message
    }
    
    try:
        response = requests.post(url, json=payload, timeout=15)
        response.raise_for_status()
        print("Telegram alert sent successfully.")
    except Exception as e:
        print(f"Failed to send Telegram alert: {e}")

def send_slack_alert(webhook_url: str, drift_results: list):
    if not webhook_url:
        return

    message_lines = ["*DriftWatch Alert: Infrastructure Drift Detected!*"]
    message_lines.extend(_format_drift_results(drift_results))

    payload = {"text": "\n".join(message_lines)}
    req = urllib.request.Request(
        webhook_url, 
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        urllib.request.urlopen(req, timeout=15)
        print("Slack alert sent successfully.")
    except Exception as e:
        print(f"Failed to send Slack alert: {e}")

def send_email_alert(smtp_server: str, smtp_port: int, sender_email: str, sender_password: str, recipient_email: str, drift_results: list):
    if not all([smtp_server, sender_email, sender_password, recipient_email]):
        return

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = "DriftWatch Alert: Infrastructure Drift Detected"

    body_lines = ["DriftWatch has detected changes in your infrastructure:\n"]
    body_lines.extend(_format_drift_results(drift_results))

    msg.attach(MIMEText("\n".join(body_lines), 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        print("Email alert sent successfully.")
    except Exception as e:
        print(f"Failed to send Email alert: {e}")

def process_alerts(drift_results: list):
    if not drift_results:
        return
        
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    sender_email = os.environ.get("SENDER_EMAIL")
    sender_password = os.environ.get("SENDER_PASSWORD")
    recipient_email = os.environ.get("RECIPIENT_EMAIL")
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if slack_webhook:
        send_slack_alert(slack_webhook, drift_results)
    
    if sender_email and sender_password and recipient_email:
        send_email_alert(smtp_server, smtp_port, sender_email, sender_password, recipient_email, drift_results)

    if bot_token and chat_id:
        message_lines = ["DriftWatch Alert Summary:"]
        message_lines.extend(_format_drift_results(drift_results, include_ai=False))
            
        telegram_message = "\n".join(message_lines)
        
        if len(telegram_message) > 4000:
            telegram_message = telegram_message[:4000] + "\n...[TRUNCATED]"
            
        send_telegram_alert(telegram_message)