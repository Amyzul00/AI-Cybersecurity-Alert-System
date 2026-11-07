import logging
import logging.handlers
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# 1. Configure Syslog for SIEM (ELK, Splunk, Graylog)
logger = logging.getLogger("SystemSecurityLogger")
logger.setLevel(logging.INFO)

syslog_handler = logging.handlers.SysLogHandler(address=('127.0.0.1', 514))
formatter = logging.Formatter('%(name)s: [%(levelname)s] %(message)s')
syslog_handler.setFormatter(formatter)
logger.addHandler(syslog_handler)

# 2. Configure Webhook Alerts (Slack)
def send_security_webhook(event_message, severity="HIGH"):
    webhook_url = "https://hooks.slack.com/services/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"
    
    payload = {
        "text": f"🚨 *Security Alert [{severity}]*: {event_message}"
    }
    
    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Failed to send webhook alert: {e}")

# 3. Configure Email Alerts (Gmail)
def send_security_email(event_message, severity="HIGH"):
    sender_email = "sendermalwaree@gmail.com"
    receiver_email = "justmeameyzul@gmail.com"
    
    # Generate this 16-digit App Password from the sendermalwaree@gmail.com Google Account security settings
    app_password = "YOUR_16_DIGIT_APP_PASSWORD" 
    
    message = MIMEMultipart("alternative")
    message["Subject"] = f"🚨 Security Alert [{severity}]: AI Malware Detection System"
    message["From"] = sender_email
    message["To"] = receiver_email
    
    html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #d9534f;">🚨 Security Event Alert</h2>
        <p><b>Severity:</b> <span style="color: red;">{severity}</span></p>
        <p><b>Details:</b> {event_message}</p>
        <hr>
        <p style="font-size: 12px; color: #777;">Automated alert from AI Real-Time Deep LSTM Malware Detection Engine.</p>
      </body>
    </html>
    """
    message.attach(MIMEText(html, "html"))
    
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email alert sent successfully!")
    except Exception as e:
        print(f"Failed to send email alert: {e}")

# 4. Main Security Event Handler function
def handle_security_event(event_description, is_critical=False):
    # Log to SIEM / Syslog
    logger.warning(event_description)
    
    # Dispatch both Slack and Email notifications for critical alerts
    if is_critical:
        send_security_webhook(event_description, severity="CRITICAL")
        send_security_email(event_description, severity="CRITICAL")