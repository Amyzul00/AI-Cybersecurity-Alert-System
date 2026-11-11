import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from plyer import notification

def trigger_alert(ip, threat_type, user_email=None):
    # 1. Trigger Local Desktop Notification
    try:
        notification.notify(
            title="🚨 MALWARE THREAT DETECTED!",
            message=f"IP: {ip}\nDetected Malware Type: {threat_type}",
            app_name="Warisan Security Malware Operations",
            timeout=5
        )
        print("Desktop notification triggered successfully.")
    except Exception as e:
        print(f"Failed to trigger desktop notification: {e}")

    # 2. Trigger Email Notification (if user email is provided)
    if user_email:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "warisansecurityalerts@gmail.com" # Put your sender Gmail address here
        sender_password = "zjmmvunmngecwkvu"             # Your 16-character App Password (spaces removed)
        
        subject = "SECURITY ALERT: Malware Threat Detected!"
        body = f"""
        Hello,
        
        Our system has detected suspicious activity or a malware threat on your account/device.
        
        Threat Details:
        - IP Address: {ip}
        - Detected Malware Type: {threat_type}
        
        Please log in to your Warisan Security dashboard immediately to take action.
        
        Best regards,
        Warisan Security Malware Operations
        """
        
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = user_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, user_email, msg.as_string())
            server.quit()
            print("Threat notification email sent successfully.")
        except Exception as e:
            print(f"Failed to send email: {e}")