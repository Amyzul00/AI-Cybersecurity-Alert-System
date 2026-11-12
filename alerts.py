import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from plyer import notification
import streamlit as st
from database import get_all_registered_users

def send_security_alert_to_all(ip_address, malware_type):
    # 1. Trigger Local Desktop Notification
    try:
        notification.notify(
            title="🚨 MALWARE THREAT DETECTED!",
            message=f"IP: {ip_address}\nDetected Malware Type: {malware_type}",
            app_name="Warisan Security Malware Operations",
            timeout=5
        )
        print("Desktop notification triggered successfully.")
    except Exception as e:
        print(f"Failed to trigger desktop notification: {e}")

    # 2. Broadcast Email Notification to All Registered Users
    recipients = get_all_registered_users()
    if not recipients:
        print("[-] No registered users found to send email alerts.")
        return

    # Retrieve credentials securely from Streamlit secrets (with local fallback)
    try:
        sender_email = st.secrets["EMAIL_SENDER"]
        sender_password = st.secrets["EMAIL_PASSWORD"]
    except Exception:
        sender_email = "warisansecurityalerts@gmail.com"
        sender_password = "zjmm vunm ngec wkvu"

    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    
    subject = "SECURITY ALERT: Malware Threat Detected!"
    
    success_count = 0
    for user_email in recipients:
        body = f"""
        Hello,
        
        Our system has detected suspicious activity or a malware threat on your network/device.
        
        Threat Details:
        - IP Address: {ip_address}
        - Detected Malware Type: {malware_type}
        
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
            success_count += 1
            print(f"Threat notification email sent successfully to {user_email}.")
        except Exception as e:
            print(f"Failed to send email to {user_email}: {e}")
            
    print(f"[+] Alert broadcast complete: {success_count}/{len(recipients)} emails sent.")