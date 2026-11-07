from plyer import notification

def trigger_alert(ip, threat_type):
    notification.notify(
        title="🚨 MALWARE THREAT DETECTED!",
        message=f"IP: {ip}\nDetected Malware Type: {threat_type}",
        app_name="Threat Detection System",
        timeout=5
    )