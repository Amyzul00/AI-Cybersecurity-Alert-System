from alerts import trigger_alert

# Replace with your own email address so you can check if you receive it
test_email = "warisansecurityalerts@gmail.com"

print("Triggering test alert...")
trigger_alert(ip="192.168.1.100", threat_type="Ransomware-Trojan", user_email=test_email)
print("Test completed!")