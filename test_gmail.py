from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib


def test_gmail_connection():
  # --- Your Current Credentials ---
  sender_email = "sendermalwaree@gmail.com"
  app_password = "qldpqrxkfbeeqyhf"  # Your 16-character App Password (no spaces)
  receiver_email = "justmeameyzul@gmail.com"

  smtp_server = "smtp.gmail.com"
  port = 587  # TLS

  print(f"Connecting to SMTP server ({smtp_server}:{port})...")

  # Create message
  message = MIMEMultipart("alternative")
  message["Subject"] = "🧪 Test Security Alert - Warisan Security"
  message["From"] = sender_email
  message["To"] = receiver_email

  html_content = """
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #121212; color: #ffffff; padding: 20px;">
        <div style="max-width: 600px; margin: auto; background: #1e1e1e; padding: 20px; border-radius: 8px; border: 1px solid #4CAF50;">
          <h2 style="color: #4CAF50;">✅ Gmail Connection Successful!</h2>
          <p>Your Warisan Security Threat Detection system can now successfully send email alerts via Gmail.</p>
          <p style="font-size: 12px; color: #888;">This is an automated test script execution.</p>
        </div>
      </body>
    </html>
    """
  message.attach(MIMEText(html_content, "html"))

  try:
    # Establish secure session
    server = smtplib.SMTP(smtp_server, port)
    server.starttls()
    print("Securing connection with TLS...")

    server.login(sender_email, app_password)
    print("Authentication successful!")

    server.sendmail(sender_email, receiver_email, message.as_string())
    server.quit()

    print(f"🎉 Test email successfully sent to {receiver_email}!")
    return True

  except Exception as e:
    print(f"❌ Failed to connect or send email: {e}")
    return False


if __name__ == "__main__":
  test_gmail_connection()