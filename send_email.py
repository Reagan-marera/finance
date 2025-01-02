import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email configuration
SMTP_SERVER = 'mail.boogiecoin.com'  # Replace with your mail server
SMTP_PORT = 587  # Port number
EMAIL_ADDRESS = 'finance@boogiecoin.com'  # Your email address
EMAIL_PASSWORD = 'finance@2025'  # Your email password

def send_email(to_email, subject, message_body):
    try:
        # Create the email components
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject

        # Add the body of the email
        msg.attach(MIMEText(message_body, 'plain'))

        # Connect to the SMTP server
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Upgrade to secure connection
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
            print(f"Email sent to {to_email} successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Usage example
if __name__ == '__main__':
    recipient = 'amososwom162@gmail.com'  # Replace with recipient email
    subject = 'Test Email'
    body = 'This is a test email sent using Python.'
    send_email(recipient, subject, body)
