import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

# Dictionary to track last email sent times for specific alert signatures
_LAST_ALERT_TIMES = {}
# Dictionary to track occurrence count of an alert signature
_ALERT_COUNTS = {}

COOLDOWN_MINUTES = 5
ALERT_THRESHOLD = 8

def send_critical_alert_email(alert_data):
    """
    Sends an HTML email notification for high-severity SOC alerts, with threshold throttling.
    """
    email_user = os.getenv("SMTP_USER")
    email_pass = os.getenv("SMTP_APP_PASSWORD")
    
    if not email_user or not email_pass:
        print("[Notifier] Missing SMTP credentials in .env file.")
        return

    # Extract data securely
    attack_type = alert_data.get("attack_type", "Unknown Threat")
    severity = alert_data.get("severity", "Unknown")
    description = alert_data.get("rule", {}).get("description", "No description provided.")
    agent_name = alert_data.get("agent", {}).get("name", "Unknown System")
    
    # Check threshold before doing heavy work
    alert_signature = f"{agent_name}_{description}"
    now = datetime.now()
    
    # Increment occurrence count
    current_count = _ALERT_COUNTS.get(alert_signature, 0) + 1
    _ALERT_COUNTS[alert_signature] = current_count
    
    # If we haven't reached the threshold, just log and return quietly
    if current_count < ALERT_THRESHOLD:
        print(f"[Notifier] Monitoring '{attack_type}' on '{agent_name}'. Count -> {current_count}/{ALERT_THRESHOLD}. No email yet.")
        return
    
    # We reached the threshold! Check the Time Cooldown
    if alert_signature in _LAST_ALERT_TIMES:
        time_since_last = now - _LAST_ALERT_TIMES[alert_signature]
        if time_since_last < timedelta(minutes=COOLDOWN_MINUTES):
            print(f"[Notifier] Email throttled for '{attack_type}'. Cooldown active ({COOLDOWN_MINUTES}m).")
            return
            
    # Success: Met threshold AND passed the cooldown lock!
    # Update timestamp and reset count so the whole process starts fresh after the cooldown
    _LAST_ALERT_TIMES[alert_signature] = now
    _ALERT_COUNTS[alert_signature] = 0

    # Make the email subject/body reflect that this is a batch of alerts
    attack_type = f"{attack_type} (Detected {current_count} Times)"

    remediation = alert_data.get("remediation", "No remediation suggested.")
    timestamp = alert_data.get("timestamp", "Unknown Time").replace("T", " ")[:19]
    
    attacker_ip = alert_data.get('data', {}).get('srcip')
    if not attacker_ip:
        attacker_ip = alert_data.get('data', {}).get('win', {}).get('system', {}).get('ipAddress')
        
    if not attacker_ip:
        attacker_ip = "Local System (No Network IP)"

    # Set up email
    msg = EmailMessage()
    msg['Subject'] = f"🚨 BLUEGUARD ALERT: {severity.upper()} Threat Detected on {agent_name}"
    msg['From'] = email_user
    msg['To'] = email_user # Both sender and receiver are the same for direct alerts

    # HTML Body
    color = "#ef4444" if severity == "Critical" else "#f97316" # Red vs Orange
    
    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #f8fafc; color: #334155; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-top: 5px solid {color}; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden;">
          <div style="background-color: #0f172a; padding: 20px; text-align: center;">
            <h2 style="color: #ffffff; margin: 0; letter-spacing: 2px;">BLUE<span style="color: #3b82f6;">GUARD</span> SOC</h2>
            <p style="color: {color}; font-weight: bold; margin-top: 5px; font-size: 14px;">AUTOMATED INCIDENT REPORT</p>
          </div>
          
          <div style="padding: 30px;">
            <h3 style="color: {color}; margin-top: 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px;">
              ⚠️ {attack_type}
            </h3>
            
            <table style="width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px;">
              <tr>
                <td style="padding: 8px 0; font-weight: bold; width: 35%;">📍 Severity:</td>
                <td style="padding: 8px 0; color: {color}; font-weight: bold;">{severity.upper()}</td>
              </tr>
              <tr>
                <td style="padding: 8px 0; font-weight: bold; width: 35%;">🕒 Timestamp:</td>
                <td style="padding: 8px 0;">{timestamp}</td>
              </tr>
              <tr>
                <td style="padding: 8px 0; font-weight: bold;">💻 Affected Agent:</td>
                <td style="padding: 8px 0; font-family: monospace;">{agent_name}</td>
              </tr>
              <tr>
                <td style="padding: 8px 0; font-weight: bold;">🌐 Attacker IP:</td>
                <td style="padding: 8px 0; color: #ef4444; font-family: monospace; font-weight: bold;">{attacker_ip}</td>
              </tr>
            </table>

            <div style="background-color: #f1f5f9; padding: 15px; border-left: 4px solid #64748b; margin-top: 20px; border-radius: 4px;">
              <h4 style="margin: 0 0 10px 0; color: #475569;">Description</h4>
              <p style="margin: 0; font-size: 14px; font-family: monospace;">{description}</p>
            </div>

            <div style="background-color: #ecfdf5; border: 1px solid #a7f3d0; padding: 15px; margin-top: 20px; border-radius: 4px;">
              <h4 style="margin: 0 0 10px 0; color: #059669;">🛡️ AI Remediation Guidance</h4>
              <p style="margin: 0; font-size: 14px; color: #065f46; line-height: 1.5;">{remediation}</p>
            </div>
          </div>
          
          <div style="background-color: #f8fafc; padding: 15px; text-align: center; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8;">
            This is an automated alert generated by the BlueGuard AI SOC Platform.<br>
            Please investigate this incident immediately.
          </div>
        </div>
      </body>
    </html>
    """
    
    msg.set_content("BlueGuard SOC Alert: A critical/high severity threat has been detected. Please enable HTML email viewing to see full report.")
    msg.add_alternative(html_content, subtype='html')

    try:
        # Connect to Gmail SMTP
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(email_user, email_pass)
            smtp.send_message(msg)
        print(f"[Notifier] Email successfully sent for {attack_type} on {agent_name}!")
    except Exception as e:
        print(f"[Notifier] Error sending email: {e}")
