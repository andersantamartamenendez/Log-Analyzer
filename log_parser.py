import re
import pandas as pd
from collections import defaultdict
import os
import smtplib
from email.mime.text import MIMEText
import matplotlib.pyplot as plt

# Load log file
log_file_path = 'data/sample_auth.log'
alerts_output_path = 'data/alerts.csv'
chart_output_path = 'data/failed_ips_chart.png'

# Ensure output directory exists
os.makedirs('data', exist_ok=True)

# Regex pattern for failed login attempts
pattern = re.compile(
    r'(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: (?P<status>Failed|Accepted) password for( invalid user)? (?P<user>\w+) from (?P<ip>[\d.]+)'
)

# Store parsed data
parsed_logs = []
failed_login_counter = defaultdict(int)

with open(log_file_path, 'r') as file:
    for line in file:
        match = pattern.search(line)
        if match:
            log_data = match.groupdict()
            parsed_logs.append(log_data)

            # Count failed logins per IP
            if log_data['status'] == 'Failed':
                failed_login_counter[log_data['ip']] += 1

# Detect IPs with >1 failed logins (lowered threshold for testing)
alert_ips = {ip: count for ip, count in failed_login_counter.items() if count > 1}

# Create alert DataFrame
alerts = [log for log in parsed_logs if log['ip'] in alert_ips and log['status'] == 'Failed']
alerts_df = pd.DataFrame(alerts)

# Save alerts to CSV
alerts_df.to_csv(alerts_output_path, index=False)
print(f"\n[+] Alerts saved to {alerts_output_path} with {len(alerts_df)} flagged entries")

# Optional: print summary
alert_messages = []
for ip, count in alert_ips.items():
    msg = f"[!] Suspicious IP: {ip} with {count} failed login attempts"
    print(msg)
    alert_messages.append(msg)

# Email alert function using Gmail App Password
def send_email_alert(subject, body, to_email):
    from_email = "andersantamarta@gmail.com"
    password = "fnxy zkwb wmck tzts" 

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(from_email, password)
            server.sendmail(from_email, to_email, msg.as_string())
        print("[+] Email alert sent successfully")
    except Exception as e:
        print(f"[!] Failed to send email: {e}")

# Send email if alerts found
if alert_messages:
    email_body = "\n".join(alert_messages)
    send_email_alert("[ALERT] Suspicious Login Attempts Detected", email_body, "andersantamartamenendez@stfrancis.edu")  

# Visualize top offender IPs
if failed_login_counter:
    top_ips = sorted(failed_login_counter.items(), key=lambda x: x[1], reverse=True)[:5]  # Top 5 IPs
    ips, counts = zip(*top_ips)

    plt.figure(figsize=(10, 6))
    plt.bar(ips, counts, color='red')
    plt.xlabel('IP Address')
    plt.ylabel('Failed Login Attempts')
    plt.title('Top Failed Login IPs')
    plt.tight_layout()
    plt.savefig(chart_output_path)
    plt.close()
    print(f"[+] Chart saved to {chart_output_path}")
