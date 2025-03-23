import os
import platform
import smtplib
import requests
import hashlib
import sqlite3
import datetime
import shutil
import time
import psutil
import pytz
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# SMTP Configuration for Email Alerts
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "YOUR EMAIL"
EMAIL_PASSWORD = "PASSWORD"
SECURITY_TEAM_EMAIL = "YOUR SECURITY EMAIL"

# Telegram Configuration
TELEGRAM_BOT_TOKEN = "TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "TELEGRAM_CHAT_ID"

# Webhook URL (For Discord, SIEM, TheHive, etc.)
WEBHOOK_URL = "WEBHOOK_URL"

# VirusTotal API Key
VIRUSTOTAL_API_KEY = "VIRUSTOTAL_API_KEY"

# Splunk HEC Configuration
SPLUNK_HEC_URL = "http://localhost:8088"
SPLUNK_HEC_TOKEN = "SPLUNK_HEC"

# Suspicious Directories to Monitor
# SUSPICIOUS_DIRS = ["C:\\Users\\Public\\", "C:\\Temp\\", "C:\\Windows\\Temp\\", "C:\\Users\\vivek\\Downloads\\"]
SUSPICIOUS_DIRS = ["C:\\Users\\vivek\\Downloads\\"]

# Initialize SQLite Database for Logging Incidents
conn = sqlite3.connect("incident_logs.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        target TEXT,
        attack_type TEXT,
        status TEXT
    )
""")
conn.commit()

# Function to Send Logs to Splunk
def send_to_splunk(log_data):
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"event": log_data}

    try:
        response = requests.post(f"{SPLUNK_HEC_URL}/services/collector", json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            print("[SPLUNK] Log sent successfully!")
        else:
            print(f"[SPLUNK ERROR] Failed to send log: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[SPLUNK ERROR] Could not reach Splunk: {e}")

# Function to Send Email Alerts
def send_email_alert(subject, message):
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = ",".join(SECURITY_TEAM_EMAIL)
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, SECURITY_TEAM_EMAIL, msg.as_string())
        server.quit()
        print("[ALERT] Email notification sent successfully!")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")


# Function to Send Telegram Alerts
def send_telegram_alert(message):
    """Sends a Telegram alert with retries in case of timeout."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    
    for attempt in range(3):  # Retry up to 3 times
        try:
            response = requests.post(url, json=data, timeout=10)  # 10-second timeout
            if response.status_code == 200:
                print("[ALERT] Telegram notification sent successfully!")
                return
            else:
                print(f"[ERROR] Failed to send Telegram alert. Response: {response.text}")
        except requests.exceptions.ConnectTimeout:
            print(f"[ERROR] Telegram API Timeout. Retrying... ({attempt + 1}/3)")
            time.sleep(5)  # Wait 5 seconds before retrying
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Telegram API Request Failed: {e}")
            return
    print("[ERROR] Telegram notification failed after 3 attempts.")

# Function to Send Webhook Alerts
def send_webhook_alert(message):
    data = {"content": message}
    response = requests.post(WEBHOOK_URL, json=data)
    if response.status_code in [200, 204]:
        print("[ALERT] Webhook notification sent successfully!")
    else:
        print(f"[ERROR] Failed to send Webhook alert: {response.text if response.text else 'Unknown error'}")

# Function to Verify File Hash with VirusTotal
def verify_file_with_virustotal(file_path):
    """Checks if a file is malicious by verifying its hash with VirusTotal."""
    
    if not os.path.exists(file_path):  # Check if file exists before proceeding
        print(f"[ERROR] File not found: {file_path}")
        return False

    try:
        with open(file_path, "rb") as file:
            file_hash = hashlib.sha256(file.read()).hexdigest()
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            return malicious_count > 0  # Returns True if VirusTotal reports the file as malicious
    except Exception as e:
        print(f"[ERROR] VirusTotal API request failed: {e}")

    return False  # If API fails, assume the file is safe


# Function to Check if a File is Suspicious
# Store files that have already been verified as safe
safe_files = set()
FORCE_DELETE_KEYWORDS = ["payload", "ransomware", "malware", "trojan", "virus"]

def is_suspicious(file_path):
    """Checks if a file is in a monitored directory and verifies with VirusTotal.
    Force deletes if it contains high-risk keywords in the filename.
    """
    file_name = os.path.basename(file_path).lower()

    # Force delete files with dangerous names
    if any(keyword in file_name for keyword in FORCE_DELETE_KEYWORDS):
        print(f"[FORCE DELETE] File contains a high-risk name: {file_path}")
        return True  # Mark as suspicious so it gets deleted

    # Check if file is in a monitored directory
    if not any(file_path.startswith(dir) for dir in SUSPICIOUS_DIRS):
        return False  

    # Verify with VirusTotal before marking as malware
    is_malicious = verify_file_with_virustotal(file_path)

    # If the file is NOT malicious, prevent duplicate SAFE alerts
    if not is_malicious:
        if file_path not in safe_files:
            safe_message = f"[SAFE] File is verified and safe: {file_path}"
            print(safe_message)
            send_email_alert("File Verification Result", safe_message)
            send_telegram_alert(safe_message)
            send_webhook_alert(safe_message)

            # Store the safe file in the set to prevent duplicate alerts
            safe_files.add(file_path)

    return is_malicious  # Returns True if malicious, False if safe


# Function to Check an IP Address Against VirusTotal Before Blocking
def check_ip_with_virustotal(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        return malicious_count > 0  # Returns True if VirusTotal reports the IP as malicious
    return False

# Function to Block Malicious IPs
def block_ip(ip_address):
    """Blocks a malicious IP address on Windows or Linux and logs the incident."""

    alert_message = f"[ALERT] Blocked Malicious IP: {ip_address}"
    print(alert_message)

    # Windows Firewall Rule
    if platform.system() == "Windows":
        command = f'powershell.exe -Command "New-NetFirewallRule -DisplayName \'Block {ip_address}\' -Direction Inbound -Action Block -RemoteAddress {ip_address}"'
        os.system(command)
    else:
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")

    # Send alerts
    send_email_alert("Security Alert: IP Blocked", alert_message)
    send_telegram_alert(alert_message)
    send_webhook_alert(alert_message)

    # Log the incident
    log_incident(ip_address, "IP Blocked")

    # Generate Dynamic Incident Response Report
    generate_incident_response_report("ip_block", ip_address)


# Function to Log Incidents into SQLite and Splunk
def log_incident(target, attack_type):
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    cursor.execute("INSERT INTO incidents (timestamp, target, attack_type, status) VALUES (?, ?, ?, ?)",
                   (timestamp, target, attack_type, "Blocked"))
    conn.commit()

    log_data = {
        "timestamp": timestamp,
        "target": target,
        "attack_type": attack_type,
        "status": "Blocked"
    }
    
    send_to_splunk(log_data)  # Send log to Splunk

# Monitor for Suspicious File Execution
class RansomwareMonitor(FileSystemEventHandler):
    def on_created(self, event):
        """Detects new file creations and checks for suspicious .exe files."""
        if event.is_directory:
            return
        file_path = event.src_path

        file_name = os.path.basename(file_path).lower()
        force_deleted = any(keyword in file_name for keyword in FORCE_DELETE_KEYWORDS)

        if file_path.endswith(".exe") and is_suspicious(file_path):
            alert_message = f"[ALERT] Suspicious file detected: {file_path}"
            print(alert_message)

            # Send alerts
            send_email_alert("Security Alert: Suspicious File Detected", alert_message)
            send_telegram_alert(alert_message)
            send_webhook_alert(alert_message)

            # Log the incident
            log_incident(file_path, "Malware File Execution")

            # Generate Dynamic Incident Response Report
            generate_incident_response_report("malware_deleted" if force_deleted else "malware", file_path, force_deleted)

            # Delete the malicious file safely
            delete_malicious_file(file_path)


    def on_modified(self, event):
        """Detects unauthorized modifications to monitored files."""
        if event.is_directory:
            return
        file_path = event.src_path

        if is_suspicious(file_path):  # File modified in a monitored directory
            alert_message = f"[ALERT] Unauthorized modification detected: {file_path}"
            print(alert_message)

            # Send alerts
            send_email_alert("Security Alert: Unauthorized File Modification", alert_message)
            send_telegram_alert(alert_message)
            send_webhook_alert(alert_message)

            # Log the incident
            log_incident(file_path, "Unauthorized File Modification")

            # Generate Dynamic Incident Response Report
            generate_incident_response_report("file_modification", file_path)

    def on_deleted(self, event):
        """Logs when a file is deleted from monitored directories."""
        if event.is_directory:
            return
        file_path = event.src_path

        if is_suspicious(file_path):
            alert_message = f"[INFO] File deleted: {file_path}"
            print(alert_message)

            # Log the incident
            log_incident(file_path, "File Deleted")

            # Send alerts for deleted files (Optional)
            send_webhook_alert(f"File deleted: {file_path}")
            send_telegram_alert(alert_message)


# Function to Generate a Dynamic Incident Response Report
def generate_incident_response_report(incident_type, target, force_deleted=False, additional_info=None):
    """Generates a structured incident response report dynamically based on incident type."""

    # Define timestamp format (Convert UTC to IST)
    IST = pytz.timezone("Asia/Kolkata")
    current_time_utc = datetime.datetime.now(datetime.UTC)
    current_time_ist = current_time_utc.astimezone(IST)
    formatted_time = current_time_ist.strftime("%Y-%m-%d %H:%M:%S IST")

    # Incident Category Mapping
    category_map = {
        "malware": "Malware Execution",
        "malware_deleted": "Malware Execution & File Deletion",
        "ip_block": "Malicious IP Activity",
        "file_modification": "Unauthorized File Modification",
        "monitoring_stopped": "Monitoring Stopped",
    }
    category = category_map.get(incident_type, "Unknown Incident")

    # Root Cause Analysis & Recommended Actions (Dynamic)
    if incident_type in ["malware", "malware_deleted"]:
        root_cause = f"- Attack Vector: Suspicious EXE file detected in {target}.\n" \
                     f"- Possible Cause: Lack of endpoint protection or untrusted file download."

        recommendations = "Recommended Actions:\n" \
                          "1. Restrict execution of EXE files from untrusted sources.\n" \
                          "2. Enable real-time antivirus scanning.\n" \
                          "3. Educate users on phishing and malware risks."

    elif incident_type == "ip_block":
        root_cause = f"- Attack Vector: Unauthorized access attempt from IP {target}.\n" \
                     f"- Possible Cause: Brute-force attack, botnet activity, or suspicious connections."

        recommendations = "Recommended Actions:\n" \
                          "1. Block the IP in the firewall and monitor further attempts.\n" \
                          "2. Conduct threat intelligence analysis on the IP.\n" \
                          "3. Enable geolocation-based access restrictions."

    elif incident_type == "file_modification":
        root_cause = f"- Attack Vector: Unexpected modification detected in {target}.\n" \
                     f"- Possible Cause: Unauthorized process tampered with system files."

        recommendations = "Recommended Actions:\n" \
                          "1. Check logs for unauthorized file access.\n" \
                          "2. Restore original system files from backups.\n" \
                          "3. Implement file integrity monitoring."

    elif incident_type == "monitoring_stopped":
        root_cause = "- Monitoring was manually stopped by the user."
        recommendations = "Recommended Actions:\n" \
                          "1. Ensure monitoring is restarted when required.\n" \
                          "2. Review the latest incident logs before stopping.\n" \
                          "3. Consider automating monitoring restarts."

    else:
        root_cause = "- No specific root cause found."
        recommendations = "Recommended Actions:\n- Conduct further investigation."

    # Add Forced Deletion Notice If Applicable
    force_delete_notice = ""
    if force_deleted:
        force_delete_notice = "\nForce Deletion Notice:\n" \
                              "This file was forcefully deleted because its name matched high-risk keywords (e.g., 'payload', 'ransomware', 'malware').\n" \
                              "Ensure security policies are enforced to prevent execution of such files."

    # Generate Report Content
    report_content = f"""
    SECURITY INCIDENT RESPONSE REPORT
    ======================================  
    Date & Time: {formatted_time}  
    Incident Type: {category}  
    Target: {target}  
    Affected System: Security Monitoring System  
    Actions Taken:
       - Logged the incident  
       - Alert sent via Email, Telegram, and Webhook  
       - File Deleted: {'Yes' if force_deleted else 'No'}
    """

    if additional_info:
        report_content += f"   - Additional Info: {additional_info}\n"

    report_content += f"""
    Root Cause Analysis:
    {root_cause}

    {recommendations}

    ======================================
    """

    # Save the report to a file
    report_filename = "Incident_Response_Report.txt"
    with open(report_filename, "w", encoding="utf-8") as report_file:
        report_file.write(report_content)

    print(f"[REPORT] Incident Response Report Generated: {report_filename}")


    #send_to_splunk(report_content)  # Send the report to Splunk



# Function to Delete Malicious Files
def delete_malicious_file(file_path):
    """Deletes a file if it is flagged as malicious by VirusTotal OR if it has a suspicious name."""

    # Convert file path to lowercase for case-insensitive matching
    file_name = os.path.basename(file_path).lower()

    # Always delete if the file name contains "payload", "ransomware", or "malware"
    if any(keyword in file_name for keyword in FORCE_DELETE_KEYWORDS):
        print(f"[ALERT] File name matches suspicious pattern and will be deleted: {file_path}")
        is_malicious = True  # Always treat as malicious
        force_deleted = True
    else:
        is_malicious = verify_file_with_virustotal(file_path)  # Otherwise, verify with VirusTotal
        force_deleted = False

    # Delete if file is suspicious or VirusTotal flags it as malicious
    if is_malicious:
        try:
            if os.path.exists(file_path):
                os.chmod(file_path, 0o777)  # Ensure write permissions
                os.remove(file_path)
                print(f"[ACTION] Deleted malicious file: {file_path}")

                # Generate a dynamic report for deleted malware
                generate_incident_response_report("malware_deleted", file_path, force_deleted)

        except PermissionError:
            print("[ERROR] Permission denied! Trying forced deletion...")
            shutil.rmtree(file_path, ignore_errors=True)
        except FileNotFoundError:
            print(f"[INFO] File already deleted: {file_path}")
    else:
        print(f"[INFO] File is not confirmed as malicious. Skipping deletion: {file_path}")


# Start Monitoring
def start_monitoring():
    path_to_monitor = "C:\\Users"
    event_handler = RansomwareMonitor()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_monitor, recursive=True)
    observer.start()
    print("[MONITORING] Security file monitoring started...")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[INFO] Stopping monitoring and generating incident response report...")
        observer.stop()
        observer.join()
        generate_incident_response_report("monitoring_stopped", "N/A")

# Start the Security Monitoring System
if __name__ == "__main__":
    start_monitoring()
