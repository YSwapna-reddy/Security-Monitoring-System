# 🛡 Security Monitoring System

The Security Monitoring System is designed to detect suspicious file activity, send alerts, and integrate with security platforms like **Splunk, VirusTotal, Telegram, Webhooks, and Email**.

---

## ⚠️ Setup Instructions

Before running the system, **update the configuration** in the script to enable alerts and monitoring.

### 1️⃣ Edit Configuration Settings

Open the `Security_Monitoring_System.py` file and update the following:

#### **📧 Email Configuration**
Replace with your SMTP credentials:
```python
EMAIL_ADDRESS = "YOUR EMAIL"
EMAIL_PASSWORD = "YOUR EMAIL PASSWORD"
SECURITY_TEAM_EMAIL = "YOUR SECURITY EMAIL"
```

#### **📲 Telegram Bot Configuration**
Get your bot token from [BotFather](https://t.me/botfather) and update:
```python
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"
```

#### **🌐 Webhook URL (Discord, SIEM, etc.)**
Update the webhook URL:
```python
WEBHOOK_URL = "YOUR_WEBHOOK_URL"
```

#### **📊 Splunk HEC Configuration**
Ensure your **Splunk HTTP Event Collector (HEC)** is set up and update:
```python
SPLUNK_HEC_URL = "http://your-splunk-server:8088"
SPLUNK_HEC_TOKEN = "YOUR_SPLUNK_TOKEN"
```

#### **🛡 VirusTotal API Key**
Sign up on [VirusTotal](https://www.virustotal.com) and get an API key:
```python
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

#### **📁 Suspicious Directories**
Modify the directories to monitor:
```python
SUSPICIOUS_DIRS = ["C:\Users\YourUsername\Downloads\", "C:\Windows\Temp\"]
```

---

## 📥 Installation & Usage

### **Step 1: Download the Code**
Clone this repository:
```sh
git clone https://github.com/your-repo/Security-Monitoring-System.git
cd Security-Monitoring-System
```

### **Step 2: Install Dependencies**
Run:
```sh
pip install -r requirements.txt
```

### **Step 3: Run the Security Monitoring System**
```sh
python Security_Monitoring_System.py
```

---

## 🚀 Features  
✅ **Monitors suspicious directories** for changes  
✅ **Sends alerts** via Email, Telegram, and Webhooks  
✅ **Integrates with Splunk** for log management  
✅ **Checks file hashes** with VirusTotal  
✅ **Deletes malicious files automatically**  

---

## 📌 Notes  
- Ensure your email provider **allows SMTP access**.  
- **Splunk must have HEC enabled** for logs to be received.  
- **Telegram bot must be added** to the chat group where alerts will be sent.  
- **Run the script with administrator privileges** for full functionality.  

---

## 🛠 Troubleshooting  

### **🔒 Permission Denied Errors**  
Run the following command:  
```sh
chmod +x Security_Monitoring_System.py
```

### **📦 Missing Dependencies**  
Install required packages:  
```sh
pip install -r requirements.txt
```

### **📊 Splunk Connection Issues**  
1. Verify **Splunk is running**.  
2. Check **HEC token and URL**.  
3. Ensure **port 8088 is open**.  

---

## 👨‍💻 Contribution & Support  

- Feel free to **fork and improve** this tool.  
- For issues, **open a GitHub issue** or contact us.  

🚀 Happy Monitoring! 🛡  
