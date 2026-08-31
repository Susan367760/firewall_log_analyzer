# 🔥 Firewall Log Analyzer

A Python-based cybersecurity tool for analyzing firewall logs, identifying suspicious network activity, and generating security insights through an interactive web dashboard.

This project is part of my **#CyberBuildsBySusan** cybersecurity project journey, where I build practical security tools while strengthening my skills in Python, network security, log analysis, and security monitoring.

---

## 🎯 Project Overview

Firewall logs contain valuable information about network traffic, connection attempts, blocked requests, and potentially suspicious activity.

The **Firewall Log Analyzer** helps transform raw firewall log data into meaningful security information by providing an easy-to-use interface for analyzing and visualizing network activity.

The goal of the project is to demonstrate how Python can be used to support security monitoring and log analysis.

---

## ✨ Features

* 📂 Upload and analyze firewall log files
* 🔍 Parse firewall log entries
* 🌐 Analyze source and destination IP addresses
* 🚦 Identify allowed and blocked traffic
* 📊 Generate security statistics
* 🚨 Highlight potentially suspicious activity
* 📈 Display analyzed data through a web dashboard
* 📝 Generate analysis reports
* 💻 Simple browser-based interface
* 🐍 Built with Python and Flask

---

## 🛠️ Technologies Used

| Technology   | Purpose                   |
| ------------ | ------------------------- |
| Python       | Core application logic    |
| Flask        | Web application framework |
| HTML5        | Dashboard structure       |
| CSS3         | User interface styling    |
| JavaScript   | Frontend interactions     |
| SQLite       | Application data storage  |
| Git & GitHub | Version control           |

---

## 📁 Project Structure

```text
firewall_log_analyzer/
│
├── app.py
├── requirements.txt
├── README.md
│
├── templates/
│   └── index.html
│
├── static/
│   └── css/
│       └── style.css
│
├── reports/
│
└── venv/
```

> The `venv/` directory is excluded from GitHub using `.gitignore`.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/Susan367760/firewall_log_analyzer.git
```

### 2. Navigate into the project

```bash
cd firewall_log_analyzer
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

**Windows PowerShell:**

```powershell
venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, you can temporarily allow scripts for the current PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the environment again:

```powershell
venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Application

Start the Flask application:

```bash
python app.py
```

Then open your browser and visit:

```text
http://127.0.0.1:5000
```

---

## 🔎 How It Works

The application follows a simple log-analysis workflow:

```text
Firewall Log
     │
     ▼
Log Upload
     │
     ▼
Log Parsing
     │
     ▼
Traffic Analysis
     │
     ├── Source IP Analysis
     ├── Destination Analysis
     ├── Allowed Traffic
     ├── Blocked Traffic
     └── Suspicious Activity
     │
     ▼
Security Dashboard
     │
     ▼
Analysis Report
```

---

## 🛡️ Cybersecurity Use Cases

The project demonstrates practical applications of firewall log analysis, including:

* Network security monitoring
* Detection of unusual traffic patterns
* Identification of repeated connection attempts
* Analysis of blocked network traffic
* Source IP investigation
* Security event reporting
* Basic threat detection
* SOC-style log analysis

---

## 📊 Example Security Questions

The analyzer can help answer questions such as:

* Which IP addresses are generating the most traffic?
* How many connections were allowed?
* How many connections were blocked?
* Which source IPs appear repeatedly?
* What types of traffic are being observed?
* Are there unusual patterns that may require investigation?

---

## 🔐 Security Considerations

This project is designed for **defensive cybersecurity and security monitoring purposes**.

When analyzing real firewall logs:

* Protect sensitive IP and network information.
* Avoid uploading confidential logs to public repositories.
* Remove credentials, tokens, and other secrets before sharing logs.
* Use sanitized sample data when demonstrating the project publicly.

---

## 🚀 Future Improvements

Planned improvements may include:

* [ ] Real-time log monitoring
* [ ] Advanced threat detection rules
* [ ] IP reputation checking
* [ ] GeoIP visualization
* [ ] Attack-pattern detection
* [ ] Exportable PDF reports
* [ ] Interactive charts
* [ ] Authentication and role-based access
* [ ] SIEM integration
* [ ] Email security alerts
* [ ] Docker deployment
* [ ] Cloud deployment

---

## 📸 Screenshots

Screenshots of the application dashboard and analysis results will be added here.

---

## 📚 Learning Objectives

Through this project, I am strengthening practical skills in:

* Python programming
* Flask development
* Firewall log analysis
* Network security
* Security monitoring
* Data visualization
* Threat detection
* Git and GitHub
* Cybersecurity automation

---

## 👩🏽‍💻 About the Project

**Project:** Firewall Log Analyzer
**Project Series:** #CyberBuildsBySusan
**Focus:** Cybersecurity | Network Security | Log Analysis | Python

Built as part of my ongoing journey of developing practical cybersecurity projects and documenting my learning through hands-on implementation.

---

## 🔗 Repository

**GitHub:**
https://github.com/Susan367760/firewall_log_analyzer

---

### #CyberBuildsBySusan

**Building. Learning. Securing. One project at a time. 🔐🐍**
