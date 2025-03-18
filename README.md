# Log Analyzer & Alert System 🔎🔌

This project analyzes Linux-style authentication logs to detect suspicious login attempts and generate real-time alerts. It includes visualization of top offender IPs and supports email notifications.

---

## 🛡️ Features
- Parse logs (e.g., `auth.log`) for failed login attempts
- Detect IPs with repeated login failures
- Generate CSV report of flagged activity
- Visualize top IP offenders (bar chart)
- Send email alerts using Gmail App Passwords

---

## 🛠️ Tech Stack
- Python 3.x
- pandas, matplotlib
- smtplib (for email alerts)
- Regular expressions for log parsing

---

## 📁 Project Structure
```
log-analyzer/
├── data/
│   ├── sample_auth.log              # Sample log file
│   ├── alerts.csv                   # Output alerts file
│   └── failed_ips_chart.png         # Visualization
│
├── src/
│   └── log_parser.py               # Main script
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## 🚀 How to Run
1. Clone this repository
2. Set up virtual environment:
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# OR
source venv/bin/activate  # macOS/Linux
```
3. Install dependencies:
```bash
pip install -r requirements.txt
```
4. Add your Gmail address + App Password to `log_parser.py`
5. Run the script:
```bash
python src/log_parser.py
```

---

## 📊 Insights
- Quickly identify IPs with suspicious activity
- Automate alerting and reporting
- Visual overview of threat landscape

---

## 🚀 Future Enhancements
- Slack webhook alerts
- Real-time log monitoring
- Command-line arguments support

---

## 💼 Author
**Ander Santamarta**  
Cybersecurity Analyst | Python Developer   

---

## 👀 License
Open-source project for educational and demonstration purposes.

