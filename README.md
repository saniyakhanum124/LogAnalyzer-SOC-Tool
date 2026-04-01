# 🛡️ SOC Log Analyzer & Threat Detection Engine

## 📌 Project Overview
This project is a Python-based **Security Information and Event Management (SIEM)** utility designed for SOC analysts. It automates the ingestion of server and web traffic logs, identifies malicious patterns using a custom detection engine, and generates a visual security dashboard for incident response.

### 🎯 Key Objectives
* **Log Ingestion:** Processing Apache server logs and web traffic CSVs.
* **Threat Intelligence:** Identifying SQL Injection (SQLi), Cross-Site Scripting (XSS), Brute Force, and Directory Traversal.
* **Risk Scoring:** Categorizing alerts by severity (Critical, High, Medium, Low).
* **Data Visualization:** Creating an executive-level dashboard for security trends.

---

## 🛠️ Implementation Details

### 1. Detection Logic
The script utilizes regular expressions (Regex) to scan log payloads against known attack signatures. It maps detected threats to **MITRE ATT&CK Framework** IDs (e.g., T1190 for SQL Injection) to help analysts understand the adversary's techniques.

### 2. Data Processing (`pandas`)
* **Cleaning:** Standardizes column names and handles missing data.
* **Feature Engineering:** Simulates source IP identification for more realistic threat mapping.
* **Filtering:** Isolates "Suspicious" traffic from "Benign" requests to reduce alert fatigue.

### 3. Visual Dashboard (`seaborn` & `matplotlib`)
The tool generates a 4-pane PNG dashboard (`SOC_Dashboard_Fixed.png`) displaying:
* **Threat Type Distribution:** Most frequent attack vectors.
* **Top Attacker IPs:** Identifies the primary sources of malicious traffic.
* **Severity Breakdown:** Pie chart of risk levels.
* **Log Health:** Monitoring server log levels (Critical vs. Info).

---

## 📂 Project Structure
```text
LOGANALYZER1/
├── logs/                      # Raw dataset (Apache & Web logs)
├── security_reports/          # Output folder (Dashboard & CSV Reports)
│   ├── final_incident_report.csv
│   └── SOC_Dashboard_Fixed.png
├── main.py                    # The core detection & visualization logic
└── README.md                  # Project documentation
```

---

## 🚀 How to Set Up & Run

### Prerequisites
1.  **Python 3.x**
2.  Install required libraries:
    ```bash
    pip install pandas matplotlib seaborn
    ```

### Execution
1.  Navigate to the folder in CMD/Terminal.
2.  Run the script:
    ```bash
    python main.py
    ```
3.  Check the `security_reports/` folder for the generated results.

---

## 📈 Future Enhancements
* **Real-time Tail:** Integrate `watchdog` to analyze logs as they are written.
* **IP Geolocation:** Map attacker IPs to physical countries.
* **Database Integration:** Export logs to SQL or Elasticsearch for long-term storage.

---

## ⚠️ Limitations
* **Signature Based:** Only detects attacks matching the regex patterns.
* **Static Analysis:** Does not account for behavior-based anomalies (ML-based detection).

---

> **Disclaimer:** This tool is for educational use and authorized security auditing only. Using this to monitor systems without permission is strictly prohibited.

---
On your GitHub repository page, click the **"Add file"** button, select **"Create new file"**, name it `README.md`, and paste the text above. 

Once you save it, your repo will look incredibly professional. Which of these two projects (the Keylogger or the SOC Tool) was your favorite to build?
