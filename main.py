import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import os

# --- ⚙️ Configuration ---
LOG_PATHS = {
    "error_log": "logs/Apache_2k.log_structured.csv",  # Previously 'windows_logs'
    "traffic_log": "logs/web log.csv"                 # Previously 'web_logs'
}
OUTPUT_DIR = "security_reports"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- 1️⃣ Load & Preprocess Data ---
print("[*] Initializing Log Ingestion...")

try:
    # Load Error Logs (Apache/Server Errors)
    error_df = pd.read_csv(LOG_PATHS["error_log"])
    error_df.dropna(inplace=True)
    error_df['Level'] = error_df['Level'].astype(str).str.strip().str.lower()
    print(f"   [+] Error Logs Loaded: {error_df.shape}")

    # Load Traffic Logs (Web Requests)
    traffic_df = pd.read_csv(LOG_PATHS["traffic_log"])
    # Standardize columns
    traffic_df.columns = [col.strip().lower().replace(' ', '_') for col in traffic_df.columns]
    
    # Ensure critical columns exist (Simulating Source IP if missing for demonstration)
    if 'source_ip' not in traffic_df.columns:
        import numpy as np
        # Simulating IPs for the sake of the project demo if column is missing
        traffic_df['source_ip'] = np.random.choice(['192.168.1.5', '10.0.0.2', '172.16.55.1', '203.0.113.5'], size=len(traffic_df))
        
    print(f"   [+] Traffic Logs Loaded: {traffic_df.shape}")

except FileNotFoundError as e:
    print(f"   [!] CRITICAL ERROR: File not found - {e}")
    exit()

# --- 2️⃣ Threat Intelligence Logic (The Brain) ---

def classify_threat(payload):
    """
    Analyzes a log payload string against regex signatures.
    Returns: (Attack Type, MITRE ID, Severity)
    """
    payload = str(payload).lower()
    
    # Signature Database
    signatures = [
        (r"(\bselect\b|\bunion\b|\binsert\b|\bdelete\b)", "SQL Injection", "T1190", "High"),
        (r"(<script>|%3cscript|alert\(|onerror=)", "Cross-Site Scripting (XSS)", "T1059", "Medium"),
        (r"(\.\./|\.\.\\|/etc/passwd|/windows/system32)", "Directory Traversal", "T1083", "High"),
        (r"(cmd=|exec=|system\(|shell)", "Command Injection", "T1059.004", "Critical"),
        (r"(login|failed|unauthorized|invalid password)", "Brute Force / Auth Failure", "T1110", "Medium")
    ]
    
    for pattern, name, mitre, severity in signatures:
        if re.search(pattern, payload):
            return pd.Series([name, mitre, severity])
    
    return pd.Series(["Benign", "N/A", "Low"])

print("[*] Running Threat Detection Signatures...")

# Apply detection to Traffic Logs (Checking URL/Payloads)
# Note: prioritizing 'url', then 'method', then 'host'
target_col = 'url' if 'url' in traffic_df.columns else 'classification' 
traffic_df[['Threat_Type', 'MITRE_ID', 'Severity']] = traffic_df[target_col].apply(classify_threat)

# Apply detection to Error Logs (Checking Error Levels)
# Simple rule: If level is Critical/Error/Fatal -> Flag it
error_df['Threat_Type'] = error_df['Level'].apply(
    lambda x: "Server Critical Error" if x in ['fatal', 'error', 'critical'] else "Info"
)

# --- 3️⃣ Filtering Alerts ---
suspicious_traffic = traffic_df[traffic_df['Threat_Type'] != "Benign"]
suspicious_errors = error_df[error_df['Threat_Type'] != "Info"]

print(f"   [!] Threats Detected in Traffic: {len(suspicious_traffic)}")
print(f"   [!] Critical Server Errors: {len(suspicious_errors)}")

# --- 📊 Block 6: Visualization (The Dashboard) ---
# 1. Increase canvas size slightly for better spacing
plt.figure(figsize=(10, 6))

# Plot 1: Attack Distribution (Top Left)
plt.subplot(2, 2, 1)
# Using hue= and legend=False to fix the warning
# Old: sns.countplot(y='Threat_Type', data=suspicious_traffic, order=..., palette='viridis')
# New: Add hue='Threat_Type' and legend=False
sns.countplot(y='Threat_Type', data=suspicious_traffic, 
              order=suspicious_traffic['Threat_Type'].value_counts().index, 
              palette='viridis', hue='Threat_Type', legend=False)
plt.title("Detected Threats by Type", fontsize=14)
plt.xlabel("Alert Count", fontsize=12)
plt.ylabel("Threat Type", fontsize=12)
plt.tick_params(axis='both', which='major', labelsize=11)

# Plot 2: Top Attacking IPs (Top Right)
plt.subplot(2, 2, 2)
top_ips = suspicious_traffic['source_ip'].value_counts().head(5)
# Using hue= and legend=False to fix the warning
# Old: sns.barplot(x=top_ips.values, y=top_ips.index, palette='magma')
# New: Add hue=top_ips.index and legend=False
sns.barplot(x=top_ips.values, y=top_ips.index, palette='magma', hue=top_ips.index, legend=False)
plt.title("Top 5 Attacking Source IPs", fontsize=14)
plt.xlabel("Alert Count", fontsize=12)
plt.ylabel("Source IP", fontsize=12)
plt.tick_params(axis='both', which='major', labelsize=11)

# Plot 3: Severity Breakdown (Bottom Left)
plt.subplot(2, 2, 3)
# Using a distinct color palette for clarity
traffic_df['Severity'].value_counts().plot.pie(
    autopct='%1.1f%%', 
    colors=['#ff9999', '#66b3ff', '#99ff99', '#ffcc99'], # Red, Blue, Green, Orange
    explode=(0.1, 0, 0, 0), # Explode the first slice (usually "Low") slightly
    shadow=True, 
    startangle=90,
    labels=None # Turn off labels on the pie itself to avoid clashing
)
plt.title("Traffic Severity Breakdown", fontsize=14)
plt.ylabel("") # Remove the default 'Severity' ylabel
# Add a clean legend to the side
plt.legend(labels=traffic_df['Severity'].value_counts().index, loc="best")

# Plot 4: Server Error Levels (Bottom Right)
plt.subplot(2, 2, 4)
# Using hue= and legend=False to fix the warning
# Old: sns.countplot(x='Level', data=error_df, palette='Reds')
# New: Add hue='Level' and legend=False
sns.countplot(x='Level', data=error_df, palette='Reds', hue='Level', legend=False)
plt.title("Server Log Error Levels", fontsize=14)
plt.xlabel("Log Level", fontsize=12)
plt.ylabel("Count", fontsize=12)
plt.tick_params(axis='both', which='major', labelsize=11)

# --- THE KEY FIX FOR ALIGNMENT ---
# hspace = height space (vertical padding between rows)
# wspace = width space (horizontal padding between columns)
plt.subplots_adjust(hspace=0.5, wspace=0.3)

# tight_layout does a final check to prevent clipping at the edges
plt.tight_layout()

# Save and Show
plt.savefig(f"{OUTPUT_DIR}/SOC_Dashboard_Fixed.png", dpi=300) # Increased DPI for sharper image
print(f"[*] Fixed Dashboard saved to {OUTPUT_DIR}/SOC_Dashboard_Fixed.png")
plt.show()

# --- 5️⃣ Reporting ---
report_file = f"{OUTPUT_DIR}/final_incident_report.csv"
suspicious_traffic.to_csv(report_file, index=False)

print("\n" + "="*50)
print("🛡️  SOC ANALYST SUMMARY REPORT  🛡️")
print("="*50)
print(f"Total Traffic Analyzed: {len(traffic_df)}")
print(f"Total Threats Identified: {len(suspicious_traffic)}")
print("-" * 30)
print("Top Detected Threat:", suspicious_traffic['Threat_Type'].mode()[0] if not suspicious_traffic.empty else "None")
print("Most Active Attacker IP:", suspicious_traffic['source_ip'].mode()[0] if not suspicious_traffic.empty else "None")
print("-" * 30)
print(f"Full report saved to: {report_file}")
print("="*50)