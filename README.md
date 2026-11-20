# NetSentry AI – Adaptive Network Behavior Analysis & Potential Data Exfiltration Detection System

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Flask 3.1](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.9-orange.svg)](https://scikit-learn.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.8-red.svg)](https://scapy.net/)
[![ReportLab](https://img.shields.io/badge/ReportLab-5.1-purple.svg)](https://www.reportlab.com/)
[![Theme](https://img.shields.io/badge/Theme-Enterprise%20Light-brightgreen.svg)]()

**NetSentry AI** is a fully functional, enterprise-grade AI-powered cybersecurity platform that analyzes network telemetry, establishes per-device behavioral baselines, detects anomalous traffic patterns using machine learning (Isolation Forest & Random Forest), calculates dynamic security risk scores (0–100), provides transparent Explainable AI (XAI) feature attribution, and generates audit-ready PDF forensic investigation reports.

---

## 1. System Architecture & Core Capabilities

```
       +-----------------------------------------------------------+
       |                  NETWORK TELEMETRY SOURCES                |
       |  • Live Continuous Stream    • Wireshark PCAPs (.pcapng)  |
       +-----------------------------+-----------------------------+
                                     |
                                     v
                       +---------------------------+
                       |  Scapy Flow Reconstructor |
                       | (Bidirectional 5-Tuples)  |
                       +-------------+-------------+
                                     |
                                     v
                       +---------------------------+
                       |  13-Feature Flow Vector   |
                       | (Bytes, Ratios, Velocity) |
                       +-------------+-------------+
                                     |
             +-----------------------+-----------------------+
             |                                               |
             v                                               v
+---------------------------+                   +---------------------------+
|     Isolation Forest      |                   |   Random Forest Engine    |
| (Unsupervised Anomaly     |                   | (Supervised Multi-Class   |
|  Distance: 0.00 to 1.00)  |                   |  CIC-IDS Classification)  |
+-------------+-------------+                   +-------------+-------------+
             |                                               |
             +-----------------------+-----------------------+
                                     |
                                     v
                  +-------------------------------------+
                  |    Adaptive Behavioral Profiler     |
                  | (Per-Device Historical Mean & Std)  |
                  +------------------+------------------+
                                     |
                                     v
                  +-------------------------------------+
                  |   Dynamic Weighted Risk Engine      |
                  | (0-100 Score: Low, Med, High, Crit) |
                  +------------------+------------------+
                                     |
                                     v
                  +-------------------------------------+
                  |        Explainable AI (XAI)         |
                  | (Feature Attribution, SOC Checklist)|
                  +------------------+------------------+
                                     |
        +----------------------------+----------------------------+
        |                                                         |
        v                                                         v
+-------------------------------+                         +-------------------------------+
|  Enterprise Light UI (10 pgs) |                         | ReportLab PDF Dossier Engine  |
|  (Live Tables, Chart.js)      |                         | (Board-Ready Audit Reports)   |
+-------------------------------+                         +-------------------------------+
```

### Innovative Capabilities:
1. **Adaptive Behavioral Profiling:** Automatically learns per-workstation baseline metrics (outbound bytes mean/std, transfer ratio, active hours) and detects statistical z-score divergence.
2. **Baseline Poisoning Protection:** Prevents adversaries from slowly training the model to tolerate high-volume exfiltration by updating behavioral baselines **strictly using analyst-validated normal traffic**.
3. **Hybrid AI Detection Engine:**
   - **Isolation Forest:** Unsupervised statistical outlier detection on multidimensional flow features (0.00 to 1.00 scale).
   - **Random Forest:** Supervised 4-class classifier (*Normal Traffic*, *Suspicious Outbound Transfer*, *Abnormal Connection Behavior*, *Potential Data Exfiltration*).
4. **Dynamic Weighted Risk Assessment (0–100):** Synthesizes Isolation Forest anomaly distance (30%), Random Forest probability (30%), Behavioral deviation (20%), Outbound volume bursts (10%), and Destination threat intelligence (10%).
5. **Explainable AI (XAI):** Explicitly explains *why* each event was flagged, displaying contributing feature weights, baseline comparisons, and actionable remediation steps.
6. **Dual Ingestion Modes:**
   - **PCAP Analysis:** Upload `.pcap`, `.cap`, or `.pcapng` files for flow reconstruction and AI inference.
   - **Live Network Monitoring:** Real-time continuous streaming feed with pause, resume, speed controls (1x, 2.5x, 5x), and live attack scenario injection.
7. **Pre-Bundled Test PCAP Datasets:** 1-click download of authentic Wireshark-compatible sample PCAPs directly from the console.
8. **Closed-Loop False Positive Feedback:** Marking an alert as *False Positive* automatically feeds the egress pattern into the device's behavioral baseline.
9. **Automated PDF Reporting:** ReportLab engine produces comprehensive, multi-page security audit reports with KPI summaries and investigation findings.
10. **Enterprise Light Theme Only:** Designed with clean slate whites, subtle borders (`#e2e8f0`), professional royal blues (`#2563eb`), and distinct alert status colors.

---

## 2. Technology Stack

- **Backend:** Python 3.12, Flask 3.1, Werkzeug
- **AI & Machine Learning:** Scikit-learn (Isolation Forest & Random Forest), NumPy, Pandas, Joblib
- **Network Packet Analysis:** Scapy (pure-Python `rdpcap`, `wrpcap`, packet layers)
- **Database:** SQLite with standard thread-safe row factories and foreign key enforcement
- **Reporting:** ReportLab 5.1 (Platypus Flowables, Tables, custom typography)
- **Frontend:** HTML5, CSS3, JavaScript, Bootstrap 5.3 (100% locally vendor-cached for offline resilience), Chart.js 4.4, Bootstrap Icons

---

## 3. Directory Structure

```
NetSentry AI/
├── app.py                     # Main Flask web application & REST APIs
├── config.py                  # System configuration, paths, default weights
├── requirements.txt           # Python dependency specifications
├── test_app.py                # Automated 9-part unit test suite
├── database/
│   ├── __init__.py
│   ├── db.py                  # SQLite schema initialization & connection helpers
│   └── models.py              # Data access models (User, Flow, Profile, Alert, Incident, Settings)
├── ai_engine/
│   ├── __init__.py
│   ├── sklearn_patch.py       # Patch for AppLocker/WDAC policy compatibility
│   ├── feature_extractor.py   # 13-feature numerical flow vector extraction
│   ├── isolation_forest.py    # Unsupervised Anomaly Detector
│   ├── random_forest.py       # Supervised Multi-Class Classifier
│   ├── behavioral_profiler.py # Device baseline tracker & drift evaluator
│   ├── risk_engine.py         # Dynamic 0-100 risk scoring
│   ├── explainable_ai.py      # Feature attribution & SOC guidance
│   ├── trainer.py             # Realistic CIC-IDS2018 model trainer & evaluator
│   └── saved_models/          # Persisted trained joblib model binaries
├── network/
│   ├── __init__.py
│   ├── pcap_parser.py         # Bidirectional 5-tuple flow aggregator & AI pipeline
│   ├── traffic_simulator.py   # Continuous realistic background streaming feed
│   └── sample_pcaps.py        # Wireshark-compatible PCAP generator
├── threat_intel/
│   ├── __init__.py
│   └── intel_service.py       # IP reputation engine & VirusTotal integration
├── reports/
│   ├── __init__.py
│   ├── pdf_generator.py       # ReportLab PDF report builder
│   └── generated/             # Stored PDF reports
├── sample_pcaps/              # Pre-bundled PCAP files for instant testing
│   ├── normal_workstation_traffic.pcap
│   ├── data_exfiltration_incident.pcap
│   └── dns_tunneling_and_c2.pcap
├── static/
│   ├── css/style.css          # Custom enterprise light theme stylesheet
│   └── vendor/                # 100% offline Bootstrap 5.3, Chart.js, Bootstrap Icons
└── templates/
    ├── base.html              # Responsive layout with 10-page sidebar navigation
    ├── login.html             # Enterprise login portal
    ├── overview.html          # Page 1: Overview
    ├── live_monitoring.html   # Page 2: Live Network Monitoring
    ├── pcap_analysis.html     # Page 3: PCAP Analysis
    ├── ai_threat_detection.html # Page 4: AI Threat Detection
    ├── behavioral.html        # Page 5: Behavioral Analytics
    ├── threat_intelligence.html # Page 6: Threat Intelligence
    ├── risk_assessment.html   # Page 7: Risk Assessment
    ├── incidents.html         # Page 8: Incident Investigation
    ├── reports.html           # Page 9: Reports
    └── settings.html          # Page 10: Settings
```

---

## 4. Installation & Quick Start

### Step 1: Install Dependencies
Open PowerShell or your terminal in the project directory:
```bash
pip install -r requirements.txt
```

### Step 2: Run Automated Verification Tests
Verify all AI models, database operations, PCAP parsers, and Flask endpoints:
```bash
python -m unittest test_app.py
```

### Step 3: Start the NetSentry AI Platform
```bash
python app.py
```

The application will start immediately on:
👉 **`http://127.0.0.1:5050`**

### Step 4: Sign In
Use either of the built-in demo credentials:
- **Administrator Role:** Username `admin` | Password `admin123`
- **Security Analyst Role:** Username `analyst` | Password `analyst123`

---

## 5. Testing & Verification Guide

### 1. Overview (`/overview`)
- Verify KPI summary cards (Total Flows, Normal Traffic %, Suspicious Flows, Potential Exfiltration, Critical Alerts, Mean Anomaly Score).
- Inspect the interactive **Outbound vs Inbound Byte Volume** chart, **AI Threat Distribution** doughnut, and **Risk Severity Breakdown** bar chart.

### 2. Live Network Monitoring (`/live-monitoring`)
- Watch live flow records stream into the table in real-time.
- Click **"Pause Feed"** to pause the background ingestion; click **"Resume Feed"** to continue.
- Test stream acceleration using the **1x**, **2.5x**, and **5x** speed buttons.
- Click **"Data Exfiltration"** under *Inject Scenario* to inject an immediate high-volume exfiltration flow. Watch it appear with a Critical risk badge.

### 3. PCAP Analysis (`/pcap-analysis`)
- Under *Pre-Bundled Test PCAP Datasets*, click **".PCAP"** next to **Data Exfiltration PCAP** to download `data_exfiltration_incident.pcap`.
- Drag and drop or browse to upload the downloaded `.pcap` file.
- Click **"Start AI Flow Analysis"**.
- Review reconstructed 5-tuple flows, extracted features, anomaly scores, and classification results. Click **"Investigate"** on any flagged flow.

### 4. AI Threat Detection (`/ai-threat-detection`)
- Review model performance metrics (**Accuracy**, **Precision**, **Recall**, **F1-Score**) and the interactive **Multi-Class Confusion Matrix**.
- Inspect global feature importances in the horizontal bar chart.
- Use the **XAI Flow Inspector** dropdown to select any incident: view its primary detection rationale, Isolation Forest anomaly score, Random Forest confidence, feature attribution bars, and recommended SOC investigation actions.

### 5. Behavioral Analytics (`/behavioral-analytics`)
- Inspect learned per-device baseline profiles (IP, Hostname, Total Flows Analyzed, Baseline Outbound Avg, Max Outbound, Ratio, Model Confidence).
- View the **Current Device Egress vs Historical Baseline Mean** bar chart.
- Click **"Feed Validated Normal Traffic"** to submit a normal transfer and adapt a device's baseline without risking baseline poisoning.

### 6. Threat Intelligence (`/threat-intelligence`)
- Enter an IP in the **On-Demand IP Threat Intelligence Lookup** tool (e.g. `198.51.100.77` for C2, `203.0.113.88` for DNS Tunneling, `8.8.8.8` for Clean DNS).
- Review the cached destination indicators table with risk categories, countries, and threat tags.

### 7. Risk Assessment (`/risk-assessment`)
- Review the dynamic risk equation breakdown and the 5x5 Enterprise Risk Matrix.
- Use the **Interactive Risk Calculator** sliders (Isolation Forest score, tactical class, volume multiplier, threat reputation) to observe real-time recalculation of risk scores and severity bands.

### 8. Incident Investigation (`/incidents`)
- Filter alerts by status (*All*, *New*, *Under Investigation*, *Confirmed*, *False Positive*).
- Click **"Investigate"** on any incident to open the detailed dossier modal containing the incident timeline, detection rationale, and remediation checklist.
- Change status to **"False Positive / Legitimate Traffic"** and click **"Save Case Status & Feedback"**. Notice how the platform updates the status and automatically feeds the traffic volume back into the device's behavioral baseline!

### 9. Reports (`/reports`)
- Click **"Generate New PDF"**, enter an executive title and lead analyst name, and click **"Generate PDF"**.
- View the newly generated report in the archive table and click **"Download PDF"** to inspect the ReportLab-generated document.

### 10. Settings (`/settings`)
- Adjust dynamic risk scoring weights and save them.
- Click **"Retrain AI Detection Models Now"** to trigger live on-demand training of Isolation Forest and Random Forest on fresh CIC-IDS distribution data.
- Reset device baselines to factory defaults if desired.

---

## 6. Safety & Ethical Compliance

NetSentry AI adheres strictly to cybersecurity best practices:
- Analyzes metadata and flow statistics without collecting private payload passwords or sensitive document contents.
- Employs calibrated terms such as *"Suspicious Activity"* and *"Potential Data Exfiltration"*; statistical deviations are presented as investigation leads rather than definitive accusations of data theft.
