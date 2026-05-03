# AIRP - Automated Incident Response and Security Operations Framework

I built AIRP to solve a real problem I kept seeing in SOC workflows incident 
response documentation is slow, inconsistent, and mostly manual. Analysts spend 
time writing the same containment steps over and over instead of focusing on 
investigation. AIRP automates that entire process.

This is a 5-module Python framework that handles phishing analysis, threat 
intelligence enrichment, IR playbook execution, vulnerability reporting, and 
NIST CSF compliance tracking  and produces real output files every time it runs.

## Why I Built This

Coming from a background in cybersecurity and information systems and business analysis, I wanted a 
project that reflected how security operations actually work, not just theory. 
Every module in AIRP mirrors a real analyst workflow I studied across SOC 
environments. The goal was to show that I can build tools, not just use them.

## Architecture

![AIRP Architecture](architecture/AIRP_architecture.png)

## Modules

| Module | Name | Tools | Output |
|--------|------|-------|--------|
| 1 | Phishing Analysis Engine | Python, VirusTotal API | JSON report |
| 2 | Threat Intel Feed Integration | AbuseIPDB, AlienVault OTX | JSON report |
| 3 | Automated IR Playbooks | Python, fpdf2 | 3 PDF reports |
| 4 | Vulnerability Reporting Dashboard | Python, pandas, Power BI | CSV + JSON |
| 5 | Compliance Control Tracker | Python, openpyxl, Power BI | XLSX + JSON |

## Setup

```bash
git clone https://github.com/dirgh2330/AIRP.git
cd AIRP
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Add your API keys to `config.py`:
```python
VIRUSTOTAL_API_KEY = "your_key_here"
ABUSEIPDB_API_KEY  = "your_key_here"
OTX_API_KEY        = "your_key_here"
```

## Running the Modules

```bash
# Module 1 - Phishing Analysis
py module1_phishing/phishing_analyzer.py

# Module 2 - Threat Intel Enrichment
py module2_threat_intel/threat_intel.py

# Module 3 - IR Playbooks
py module3_ir_playbooks/phishing_response.py
py module3_ir_playbooks/malware_containment.py
py module3_ir_playbooks/unauthorized_access.py

# Module 4 - Vulnerability Dashboard
py module4_vuln_dashboard/vuln_processor.py

# Module 5 - Compliance Tracker
py module5_compliance/control_mapper.py
```

## Sample Outputs

Every module produces real files, nothing is mocked at the output level:

- `reports/phishing_ir_report.pdf` - structured incident report with evidence, 
  actions, and recommendations
- `reports/malware_ir_report.pdf` - CRITICAL severity containment report
- `reports/unauthorized_access_ir_report.pdf` - brute force + privilege 
  escalation response
- `reports/phishing_analysis.json` - URL extraction, header analysis, 
  VirusTotal results, verdict
- `reports/threat_intel.json` - 8 IOCs enriched with AbuseIPDB + OTX, 
  severity scored, action recommended
- `reports/vuln_summary.json` - 12 CVEs parsed, severity breakdown, 
  remediation count
- `module5_compliance/compliance_tracker.xlsx` - 6 NIST CSF controls mapped, 
  status tracked, gaps documented

## Skills Demonstrated

Python scripting · REST API integration · incident response automation · 
threat intelligence enrichment · vulnerability management · NIST CSF mapping · 
Power BI dashboards · security documentation · pandas · fpdf2 · openpyxl

## Author

Dirgh Patel - CompTIA Security+ | PG Degree in Cybersecurity | PG Degree in Information Systems & Business Analysis  
[github.com/dirgh2330](https://github.com/dirgh2330)