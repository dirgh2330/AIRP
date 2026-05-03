import datetime, os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from module3_ir_playbooks.utils.report_generator import IRReportGenerator

def run_phishing_playbook(affected_user, email_subject, source_ip):
    print(f"[AIRP] Phishing Response Playbook initiated...")
    print(f"[AIRP] Affected user: {affected_user}")

    incident_data = {
        "incident_type": "Phishing Attack",
        "analyst": "Dirgh Patel",
        "timestamp": str(datetime.datetime.now()),
        "status": "Contained",
        "severity": "HIGH",
        "evidence": [
            f"Suspicious email received by: {affected_user}",
            f"Email subject: {email_subject}",
            f"Source IP flagged: {source_ip}",
            "Email headers extracted and preserved",
            "Malicious URLs identified and submitted to threat intel feed",
            "IOCs logged in Wazuh SIEM as custom detection rule"
        ],
        "actions": [
            "User account temporarily suspended pending investigation",
            "Malicious email quarantined from mailbox",
            "Source IP blocked at firewall level",
            "Password reset initiated for affected user",
            "All active sessions for affected user terminated",
            "IOCs submitted to Wazuh SIEM for correlation",
            "Affected user notified and security awareness briefing scheduled"
        ],
        "recommendations": [
            "Enable advanced email filtering for similar sender patterns",
            "Review and update phishing detection rules in SIEM",
            "Conduct team-wide phishing awareness refresh",
            "Add source domain to email blocklist"
        ]
    }

    os.makedirs("reports", exist_ok=True)
    output = f"reports/phishing_ir_report_{datetime.date.today()}.pdf"
    IRReportGenerator().generate(incident_data, output)
    print("[AIRP] Phishing playbook complete.")
    return incident_data

if __name__ == "__main__":
    run_phishing_playbook(
        affected_user="john.doe@company.com",
        email_subject="Urgent: Your account will be suspended",
        source_ip="192.168.100.45"
    )