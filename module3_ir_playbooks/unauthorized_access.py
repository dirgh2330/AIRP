import datetime, os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from module3_ir_playbooks.utils.report_generator import IRReportGenerator

def run_unauthorized_access_playbook(compromised_account, source_ip, target_system):
    print(f"[AIRP] Unauthorized Access Playbook initiated...")
    print(f"[AIRP] Compromised account: {compromised_account}")

    incident_data = {
        "incident_type": "Unauthorized Access",
        "analyst": "Dirgh Patel",
        "timestamp": str(datetime.datetime.now()),
        "status": "Contained",
        "severity": "HIGH",
        "evidence": [
            f"Unauthorized login detected for account: {compromised_account}",
            f"Source IP of access attempt: {source_ip}",
            f"Target system accessed: {target_system}",
            "Multiple failed login attempts prior to success (brute force pattern)",
            "Off-hours login time flagged by Wazuh correlation rule",
            "Privilege escalation attempt detected post-login via Sysmon"
        ],
        "actions": [
            f"Account {compromised_account} disabled immediately",
            "All active sessions for compromised account terminated",
            f"Source IP {source_ip} blocked at firewall and added to blocklist",
            "Password reset and MFA enrollment forced on account",
            "Access logs exported and preserved as evidence",
            "Active Directory reviewed for additional compromised accounts",
            "Incident owner notified and HR loop opened"
        ],
        "recommendations": [
            "Enforce MFA across all privileged accounts immediately",
            "Implement account lockout policy after 5 failed attempts",
            "Deploy geo-fencing rules to flag logins from anomalous locations",
            "Conduct access rights review - remove unnecessary privileges"
        ]
    }

    os.makedirs("reports", exist_ok=True)
    output = f"reports/unauthorized_access_ir_report_{datetime.date.today()}.pdf"
    IRReportGenerator().generate(incident_data, output)
    print("[AIRP] Unauthorized access playbook complete.")
    return incident_data

if __name__ == "__main__":
    run_unauthorized_access_playbook(
        compromised_account="admin.service@company.com",
        source_ip="91.108.4.177",
        target_system="DC01-WINSERVER2022"
    )