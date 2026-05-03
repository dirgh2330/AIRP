import pandas as pd, json, datetime, os

NIST_MAPPING = {
    "phishing_detected": {
        "function": "Detect",
        "control_id": "DE.AE-2",
        "control_name": "Detected events are analyzed to understand attack targets"
    },
    "ioc_enriched": {
        "function": "Detect",
        "control_id": "DE.AE-3",
        "control_name": "Event data are collected and correlated from multiple sources"
    },
    "ir_playbook_executed": {
        "function": "Respond",
        "control_id": "RS.RP-1",
        "control_name": "Response plan is executed during or after an incident"
    },
    "vulnerability_scanned": {
        "function": "Identify",
        "control_id": "ID.RA-1",
        "control_name": "Asset vulnerabilities are identified and documented"
    },
    "unauthorized_access_detected": {
        "function": "Detect",
        "control_id": "DE.CM-3",
        "control_name": "Personnel activity is monitored to detect potential cybersecurity events"
    },
    "malware_contained": {
        "function": "Respond",
        "control_id": "RS.MI-2",
        "control_name": "Incidents are mitigated"
    }
}

def map_findings_to_controls(findings_list):
    print(f"[Module 5] Mapping {len(findings_list)} findings to NIST CSF controls...")
    rows = []
    for f in findings_list:
        m = NIST_MAPPING.get(f["type"], {})
        rows.append({
            "Module Source": f["module"],
            "Finding Type": f["type"],
            "NIST CSF Function": m.get("function", "Unknown"),
            "Control ID": m.get("control_id", "Unknown"),
            "Control Name": m.get("control_name", "Unknown"),
            "Status": f["status"],
            "Gap Description": f.get("gap", "None"),
            "Remediation Action": f.get("remediation", "No action required"),
            "Owner": "Security Team",
            "Due Date": "2026-06-30"
        })

    df = pd.DataFrame(rows)

    os.makedirs("module5_compliance", exist_ok=True)
    excel_path = "module5_compliance/compliance_tracker.xlsx"
    df.to_excel(excel_path, index=False)

    os.makedirs("reports", exist_ok=True)
    summary = {
        "generated": str(datetime.datetime.now()),
        "total_controls": len(rows),
        "passed": sum(1 for r in rows if r["Status"] == "Pass"),
        "partial": sum(1 for r in rows if r["Status"] == "Partial"),
        "failed": sum(1 for r in rows if r["Status"] == "Fail"),
        "controls": rows
    }
    with open("reports/compliance_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    passed = summary["passed"]
    partial = summary["partial"]
    failed = summary["failed"]
    print(f"[Module 5] Controls mapped: {len(rows)} | Pass: {passed} | Partial: {partial} | Fail: {failed}")
    print(f"[Module 5] Compliance tracker saved: {excel_path}")
    print(f"[Module 5] Summary report saved: reports/compliance_summary.json")
    return df

if __name__ == "__main__":
    findings = [
        {
            "type": "phishing_detected",
            "module": "Module 1",
            "status": "Pass",
            "gap": ""
        },
        {
            "type": "ioc_enriched",
            "module": "Module 2",
            "status": "Pass",
            "gap": ""
        },
        {
            "type": "ir_playbook_executed",
            "module": "Module 3",
            "status": "Pass",
            "gap": ""
        },
        {
            "type": "vulnerability_scanned",
            "module": "Module 4",
            "status": "Partial",
            "gap": "Not all assets scanned",
            "remediation": "Expand scan scope to all subnets"
        },
        {
            "type": "unauthorized_access_detected",
            "module": "Module 3",
            "status": "Pass",
            "gap": ""
        },
        {
            "type": "malware_contained",
            "module": "Module 3",
            "status": "Pass",
            "gap": ""
        }
    ]
    map_findings_to_controls(findings)