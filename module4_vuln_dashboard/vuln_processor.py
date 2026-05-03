import pandas as pd, json, datetime, os

def process_scan_results(csv_path):
    print(f"[Module 4] Processing: {csv_path}")
    df = pd.read_csv(csv_path)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    if "severity" not in df.columns and "cvss" in df.columns:
        df["severity"] = df["cvss"].apply(
            lambda x: "Critical" if float(x) >= 9 else
                      "High"     if float(x) >= 7 else
                      "Medium"   if float(x) >= 4 else "Low"
        )

    summary = {
        "scan_processed": str(datetime.datetime.now()),
        "source_file": csv_path,
        "total_vulnerabilities": len(df),
        "by_severity": {
            "critical": int(len(df[df["severity"].str.lower() == "critical"])),
            "high":     int(len(df[df["severity"].str.lower() == "high"])),
            "medium":   int(len(df[df["severity"].str.lower() == "medium"])),
            "low":      int(len(df[df["severity"].str.lower() == "low"]))
        },
        "remediation_required": int(
            len(df[df["severity"].str.lower().isin(["critical", "high"])])
        )
    }

    os.makedirs("reports", exist_ok=True)
    df.to_csv("reports/cleaned_vulnerabilities.csv", index=False)
    with open("reports/vuln_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[Module 4] Total: {summary['total_vulnerabilities']} | "
          f"Critical: {summary['by_severity']['critical']} | "
          f"High: {summary['by_severity']['high']} | "
          f"Medium: {summary['by_severity']['medium']} | "
          f"Low: {summary['by_severity']['low']}")
    print(f"[Module 4] Remediation required: {summary['remediation_required']} vulnerabilities")
    print(f"[Module 4] Reports saved to reports/")
    return df, summary

if __name__ == "__main__":
    process_scan_results("module4_vuln_dashboard/data/sample_openvas_results.csv")