import requests, json, datetime, os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def check_abuseipdb(ip):
    if config.ABUSEIPDB_API_KEY == "paste_your_key_here":
        print(f"[Module 2] AbuseIPDB API key not set - using mock data for: {ip}")
        return {
            "source": "AbuseIPDB",
            "abuse_score": 85,
            "country": "RU",
            "isp": "Mock ISP",
            "total_reports": 42,
            "note": "Mock data - API key not configured"
        }
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers=headers, params=params, timeout=10)
        d = r.json().get("data", {})
        return {
            "source": "AbuseIPDB",
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", "Unknown"),
            "isp": d.get("isp", "Unknown"),
            "total_reports": d.get("totalReports", 0)
        }
    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}

def check_otx(ip):
    if config.OTX_API_KEY == "paste_your_key_here":
        print(f"[Module 2] OTX API key not set - using mock data for: {ip}")
        return {
            "source": "AlienVault OTX",
            "pulse_count": 12,
            "reputation": 2,
            "note": "Mock data - API key not configured"
        }
    headers = {"X-OTX-API-KEY": config.OTX_API_KEY}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation",
            headers=headers, timeout=10
        )
        d = r.json()
        return {
            "source": "AlienVault OTX",
            "pulse_count": d.get("pulse_count", 0),
            "reputation": d.get("reputation", 0)
        }
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}

def calculate_severity(abuse_score, pulse_count):
    if abuse_score > 75 or pulse_count > 10: return "CRITICAL"
    elif abuse_score > 50 or pulse_count > 5: return "HIGH"
    elif abuse_score > 25 or pulse_count > 1: return "MEDIUM"
    return "LOW"

def enrich_ioc(ip):
    print(f"[Module 2] Enriching IOC: {ip}")
    abuse = check_abuseipdb(ip)
    otx = check_otx(ip)
    severity = calculate_severity(
        abuse.get("abuse_score", 0),
        otx.get("pulse_count", 0)
    )
    result = {
        "ioc": ip,
        "type": "IPv4",
        "severity": severity,
        "timestamp": str(datetime.datetime.now()),
        "abuseipdb": abuse,
        "alienvault_otx": otx,
        "recommended_action": "BLOCK" if severity in ["CRITICAL", "HIGH"] else "MONITOR"
    }
    print(f"[Module 2] {ip} | Severity: {severity} | Action: {result['recommended_action']}")
    return result

def run_intel_feed(ioc_file):
    with open(ioc_file, "r") as f:
        iocs = [line.strip() for line in f if line.strip()]
    print(f"[Module 2] Processing {len(iocs)} IOCs...")
    results = [enrich_ioc(ioc) for ioc in iocs]
    os.makedirs("reports", exist_ok=True)
    out = f"reports/threat_intel_{datetime.date.today()}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    critical = sum(1 for r in results if r["severity"] == "CRITICAL")
    high = sum(1 for r in results if r["severity"] == "HIGH")
    print(f"[Module 2] Complete. Critical: {critical} | High: {high} | Report: {out}")
    return results

if __name__ == "__main__":
    run_intel_feed("module2_threat_intel/feeds/sample_ioc_list.txt")