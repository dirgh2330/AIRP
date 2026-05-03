import requests, json, re, datetime, os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def extract_urls(text):
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return list(set(re.findall(pattern, text)))

def extract_headers(raw_email):
    headers = {}
    for line in raw_email.split('\n'):
        if line.startswith("From:"):
            headers["From"] = line.replace("From:", "").strip()
        elif line.startswith("Subject:"):
            headers["Subject"] = line.replace("Subject:", "").strip()
        elif line.startswith("Reply-To:"):
            headers["Reply-To"] = line.replace("Reply-To:", "").strip()
    return headers

def check_url_virustotal(url):
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    if config.VIRUSTOTAL_API_KEY == "paste_your_key_here":
        print(f"[Module 1] VirusTotal API key not set - skipping live check for: {url}")
        return {"url": url, "submitted": False, "note": "API key not configured"}
    try:
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": url}, timeout=10
        )
        return {"url": url, "id": r.json().get("data", {}).get("id", ""), "submitted": True}
    except Exception as e:
        return {"url": url, "error": str(e), "submitted": False}

def analyze_email_file(filepath):
    print(f"[Module 1] Analyzing: {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    headers = extract_headers(raw)
    urls = extract_urls(raw)
    print(f"[Module 1] Found {len(urls)} URLs. Checking VirusTotal...")
    vt_results = [check_url_virustotal(url) for url in urls[:5]]

    indicators = []
    if headers.get("Reply-To") and headers.get("From"):
        if headers["Reply-To"] != headers["From"]:
            indicators.append("Reply-To mismatch with From address")
    if any("bit.ly" in u or "tinyurl" in u for u in urls):
        indicators.append("Shortened URLs detected")
    if len(urls) > 3:
        indicators.append("High number of URLs in email body")

    report = {
        "timestamp": str(datetime.datetime.now()),
        "file": filepath,
        "headers": headers,
        "urls_found": urls,
        "virustotal_submissions": vt_results,
        "indicators": indicators,
        "verdict": "SUSPICIOUS" if indicators else "CLEAN"
    }

    os.makedirs("reports", exist_ok=True)
    out = f"reports/phishing_analysis_{datetime.date.today()}.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[Module 1] Verdict: {report['verdict']} | Report: {out}")
    return report

if __name__ == "__main__":
    analyze_email_file("module1_phishing/samples/sample_phishing.eml")