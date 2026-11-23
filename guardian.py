#!/usr/bin/env python3
import sys
import re
import json
import ssl
import subprocess
import argparse
import urllib.request

def query_txt_records(domain):
    records = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "TAVARDT-Guardian"})
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for a in data.get("Answer", []):
                val = a.get("data", "").strip('"')
                if val:
                    records.append(val)
    except Exception:
        pass

    if records:
        return records

    try:
        proc = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, timeout=5)
        raw = proc.stdout.decode("latin1", errors="ignore")
        for line in raw.splitlines():
            line_str = line.strip()
            if "text =" in line_str:
                val = line_str.split("text =", 1)[1].strip().strip('"')
                records.append(val)
            elif line_str.startswith('"') and line_str.endswith('"'):
                records.append(line_str.strip('"'))
    except Exception:
        pass

    return records

def parse_dmarc(records):
    for r in records:
        if "v=DMARC1" in r:
            tags = {}
            for part in r.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip()
            return {"raw": r, "tags": tags}
    return None

def parse_spf(records):
    for r in records:
        if r.startswith("v=spf1") or "v=spf1 " in r:
            parts = r.split()
            qual = "none"
            for p in parts:
                if p in ["-all", "~all", "?all", "+all"]:
                    qual = p
            return {"raw": r, "parts": parts, "qualifier": qual}
    return None

def check_dkim(domain, selector):
    query = f"{selector}._domainkey.{domain}"
    records = query_txt_records(query)
    for r in records:
        if "v=DKIM1" in r or "p=" in r:
            return {"found": True, "raw": r, "query": query}
    return {"found": False, "raw": None, "query": query}

def evaluate(dmarc, spf, dkim):
    score = 0
    recs = []

    if not dmarc:
        recs.append("DMARC record not found. Domain is vulnerable to unauthenticated sender spoofing.")
    else:
        tags = dmarc.get("tags", {})
        p = tags.get("p", "").lower()
        if p == "reject":
            score += 45
        elif p == "quarantine":
            score += 35
            recs.append("DMARC policy set to p=quarantine. Progress toward p=reject to enforce strict zero trust.")
        elif p == "none":
            score += 15
            recs.append("DMARC policy set to p=none (monitoring mode). Upgrade to p=quarantine or p=reject.")
        else:
            recs.append("DMARC policy set to p=none (monitoring mode). Upgrade to p=quarantine or p=reject.")

        if "rua" in tags:
            score += 10
        else:
            recs.append("Aggregate reporting destination (rua) missing from DMARC record.")

    if not spf:
        recs.append("SPF record not found. Any external mail server may send emails as your domain.")
    else:
        qual = spf.get("qualifier", "")
        if qual == "-all":
            score += 30
        elif qual == "~all":
            score += 20
            recs.append("SPF qualifier configured as ~all (softfail). Upgrade to -all (hardfail).")
        elif qual == "?all":
            score += 10
            recs.append("SPF qualifier configured as ?all (neutral). Change to -all or ~all.")
        elif qual == "+all":
            score += 0
            recs.append("SPF qualifier configured as +all. This allows any IP address worldwide to send mail.")
        else:
            score += 10

    if dkim and dkim.get("found"):
        score += 15
    else:
        recs.append("DKIM key record not detected for the tested selector.")

    score = min(score, 100)
    if score >= 85:
        status = "Compliant (Strict Enforcement Active)"
    elif score >= 50:
        status = "Warning (Permissive or Incomplete Policy)"
    else:
        status = "Critical (Vulnerable to Domain Spoofing)"

    return score, status, recs

def main():
    parser = argparse.ArgumentParser(description="TAVARDT USA: Email Authentication Auditor (DMARC, SPF, DKIM)")
    parser.add_argument("domain", help="Target domain to inspect")
    parser.add_argument("--selector", default="default", help="DKIM selector to verify")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    domain = args.domain.strip()
    dmarc = parse_dmarc(query_txt_records(f"_dmarc.{domain}"))
    spf = parse_spf(query_txt_records(domain))
    dkim = check_dkim(domain, args.selector)
    score, status, recs = evaluate(dmarc, spf, dkim)

    if args.json:
        payload = {
            "domain": domain,
            "security_score": score,
            "status": status,
            "dmarc": dmarc,
            "spf": spf,
            "dkim": dkim,
            "recommendations": recs
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    border = "=" * 76
    print(border)
    print(f" TAVARDT USA: EMAIL AUTHENTICATION AUDITOR (DMARC, SPF, DKIM)")
    print(border)
    print(f" Domain: {domain}")
    print(f" Security Score: {score}/100")
    print(f" Overall Status: {status}")
    print("-" * 76)
    print(f" DMARC Record: {dmarc['raw'] if dmarc else 'N/A'}")
    print(f" SPF Record: {spf['raw'] if spf else 'N/A'}")
    print(f" DKIM Record ({args.selector}): {dkim['raw'] if dkim.get('found') else 'N/A'}")
    print("-" * 76)
    print(f" Technical Recommendations:")
    if recs:
        for r in recs:
            print(f"   * {r}")
    else:
        print(f"   * Robust configuration. No critical vulnerability identified.")
    print(border)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python guardian.py <domain> [--selector <name>] [--json]")
        sys.exit(1)
    main()
