#!/usr/bin/env python3
"""Subdomain enumeration for apeksi.id — recon only, no exploitation."""
import dns.resolver
import json
import ssl
import urllib.request
import concurrent.futures
import time

domain = "apeksi.id"
resolver = dns.resolver.Resolver()
resolver.lifetime = resolver.timeout = 6
resolver.nameservers = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9"]

all_results = {"dns": {}, "crt_sh": [], "subdomains": []}

# -------------------------------------------------------
# 1) DNS records
# -------------------------------------------------------
print("=" * 60)
print("1) DNS RECORDS (NS / MX / TXT / SOA / A / AAAA)")
print("=" * 60)
for qtype in ["NS", "MX", "TXT", "SOA", "A", "AAAA"]:
    try:
        answers = resolver.resolve(domain, qtype)
        vals = [str(r) for r in answers]
        all_results["dns"][qtype] = vals
        print(f"  [{qtype}] {vals if vals else 'none'}")
    except Exception:
        all_results["dns"][qtype] = []
        print(f"  [{qtype}] —")

# -------------------------------------------------------
# 2) Certificate Transparency (crt.sh) — passive
# -------------------------------------------------------
print("\n" + "=" * 60)
print("2) CERTIFICATE TRANSPARENCY (crt.sh)")
print("=" * 60)
try:
    url = f"https://crt.sh/?q={domain}&output=json&exclude=expired&full=true"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
        data = json.loads(r.read().decode())
    seen = set()
    for d in data:
        for raw in (d.get("name_value") or "").split("\n"):
            raw = raw.strip().lower()
            if raw:
                seen.add(raw)
    all_results["crt_sh"] = sorted(seen)
    print(f"  Found {len(all_results['crt_sh'])} certificates:")
    for s in all_results["crt_sh"]:
        print(f"    {s}")
except Exception as e:
    print(f"  crt.sh error: {e}")

# -------------------------------------------------------
# 3) Brute-force common subdomains
# -------------------------------------------------------
def resolve_one(sub):
    found = []
    for qtype in ["A", "AAAA", "CNAME"]:
        try:
            answers = resolver.resolve(sub, qtype)
            for r in answers:
                found.append(f"{sub} {qtype} {r}")
        except Exception:
            pass
    return found

subdomains = [
    "api", "app", "api1", "api2", "auth", "blog", "cdn", "cloud", "docs",
    "dns", "elibrary", "extranet", "ftp", "go", "idp", "intranet", "link",
    "mail", "materi", "mobile", "mx", "ns1", "ns2", "ns3", "ns4", "owa",
    "payment", "portal", "secure", "smtp", "sso", "srv", "store", "staging",
    "support", "test", "www", "bio", "kominfo", "youtube", "zoom",
]
all_results["subdomains"] = []

print("\n" + "=" * 60)
print("3) SUBdomain BRUTE-FORCE")
print("=" * 60)
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
    futures = {ex.submit(resolve_one, f"{s}.{domain}"): s for s in subdomains}
    for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
        res_list = fut.result()
        if res_list:
            all_results["subdomains"].extend(res_list)
            for line in res_list:
                print(f"  + {line}")
        if i % 10 == 0:
            print(f"  ...{i}/{len(futures)} checked")
print(f"  Total live subdomains: {len(all_results['subdomains'])}")

# -------------------------------------------------------
# 4) Save results
# -------------------------------------------------------
out = {"target": domain, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": all_results}
with open("apeksi_id_enum.json", "w") as f:
    json.dump(out, f, indent=2)
print("\nSaved to apeksi_id_enum.json")
