#!/usr/bin/env python3
"""Subdomain enumeration for *.bmkg.go.id — recon only, read-only."""
import dns.resolver, dns.reversename, ssl, urllib.request, json, time, concurrent.futures

domain = "bmkg.go.id"
resolver = dns.resolver.Resolver()
resolver.lifetime = resolver.timeout = 6
resolver.nameservers = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9"]

all_results = {"dns": {}, "crt_sh": [], "brute": [], "all": []}

# 1) DNS records
print("=== DNS RECORDS ===")
for qtype in ["NS", "MX", "TXT", "SOA", "A", "AAAA"]:
    try:
        answers = resolver.resolve(domain, qtype)
        vals = [str(r) for r in answers]
        all_results["dns"][qtype] = vals
        print(f"  [{qtype}] {vals}")
    except Exception:
        all_results["dns"][qtype] = []
        print(f"  [{qtype}] —")

# 2) Certificate Transparency (crt.sh) — passive
print("\n=== CERTIFICATE TRANSPARENCY (crt.sh) ===")
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
            if raw and raw != domain and raw != domain + ".":
                seen.add(raw)
    all_results["crt_sh"] = sorted(seen)
    print(f"  Found {len(all_results['crt_sh'])} subdomains via CT:")
    for s in all_results["crt_sh"]:
        print(f"    {s}")
except Exception as e:
    print(f"  crt.sh error: {e}")

# 3) Brute-force common subdomains
print("\n=== BRUTE-FORCE ===")
wordlist = [
    "www", "www2", "info", "blog", "api", "app", "mail", "webmail", "ftp",
    "dev", "staging", "test", "demo", "stage", "prod", "production", "live",
    "admin", "administrator", "dashboard", "portal", "cpanel", "webmail",
    "mobile", "m", "geo", "data", "report", "laporan", "download", "file",
    "situs", "web", "wwwp", "alpha", "beta", "gamma", "vpn", "ssl", "secure",
    "intranet", "extranet", "internal", "external", "partner", "vendor",
    "media", "cms", "wordpress", "wp-admin", "phpmyadmin", "mysql", "db",
    "database", "oracle", "postgresql", "sql", "redis", "memcached", "elastic",
    "kibana", "logs", "logging", "monitor", "monitoring", "nagios", "zabbix",
    "splunk", "grafana", "jenkins", "gitlab", "ci", "cd", "deploy", "build",
    "source", "code", "repo", "svn", "git", "hg", "ssh", "sftp", "rdp", "vnc",
    "wikis", "wiki", "help", "support", "faq", "about", "contact", "imprint",
    "privacy", "policy", "terms", "cookies", "sitemap", "feed", "rss", "atom",
    "oauth", "sso", "idp", "identity", "auth", "login", "signin", "login",
    "signup", "register", "user", "account", "my", "portal", "intranet",
    "informasi", "berita", "berita", "data", "kartu", "gempa", "banjir", "dhufan",
    "tropical", "cyclone", "tsunami", "geofisika", "meteorologi", "klimatologi",
    "lod", "lssdri", "katalog", "gallery", "photo", "video", "document",
    "dokumen", "pdf", "public", "pub", "files", "downloads", "storage",
    "share", "upload", "api", "rest", "soap", "graphql", "websocket",
    "ws", "wss", "mail2", "web1", "web2", "web3", "www1", "www3", "www4",
    "ns1", "ns2", "ns3", "ns4", "mx", "smtp", "pop", "imap", "pop3", "imap4",
    "postfix", "sendmail", "exim", "exim", "courier", "dovecot", "sieve",
    "autodiscover", "autoconfig", "mail.provider", "relay", "spf", "dkim",
    "dmarc", "verification", "google-site-verification", "bing-site",
    "yandex-verification", "facebook-verification", "twitter-verification",
    "apple-verification", "play-store", "app-store", "redirect", "url",
    "link", "go", "try", "preview", "sandbox", "dev1", "dev2", "dev3",
    "test1", "test2", "qa", "uat", "preprod", "staging", "stg", "prod1", "prod2",
    "backup", "restore", "archive", "old", "legacy", "deprecated", "nomatch",
    "wildcard", "ca", "certs", "certificate", "ssl", "tls", "crypto",
    "keys", "secret", "password", "wp", "joomla", "drupal", "magento",
    "shop", "store", "cart", "checkout", "pay", "payment", "bank", "bayar",
    "gw", "gateway", "edge", "proxy", "reverse", "forward", "loadbalancer",
    "lb", "haproxy", "nginx", "apache", "httpd", "tomcat", "jboss", "websphere",
    "iis", "dotnet", "aspnet", "php", "node", "nodejs", "express", "django",
    "rails", "flask", "spring", "struts", "jsf", "angular", "react", "vue",
    "reactjs", "next", "nuxt", "svelte", "graphql", "gql", "websocket",
    "wss", "socket", "socket.io", "sockjs", "longpolling", "comet",
    "cgi", "cgi-bin", "perl", "ruby", "python", "php5", "php7", "php8",
    "fastcgi", "uwsgi", "gunicorn", "mod_pagespeed", "mod_security",
    "mod_evasive", "mod_spam", "spam", "filter", "clean", "sanitize",
    "verif", "verify", "valid", "check", "status", "health", "ready", "ping",
    "alive", "up", "online", "offline", "down", "error", "error404", "404",
    "debug", "trace", "debugging", "profiling", "profiler", "metrics", "metric",
    "telemetry", "stats", "statistics", "usage", "analytics", "log", "logs",
    "debug", "dev_tools", "devtools", "tools", "utility", "util", "utils",
    "helper", "helpers", "lib", "library", "vendor", "node_modules", "bower",
    "component", "package", "packages", "npm", "yarn", "cargo", "maven", "gradle",
    "composer", "pip", "gem", "nuget", "docker", "k8s", "kubernetes", "helm",
    "chart", "charts", "master", "slave", "primary", "secondary", "leader",
    "follower", "replica", "shard", "cluster", "node1", "node2", "node3",
    "worker", "workers", "backend", "frontend", "backend", "api", "api",
    "graphql", "gql", "rest", "restful", "rpc", "grpc", "thrift", "avro",
    "protobuf", "msgpack", "bson", "json", "xml", "yaml", "yml", "toml",
    "ini", "cfg", "conf", "config", "settings", "setting", "admin_settings",
    "admin-config", "config-backup", "config-restore", "config-vars",
    "env", "environment", "production", "production", "stage", "qa", "dev",
    "development", "test", "validation", "verify", "check", "verify", "check",
    "monitor", "monitoring", "status", "health", "ping", "heartbeat",
    "alert", "alarm", "notification", "notify", "event", "events", "log",
    "log", "audit", "security", "auth", "authentication", "authorization",
    "login", "logout", "session", "token", "jwt", "oauth", "oauth2", "openid",
    "saml", "ldap", "ad", "active_directory", "kerberos", "radius", "tacacs",
    "2fa", "mfa", "totp", "sms", "email", "phone", "call", "voice", "ivr",
    "hotline", "customer", "callcenter", "csr", "csirt", "support",
    "ticket", "incident", "issue", "problem", "request", "rx", "case",
    "service", "service-desk", "helpdesk", "incident-management",
    "vulnerability", "vuln", "patch", "patching", "update", "upgrade",
    "maintenance", "maintenance", "scheduled", "maintenance", "outage",
    "incident", "incident-report", "report", "administrator", "admin",
    "superuser", "root", "operator", "devops", "ops", "it", "itadmin",
    "itadmin", "network", "netadmin", "sysadmin", "dbadmin", "dba",
    "devadmin", "webadmin", "siteadmin", "admin", "administrator",
    "superadmin", "root", "sudo", "operator", "admin", "admin1", "admin2",
    "admin3", "admin4", "admin5", "guest", "public", "anonymous", "nobody",
    "user", "users", "user1", "user2", "user3", "user4", "user5",
    "member", "members", "subscriber", "role", "roles", "permission",
    "permissions", "privilege", "priv", "access", "restricted", "protected",
    "secret", "private", "internal", "confidential", "classified", "topsecret",
    "admin", "admin", "admin1", "admin2", "admin3", "admin4", "admin5",
    "administrator", "root", "superuser", "sysadmin", "webmaster", "postmaster",
    "hostmaster", "mailadmin", "security", "info", "security-report",
    "vulnerability-report", "csirt", "incident", "incident-report",
    "incident-management", "service-desk", "helpdesk", "ticket",
    "report", "archive", "old", "backup", "restore", "dump", "sql",
    "database", "databases", "db", "mysql", "postgresql", "sqlite",
    "oracle", "mssql", "mongo", "mongodb", "redis", "memcached", "elastic",
    "elasticsearch", "kibana", "logstash", "filebeat", "metricbeat",
    "heartbeat", "stacktrace", "status", "status-report", "report",
    "status", "heartbeat", "health", "healthz", "health-check", "ping",
    "alive", "up", "down", "online", "offline", "error", "warning", "info",
    "debug", "trace", "log", "log", "log4js", "log4net", "log4php",
    "log4python", "log4r", "log4js", "winston", "bunyan", "pino",
    "soc", "siem", "noc", "security-operations", "incident-response",
    "ir", "csirt", "csirt-id", "csirt-go-id", "id", "go", "id"
]

done = set()
results = []

def check(sub):
    try:
        answers = resolver.resolve(sub + "." + domain, "A", raise_on_nxdom=False)
        for r in answers:
            results.append((sub + "." + domain, "A", " ".join([str(rr) for rr in answers])))
            done.add(sub + "." + domain)
            return True
    except Exception:
        pass
    try:
        answers = resolver.resolve(sub + "." + domain, "AAAA", raise_on_nxdom=False)
        for r in answers:
            results.append((sub + "." + domain, "AAAA", " ".join([str(rr) for rr in answers])))
            done.add(sub + "." + domain)
            return True
    except Exception:
        pass
    return False

print(f"  Checking {len(wordlist)} subdomains...")
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    futures = {ex.submit(check, s): s for s in wordlist}
    for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
        if fut.result():
            if i % 20 == 0:
                print(f"  ...{i}/{len(wordlist)} checked")

all_results["brute"] = results
all_results["all"] = sorted(done)

with open("bmkg_subdomains.json", "w") as f:
    json.dump(all_results, f, indent=2)

print(f"\n  Total live subdomains: {len(done)}")
print(f"  Saved to bmkg_subdomains.json")
