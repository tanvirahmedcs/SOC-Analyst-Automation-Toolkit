"""
=============================================================
  SOC ANALYST AUTOMATION TOOLKIT — Splunk SDK
  Covers: Alert Triage & Enrichment | Threat Hunting |
          Incident Response Playbook | IOC Correlation
=============================================================
Dependencies:
    pip install splunk-sdk requests python-dotenv colorama

Environment Variables (.env):
    SPLUNK_HOST=splunk.yourdomain.com
    SPLUNK_PORT=8089
    SPLUNK_USER=admin
    SPLUNK_PASS=yourpassword
    VIRUSTOTAL_API_KEY=<optional>
    ABUSEIPDB_API_KEY=<optional>
=============================================================
"""

import os
import sys
import json
import time
import hashlib
import datetime
import requests
import splunklib.client as splunk_client
import splunklib.results as splunk_results
from dotenv import load_dotenv
from colorama import Fore, Style, init

load_dotenv()
init(autoreset=True)

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", 8089))
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASS", "changeme")
VT_API_KEY   = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

LOG_FILE = "soc_automation.log"
REPORT_FILE = "soc_report.json"


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def log(msg, level="INFO"):
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    colors = {"INFO": Fore.CYAN, "WARN": Fore.YELLOW,
              "ERROR": Fore.RED, "SUCCESS": Fore.GREEN, "SECTION": Fore.MAGENTA}
    color = colors.get(level, Fore.WHITE)
    line = f"[{ts}] [{level}] {msg}"
    print(f"{color}{line}{Style.RESET_ALL}")
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def section(title):
    bar = "═" * 60
    log(f"\n{bar}\n  {title}\n{bar}", level="SECTION")


def connect_splunk():
    """Return an authenticated Splunk service object."""
    try:
        service = splunk_client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USER,
            password=SPLUNK_PASS,
        )
        log(f"Connected to Splunk at {SPLUNK_HOST}:{SPLUNK_PORT}", "SUCCESS")
        return service
    except Exception as e:
        log(f"Splunk connection failed: {e}", "ERROR")
        sys.exit(1)


def run_search(service, spl_query, earliest="-24h", latest="now", max_count=500):
    """Execute a blocking SPL search and return list of result dicts."""
    kwargs = {
        "exec_mode": "blocking",
        "earliest_time": earliest,
        "latest_time": latest,
    }
    try:
        job = service.jobs.create(spl_query, **kwargs)
        results = []
        for r in splunk_results.JSONResultsReader(job.results(output_mode="json", count=max_count)):
            if isinstance(r, dict):
                results.append(r)
        return results
    except Exception as e:
        log(f"Search failed: {e}", "ERROR")
        return []


# ─────────────────────────────────────────────
#  MODULE 1 — ALERT TRIAGE & ENRICHMENT
# ─────────────────────────────────────────────
class AlertTriageEngine:
    """
    Pull notable alerts from ES / correlation searches,
    score them, and auto-enrich with OSINT.
    """

    TRIAGE_QUERY = """
    index=notable OR index=main sourcetype=stash
    | eval age_minutes=round((now()-_time)/60,1)
    | eval severity=coalesce(severity,"unknown")
    | stats count by alert_name, severity, src_ip, dest_ip, user, age_minutes
    | sort -count
    """

    SEVERITY_SCORE = {"critical": 10, "high": 7, "medium": 4, "low": 1, "unknown": 0}

    def __init__(self, service):
        self.service = service

    def fetch_alerts(self, hours=24):
        section("ALERT TRIAGE — Fetching Notable Events")
        results = run_search(self.service, self.TRIAGE_QUERY, earliest=f"-{hours}h")
        if not results:
            log("No notable alerts found in window.", "WARN")
            return []
        log(f"Found {len(results)} alert groups.", "SUCCESS")
        return results

    def score_alert(self, alert):
        sev = alert.get("severity", "unknown").lower()
        base = self.SEVERITY_SCORE.get(sev, 0)
        count_bonus = min(int(alert.get("count", 1)) // 5, 5)
        age_penalty = -1 if float(alert.get("age_minutes", 0)) > 120 else 0
        return base + count_bonus + age_penalty

    def enrich_ip_virustotal(self, ip):
        if not VT_API_KEY or not ip:
            return {}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            r = requests.get(url, headers=headers, timeout=10)
            data = r.json().get("data", {}).get("attributes", {})
            return {
                "malicious_votes": data.get("last_analysis_stats", {}).get("malicious", 0),
                "country": data.get("country", "N/A"),
                "owner": data.get("as_owner", "N/A"),
            }
        except Exception as e:
            log(f"VirusTotal enrichment failed for {ip}: {e}", "WARN")
            return {}

    def enrich_ip_abuseipdb(self, ip):
        if not ABUSE_API_KEY or not ip:
            return {}
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            r = requests.get(url, headers=headers, params=params, timeout=10)
            d = r.json().get("data", {})
            return {
                "abuse_confidence": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "isp": d.get("isp", "N/A"),
            }
        except Exception as e:
            log(f"AbuseIPDB enrichment failed for {ip}: {e}", "WARN")
            return {}

    def triage(self, hours=24):
        alerts = self.fetch_alerts(hours)
        enriched = []
        for a in alerts:
            score = self.score_alert(a)
            src_enrich = self.enrich_ip_virustotal(a.get("src_ip"))
            src_abuse  = self.enrich_ip_abuseipdb(a.get("src_ip"))
            record = {**a, "triage_score": score,
                      "vt_info": src_enrich, "abuse_info": src_abuse}
            enriched.append(record)
            lvl = "ERROR" if score >= 10 else "WARN" if score >= 5 else "INFO"
            log(f"[Score:{score:>2}] {a.get('alert_name','?')} | "
                f"src={a.get('src_ip','?')} sev={a.get('severity','?')}", lvl)
        enriched.sort(key=lambda x: x["triage_score"], reverse=True)
        return enriched


# ─────────────────────────────────────────────
#  MODULE 2 — THREAT HUNTING QUERIES
# ─────────────────────────────────────────────
class ThreatHunter:
    """
    Pre-built SPL threat-hunting searches aligned to MITRE ATT&CK.
    """

    HUNTS = {
        "T1078 - Brute Force / Valid Accounts": """
            index=* (sourcetype=WinEventLog:Security OR sourcetype=linux_secure)
            (EventCode=4625 OR "Failed password")
            | stats count as failures, dc(src_ip) as src_count by user, dest
            | where failures > 10
            | eval risk=if(failures>50,"CRITICAL","HIGH")
            | sort -failures
        """,
        "T1059 - Suspicious PowerShell Execution": """
            index=* sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational
            EventCode=4104
            | search ScriptBlockText IN ("*Invoke-Mimikatz*","*IEX*","*DownloadString*",
                                          "*EncodedCommand*","*bypass*","*Hidden*")
            | stats count by host, user, ScriptBlockText
            | sort -count
        """,
        "T1486 - Ransomware File Extension Changes": """
            index=* sourcetype=sysmon EventCode=11
            | rex field=TargetFilename "(?<ext>\\.[^.]+$)"
            | search ext IN (".locked",".encrypted",".crypto",".crypt",".wnry",".zepto")
            | stats count by host, user, ext
            | sort -count
        """,
        "T1071 - DNS Beaconing / C2 Traffic": """
            index=* sourcetype=stream:dns
            | stats count, dc(query) as unique_domains, avg(bytes) as avg_bytes
              by src_ip, dest_ip
            | where count > 200 AND unique_domains < 5
            | eval beacon_score=round(count/unique_domains,2)
            | sort -beacon_score
        """,
        "T1136 - New Local Admin Account Created": """
            index=* sourcetype=WinEventLog:Security EventCode=4720
            | eval is_admin=if(match(MemberSid,"S-1-5-32-544"),"YES","NO")
            | stats count by user, src_user, host, is_admin
            | where is_admin="YES"
        """,
        "T1003 - LSASS Memory Dump (Credential Access)": """
            index=* sourcetype=sysmon EventCode=10
            TargetImage="*lsass.exe"
            | stats count by host, SourceImage, SourceUser, GrantedAccess
            | where GrantedAccess IN ("0x1010","0x1038","0x143a","0x40")
            | sort -count
        """,
    }

    def __init__(self, service):
        self.service = service

    def run_all(self, earliest="-24h"):
        section("THREAT HUNTING — Running ATT&CK-Aligned Queries")
        findings = {}
        for name, query in self.HUNTS.items():
            log(f"Hunting: {name}")
            results = run_search(self.service, query, earliest=earliest)
            findings[name] = results
            if results:
                log(f"  ⚠  {len(results)} hits found!", "WARN")
            else:
                log(f"  ✓  No hits.", "SUCCESS")
        return findings

    def run_custom(self, name, spl, earliest="-24h"):
        log(f"Running custom hunt: {name}")
        results = run_search(self.service, spl, earliest=earliest)
        log(f"  Results: {len(results)}", "SUCCESS" if not results else "WARN")
        return {name: results}


# ─────────────────────────────────────────────
#  MODULE 3 — INCIDENT RESPONSE PLAYBOOK
# ─────────────────────────────────────────────
class IncidentResponsePlaybook:
    """
    Automated IR steps: isolation check, timeline build,
    artifact collection, containment recommendations.
    """

    def __init__(self, service):
        self.service = service

    def build_timeline(self, entity, entity_type="src_ip", hours=48):
        """Pull a chronological event timeline for a given IP/user/host."""
        section(f"IR PLAYBOOK — Timeline for {entity_type}={entity}")
        field = {"src_ip": "src_ip", "user": "user", "host": "host"}.get(entity_type, "src_ip")
        query = f"""
            index=* {field}="{entity}"
            | eval ts=strftime(_time,"%Y-%m-%d %H:%M:%S")
            | table ts, index, sourcetype, {field}, src_ip, dest_ip,
                    user, host, EventCode, action, _raw
            | sort _time
        """
        results = run_search(self.service, query, earliest=f"-{hours}h")
        log(f"Timeline events: {len(results)}", "SUCCESS")
        return results

    def check_lateral_movement(self, src_ip):
        section(f"IR PLAYBOOK — Lateral Movement Check from {src_ip}")
        query = f"""
            index=* src_ip="{src_ip}"
            (sourcetype=WinEventLog:Security EventCode IN (4624,4648,4672,4776))
            | stats count, values(dest_ip) as targets, values(user) as users by src_ip
            | eval target_count=mvcount(targets)
            | where target_count > 2
        """
        results = run_search(self.service, query)
        if results:
            log(f"Lateral movement detected! Targets: {results[0].get('targets','?')}", "ERROR")
        else:
            log("No lateral movement detected.", "SUCCESS")
        return results

    def check_persistence(self, host):
        section(f"IR PLAYBOOK — Persistence Mechanisms on {host}")
        queries = {
            "Scheduled Tasks": f"""
                index=* host="{host}" sourcetype=sysmon EventCode=1
                (CommandLine="*schtasks*" OR CommandLine="*at.exe*")
                | table _time, user, CommandLine, ParentImage
            """,
            "Registry Run Keys": f"""
                index=* host="{host}" sourcetype=sysmon EventCode=13
                TargetObject IN ("*Run*","*RunOnce*","*Services*")
                | table _time, user, TargetObject, Details
            """,
            "New Services": f"""
                index=* host="{host}" sourcetype=WinEventLog:Security EventCode=4697
                | table _time, user, ServiceName, ServiceFileName
            """,
        }
        findings = {}
        for name, q in queries.items():
            r = run_search(self.service, q)
            findings[name] = r
            log(f"  {name}: {len(r)} events", "WARN" if r else "SUCCESS")
        return findings

    def generate_containment_steps(self, alert_data):
        section("IR PLAYBOOK — Containment Recommendations")
        steps = []
        score = alert_data.get("triage_score", 0)
        src   = alert_data.get("src_ip", "unknown")
        user  = alert_data.get("user", "unknown")
        host  = alert_data.get("dest_ip", "unknown")

        if score >= 10:
            steps += [
                f"[CRITICAL] Isolate host {host} from network immediately.",
                f"[CRITICAL] Disable AD account: {user}",
                f"[CRITICAL] Block src_ip {src} at perimeter firewall.",
                "[CRITICAL] Escalate to Tier 3 / CISO. Open P1 ticket.",
            ]
        elif score >= 5:
            steps += [
                f"[HIGH] Investigate src_ip {src} — pull full NetFlow.",
                f"[HIGH] Reset credentials for user: {user}",
                f"[HIGH] Enable enhanced logging on host {host}.",
                "[HIGH] Assign to Tier 2. Open P2 ticket.",
            ]
        else:
            steps += [
                f"[MEDIUM] Monitor src_ip {src} for 24h.",
                "[MEDIUM] Document and close if no recurrence.",
            ]

        for s in steps:
            lvl = "ERROR" if "CRITICAL" in s else "WARN" if "HIGH" in s else "INFO"
            log(s, lvl)
        return steps


# ─────────────────────────────────────────────
#  MODULE 4 — IOC CORRELATION & LOOKUP
# ─────────────────────────────────────────────
class IOCCorrelator:
    """
    Search Splunk for known IOCs (IPs, domains, hashes, users).
    Generates a correlation report and optionally updates a lookup table.
    """

    def __init__(self, service):
        self.service = service

    def search_ioc(self, ioc, ioc_type="ip", hours=168):
        """
        ioc_type: ip | domain | hash | user
        """
        field_map = {
            "ip":     '(src_ip="{v}" OR dest_ip="{v}")',
            "domain": '(query="{v}" OR url="{v}" OR domain="{v}")',
            "hash":   '(file_hash="{v}" OR MD5="{v}" OR SHA256="{v}")',
            "user":   '(user="{v}" OR src_user="{v}")',
        }
        filt = field_map.get(ioc_type, 'src_ip="{v}"').format(v=ioc)
        query = f"""
            index=* {filt}
            | eval ioc="{ioc}", ioc_type="{ioc_type}"
            | stats count, values(index) as indexes,
                    values(sourcetype) as sourcetypes,
                    min(_time) as first_seen, max(_time) as last_seen
              by ioc, ioc_type
            | eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S"),
                   last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
        """
        results = run_search(self.service, query, earliest=f"-{hours}h")
        found = bool(results)
        log(f"IOC [{ioc_type}] {ioc} — {'HIT ⚠' if found else 'CLEAN ✓'}",
            "WARN" if found else "SUCCESS")
        return results

    def bulk_ioc_search(self, ioc_list):
        """
        ioc_list: list of dicts [{"value": "1.2.3.4", "type": "ip"}, ...]
        """
        section("IOC CORRELATION — Bulk IOC Search")
        report = []
        for item in ioc_list:
            val  = item.get("value", "")
            kind = item.get("type", "ip")
            hits = self.search_ioc(val, kind)
            report.append({"ioc": val, "type": kind, "hits": hits, "found": bool(hits)})
        matched = [r for r in report if r["found"]]
        log(f"IOCs checked: {len(report)} | Matched: {len(matched)}", "SUCCESS")
        return report

    def update_lookup_table(self, service, lookup_name, ioc_list):
        """Push IOCs into a Splunk KV Store lookup."""
        section(f"IOC CORRELATION — Updating Lookup: {lookup_name}")
        try:
            collection = service.kvstore[lookup_name]
            inserted = 0
            for item in ioc_list:
                collection.data.insert(json.dumps({
                    "ioc_value": item.get("value"),
                    "ioc_type":  item.get("type"),
                    "added_by":  "soc_automation",
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "threat_level": item.get("threat_level", "medium"),
                }))
                inserted += 1
            log(f"Inserted {inserted} IOCs into {lookup_name}", "SUCCESS")
        except Exception as e:
            log(f"KV Store update failed: {e}", "ERROR")

    def detect_ioc_in_traffic(self, lookup_name="ioc_lookup"):
        """Run a correlation search against the IOC lookup table."""
        query = f"""
            index=* 
            | lookup {lookup_name} ioc_value AS src_ip OUTPUT ioc_type, threat_level
            | where isnotnull(threat_level)
            | stats count by src_ip, ioc_type, threat_level, host, user
            | sort -count
        """
        results = run_search(self.service, query)
        if results:
            log(f"IOC matches in live traffic: {len(results)}", "ERROR")
        else:
            log("No live IOC matches found.", "SUCCESS")
        return results


# ─────────────────────────────────────────────
#  REPORTING
# ─────────────────────────────────────────────
def save_report(data, path=REPORT_FILE):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log(f"Report saved → {path}", "SUCCESS")


# ─────────────────────────────────────────────
#  MAIN — FULL AUTOMATION RUN
# ─────────────────────────────────────────────
def main():
    section("SOC ANALYST AUTOMATION TOOLKIT — STARTING")
    report = {"run_time": datetime.datetime.utcnow().isoformat(), "modules": {}}

    service = connect_splunk()

    # ── 1. Alert Triage & Enrichment ─────────
    triage = AlertTriageEngine(service)
    enriched_alerts = triage.triage(hours=24)
    report["modules"]["alert_triage"] = enriched_alerts

    # ── 2. Threat Hunting ─────────────────────
    hunter = ThreatHunter(service)
    hunt_findings = hunter.run_all(earliest="-24h")
    report["modules"]["threat_hunting"] = {k: len(v) for k, v in hunt_findings.items()}

    # ── 3. Incident Response Playbook ────────
    #  Auto-run IR on the top-scored alert
    ir = IncidentResponsePlaybook(service)
    if enriched_alerts:
        top = enriched_alerts[0]
        src  = top.get("src_ip", "")
        host = top.get("dest_ip", "")
        timeline    = ir.build_timeline(src, "src_ip", hours=48)
        lateral     = ir.check_lateral_movement(src)
        persistence = ir.check_persistence(host) if host else {}
        steps       = ir.generate_containment_steps(top)
        report["modules"]["incident_response"] = {
            "entity": src,
            "timeline_events": len(timeline),
            "lateral_movement": bool(lateral),
            "persistence_checks": {k: len(v) for k, v in persistence.items()},
            "containment_steps": steps,
        }

    # ── 4. IOC Correlation ────────────────────
    #  Sample IOC list — replace with your threat intel feed
    sample_iocs = [
        {"value": "185.220.101.45", "type": "ip",     "threat_level": "high"},
        {"value": "malware.example.com", "type": "domain", "threat_level": "critical"},
        {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "hash", "threat_level": "medium"},
    ]
    correlator = IOCCorrelator(service)
    ioc_report = correlator.bulk_ioc_search(sample_iocs)
    live_hits  = correlator.detect_ioc_in_traffic()
    report["modules"]["ioc_correlation"] = {
        "iocs_checked": len(sample_iocs),
        "iocs_matched": sum(1 for r in ioc_report if r["found"]),
        "live_hits":    len(live_hits),
    }

    # ── Save Report ───────────────────────────
    save_report(report)
    section("AUTOMATION COMPLETE")
    log(f"Full report → {REPORT_FILE} | Log → {LOG_FILE}", "SUCCESS")


if __name__ == "__main__":
    main()
