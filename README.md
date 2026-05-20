# 🛡️ SOC Analyst Automation Toolkit

> **Splunk SDK-powered automation for Alert Triage, Threat Hunting, Incident Response, and IOC Correlation**

---

## 📋 Overview

The **SOC Analyst Automation Toolkit** is a Python-based framework built on the Splunk SDK that automates the most time-intensive tasks in a Security Operations Center. It consolidates four critical workflows into a single, opinionated pipeline: alert triage with OSINT enrichment, MITRE ATT&CK-aligned threat hunting, guided incident response, and bulk IOC correlation against live traffic.

---

## 🏗️ Architecture

```
soc_automation_toolkit/
├── main.py                  # Entry point — full automation run
├── .env                     # Environment config (see setup)
├── soc_report.json          # Auto-generated JSON report (output)
├── soc_automation.log       # Timestamped run log (output)
└── modules/
    ├── AlertTriageEngine     # Module 1 — Alert triage & enrichment
    ├── ThreatHunter          # Module 2 — Threat hunting queries
    ├── IncidentResponsePlaybook  # Module 3 — IR playbook automation
    └── IOCCorrelator         # Module 4 — IOC correlation & lookup
```

---

## ⚙️ Prerequisites & Installation

**Python 3.8+** is required.

```bash
pip install splunk-sdk requests python-dotenv colorama
```

### Environment Variables

Create a `.env` file in the project root:

```env
SPLUNK_HOST=splunk.yourdomain.com
SPLUNK_PORT=8089
SPLUNK_USER=admin
SPLUNK_PASS=yourpassword

# Optional — enables OSINT enrichment
VIRUSTOTAL_API_KEY=<your_vt_key>
ABUSEIPDB_API_KEY=<your_abuse_key>
```

> **Note:** VirusTotal and AbuseIPDB API keys are optional. If omitted, enrichment steps are silently skipped.

---

## 🚀 Usage

### Full Automation Run

```bash
python main.py
```

This executes all four modules in sequence and writes:
- `soc_report.json` — structured findings report
- `soc_automation.log` — timestamped console log

### Run Individual Modules

```python
from main import connect_splunk
from modules import ThreatHunter, AlertTriageEngine, IOCCorrelator

service = connect_splunk()

# Run only threat hunting
hunter = ThreatHunter(service)
findings = hunter.run_all(earliest="-48h")

# Run a single custom hunt
hunter.run_custom("My Hunt", "index=* src_ip=* | stats count by src_ip")
```

---

## 🔍 Module Reference

### Module 1 — Alert Triage & Enrichment (`AlertTriageEngine`)

Pulls notable events from Splunk ES / correlation searches, assigns a triage score, and enriches source IPs via VirusTotal and AbuseIPDB.

**Scoring Logic:**

| Factor | Weight |
|---|---|
| Severity (critical/high/medium/low) | +10 / +7 / +4 / +1 |
| Event count (per 5 events, max +5) | +1 to +5 |
| Alert age > 120 minutes | −1 |

**Output fields per alert:** `alert_name`, `severity`, `src_ip`, `dest_ip`, `user`, `triage_score`, `vt_info`, `abuse_info`

---

### Module 2 — Threat Hunting (`ThreatHunter`)

Six pre-built SPL queries mapped to MITRE ATT&CK techniques:

| Technique | Detection |
|---|---|
| **T1078** — Valid Accounts | Brute force: >10 failed logins per user/dest |
| **T1059** — PowerShell | Malicious script blocks (Mimikatz, IEX, EncodedCommand, etc.) |
| **T1486** — Ransomware | Known ransomware file extensions via Sysmon Event 11 |
| **T1071** — C2 Beaconing | DNS: >200 queries to <5 unique domains from single src |
| **T1136** — Persistence | New local admin account creation (Event 4720 + S-1-5-32-544) |
| **T1003** — Credential Access | LSASS memory access via Sysmon Event 10 |

Add a custom hunt at runtime:
```python
hunter.run_custom("My Hunt Name", "<your SPL query>", earliest="-7d")
```

---

### Module 3 — Incident Response Playbook (`IncidentResponsePlaybook`)

Automated IR steps triggered on the **top-scored alert** from Module 1.

**Steps executed:**
1. **Timeline Build** — Chronological event log for the source IP/user/host (default: 48h window)
2. **Lateral Movement Check** — Detects auth events to >2 distinct targets (Events 4624, 4648, 4672, 4776)
3. **Persistence Check** — Scans for scheduled tasks, registry run keys, and new services
4. **Containment Recommendations** — Generated based on triage score:

| Score | Action Level |
|---|---|
| ≥ 10 | CRITICAL — Isolate host, disable AD account, block IP, escalate P1 |
| 5–9 | HIGH — Investigate NetFlow, reset credentials, enable logging, P2 ticket |
| < 5 | MEDIUM — Monitor for 24h, document |

---

### Module 4 — IOC Correlation (`IOCCorrelator`)

Search Splunk for known-bad indicators and optionally update a KV Store lookup table.

**Supported IOC types:** `ip`, `domain`, `hash`, `user`

```python
iocs = [
    {"value": "185.220.101.45",                    "type": "ip",     "threat_level": "high"},
    {"value": "malware.example.com",               "type": "domain", "threat_level": "critical"},
    {"value": "d41d8cd98f00b204e9800998ecf8427e",  "type": "hash",   "threat_level": "medium"},
]

correlator = IOCCorrelator(service)
correlator.bulk_ioc_search(iocs)
correlator.detect_ioc_in_traffic(lookup_name="ioc_lookup")
```

Persist IOCs to a Splunk KV Store for ongoing detection:
```python
correlator.update_lookup_table(service, "ioc_lookup", iocs)
```

---

## 📄 Report Output

After each run, `soc_report.json` is written with the following structure:

```json
{
  "run_time": "2025-01-01T00:00:00",
  "modules": {
    "alert_triage": [ ... ],
    "threat_hunting": { "T1078 - Brute Force": 3, ... },
    "incident_response": {
      "entity": "1.2.3.4",
      "timeline_events": 47,
      "lateral_movement": true,
      "persistence_checks": { "Scheduled Tasks": 2, ... },
      "containment_steps": [ ... ]
    },
    "ioc_correlation": {
      "iocs_checked": 3,
      "iocs_matched": 1,
      "live_hits": 2
    }
  }
}
```

---

## 🖥️ Console Log Levels

| Color | Level | Meaning |
|---|---|---|
| 🔵 Cyan | INFO | Standard progress messages |
| 🟡 Yellow | WARN | Findings requiring attention |
| 🔴 Red | ERROR | Critical hits / connection failures |
| 🟢 Green | SUCCESS | Clean results / successful operations |
| 🟣 Magenta | SECTION | Module / phase headers |

---

## 🔐 Security Notes

- Store credentials exclusively in `.env` — never commit this file. Add `.env` to `.gitignore`.
- API keys (VirusTotal, AbuseIPDB) are read-only enrichment keys and do not require write permissions.
- The KV Store update function requires Splunk `admin` or a role with `edit_kvstore` capability.
- All SPL queries use `blocking` exec mode — tune `max_count` and time windows for large environments.

---

## 🗺️ Roadmap

- [ ] Slack / Teams webhook alerting for critical-score events
- [ ] TheHive / MISP integration for case management
- [ ] Async search mode for large-scale hunts
- [ ] CSV/PDF report export
- [ ] Docker container with pre-configured `.env` template
- [ ] Unit tests with mock Splunk responses

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-hunt`
3. Commit your changes: `git commit -m 'Add T1055 process injection hunt'`
4. Push and open a Pull Request

Please keep new SPL queries mapped to a MITRE ATT&CK technique and include a comment explaining detection logic.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
