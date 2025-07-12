# 🕵️ Splunk Threat Hunting Lab

This repository contains hands-on exercises simulating real-world threat hunting scenarios using Splunk. It showcases how a Security Analyst can use log data to detect suspicious activity, investigate anomalies, and respond to potential threats.

---

## 🔧 Tools Used

- [Splunk Enterprise Free](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- Sample Apache access logs
- [AbuseIPDB](https://abuseipdb.com) and [VirusTotal](https://virustotal.com) for IP threat intel
- [MITRE ATT&CK Framework](https://attack.mitre.org)

---

## 📁 Folder Structure

splunk-threat-hunting/
├── README.md
└── reports/
├── 2025-07-12-threat-hunt.md


---

## 🧪 Included Reports

### ✅ 2025-07-12 Threat Hunt

- Reviewed Apache logs for suspicious patterns
- Detected 120 failed requests from IP `208.91.156.11`
- Identified scanning behavior targeting outdated Logstash software
- Mapped behavior to MITRE T1595: Active Scanning

[View the report →](./reports/2025-07-12-threat-hunt.md)

---

## 📊 Splunk Queries Used

```spl
index=main status=404 | stats count by clientip | sort -count
index=main | top uri_path
index=main | stats count by clientip
