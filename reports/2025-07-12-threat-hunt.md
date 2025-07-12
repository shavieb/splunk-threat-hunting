# 🔍 Splunk Threat Hunt – July 12, 2025

## Summary

While reviewing Apache access logs using Splunk, one IP address stood out due to an unusually high number of failed page requests (404 errors) and suspicious targeting of outdated internal tools.

---

## 🚨 Suspicious IP: 208.91.156.11

- **Total Requests:** 120
- **Status Codes:** Mostly 404
- **URI Path Example:** `/files/logstash/logstash-1.3.2-monolithic.jar`
- **Behavior Pattern:** Automated scanning for outdated Logstash file
- **Timestamps:** Activity occurred over a short time window, indicating non-human traffic

---

## 🔎 Why It Matters

The IP appears to be scanning for vulnerable endpoints. Attempting to access internal or outdated JAR files is a known prelude to further exploitation — either by attempting to download internal code or exploit known vulnerabilities in old software.

This matches the **MITRE ATT&CK technique T1595: Active Scanning**, which falls under the **Reconnaissance** tactic.

---

## ✅ Recommendation

- Block IP `208.91.156.11` at perimeter firewall or WAF
- Monitor future scans for `/logstash`, `/admin`, or `.jar` files
- Consider setting up honey URLs to track these scanners over time

---

## Splunk Query Used

```spl
index=main status=404 | stats count by clientip | sort -count
