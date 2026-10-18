# Splunk SOC Detection Lab

A hands-on Splunk SIEM lab that detects and correlates attacker activity across five
log sources (SSH, web, Windows Security, DNS, firewall), using a reproducible
synthetic dataset with embedded attack scenarios, noise and deliberate false positives.

## The security problem

An internet-facing Linux server and a Windows domain controller are probed, brute-forced
and, in two cases, compromised. Each source holds only part of the story: a scan in the
firewall, content discovery in web logs, password guessing in SSH or Windows logs,
suspicious DNS afterwards. The lab shows how to detect each stage, link them across
sources, and avoid mistaking an alert for a confirmed incident.

## Lab objectives

- Ingest heterogeneous logs into Splunk with custom sourcetypes.
- Write detections with time windows and configurable thresholds.
- Correlate sources by actor and host, respecting event order.
- Triage like an L1 analyst: context, source, timeline, correlation, criticality, escalation.
- Document each detection with false positives, limits and MITRE ATT&CK mapping.

## Technologies

Splunk Enterprise 10.0.1 (SPL), Python 3 (data generator and reference checker),MITRE ATT&CK.

## Prerequisites

- Splunk Enterprise or Splunk Free on a lab machine.
- Python 3.8+ (to regenerate data or run the reference checker).

## Quick start

1. Create the index `splunk_learning` and install `config/` as described in
   [`docs/installation.md`](docs/installation.md).
2. Upload the five files from `data/raw/` with the sourcetypes in the table below.
3. Upload the two CSV lookups from `data/lookups/`.
4. Set your user timezone to a UTC+2 zone and choose a time range covering 2025-06-01 to 2025-06-07.
5. Run the post-ingestion checks in the installation guide **before** any detection.

| File | Sourcetype |
|---|---|
| `apache.log` | `access_combined` |
| `secure.log` | `linux_secure` |
| `windows_security.csv` | `winsec_csv` |
| `dns.log` | `dns_tsv` |
| `firewall.log` | `firewall_csv` |


## Skills demonstrated

- **SPL:** `stats`, `bin`, `streamstats time_window`, `eval`/`case`, `rex`, `lookup`, `join`, `transaction` (and why to avoid it), `cidrmatch`.
- **Detection engineering:** time windows, configurable thresholds, sequence logic, deliberate false positives and near misses.
- **Investigation:** repeatable L1 triage method, separation of confirmed facts from inference.
- **Data handling:** custom sourcetypes, timestamps and timezones, reproducible synthetic data.
- **Dashboard Creation:** Detection Overview
- **MITRE ATT&CK:** justified mapping, parent technique when the logs cannot tell sub-techniques apart.

## Author

Justin Marius, Master's student in AI, IoT and cybersecurity (ENI), focused on defensive
security, AI security and SOC work.
