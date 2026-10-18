# Detection: suspicious external activity across log sources

| | |
|---|---|
| **Type** | Correlation (prioritisation, not a confirmation) |
| **Search IDs** | corr-04 (overview), corr-05 (stages per IP); corr-01 as pivot |
| **Data domain** | Web, SSH, Windows, firewall |

## Objective
Rank external addresses by how much risky activity they produce and across how many
kinds of log, and show which attack stages each one reached.

## Threat Scenario
Attackers often leave traces in several places: a port scan in the firewall, content
discovery in web logs, password guessing in SSH or Windows logs. An address visible in
more than one place, or reaching a later stage, deserves attention first.

## Required Telemetry
`access_combined` (404), `linux_secure` (failures and successes), `winsec_csv`
(4624/4625), `firewall_csv` (DROP).

## SPL Query

**corr-04: overview** (`spl/correlation/corr-04-external-risky-ips-overview.spl`)

```spl
index=splunk_learning ((sourcetype=access_combined status=404) OR (sourcetype=linux_secure "Failed password") OR (sourcetype=winsec_csv EventCode=4625) OR (sourcetype=firewall_csv action=DROP))
| rex field=_raw "Failed password for (?:invalid user\s+)?\S+ from (?<ssh_ip>\d+\.\d+\.\d+\.\d+)"
| eval risk_ip=case(sourcetype="access_combined", clientip, sourcetype="linux_secure", ssh_ip, true(), src_ip)
| where isnotnull(risk_ip) AND NOT (cidrmatch("10.0.0.0/8", risk_ip) OR cidrmatch("172.16.0.0/12", risk_ip) OR cidrmatch("192.168.0.0/16", risk_ip))
| eval risk_type=case(sourcetype="access_combined", "web_404", sourcetype="linux_secure", "ssh_failed", sourcetype="winsec_csv", "windows_4625", sourcetype="firewall_csv", "firewall_drop")
| stats count AS events dc(risk_type) AS risk_types values(risk_type) AS risk_type_list min(_time) AS first_seen max(_time) AS last_seen BY risk_ip
| eval min_events=10 ```THRESHOLD: ignore IPs with only a few risky events (ordinary broken links, typos)```
| where events>=min_events
| convert ctime(first_seen) ctime(last_seen)
| sort - risk_types - events
| head 10
```

**corr-05: stages per IP** (`spl/correlation/corr-05-attack-stages-per-ip.spl`)

```spl
index=splunk_learning ((sourcetype=firewall_csv action=DROP) OR (sourcetype=access_combined status=404) OR (sourcetype=linux_secure ("Failed password" OR "Accepted password")) OR (sourcetype=winsec_csv (EventCode=4625 OR EventCode=4624)))
| rex field=_raw "sshd\[\d+\]:\s+(?<ssh_result>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?\S+\s+from\s+(?<ssh_ip>\d+\.\d+\.\d+\.\d+)"
| eval actor_ip=case(sourcetype="access_combined", clientip, sourcetype="linux_secure", ssh_ip, true(), src_ip)
| where isnotnull(actor_ip) AND NOT (cidrmatch("10.0.0.0/8", actor_ip) OR cidrmatch("172.16.0.0/12", actor_ip) OR cidrmatch("192.168.0.0/16", actor_ip))
| eval stage=case(sourcetype="firewall_csv", "1_port_scan", sourcetype="access_combined", "2_web_recon", sourcetype="linux_secure" AND ssh_result="Failed", "3_ssh_failures", sourcetype="winsec_csv" AND EventCode=4625, "3_windows_failures", sourcetype="linux_secure" AND ssh_result="Accepted", "4_ssh_success", sourcetype="winsec_csv" AND EventCode=4624, "4_windows_success")
| stats count AS events dc(stage) AS stage_count values(stage) AS stages min(_time) AS first_seen max(_time) AS last_seen BY actor_ip
| where stage_count>=2
| convert ctime(first_seen) ctime(last_seen)
| sort - stage_count - events
```

## Detection Logic
Both searches reduce each source to a single "actor address" with `case()`, drop private
ranges, and aggregate per address. corr-04 counts risk types and events (minimum 10
events). corr-05 maps events to numbered stages (1 port scan, 2 web recon, 3 failures,
4 success) and keeps addresses with at least two distinct stages.

## Analyst Investigation Steps
1. Start from corr-05 and look at the **highest stage** reached by each address, not the
   count.
2. For each address, pivot with `corr-01` to build a timeline across sources.
3. Any address with a success stage: continue with the matching chain
   (`ssh-compromise-to-c2.md` or `windows-rdp-compromise-chain.md`).
4. Addresses with only reconnaissance: record, block, monitor.
5. Check whether an address is internal infrastructure that the range filter missed.

## False Positives
- Corporate egress, VPN or NAT addresses that aggregate many users.
- Search-engine crawlers (404s) and security scanners.
- Cloud addresses used by legitimate partners.

## Severity Rationale
This is a **triage aid**, so it carries no severity of its own. Priority comes from the
stage reached (success beats attempt) and the asset affected.

## MITRE ATT&CK Mapping
Not mapped as a whole: the stages correspond to techniques documented in the other
cards (T1595 / T1595.003, T1110.001, T1078, T1133). A ranking is not a technique.

## Recommended Response
Use the ranking to order work, not to close alerts: investigate success stages first,
then block reconnaissance-only addresses.
