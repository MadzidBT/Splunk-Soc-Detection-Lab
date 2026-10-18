# Detection: port scan from firewall DROP events

| | |
|---|---|
| **Type** | Detection |
| **Search ID** | fw-02 |
| **Data domain** | Firewall (`firewall_csv`) |

## Objective
Find a source address that probes many distinct destination ports in a short time.

## Threat Scenario
An external host sweeps the ports of `web01` to learn which services are exposed.
In the dataset `198.51.100.23` hits 124 distinct ports on 2025-06-02 (all dropped).

## Required Telemetry
Sourcetype `firewall_csv` with `src_ip`, `dest_ip`, `dest_port` and `action`.

## SPL Query
`spl/firewall/fw-02-port-scan-drop.spl`

```spl
index=splunk_learning sourcetype=firewall_csv action=DROP
| bin span=10m _time AS window_start
| stats count AS drops dc(dest_port) AS distinct_ports dc(dest_ip) AS distinct_targets values(dest_ip) AS targets min(_time) AS first_seen max(_time) AS last_seen BY src_ip window_start
| eval min_ports=20 ```THRESHOLD: distinct destination ports per source IP per 10 minutes```
| where distinct_ports>=min_ports
| eval scan_type=if(distinct_targets=1, "vertical (one host, many ports)", "horizontal/mixed")
| convert ctime(window_start) ctime(first_seen) ctime(last_seen)
| sort - distinct_ports
```

## Detection Logic
Only `DROP` events are used. In each 10-minute window, count distinct destination
ports and targets per source. At least 20 distinct ports alerts. One target with many
ports is labelled *vertical*; several targets, *horizontal/mixed*.

## Analyst Investigation Steps
1. **Context.** Which asset is targeted, and which ports are legitimately exposed?
2. **Source.** External address? Seen in web logs (`corr-01`)?
3. **Timeline.** Duration and rate. A scan that ends is informational.
4. **Outcome.** Were any scanned ports **allowed** for this address? Search the firewall
   for `ALLOW` from the same source: a hit on an open port is the next stage.
5. **Correlation.** `corr-05` shows the same address doing web reconnaissance.
6. **Decision.** Blocked scan with no success: log, block, monitor. Allowed traffic
   to a sensitive port afterwards: escalate.

## False Positives
- Authorised vulnerability scanners and asset-discovery tools.
- Load balancers and monitoring probes hitting several ports.
- Misconfigured clients retrying many ephemeral ports.

## Severity Rationale
**Low.** Internet-facing hosts are scanned constantly. It becomes **Medium** when the
same address also reaches an open service or appears in other sources.

## MITRE ATT&CK Mapping
| Technique | Why |
|---|---|
| T1595 Active Scanning | Probing of a host's ports from outside. The logs cannot tell scanning of IP blocks (T1595.001) from vulnerability scanning (T1595.002), so the parent technique is used. If the source were *inside* the network, T1046 (Network Service Discovery) would be the better fit. |

## Recommended Response
Block the address, confirm exposed ports match the intended service list, and watch for
follow-up connections from the same source.
