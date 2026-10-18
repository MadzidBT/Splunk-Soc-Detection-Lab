# Detection: web directory scan (404 burst)

| | |
|---|---|
| **Type** | Detection |
| **Search ID** | web-04 |
| **Data domain** | Web access (`access_combined`) |

## Objective
Identify a client that requests many different non-existent paths in a short time,
typical of automated content discovery.

## Threat Scenario
Before attacking, an adversary enumerates common paths (`/.env`, `/wp-admin/`,
`/phpmyadmin/`, `/.git/config`, `/backup.zip`) to find exposed files and admin panels.
In the dataset `198.51.100.23` does this on 2025-06-02 and 2025-06-03.

## Required Telemetry
- Sourcetype `access_combined` with `clientip`, `status` and `useragent` extracted.
- The requested path is read from the raw request line with `rex`.

## SPL Query
`spl/web/web-04-directory-scan-404.spl`

```spl
index=splunk_learning sourcetype=access_combined status=404
| rex field=_raw "\"(?<http_method>[A-Z]+)\s+(?<requested_uri>\S+)\s+HTTP/"
| bin span=5m _time AS window_start
| stats count AS not_found dc(requested_uri) AS distinct_uris values(http_method) AS methods values(useragent) AS user_agents min(_time) AS first_seen max(_time) AS last_seen BY clientip window_start
| eval min_404=20, min_distinct_uris=10 ```THRESHOLDS per 5-minute window```
| where not_found>=min_404 AND distinct_uris>=min_distinct_uris
| convert ctime(window_start) ctime(first_seen) ctime(last_seen)
| sort - not_found
```

## Detection Logic
Count `404` responses and distinct requested paths per client in 5-minute windows.
A window alerts when it has at least 20 `404`s **and** at least 10 distinct paths.
Both conditions matter: many 404s on the same path is usually a broken link, many
different paths is enumeration.

## Analyst Investigation Steps
1. **Context.** Is the server public? Does the application legitimately generate 404s?
2. **Source.** Look at `user_agents`: empty, `curl` or `python-requests` favours automation.
   Check whether the address is a known scanner or partner.
3. **Timeline.** Duration and rate of the burst, and whether it repeats on other days.
4. **Responses.** Look at non-404 answers for the same client (`200`, `403`): a `200` on a
   sensitive path means exposure, not just a scan.
5. **Correlation.** Run `corr-01` and `corr-05`: the same address also appears in the
   firewall log (port scan). A single actor across two sources strengthens the case.
6. **Decision.** No sensitive path answered `200`: block and monitor. Sensitive file
   served: escalate.

## False Positives
- Search-engine crawlers and uptime monitors following stale links.
- A broken deployment (missing assets) producing many 404s from real users, which
  usually targets few distinct paths.
- Authorised vulnerability scans.

## Severity Rationale
**Low to Medium.** Reconnaissance alone does not compromise anything. Raise to **High**
if the scan obtains `200` responses on sensitive files, or if the address then logs in
elsewhere.

## MITRE ATT&CK Mapping
| Technique | Why |
|---|---|
| T1595.003 Active Scanning: Wordlist Scanning | A wordlist of common paths requested against one server in a short burst. |

## Recommended Response
Block the address at the WAF or firewall, check logs for any `200` on sensitive paths,
review exposed files, and watch for follow-up logins from the same address.
