# Detection: SSH compromise followed by command execution and C2 beaconing

| | |
|---|---|
| **Type** | Correlation (investigation chain) |
| **Search IDs** | auth-03, corr-06, corr-02, corr-03 (corr-01 as pivot) |
| **Data domain** | Linux authentication, firewall, DNS, asset lookups |

## Objective
Follow one compromised host across four sources: initial access, command execution,
outbound connections and DNS to suspicious domains, in that order.

## Threat Scenario
After `203.0.113.50` logs in as `root` on `web01` (2025-06-03 02:18:24), root runs
`curl` to download a script from the attacker's address (02:19:09). Ten minutes later
`web01` starts resolving `evil-update.net` and, the next day, `malware.xyz`, and
connects outbound on port 443 to `203.0.113.50`.

## Required Telemetry
`linux_secure` (sshd and sudo), `firewall_csv`, `dns_tsv`, plus the lookups
`asset_inventory.csv` and `suspicious_domains.csv`.

## SPL Query
Each step has its own search; run them in order.

**corr-06: sudo shortly after an external login**
(`spl/correlation/corr-06-sudo-shortly-after-external-ssh-login.spl`)

```spl
index=splunk_learning sourcetype=linux_secure ("Accepted password" OR "Accepted publickey" OR "sudo:")
| rex field=_raw "Accepted\s+(?:password|publickey)\s+for\s+(?<ssh_user>\S+)\s+from\s+(?<ssh_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "sudo:\s+(?<sudo_user>\S+)\s+:.*COMMAND=(?<command>.+)$"
| eval external_login_ip=if(isnotnull(ssh_ip) AND NOT (cidrmatch("10.0.0.0/8", ssh_ip) OR cidrmatch("172.16.0.0/12", ssh_ip) OR cidrmatch("192.168.0.0/16", ssh_ip)), ssh_ip, null())
| sort 0 _time ```ascending order required by time_window```
| streamstats time_window=5m latest(external_login_ip) AS recent_external_login_ip BY host
| where isnotnull(command) AND isnotnull(recent_external_login_ip)
| eval downloads_payload=if(match(command, "(?i)\b(curl|wget)\b"), "yes", "no")
| table _time host sudo_user command recent_external_login_ip downloads_payload
```

**corr-02: SSH-failure IP also in firewall logs**
(`spl/correlation/corr-02-ssh-bruteforce-ip-in-firewall.spl`)

```spl
index=splunk_learning ((sourcetype=linux_secure "Failed password") OR sourcetype=firewall_csv)
| rex field=_raw "Failed password for (?:invalid user\s+)?\S+ from (?<ssh_ip>\d+\.\d+\.\d+\.\d+)"
| eval fw_src_internal=if(sourcetype="firewall_csv" AND (cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip)), 1, 0)
| eval remote_ip=case(sourcetype="linux_secure", ssh_ip, fw_src_internal=1, dest_ip, true(), src_ip) ```remote end of the connection```
| where isnotnull(remote_ip) AND NOT (cidrmatch("10.0.0.0/8", remote_ip) OR cidrmatch("172.16.0.0/12", remote_ip) OR cidrmatch("192.168.0.0/16", remote_ip))
| stats count(eval(sourcetype="linux_secure")) AS ssh_failures count(eval(sourcetype="firewall_csv")) AS firewall_events count(eval(fw_src_internal=1)) AS outbound_from_internal count(eval(fw_src_internal=0 AND sourcetype="firewall_csv")) AS inbound_to_internal min(_time) AS first_seen max(_time) AS last_seen BY remote_ip
| eval min_ssh_failures=10 ```THRESHOLD```
| where ssh_failures>=min_ssh_failures AND firewall_events>=1
| convert ctime(first_seen) ctime(last_seen)
| sort - ssh_failures
```

**corr-03: external SSH success, then suspicious DNS from the same asset**
(`spl/correlation/corr-03-external-ssh-success-then-suspicious-dns.spl`)

```spl
index=splunk_learning sourcetype=dns_tsv
| rex field=_raw "^(?<dns_ts>[^\t]+)\t(?<client_ip>[^\t]+)\t(?<resolver_ip>[^\t]+)\t(?<query>[^\t]+)\t(?<qtype>[^\t]+)\t(?<rcode>[^\t]+)\t(?<answers>.*)$"
| where isnotnull(query)
| eval base_domain=replace(lower(query), "^.*?([^.]+\.[^.]+)$", "\1") ```naive registered-domain: handles subdomains, not multi-label TLDs such as .co.uk```
| lookup suspicious_domains.csv domain AS base_domain OUTPUT category
| where isnotnull(category)
| lookup asset_inventory.csv ip AS client_ip OUTPUT host AS asset_host
| where isnotnull(asset_host)
| stats count AS suspicious_queries count(eval(rcode="NOERROR")) AS resolved values(base_domain) AS domains values(category) AS categories min(_time) AS first_dns max(_time) AS last_dns BY asset_host client_ip
| join type=inner asset_host
    [ search index=splunk_learning sourcetype=linux_secure "Accepted password"
      | rex field=_raw "Accepted password for \S+ from (?<ssh_ip>\d+\.\d+\.\d+\.\d+)"
      | where isnotnull(ssh_ip) AND NOT (cidrmatch("10.0.0.0/8", ssh_ip) OR cidrmatch("172.16.0.0/12", ssh_ip) OR cidrmatch("192.168.0.0/16", ssh_ip))
      | stats min(_time) AS first_external_ssh_success values(ssh_ip) AS ssh_source BY host
      | rename host AS asset_host ]
| where first_dns>=first_external_ssh_success
| eval minutes_after_ssh_success=round((first_dns-first_external_ssh_success)/60, 1)
| convert ctime(first_dns) ctime(last_dns) ctime(first_external_ssh_success)
| table asset_host client_ip ssh_source first_external_ssh_success first_dns minutes_after_ssh_success suspicious_queries resolved domains categories
```

auth-03 (success after failures) is documented in `brute-force-ssh.md`.

## Detection Logic
- **corr-06** tags external SSH logins, uses `streamstats time_window=5m` to carry the
  latest one forward per host, and keeps `sudo` events with a recent external login.
  A `curl`/`wget` command is flagged.
- **corr-02** lists external addresses with at least 10 SSH failures that also appear in
  the firewall, as source or as destination, and counts the direction.
- **corr-03** maps DNS clients to hosts through the asset inventory, matches queried
  base domains against the suspicious list, and requires the first suspicious query to
  happen **after** the host's first external SSH success.

## Analyst Investigation Steps
1. Start from the SSH success (auth-03) and confirm the external address.
2. **Execution.** corr-06: what was run, as which user, how soon after login?
3. **Network.** corr-02: does the host connect out to the same address? Check ports and
   regularity of the connections (every 3 to 8 minutes here).
4. **DNS.** corr-03: which domains, and did they resolve (`NOERROR`) or fail?
5. **Scope.** Search other hosts for the same address and domains (`corr-01`,
   `corr-04`).
6. **Decision.** Login, command and outbound traffic to the same address in a short
   sequence is strong evidence of compromise. **Escalate as critical**; state what is
   confirmed (events) separately from what is inferred (attacker intent, payload
   executed).

## False Positives
- An administrator working from an unusual external address, running `curl` for a real
  maintenance task.
- A host legitimately resolving a domain that a threat feed wrongly lists.
- A vendor remote-support session.

## Severity Rationale
**Critical** when the chain is complete (login, command, outbound traffic). Each link
alone is Low to Medium: a lone external login may be a legitimate admin, a lone
suspicious DNS query may be a user mistake.

## MITRE ATT&CK Mapping
| Technique | Why |
|---|---|
| T1078.003 Valid Accounts: Local Accounts | Successful login as `root`. |
| T1105 Ingress Tool Transfer | `curl` downloading a script from an external address. Execution of the file is **not** visible in these logs, so no execution technique is mapped. |
| T1071 Application Layer Protocol | Regular outbound connections on 443 combined with DNS lookups of suspicious domains. DNS and firewall logs cannot confirm the protocol (T1071.001 web protocols), so the parent technique is used. |

## Recommended Response
Isolate `web01` per procedure, **escalate to L2**, block `203.0.113.50` and the domains,
capture evidence (the script, memory, connections) before cleanup, reset credentials,
and hunt for the same indicators on other hosts.