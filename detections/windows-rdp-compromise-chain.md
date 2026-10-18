# Detection: RDP brute force, privileges and new account

| | |
|---|---|
| **Type** | Detection (attempts) plus sequence detection |
| **Search IDs** | auth-06 (RDP brute force), win-01 (logon, privileges, account creation) |
| **Data domain** | Windows Security events (`winsec_csv`) |

## Objective
Detect external RDP password guessing against a domain controller, and the follow-on
sequence: successful logon, special privileges, then creation of a new account.

## Threat Scenario
`203.0.113.77` fails 40 RDP logons on 2025-06-05 against `administrator`, `admin`,
`backup` and `svc_sql`, locks `administrator`, then logs in as `svc_sql` (weak
password), receives special privileges and creates `svc_backup`, which looks like a
persistence account.

## Required Telemetry
`winsec_csv` events 4624, 4625, 4672, 4720 (and 4740 for context), with `Account_Name`,
`src_ip`, `Logon_Type` and `ComputerName`.

## SPL Query

**auth-06** (`spl/authentication/auth-06-rdp-bruteforce-external.spl`)

```spl
index=splunk_learning sourcetype=winsec_csv EventCode=4625 Logon_Type=10
| where NOT (cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip))
| bin span=10m _time AS window_start
| stats count AS failures dc(Account_Name) AS distinct_accounts values(Account_Name) AS accounts_targeted min(_time) AS first_seen max(_time) AS last_seen BY src_ip ComputerName window_start
| eval min_failures=10 ```THRESHOLD: failed RDP logons per external IP per 10 minutes```
| where failures>=min_failures
| convert ctime(window_start) ctime(first_seen) ctime(last_seen)
| sort - failures
```

**win-01** (`spl/windows/win-01-external-logon-privileges-new-account.spl`)

```spl
index=splunk_learning sourcetype=winsec_csv (EventCode=4624 OR EventCode=4672 OR EventCode=4720)
| where NOT (cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip))
| eval t_logon=if(EventCode=4624, _time, null()), t_priv=if(EventCode=4672, _time, null()), t_newacct=if(EventCode=4720, _time, null())
| eval logon_account=if(EventCode=4624, Account_Name, null()), created_account=if(EventCode=4720, Account_Name, null())
| stats min(t_logon) AS t_logon min(t_priv) AS t_priv min(t_newacct) AS t_newacct values(logon_account) AS logon_account values(created_account) AS created_account BY src_ip ComputerName
| eval max_gap_s=3600 ```WINDOW: logon -> new account must happen within this many seconds```
| where isnotnull(t_logon) AND isnotnull(t_priv) AND isnotnull(t_newacct) AND t_logon<=t_priv AND t_priv<=t_newacct AND (t_newacct-t_logon)<=max_gap_s
| eval minutes_logon_to_new_account=round((t_newacct-t_logon)/60, 1)
| convert ctime(t_logon) ctime(t_priv) ctime(t_newacct)
| table src_ip ComputerName logon_account created_account t_logon t_priv t_newacct minutes_logon_to_new_account
```

## Detection Logic
- **auth-06** keeps failed network-interactive RDP logons (`Logon_Type=10`) from
  non-private addresses and counts them per source, host and 10-minute window
  (`min_failures=10`).
- **win-01** groups logon (4624), special privileges (4672) and account creation (4720)
  by source address and host, and requires that order within one hour
  (`max_gap_s=3600`). The earlier version grouped by account name and could never link
  the compromised account with the new one.

## Analyst Investigation Steps
1. **Context.** `WINDC01` is a domain controller: highest criticality. Is RDP supposed
   to be reachable from the internet at all?
2. **Source.** External address; pivot with `corr-01` and check the firewall for allowed
   RDP connections from it.
3. **Timeline.** Failures from 03:05, a lockout of `administrator` at 03:07:29 (event
   4740), success at 03:09:34, privileges 20 seconds later, account created 90 seconds
   after the logon.
4. **Compromised account.** Which account succeeded (`svc_sql`) and is it a service
   account with a weak password and RDP rights?
5. **New account.** Who created `svc_backup`, is it authorised (change ticket), does it
   have group memberships or logons since?
6. **Decision.** The sequence is not a normal onboarding pattern when the source is
   external. **Escalate immediately.**

## False Positives
- auth-06: users locked out after a password change, remote administrators behind a
  shared NAT address, vulnerability scanners.
- win-01: IT onboarding creates an account and grants privileges from a jump host. The
  external-source condition removes most of these, but a VPN or jump-host address
  appearing as "external" would reintroduce them.

## Severity Rationale
- auth-06 alone: **Medium** (attempts against a critical asset).
- win-01 firing: **Critical**. A domain controller with external logon, privileges and a
  new account in minutes is an active compromise until disproved.

## MITRE ATT&CK Mapping
| Technique | Why |
|---|---|
| T1110.001 Brute Force: Password Guessing | Repeated failed logons against several accounts (sub-technique is the closest fit; the logs do not reveal the password strategy). |
| T1133 External Remote Services | RDP exposed to and used from the internet. |
| T1021.001 Remote Services: Remote Desktop Protocol | The successful `Logon_Type=10` session. |
| T1136.002 Create Account: Domain Account | Account created on a domain controller. It would be T1136.001 (local) if the event came from a non-DC. |

## Recommended Response
Isolate the domain controller per procedure, **escalate to L2/incident response at
once**, disable `svc_backup` and reset `svc_sql` after approval, review logons and group
changes since 03:09, block the address, and restrict RDP exposure.
