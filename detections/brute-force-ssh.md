# Detection: SSH brute force and success after failures

| | |
|---|---|
| **Type** | Detection (two linked searches) |
| **Search IDs** | auth-02 (attempts), auth-03 (success after failures); auth-04 is a legacy variant |
| **Data domain** | Linux authentication (`linux_secure`) |

## Objective
Find external sources that repeatedly fail SSH authentication, and separately flag
the higher-severity case where a login **succeeds** shortly after many failures.

## Threat Scenario
An internet-facing server (`web01`) is attacked with automated password guessing
against `root`, `admin` and common names. If one guess works, the attacker has a
valid session. In the dataset: `203.0.113.50` fails 68 times on 2025-06-03 and then
logs in as `root`.

## Required Telemetry
- Sourcetype `linux_secure` with sshd `Failed password` / `Accepted password` lines.
- The source address is extracted with `rex` from the message.

## SPL Query

**auth-02: attempts** (`spl/authentication/auth-02-ssh-bruteforce-attempts.spl`)

```spl
index=splunk_learning sourcetype=linux_secure "Failed password"
| rex field=_raw "sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid user\s+)?(?<user>\S+)\s+from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| where isnotnull(src_ip)
| bin span=10m _time AS window_start

| stats count AS failures dc(user) AS distinct_users values(user) AS users_targeted min(_time) AS first_seen max(_time) AS last_seen BY src_ip host window_start
| eval min_failures=10 ```THRESHOLD: failures per source IP per 10 minutes```
| where failures>=min_failures
| eval duration_s=last_seen-first_seen
| convert ctime(window_start) ctime(first_seen) ctime(last_seen)
| sort - failures
```

**auth-03: success after failures** (`spl/authentication/auth-03-ssh-success-after-failures.spl`)

```spl
index=splunk_learning sourcetype=linux_secure ("Failed password" OR "Accepted password" OR "Accepted publickey")
| rex field=_raw "sshd\[\d+\]:\s+(?<result>Failed|Accepted)\s+(?<auth_method>password|publickey)\s+for\s+(?:invalid user\s+)?(?<user>\S+)\s+from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| where isnotnull(src_ip)
| sort 0 _time ```streamstats time_window needs ascending time order```
| streamstats time_window=30m count(eval(result="Failed")) AS prior_failures BY src_ip host
| eval min_failures=10 ```THRESHOLD: failures in the 30 minutes before the success```
| where result="Accepted" AND prior_failures>=min_failures
| eval external=if(cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip), "no", "yes")
| table _time host src_ip external user auth_method prior_failures
```

## Detection Logic
- **auth-02** buckets events into 10-minute windows and counts failures per
  source IP and host. Threshold `min_failures=10`. It fires with or without a later
  success, so it also covers brute force that failed.
- **auth-03** sorts events by time and uses `streamstats time_window=30m` to count the
  failures seen from the same source before each event. It keeps only `Accepted`
  events preceded by at least `min_failures` failures.
- The two searches answer different questions: "who is attacking?" and "did it work?".

| Search | Expected rows |
|---|---|
| auth-02 | `203.0.113.50`: 68 failures, 5 distinct users, bucket 2025-06-03 02:10. `198.51.100.99`: 30 failures, 3 users, bucket 2025-06-06 14:00 |
| auth-03 | 2025-06-03 02:18:24, `web01`, `203.0.113.50`, `root`, 68 prior failures, external = yes |

`198.51.100.99` appears in auth-02 but not in auth-03: it never logs in. User
`mtremblay` (3 failures then success every day, internal address) matches neither.

## Analyst Investigation Steps
1. **Context.** Which host and account were targeted? Is SSH meant to be reachable
   from the internet? Check the asset inventory.
2. **Source.** External or internal address? Run `corr-01` to see the address in all
   other sources.
3. **Timeline.** First and last failure, rate, and which accounts were tried. A burst of
   a few minutes against `root` and invalid users indicates automation.
4. **Success?** Run auth-03. A success from the same address is the pivotal fact.
5. **After the login.** Run `corr-06` (commands run), `corr-02` (outbound connections to
   the address) and `corr-03` (DNS from the host). See `ssh-compromise-to-c2.md`.
6. **Criticality and decision.** Failures only: monitor and block. Success: escalate
   (see below).

## False Positives
- A legitimate user repeatedly mistyping a password (internal source, few attempts).
- Monitoring or backup tools with a stale credential (same account, constant interval).
- Penetration tests and authorised vulnerability scanners.
- Many users behind one NAT address, which accumulates failures together.

## Severity Rationale
- Failures only, external: **Low to Medium**. Constant background noise on any exposed
  host; priority rises with volume and target accounts (`root`).
- Success after failures: **High**. A valid session probably exists. Becomes **Critical**
  if follow-up activity is found (command execution, outbound connections).

## MITRE ATT&CK Mapping
| Technique | Why |
|---|---|
| T1110.001 Brute Force: Password Guessing | Repeated failed password attempts against several account names. The logs do not show whether one password was tried against many accounts (T1110.003) or many passwords against one, so the sub-technique is the closest fit, not a certainty. |
| T1078.003 Valid Accounts: Local Accounts | Applies only after auth-03 fires: a successful login with a local account (`root`). |

## Recommended Response
- Failures only: block the source at the perimeter, confirm password authentication is
  required at all, enable key-only login and rate limiting.
- Success after failures: isolate the host per procedure, **escalate to L2**, force a
  credential reset for the account, preserve logs, and run the follow-up searches.