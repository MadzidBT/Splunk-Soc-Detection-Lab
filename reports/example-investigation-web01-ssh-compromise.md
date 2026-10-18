# Investigation report: SSH brute force followed by a root login on web01

| Field | Value |
|---|---|
| Case ID | LAB-SSH-001 |
| Analyst | <YOUR_NAME> |
| Investigation date | 2026-10-15 |
| Splunk version | <YOUR_SPLUNK_VERSION> |
| Index / time range | `splunk_learning`, All time |
| Alert source | Searches `auth-02` and `auth-03` (card: [`brute-force-ssh.md`](../detections/brute-force-ssh.md)) |
| Time convention | **UTC**, as displayed by my Splunk user. The log lines carry `+02:00`; converted times are given in brackets. |
| Status | Escalation recommended (see section 7) |

## 1. Summary

On 2025-06-03 between 00:12:00 and 00:18:10 UTC (02:12:00 to 02:18:10 at +02:00), the
external address `203.0.113.50` made **68 failed SSH password attempts** against `web01`,
trying **five account names**. At **00:18:24 UTC**, 14 seconds after the last failure, a
password login **succeeded as `root`** from the same address. A second address,
`198.51.100.99`, also attempted password guessing (30 failures on 2025-06-06) but no
success following those failures was found.

The evidence supports a successful password-guessing attack on `web01`. What the
session did afterwards has **not yet been examined**. Provisional severity: **High**.

## 2. Context

- **Asset:** `web01`, the Linux web server of the lab (inventory in `data/README.md`).
  It accepts SSH logins from an external address, which is itself worth questioning.
- **Why this was investigated:** `auth-02` exceeded its threshold (10 failures per
  source per 10 minutes) and `auth-03` found a success preceded by at least 10 failures.
- **Baseline (search `auth-01`):** over the whole dataset there are **180 failed-password
  events from 39 source addresses**. The two largest sources (68 and 30 failures) stand
  far above the others. The ten sources listed after them on the first page are all
  private addresses (`192.168.1.x`, `10.0.0.x`) with **3 to 7 failures each over the
  entire week**: typical typos, nowhere near the threshold.

## 3. Investigation steps and evidence

| Step | Search | What it showed | Evidence |
|---|---|---|---|
| 1. Baseline | `auth-01` | 180 events, 39 sources; `203.0.113.50` leads with 68 failures against 5 distinct users; `198.51.100.99` second with 30 | [`02-ssh-failed-login-overview.png`](../screenshots/02-ssh-failed-login-overview.png) |
| 2. Attempts | `auth-02` | Exactly two sources exceed 10 failures in a 10-minute window (details below) | [`03-ssh-bruteforce-attempts.png`](../screenshots/03-ssh-bruteforce-attempts.png) |
| 3. Success? | `auth-03` | **One** result: an accepted password login for `root` from `203.0.113.50` after 68 failures | [`04-ssh-success-after-failures.png`](../screenshots/04-ssh-success-after-failures.png) |

### 3.1 The two sources above the threshold (`auth-02`)

| Source | Window start (UTC) | Failures | Accounts targeted | First | Last | Duration |
|---|---|---|---|---|---|---|
| `203.0.113.50` | 2025-06-03 00:10 | 68 | `admin`, `oracle`, `root`, `test`, `web01` | 00:12:00 | 00:18:10 | 370 s |
| `198.51.100.99` | 2025-06-06 12:00 | 30 | `admin`, `root`, `test` | 12:01:00 | 12:09:56 | 536 s |

### 3.2 The success (`auth-03`)

| Time (UTC) | Host | Source | External | Account | Method | Failures in the previous 30 min |
|---|---|---|---|---|---|---|
| 2025-06-03 00:18:24 | `web01` | `203.0.113.50` | yes | `root` | password | 68 |

All 68 failures fall inside the 30 minutes before the success: the whole burst preceded
the login.

## 4. Timeline

| Time (UTC) | [+02:00] | Event | Source of the fact |
|---|---|---|---|
| 2025-06-03 00:12:00 | [02:12:00] | First failed attempt from `203.0.113.50` | `auth-02`, `first_seen` |
| 2025-06-03 00:18:10 | [02:18:10] | Last failed attempt (68th) | `auth-02`, `last_seen` |
| 2025-06-03 00:18:24 | [02:18:24] | **Accepted password for `root` from `203.0.113.50`** | `auth-03`, `_time` |
| 2025-06-06 12:01:00 to 12:09:56 | [14:01:00 to 14:09:56] | 30 failed attempts from `198.51.100.99`, no success after them found | `auth-02`, `auth-03` |

Derived values: the failure burst lasted 370 s (about one attempt every 5.5 seconds on
average) and the success came **14 seconds** after the last failure (00:18:24 minus
00:18:10). Bracketed times are the displayed UTC values plus two hours, matching the
`+02:00` offset of the source log.

## 5. Assessment

**Confirmed (visible in the Splunk results):**
- 68 failures from one external address against five account names inside a single
  6-minute window.
- A password login for `root` from the same address 14 seconds after the last failure.
- No other source reached 10 failures per 10 minutes, apart from `198.51.100.99`.
- For `198.51.100.99`, `auth-03` returned no success preceded by 10 or more failures.

**Inferred (reasoned, not proven by these searches):**
- The pace and the list of generic account names are consistent with automated password
  guessing. The logs do not identify the tool.
- The success is most likely the result of that guessing. It could also be a coincidence
  with a legitimate use of the same address, which the data alone cannot exclude.

**Not established:**
- What the `root` session did, and for how long it lasted.
- Whether password login for `root` over SSH is intended by design (a configuration
  question, outside this dataset).
- Whether `198.51.100.99` ever logged in at another time: `auth-03` only shows that no
  success followed ten or more failures within 30 minutes.

**Severity (provisional): High.** A success after many failures from an external source
means a valid session probably existed. It would become **Critical** if post-login
activity were confirmed (see section 9).

## 6. Decision

**Escalate to L2.** Rationale: successful privileged access from an external address
after a brute-force burst cannot be closed at L1. The escalation note should state the
confirmed facts of section 5 separately from the inferred ones.

## 7. Recommended response (not performed: this is a lab)

- Treat `web01` as potentially compromised: isolate it per the incident procedure, and
  preserve the authentication logs before any change.
- Reset the `root` credentials and review other accounts reachable with password login.
- Block `203.0.113.50` and `198.51.100.99` at the perimeter.
- Review whether SSH must be exposed to the internet, and disable direct `root` login
  and password authentication in favour of keys.
- Hunt for the same source address in the other log sources before closing the case.

## 8. Detection tuning notes from this run

- **Threshold margin.** The highest internal source made 7 failures over the whole
  week, against a threshold of 10 per 10 minutes. The threshold separates the two
  attacks from background noise with a wide margin on this dataset. It is tuned to this
  data, not a general recommendation.
- **Fixed buckets.** The 68 failures fell inside one 10-minute bucket (00:10 to 00:20),
  so the burst was counted in full. A burst that crossed a bucket boundary would be
  split in two; this is the known limitation documented in `docs/limitations.md` and
  was **not triggered** here.
- **Timezone.** My Splunk user displays UTC while the data is `+02:00`, so every time is
  two hours earlier than in the log text. This does not change any result, but daily
  buckets (`span=1d`) would cut at 00:00 UTC. Times are therefore stated in UTC
  throughout this report. Setting the user timezone to UTC+2 aligns the display with the
  raw logs.
- **Syntax validated.** The comment syntax (three backticks), `streamstats time_window`
  with `count(eval(...))`, `bin ... AS`, and `cidrmatch` all executed without error.

## 9. Open questions and next pivots (searches not yet run)

| Question | Search to run |
|---|---|
| What did `root` execute shortly after the login? | `corr-06` (sudo within 5 minutes of an external login) |
| Did `web01` connect out to `203.0.113.50`? | `corr-02` (SSH-failure address also in the firewall) |
| Did `web01` then resolve suspicious domains? | `corr-03` (external SSH success, then suspicious DNS) |
| Is `203.0.113.50` visible in other sources? | `corr-01` (pivot) and `corr-05` (stages per address) |

This report should be extended with those results before the case is treated as fully
analysed.

## 10. MITRE ATT&CK

| Technique | Evidence |
|---|---|
| T1110.001 Brute Force: Password Guessing | 68 failed password attempts over five account names from one address |
| T1078.003 Valid Accounts: Local Accounts | Successful password login as the local account `root` |

The sub-technique T1110.001 is the closest fit; the logs do not show whether one
password was tried against many accounts (T1110.003) or many passwords against few.

## 11. Evidence index

| File | Search | Content |
|---|---|---|
| `screenshots/02-ssh-failed-login-overview.png` | `auth-01` | 180 events, 39 sources, ranking of failures |
| `screenshots/03-ssh-bruteforce-attempts.png` | `auth-02` | Two sources above threshold, accounts, windows, durations |
| `screenshots/04-ssh-success-after-failures.png` | `auth-03` | The single success after 68 failures |

