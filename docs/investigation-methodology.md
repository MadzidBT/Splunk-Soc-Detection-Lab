# Investigation methodology (L1 SOC triage)

A consistent routine for every alert from this repository. The aim is to decide
quickly and defensibly: **false positive, benign true positive, or escalate**.

An alert is a hypothesis. It becomes an incident only when evidence supports it.

## The six steps

1. **Context.** What fired, when, on which asset? Is the asset critical (domain
   controller, internet-facing server)? Is there a change window, a known scanner or
   a maintenance task?
2. **Source.** Who is the actor? Internal or external address? Known (asset
   inventory, allow-list) or unknown? Is the same address seen elsewhere ?
3. **Timeline.** Order the events: first and last seen, rate, burst or slow drip,
   what happened *after* the suspicious activity. Compare times across sources only
   after checking they use the same timezone.
4. **Correlation.** Look for the same actor or host in other sources (firewall,
   DNS, web, Windows). Ask what each additional source adds: new stage of the
   attack, or just the same event seen twice?
5. **Criticality.** Combine: confirmed success or only attempts, asset value, scope
   (one host or several), evidence of follow-up activity (command execution, new
   account, outbound beaconing).
6. **Decision.** Close as false positive, close as benign, monitor, or escalate to
   L2 with a written summary (see `reports/`).

## Decision guide

| Observation | Typical decision |
|---|---|
| Many failures, **no success**, external source | Monitor / block at perimeter; record the IP |
| Failures then **success** from an external source | **Escalate**: possible account compromise |
| Success followed by command execution or new account | **Escalate as high priority** |
| Few failures then success from an internal known user | Likely benign (typo); verify with the user if repeated |
| Scan from an external IP, no follow-up | Informational / block; escalate only if followed by access |
| Suspicious DNS from a host that also received a suspicious login | **Escalate**: compromise indicators on one asset |
| Suspicious DNS (NXDOMAIN only) from an unrelated workstation | Investigate the user's activity; lower priority |

## What goes into an escalation

- What was detected and which search produced it.
- Affected asset(s), account(s), source address(es).
- Timeline with timestamps and timezone.
- What is **confirmed** versus **suspected**, stated separately.
- Actions already taken and the recommended next step.

## Habits that keep an investigation honest

- Note the time range and index of every search you run.
- Record negative results ("no matching events in firewall log") as findings.
- Do not widen the conclusion beyond the evidence: "login succeeded after 68
  failures" is a fact; "the attacker had root access for N minutes" is an inference
  and must be labelled as such.
- Check the data before the detection: a missing field produces silence, not an
  error.
