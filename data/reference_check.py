#!/usr/bin/env python3
"""
Offline reference implementation of the lab detections.

Purpose: give you something to compare your Splunk results against. For each
detection in ../spl/, this script re-implements the same logic (same windows,
same default thresholds) in plain Python over the raw files in ./raw.

IMPORTANT
  * This is NOT a Splunk execution and proves nothing about the SPL itself.
  * If Splunk and this script disagree, one of them is wrong: investigate
    (field extraction, timezone, sourcetype, bucket alignment) before trusting either.
  * Time buckets are aligned on epoch multiples (the same alignment Splunk's
    `bin` uses for 5/10-minute spans when the user timezone has a whole-hour offset).

Usage:  python reference_check.py [--raw DIR]
"""

import argparse
import csv
import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(ip):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in PRIVATE)


def parse_iso(s):
    """'2025-06-03T02:18:24+0200' or '...000000+02:00' -> epoch seconds."""
    s = re.sub(r"\.\d+", "", s)
    s = re.sub(r"([+-]\d\d):?(\d\d)$", r"\1\2", s)
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z").timestamp()


def fmt(epoch, tz_offset_hours=2):
    return datetime.fromtimestamp(epoch, timezone.utc).astimezone(
        timezone(__import__("datetime").timedelta(hours=tz_offset_hours))).strftime("%Y-%m-%d %H:%M:%S")


def bucket(epoch, span):
    return int(epoch // span) * span


# ----------------------------------------------------------------- loaders
def load_ssh(raw):
    pat = re.compile(r"^(\S+) (\S+) sshd\[\d+\]: (Failed|Accepted) (password|publickey) for "
                     r"(?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
    out = []
    for line in open(raw / "secure.log", encoding="utf-8"):
        m = pat.match(line)
        if m:
            out.append(dict(t=parse_iso(m[1]), host=m[2], result=m[3], user=m[5], ip=m[6]))
    return sorted(out, key=lambda e: e["t"])


def load_sudo(raw):
    out = []
    for line in open(raw / "secure.log", encoding="utf-8"):
        m = re.match(r"^(\S+) (\S+) sudo: (\S+) : .*COMMAND=(.+)$", line.rstrip("\n"))
        if m:
            out.append(dict(t=parse_iso(m[1]), host=m[2], user=m[3], cmd=m[4]))
    return out


def load_csv(path):
    rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
    for r in rows:
        r["t"] = parse_iso(r["timestamp"])
    return rows


def load_apache(raw):
    pat = re.compile(r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) [^"]*" (\d+) ')
    out = []
    for line in open(raw / "apache.log", encoding="utf-8"):
        m = pat.match(line)
        if m:
            t = datetime.strptime(m[2], "%d/%b/%Y:%H:%M:%S %z").timestamp()
            out.append(dict(t=t, ip=m[1], method=m[3], uri=m[4], status=int(m[5])))
    return out


def load_dns(raw):
    out = []
    for line in open(raw / "dns.log", encoding="utf-8"):
        if line.startswith("#"):
            continue
        p = line.rstrip("\n").split("\t")
        out.append(dict(t=float(p[0]), client=p[1], query=p[3], rcode=p[5]))
    return out


# -------------------------------------------------------------- detections
def auth_02(ssh):
    g = defaultdict(list)
    for e in ssh:
        if e["result"] == "Failed":
            g[(e["ip"], e["host"], bucket(e["t"], 600))].append(e)
    return sorted(((ip, host, fmt(b), len(v), len({x["user"] for x in v}))
                   for (ip, host, b), v in g.items() if len(v) >= 10), key=lambda r: -r[3])


def auth_03(ssh):
    res = []
    for i, e in enumerate(ssh):
        if e["result"] != "Accepted":
            continue
        prior = sum(1 for x in ssh[:i] if x["ip"] == e["ip"] and x["host"] == e["host"]
                    and x["result"] == "Failed" and e["t"] - x["t"] <= 1800)
        if prior >= 10:
            res.append((fmt(e["t"]), e["host"], e["ip"], "no" if is_internal(e["ip"]) else "yes", e["user"], prior))
    return res


def auth_04(ssh):
    """Approximation of `transaction src_ip host startswith=fail endswith=success maxspan=30m`."""
    res, cur = [], {}
    for e in ssh:
        k = (e["ip"], e["host"])
        c = cur.get(k)
        if c and e["t"] - c[0]["t"] > 1800:
            c = None
        if c is None:
            c = [e] if e["result"] == "Failed" else None
        else:
            c.append(e)
            if e["result"] == "Accepted":
                if len(c) - 1 >= 10:
                    res.append((k[0], k[1], len(c) - 1, int(c[-1]["t"] - c[0]["t"])))
                c = None
        cur[k] = c
    return res


def auth_06(win):
    g = defaultdict(list)
    for r in win:
        if r["EventCode"] == "4625" and r["Logon_Type"] == "10" and not is_internal(r["src_ip"]):
            g[(r["src_ip"], r["ComputerName"], bucket(r["t"], 600))].append(r)
    return sorted(((ip, cn, fmt(b), len(v), len({x["Account_Name"] for x in v}))
                   for (ip, cn, b), v in g.items() if len(v) >= 10), key=lambda r: -r[3])


def web_04(apache):
    g = defaultdict(list)
    for e in apache:
        if e["status"] == 404:
            g[(e["ip"], bucket(e["t"], 300))].append(e)
    near_miss = sorted(((ip, fmt(b), len(v), len({x["uri"] for x in v})) for (ip, b), v in g.items()
                        if len(v) >= 10 and not (len(v) >= 20 and len({x["uri"] for x in v}) >= 10)),
                       key=lambda r: -r[2])
    hits = sorted(((ip, fmt(b), len(v), len({x["uri"] for x in v})) for (ip, b), v in g.items()
                   if len(v) >= 20 and len({x["uri"] for x in v}) >= 10), key=lambda r: -r[2])
    return hits, near_miss


def fw_02(fw):
    g = defaultdict(list)
    for r in fw:
        if r["action"] == "DROP":
            g[(r["src_ip"], bucket(r["t"], 600))].append(r)
    return sorted(((ip, fmt(b), len(v), len({x["dest_port"] for x in v}), len({x["dest_ip"] for x in v}))
                   for (ip, b), v in g.items() if len({x["dest_port"] for x in v}) >= 20), key=lambda r: -r[3])


def win_01(win):
    g = defaultdict(lambda: dict(logon=None, priv=None, new=None, la=set(), ca=set()))
    for r in win:
        if r["EventCode"] in ("4624", "4672", "4720") and not is_internal(r["src_ip"]):
            d = g[(r["src_ip"], r["ComputerName"])]
            if r["EventCode"] == "4624":
                d["logon"] = min(d["logon"] or r["t"], r["t"]); d["la"].add(r["Account_Name"])
            elif r["EventCode"] == "4672":
                d["priv"] = min(d["priv"] or r["t"], r["t"])
            else:
                d["new"] = min(d["new"] or r["t"], r["t"]); d["ca"].add(r["Account_Name"])
    res = []
    for (ip, cn), d in g.items():
        if None not in (d["logon"], d["priv"], d["new"]) and d["logon"] <= d["priv"] <= d["new"] \
                and d["new"] - d["logon"] <= 3600:
            res.append((ip, cn, sorted(d["la"]), sorted(d["ca"]), fmt(d["logon"]), fmt(d["priv"]), fmt(d["new"]),
                        round((d["new"] - d["logon"]) / 60, 1)))
    return res


def corr_02(ssh, fw):
    g = defaultdict(lambda: dict(ssh=0, fw=0, out=0, inn=0))
    for e in ssh:
        if e["result"] == "Failed" and not is_internal(e["ip"]):
            g[e["ip"]]["ssh"] += 1
    for r in fw:
        if is_internal(r["src_ip"]):
            remote, out = r["dest_ip"], True
        else:
            remote, out = r["src_ip"], False
        if is_internal(remote):
            continue
        g[remote]["fw"] += 1
        g[remote]["out" if out else "inn"] += 1
    return [(ip, d["ssh"], d["fw"], d["out"], d["inn"]) for ip, d in g.items() if d["ssh"] >= 10 and d["fw"] >= 1]


def corr_03(ssh, dns, inventory, domains):
    first_ssh = {}
    for e in ssh:
        if e["result"] == "Accepted" and not is_internal(e["ip"]):
            first_ssh[e["host"]] = min(first_ssh.get(e["host"], e["t"]), e["t"])
    g = defaultdict(lambda: dict(n=0, ok=0, doms=set(), first=None))
    for q in dns:
        base = ".".join(q["query"].lower().split(".")[-2:])
        host = inventory.get(q["client"])
        if base in domains and host:
            d = g[(host, q["client"])]
            d["n"] += 1; d["ok"] += q["rcode"] == "NOERROR"; d["doms"].add(base)
            d["first"] = min(d["first"] or q["t"], q["t"])
    res = []
    for (host, ip), d in g.items():
        if host in first_ssh and d["first"] >= first_ssh[host]:
            res.append((host, ip, fmt(first_ssh[host]), fmt(d["first"]),
                        round((d["first"] - first_ssh[host]) / 60, 1), d["n"], d["ok"], sorted(d["doms"])))
    return res


def corr_04_05(ssh, win, fw, apache):
    risk, stages = defaultdict(lambda: [0, set()]), defaultdict(lambda: [0, set()])

    def add(ip, rtype, stage):
        if is_internal(ip):
            return
        risk[ip][0] += 1; risk[ip][1].add(rtype)
    for a in apache:
        if a["status"] == 404:
            add(a["ip"], "web_404", None); stages[a["ip"]][0] += 1; stages[a["ip"]][1].add("2_web_recon") \
                if not is_internal(a["ip"]) else None
    for e in ssh:
        if not is_internal(e["ip"]):
            if e["result"] == "Failed":
                add(e["ip"], "ssh_failed", None)
            stages[e["ip"]][0] += 1
            stages[e["ip"]][1].add("3_ssh_failures" if e["result"] == "Failed" else "4_ssh_success")
    for r in win:
        if r["EventCode"] in ("4625", "4624") and not is_internal(r["src_ip"]):
            if r["EventCode"] == "4625":
                add(r["src_ip"], "windows_4625", None)
            stages[r["src_ip"]][0] += 1
            stages[r["src_ip"]][1].add("3_windows_failures" if r["EventCode"] == "4625" else "4_windows_success")
    for r in fw:
        if r["action"] == "DROP" and not is_internal(r["src_ip"]):
            add(r["src_ip"], "firewall_drop", None)
            stages[r["src_ip"]][0] += 1; stages[r["src_ip"]][1].add("1_port_scan")
    top = sorted(((ip, v[0], len(v[1]), sorted(v[1])) for ip, v in risk.items() if v[0] >= 10),
                 key=lambda r: (-r[2], -r[1]))[:10]
    chain = sorted(((ip, v[0], len(v[1]), sorted(v[1])) for ip, v in stages.items() if len(v[1]) >= 2),
                   key=lambda r: (-r[2], -r[1]))
    return top, chain


def corr_06(ssh, sudo):
    res = []
    for s in sudo:
        recent = [e for e in ssh if e["result"] == "Accepted" and e["host"] == s["host"]
                  and 0 <= s["t"] - e["t"] <= 300 and not is_internal(e["ip"])]
        if recent:
            res.append((fmt(s["t"]), s["host"], s["user"], s["cmd"], recent[-1]["ip"],
                        "yes" if re.search(r"\b(curl|wget)\b", s["cmd"], re.I) else "no"))
    return res


# -------------------------------------------------------------------- main
def show(title, rows):
    print(f"\n=== {title}  ({len(rows)} row(s))")
    for r in rows:
        print("   ", r)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default=str(Path(__file__).resolve().parent / "raw"))
    raw = Path(ap.parse_args().raw)
    lk = Path(__file__).resolve().parent / "lookups"

    ssh, sudo = load_ssh(raw), load_sudo(raw)
    win, fw = load_csv(raw / "windows_security.csv"), load_csv(raw / "firewall.log")
    apache, dns = load_apache(raw), load_dns(raw)
    inventory = {r["ip"]: r["host"] for r in csv.DictReader(open(lk / "asset_inventory.csv"))}
    domains = {r["domain"] for r in csv.DictReader(open(lk / "suspicious_domains.csv"))}

    print("Reference check (Python re-implementation; NOT a Splunk run)")
    show("auth-02  SSH failures >=10 / 10 min  -> (ip, host, bucket, failures, distinct_users)", auth_02(ssh))
    show("auth-03  SSH success after >=10 failures/30 min -> (time, host, ip, external, user, prior_failures)", auth_03(ssh))
    show("auth-04  legacy transaction -> (ip, host, failures, duration_s)", auth_04(ssh))
    show("auth-06  RDP failures >=10 / 10 min (external) -> (ip, host, bucket, failures, accounts)", auth_06(win))
    hits, near = web_04(apache)
    show("web-04   404 scan (>=20 and >=10 URIs / 5 min) -> (ip, bucket, 404s, distinct_uris)", hits)
    show("web-04   NEAR MISSES (>=10 404s but below thresholds)", near)
    show("fw-02    DROP, >=20 distinct ports / 10 min -> (ip, bucket, drops, ports, targets)", fw_02(fw))
    show("win-01   external logon->privileges->new account <=1h", win_01(win))
    show("corr-02  SSH-failure IPs also in firewall -> (ip, ssh_failures, fw_events, outbound, inbound)", corr_02(ssh, fw))
    show("corr-03  external SSH success then suspicious DNS from same asset", corr_03(ssh, dns, inventory, domains))
    top, chain = corr_04_05(ssh, win, fw, apache)
    show("corr-04  top external risky IPs -> (ip, events, risk_types, list)", top)
    show("corr-05  >=2 attack stages -> (ip, events, stage_count, stages)", chain)
    show("corr-06  sudo within 5 min of an external SSH login", corr_06(ssh, sudo))
