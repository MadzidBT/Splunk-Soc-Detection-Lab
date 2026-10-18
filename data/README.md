# Dataset

**100% synthetic.** Every event is produced by `generate_dataset.py`. No real traffic,
user, host or credential is involved.

- External addresses come from the documentation ranges reserved by RFC 5737
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). They are never routed on the internet.
- Internal addresses use RFC 1918 space (`192.168.1.0/24`, `10.0.0.0/24`).
- Domains used for "benign" traffic are well-known real names; the four "malicious"
  names are invented.

## Files

| File | Sourcetype | Events | Format |
|---|---|---|---|
| `raw/apache.log` | `access_combined` | 982 | Apache combined log format |
| `raw/secure.log` | `linux_secure` | 914 | sshd and sudo lines, ISO 8601 timestamps with offset |
| `raw/windows_security.csv` | `winsec_csv` | 806 | CSV with header: `timestamp,EventCode,Account_Name,src_ip,Logon_Type,ComputerName` |
| `raw/dns.log` | `dns_tsv` | 1179 | Tab-separated, header line starting with `#`, epoch time |
| `raw/firewall.log` | `firewall_csv` | 1246 | CSV with header: `timestamp,src_ip,dest_ip,src_port,dest_port,action,protocol` |

Period: 2025-06-01 to 2025-06-07, timezone UTC+2. Counts exclude header lines.
`lookups/` holds the asset inventory and the suspicious-domain list.

## Hosts

| Name | Address | Role |
|---|---|---|
| `web01` | `192.168.1.15` | Linux web server, SSH and Apache, exposed |
| `WINDC01` | `192.168.1.10` | Windows domain controller |
| `dns01` | `10.0.0.2` | Internal resolver |
| workstations | `192.168.1.20` to `.59` | Internal users |
| servers | `10.0.0.10` to `.24` | Internal servers |

## Actors

| Address | Role in the data |
|---|---|
| `198.51.100.23` | Scanner: port scan (06-02), web directory scan (06-02 and 06-03) |
| `203.0.113.50` | SSH brute force then root login on `web01` (06-03), then C2 beaconing |
| `203.0.113.77` | RDP brute force then compromise of `WINDC01` (06-05) |
| `198.51.100.99` | Low-volume recon: 15 `HEAD` requests per day (06-02, 06-03), then 30 failed SSH logins (06-06) with no success |
| `192.0.2.x` | 150 ordinary external clients (web traffic, occasional invalid-user SSH probes) |

## Embedded scenarios (ground truth)

| Day | Time (UTC+2) | What the data contains |
|---|---|---|
| 06-02 | 01:40 to 01:45 | Port scan: 124 `DROP` events on 124 distinct ports of `web01` |
| 06-02, 06-03 | early morning | Web scan: 64 requests per day over a 32-path wordlist, two passes |
| 06-03 | 02:12 to 02:18 | SSH brute force: 68 failures against `root`, `admin` and invalid users |
| 06-03 | 02:18:24 | Successful root login from `203.0.113.50` |
| 06-03 | 02:19:09 | `sudo curl` downloading `payload.sh` from `203.0.113.50` into `/tmp/.x.sh` |
| 06-03 | from 02:28 | `web01` queries `evil-update.net` every 3 to 8 minutes; each resolved name is followed by a firewall `ALLOW` to `203.0.113.50:443` |
| 06-04 | early morning | Same beaconing, domain `malware.xyz` |
| 06-05 | 03:05 to 03:11 | RDP brute force (40 failed logons, `administrator` locked at 03:07:29), success as `svc_sql` at 03:09:34, privileges at 03:09:54, account `svc_backup` created at 03:11:04 |
| 06-06 | afternoon | 30 failed SSH logins from `198.51.100.99`, never successful |

Deliberate non-incidents (to test tuning):
- `mtremblay` fails 3 times and then succeeds, every day, from an internal workstation.
- Workstation `192.168.1.47` queries `phishing-bank.info` and `c2server.top`; all answers are NXDOMAIN.
- `198.51.100.99` stays just below the web-scan thresholds.
- Routine `DENY` events (ports 25, 135, 445) and invalid-user SSH probes from ordinary clients.

## Regenerating and checking

```powershell
python .\generate_dataset.py          # writes .\raw\ ; ends with a self-check
python .\reference_check.py           # prints what each detection should return
```

