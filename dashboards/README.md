# Dashboards

## Panel 1: Events Total By Source (last 24 Hours)

index="splunk_learning" source="apache.log" | stats count
index="splunk_learning" source="firewall.log" | stats count
index="splunk_learning" source="secure.log" | stats count
index="splunk_learning" source="windows_security.csv" | stats count

## Panel 2: external addresses ranked by risky activity

index=splunk_learning ((sourcetype=access_combined status=404) OR (sourcetype=linux_secure "Failed password") OR (sourcetype=winsec_csv EventCode=4625) OR (sourcetype=firewall_csv action=DROP))
| rex field=_raw "Failed password for (?:invalid user\s+)?\S+ from (?<ssh_ip>\d+\.\d+\.\d+\.\d+)"
| eval risk_ip=case(sourcetype="access_combined", clientip, sourcetype="linux_secure", ssh_ip, true(), src_ip)
| where isnotnull(risk_ip) AND NOT (cidrmatch("10.0.0.0/8", risk_ip) OR cidrmatch("172.16.0.0/12", risk_ip) OR cidrmatch("192.168.0.0/16", risk_ip))
| eval risk_type=case(sourcetype="access_combined", "web_404", sourcetype="linux_secure", "ssh_failed", sourcetype="winsec_csv", "windows_4625", sourcetype="firewall_csv", "firewall_drop")
| stats count AS events dc(risk_type) AS risk_types values(risk_type) AS risk_type_list min(_time) AS first_seen max(_time) AS last_seen BY risk_ip
| eval min_events=10 ```THRESHOLD: ignore IPs with only a few risky events (ordinary broken links, typos)```
| where events>=min_events
| convert ctime(first_seen) ctime(last_seen)
| sort - risk_types - events
| head 10

## Panel 3: daily risk events by type

index=splunk_learning
    ((sourcetype=linux_secure "Failed password")
     OR (sourcetype=winsec_csv EventCode=4625)
     OR (sourcetype=firewall_csv action=DROP)
     OR (sourcetype=access_combined status=404))
| eval risk_type=case(
    sourcetype="linux_secure", "SSH failed login",
    sourcetype="winsec_csv", "Windows failed logon",
    sourcetype="firewall_csv", "Firewall drop (scan)",
    sourcetype="access_combined", "Web 404 (recon)")
| timechart span=1d count BY risk_type
