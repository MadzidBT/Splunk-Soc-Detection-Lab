# Installation and ingestion

## 1. Prerequisites

- Splunk Enterprise installed locally, with admin access.
- Python 3.8+

## 2. Create the index

*Settings > Indexes > New Index*, name: `splunk_learning` 

## 3. Install the parsing configuration (before uploading data)

Copy `config/props.conf` and `config/transforms.conf` to
`$SPLUNK_HOME/etc/apps/soc_lab/local/` (create the folders), then restart Splunk.
On Windows the default path is `C:\Program Files\Splunk\etc\apps\soc_lab\local\`.

## 4. Ingest the five files

For each file in `data/raw/`: *Settings > Add Data > Upload*, then:

| File | Sourcetype | Notes |
|---|---|---|
| `apache.log` | `access_combined` | Built-in. |
| `secure.log` | `linux_secure` | Must be typed manually if not suggested. |
| `windows_security.csv` | `winsec_csv` | Custom (from `props.conf`). |
| `dns.log` | `dns_tsv` | Custom (from `props.conf`). |
| `firewall.log` | `firewall_csv` | Custom (from `props.conf`). |

Select index `splunk_learning` on the *Input Settings* step.

## 5. Upload the lookups

*Settings > Lookups > Lookup table files > New Lookup Table File*, destination app
`soc_lab` (or `search`), upload:

- `data/lookups/asset_inventory.csv`
- `data/lookups/suspicious_domains.csv`

## 6. Post-ingestion checks

**Check A: events per sourcetype**

index=splunk_learning | stats count by sourcetype

**Check B: fields exist**

index=splunk_learning sourcetype=firewall_csv | head 3 | table _time src_ip dest_ip dest_port action

index=splunk_learning sourcetype=winsec_csv | head 3 | table _time EventCode Account_Name src_ip Logon_Type ComputerName

index=splunk_learning sourcetype=access_combined | head 3 | table _time clientip status useragent


