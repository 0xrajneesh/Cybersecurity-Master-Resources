# Unusual Data Transfer (Exfiltration) - SOC Investigation Playbook

A practitioner playbook for triaging, investigating, and responding to an alert about an outbound traffic spike or possible data exfiltration, using Microsoft Defender XDR, Splunk, and threat intelligence.

> **Level:** Beginner to Intermediate · **Time:** ~45 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to tie an outbound spike to a process and user, how to tell approved transfers from exfiltration, how to contain and preserve evidence
>
> **Prerequisites:** basic networking (IPs, ports, HTTPS), proxy/firewall logs, and KQL/SPL syntax

---

## Table of Contents

- [60-Second Triage](#60-second-triage)
1. [What This Alert Means](#1-what-this-alert-means)
2. [Alert Triage](#2-alert-triage)
3. [Investigation in Microsoft Defender XDR](#3-investigation-in-microsoft-defender-xdr)
4. [Investigation in Splunk](#4-investigation-in-splunk)
5. [Threat Intelligence Enrichment](#5-threat-intelligence-enrichment)
6. [Verdict: True Positive vs Benign](#6-verdict-true-positive-vs-benign)
7. [Response Checklist](#7-response-checklist)
8. [Quick Reference](#8-quick-reference)
9. [Practice and Learn More](#9-practice-and-learn-more)

---

## 60-Second Triage

1. Note the host, user, destination, byte count, and time window from the alert.
2. Check whether the user and host normally send this much data at this hour (7/30-day baseline).
3. Identify the process that made the connection and its parent (query 3.1 or 4.6).
4. Check destination prevalence: has anyone else in the organization talked to it (query 3.2)?
5. Look for an archive created minutes before the transfer (query 3.4 or 4.7).
6. Search for a change ticket, backup job, or approved vendor transfer that explains it.

**Escalate immediately if:** an archive was staged before a large upload to a rare or personal cloud destination by an unexpected tool (rclone, curl, PowerShell), or DLP flags sensitive data.

---

## 1. What This Alert Means

An "unusual data transfer" alert fires when a host, user, or cloud account sends more data outbound than expected, to a destination that is new or rare, at an unusual time, or from a process that does not normally talk to the internet. It means "suspicious, not confirmed": the job of the analyst is to prove or disprove that data left the organization without authorization.

Typical exfiltration flow:

| Time (sample) | Stage | What usually happens |
|---|---|---|
| 21:07 | Collection / staging | Files gathered and compressed into an archive (`7z.exe`, `rar.exe`, `tar.exe`, `Compress-Archive`) in a temp or user folder |
| 21:09 | Outbound connection | A process (often `powershell.exe`, `curl.exe`, `rclone.exe`, a browser, or a sync client) opens a connection to an external host |
| 21:11 | Volume spike | Gigabytes leave the host over HTTPS, SFTP, FTP, or a cloud storage API |

### Why Attackers Do It

- **Double-extortion ransomware**: steal data first, then encrypt, then threaten to leak.
- **Espionage / IP theft**: source code, designs, customer lists, M&A documents.
- **Insider threat**: departing employees copying data to personal cloud storage or USB.
- **Credential and secret theft**: browser stores, password vaults, keys, `.env` files.

Attackers favor channels that blend in: HTTPS to legitimate cloud storage (Google Cloud Storage, AWS S3, OneDrive, Dropbox, MEGA), CDN fronting, or tools like `rclone` that look like admin activity.

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Name |
|---|---|---|
| Collection | T1560 / T1560.001 | Archive Collected Data / Archive via Utility |
| Collection | T1074.001 | Data Staged: Local Data Staging |
| Collection | T1005 | Data from Local System |
| Collection | T1039 | Data from Network Shared Drive |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |
| Exfiltration | T1048 / T1048.003 | Exfiltration Over Alternative Protocol / Over Unencrypted Non-C2 Protocol |
| Exfiltration | T1567 / T1567.002 | Exfiltration Over Web Service / Exfiltration to Cloud Storage |
| Exfiltration | T1029 | Scheduled Transfer |
| Exfiltration | T1030 | Data Transfer Size Limits |
| Exfiltration | T1052.001 | Exfiltration Over Physical Medium: Exfiltration over USB |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell |

### Key Terms

| Term | Meaning |
|---|---|
| Exfiltration | Moving data out of the organization without authorization. |
| Staging | Gathering and compressing files in one place before sending them out. |
| Baseline | What normal activity looks like for a host or user over a past period. |
| Prevalence | How many devices in the organization have contacted a destination or run a file. |
| Asymmetric traffic | Far more bytes sent than received, the typical shape of an upload. |
| DLP | Data Loss Prevention: controls that detect or block sensitive data leaving the organization. |
| CASB | Cloud Access Security Broker: monitors and controls use of cloud apps such as personal storage. |
| rclone | A legitimate command-line cloud sync tool that attackers often abuse for exfiltration. |

---

## 2. Alert Triage

### Sample Scenario

- **Host:** WS-2847 - **User:** jdoe
- **2.4 GB outbound** to an unfamiliar destination
- **Outside normal hours** (21:07-21:11)
- **Rare process** (uncommon on this host)
- Status: **Suspicious - Not Confirmed**

### Investigation Checklist

- [ ] **Baseline** - Is this activity normal for this host and user? Compare against the last 7/30 days at the same hour.
- [ ] **Process owner** - Which process created the transfer, who launched it, and what is its parent chain?
- [ ] **Destination** - Where did the data go? IP, domain, ASN, cloud tenant. Is it known or trusted?
- [ ] **Protocol** - HTTPS, SFTP/SSH, FTP, SMB, DNS? Is the port consistent with the protocol?
- [ ] **Approved transfer** - Is there a change ticket, backup job, migration, or vendor exchange that explains it?
- [ ] **DLP events** - Any Purview DLP / CASB alerts or sensitivity-label hits for the same user and time window?
- [ ] Was an archive created just before the transfer?
- [ ] Is the user still employed, recently resigned, or on a watchlist?
- [ ] Are other hosts or users sending to the same destination?

### Key Fields to Collect

| Field | Example | Why it matters |
|---|---|---|
| Hostname / DeviceId | WS-2847 | Scope, isolation target |
| User / UPN | jdoe | Account to review and possibly disable |
| Initiating process + command line | `powershell.exe -c Invoke-WebRequest ...` | Distinguishes tooling from normal apps |
| Parent process | `explorer.exe`, `wscript.exe` | Reveals execution chain |
| Process SHA256 | `<SHA256>` | TI lookup, prevalence |
| Destination IP / domain / URL | `<RemoteIP>`, `<RemoteUrl>` | TI enrichment and blocking |
| Remote port / protocol | 443 / HTTPS | Expected vs abnormal channel |
| Bytes out / bytes in | 2.4 GB / 4 MB | Strongly asymmetric = upload |
| First seen / last seen | 21:09 / 21:11 | Duration and timeline |
| Files touched / archive name | `C:\Users\jdoe\AppData\Local\Temp\data.7z` | What data was taken |
| DLP / sensitivity labels | Confidential | Business impact, notification duty |

---

## 3. Investigation in Microsoft Defender XDR

Use Advanced Hunting to find the process behind the outbound activity and scope the host.

> Field availability varies by OS, Defender plan, and data source. Note that the documented `DeviceNetworkEvents` schema does **not** include byte counters. Use connection counts and timing in Defender, and take byte volume from firewall/proxy logs (section 4), Defender for Cloud Apps, or Sentinel `CommonSecurityLog`.

### 3.1 Outbound Connections by the User (Process and Destination)

Purpose: list external connections made by processes running as the user, grouped by process and destination.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName =~ "<UserName>"
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Ports = make_set(RemotePort), Urls = make_set(RemoteUrl, 20)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP
| order by Connections desc
```

**What to look for:** Processes like `rclone.exe`, `curl.exe`, or `powershell.exe` talking to rare public IPs are suspicious; browsers, Teams, and OneDrive to well-known services are usually normal.

### 3.2 Rare Destination for the Organization

Purpose: check whether the destination has ever been contacted by other devices (prevalence) in the last 30 days.

```kql
let target = "<RemoteIP>";
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == target or RemoteUrl has "<RemoteDomain>"
| summarize Devices = dcount(DeviceId), DeviceList = make_set(DeviceName, 50),
            Processes = make_set(InitiatingProcessFileName), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
```

**What to look for:** Only the alert host contacting the destination is suspicious; many devices over weeks suggests a common, likely legitimate service.

### 3.3 Rare Process Making Network Connections on the Host

Purpose: find processes on the host whose network activity is new compared to the prior 30 days.

```kql
let host = "<DeviceName>";
let baseline = DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where DeviceName =~ host
    | distinct InitiatingProcessFileName;
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where DeviceName =~ host and RemoteIPType == "Public"
| where InitiatingProcessFileName !in (baseline)
| summarize Connections = count(), Destinations = make_set(RemoteIP, 20)
            by InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
```

**What to look for:** Every result is a process that did not use the network on this host in the prior 30 days; unsigned binaries in user or temp folders deserve close review.

### 3.4 Archive Creation and Staging (DeviceFileEvents)

Purpose: find archives or large files created shortly before the transfer (T1560, T1074).

```kql
DeviceFileEvents
| where Timestamp between (datetime(<StartTime>) .. datetime(<EndTime>))
| where DeviceName =~ "<DeviceName>"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName matches regex @"(?i)\.(zip|7z|rar|tar|gz|tgz|cab)$" or FileSize > 100000000
| project Timestamp, FileName, FolderPath, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
```

**What to look for:** An archive or very large file created in a temp or user folder minutes before the transfer strongly suggests staging; archives from build or backup tools are usually benign.

### 3.5 Exfiltration and Archiving Tools on the Command Line

Purpose: detect common exfil utilities and suspicious upload command lines.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<DeviceName>" or AccountName =~ "<UserName>"
| where FileName in~ ("rclone.exe", "curl.exe", "winscp.exe", "pscp.exe", "ftp.exe", "7z.exe", "rar.exe", "megacmd.exe")
    or ProcessCommandLine has_any ("Invoke-WebRequest", "Invoke-RestMethod", "UploadFile", "-T ", "--upload-file", "rclone copy", "rclone sync", "Compress-Archive")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp asc
```

**What to look for:** Archive commands followed by upload commands (`rclone copy`, `Invoke-WebRequest`, `curl -T`) on the same host form a classic exfiltration chain; check whether an admin task explains it.

### 3.6 USB and Removable Media Copies

Purpose: rule out or confirm a parallel physical exfiltration path (T1052.001).

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<DeviceName>"
| where ActionType in ("UsbDriveMounted", "PnpDeviceConnected")
| project Timestamp, ActionType, AdditionalFields
| order by Timestamp asc
```

**What to look for:** A USB mount in the same window as the alert suggests a parallel physical path; no results makes this channel unlikely.

### 3.7 Cloud Uploads by the User (Defender for Cloud Apps)

Purpose: check uploads and sharing to SaaS (OneDrive, SharePoint, Dropbox, etc.) for the same user.

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where AccountDisplayName has "<UserName>" or AccountObjectId == "<AccountObjectId>"
| where ActionType in~ ("FileUploaded", "FileSyncUploadedFull", "AnonymousLinkCreated", "SharingSet", "FileDownloaded")
| summarize Events = count(), Objects = make_set(ObjectName, 50) by Application, ActionType, IPAddress
| order by Events desc
```

**What to look for:** Many uploads, anonymous links, or sharing to personal or unknown apps around the alert time are suspicious; uploads to the corporate tenant are usually normal work.

### 3.8 Build the Endpoint Timeline

Purpose: merge process, file, and network events on the host into one sequence around the alert.

```kql
let host = "<DeviceName>";
let t0 = datetime(<AlertTime>);
union
  (DeviceProcessEvents | project Timestamp, DeviceName, Table = "Process", Detail = ProcessCommandLine, Proc = InitiatingProcessFileName),
  (DeviceFileEvents    | project Timestamp, DeviceName, Table = "File", Detail = strcat(ActionType, " ", FolderPath), Proc = InitiatingProcessFileName),
  (DeviceNetworkEvents | project Timestamp, DeviceName, Table = "Network", Detail = strcat(RemoteIP, ":", RemotePort, " ", RemoteUrl), Proc = InitiatingProcessFileName)
| where DeviceName =~ host and Timestamp between ((t0 - 1h) .. (t0 + 1h))
| order by Timestamp asc
```

**What to look for:** Read the timeline top to bottom: discovery, then archive creation, then outbound connection is the exfiltration pattern; isolated network events without staging lean benign.

---

## 4. Investigation in Splunk

Use Splunk to quantify traffic, normalize it per time window, compare it to a baseline, and pivot the destination across DNS, firewall, and proxy.

> Index, sourcetype, and field names vary per environment. The examples assume CIM-style fields (`bytes_out`, `dest`, `src`, `user`). Adjust to your proxy/firewall add-on, or use the `Web` / `Network_Traffic` data models with `tstats`.

### 4.1 Total Bytes Out per Host and User (Core Query, Expanded)

Purpose: rank users and hosts by outbound volume and list destinations and processes.

```spl
index=proxy action=allowed user="jdoe"
| stats sum(bytes_out) as total_out sum(bytes_in) as total_in values(dest) as dest values(process) as process by host user
| eval out_GB=round(total_out/1024/1024/1024,2), ratio=round(total_out/(total_in+1),1)
| sort - total_out
```

**What to look for:** A high `out_GB` with a large `ratio` (far more sent than received) points to an upload; low ratios are typical of browsing or downloads.

### 4.2 Normalize Bytes per Time Window

Purpose: convert totals to a rate (bytes per 30m) so hosts and times are comparable.

```spl
index=proxy action=allowed src="<SrcIP>" earliest=-24h
| bin _time span=30m
| stats sum(bytes_out) as bytes_out by _time src user
| eval MB_out=round(bytes_out/1024/1024,1)
```

**What to look for:** A single window with far more MB than the rest is a burst worth investigating; steady, similar values across the day are normal.

### 4.3 Compare Against a Historical Baseline (Same Hour)

Purpose: flag windows where volume is far above the user's 30-day average for that hour of day.

```spl
index=proxy action=allowed user="<UserName>" earliest=-30d
| bin _time span=30m
| stats sum(bytes_out) as bytes_out by _time user
| eval hour=strftime(_time,"%H")
| eventstats avg(bytes_out) as avg_out stdev(bytes_out) as sd_out by user hour
| eval zscore=round((bytes_out-avg_out)/(sd_out+1),2)
| where zscore > 3 AND bytes_out > 104857600
| sort - zscore
```

**What to look for:** Rows with a z-score above 3 (and over 100 MB) are windows well above this user's normal for that hour; no rows means the volume fits the baseline.

### 4.4 Firewall View of the Destination

Purpose: confirm volume, ports, and session counts at the network edge (covers non-proxied protocols such as SFTP/FTP).

```spl
index=firewall dest_ip="<RemoteIP>" OR src_ip="<SrcIP>"
| stats sum(bytes_out) as bytes_out count as sessions values(dest_port) as ports values(app) as app min(_time) as first max(_time) as last by src_ip dest_ip
| convert ctime(first) ctime(last)
| sort - bytes_out
```

**What to look for:** High `bytes_out` over SFTP/FTP or unusual ports to this destination confirms the transfer at the edge; small volumes on standard ports are weaker evidence.

### 4.5 DNS Pivot on the Destination

Purpose: find who resolved the domain, when it first appeared, and what it resolves to.

```spl
index=dns query="*<RemoteDomain>*"
| stats count min(_time) as first_seen values(answer) as answers dc(src) as clients values(src) as src by query
| convert ctime(first_seen)
```

**What to look for:** A domain first seen recently and resolved by only one client is suspicious; long-standing domains resolved by many clients are likely common services.

### 4.6 Sysmon: Process That Made the Connection

Purpose: tie the network flow back to a process and command line on the endpoint (Sysmon Event ID 3 = Network connection, 1 = Process creation).

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="<DeviceName>" (EventCode=3 DestinationIp="<RemoteIP>") OR (EventCode=1 (Image="*\\rclone.exe" OR Image="*\\7z.exe" OR Image="*\\curl.exe" OR CommandLine="*Invoke-WebRequest*"))
| table _time EventCode User Image CommandLine ParentImage DestinationIp DestinationPort
| sort _time
```

**What to look for:** An EventCode 3 connection to the destination from an archiver, `curl`, or PowerShell launched by an unusual parent is suspicious; a known sync or backup agent is usually benign.

### 4.7 Sysmon: Archive Staging

Purpose: find archives created before the transfer (Sysmon Event ID 11 = FileCreate).

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 host="<DeviceName>"
    (TargetFilename="*.zip" OR TargetFilename="*.7z" OR TargetFilename="*.rar" OR TargetFilename="*.tar*")
| table _time User Image TargetFilename
| sort _time
```

**What to look for:** Archives written by `7z.exe`, `rar.exe`, or PowerShell into temp or user folders just before the transfer indicate staging; archives from known installers or updaters are normal.

---

## 5. Threat Intelligence Enrichment

Question to answer: **is the destination new or trusted?** Enrich with real indicators from trusted sources, and consider cloud storage/CDN and business approvals.

### What to Check

| Indicator | Check | Sources |
|---|---|---|
| Destination IP | Reputation, ASN / owner, geolocation, hosting vs residential, abuse reports | VirusTotal, AbuseIPDB, AlienVault OTX, Cisco Talos, WHOIS/RDAP |
| Domain / URL | Registration age, registrar, passive DNS, categorization, screenshots | VirusTotal, URLScan.io, OTX, Talos |
| Process hash (SHA256) | Known tool (rclone, MEGAsync) vs malware, signer, first seen | VirusTotal, MalwareBazaar, Defender file page |
| Cloud tenant / bucket | Corporate tenant vs personal account | Proxy URL path, CASB, CloudAppEvents |
| Internal prevalence | How many devices talk to it (section 3.2, 4.5) | Defender, Splunk |

### Sample Enrichment

| Destination | ASN / Registration | Prevalence | Action |
|---|---|---|---|
| example.test (documentation only) | AS15169 Google LLC - Cloud Storage (GCS) | High (common, global) | **Likely trusted** - still confirm business need / approved cloud storage |
| 198.51.100.10 (documentation only) | TEST-NET-2, reserved by IANA | None (not seen in legitimate traffic) | **Verify** - investigate before blocking; could be test, misconfig, or benign |

### Interpreting Verdicts

- **Malicious / known exfil infrastructure**: strong signal; move to containment quickly.
- **Clean but high-prevalence cloud provider (GCS, S3, OneDrive, Akamai, Cloudflare)**: reputation tells you nothing about *whose* bucket it is. Check the URL path, tenant, and account.
- **No data / newly registered domain**: suspicious by absence; weigh with process and volume evidence.
- **Reputation is not proof.** Use it as one signal together with business, asset, and behavior context.

### Business Context

- [ ] Change tickets, exceptions, or allowlist records for this destination
- [ ] Owner of the cloud tenant or SFTP endpoint (vendor, partner, internal team)
- [ ] Ask the user's manager (not the user first, if insider threat is possible)

**Verify before block:** confirm the destination and business impact (shared cloud storage/CDN, approved use) before blocking, to avoid breaking legitimate services.

---

## 6. Verdict: True Positive vs Benign

| Indicator | Points to true positive | Points to benign |
|---|---|---|
| Process | `rclone`, `curl`, `powershell`, renamed binaries, unsigned tools | Backup agent, OneDrive/Teams, browser with known SaaS |
| Timing | Off-hours, just before resignation or ransomware deployment | Scheduled backup window, known batch job |
| Destination | New, rare, personal cloud account, VPS hosting, newly registered domain | Corporate tenant, approved vendor, high-prevalence internal service |
| Preceding activity | Archive created minutes before, file discovery, share enumeration | No staging; normal application files |
| Volume pattern | Highly asymmetric upload, chunked fixed-size transfers (T1030) | Symmetric sync, software updates, video calls |
| DLP | Sensitivity-labeled or regulated data involved | No DLP hits, public data |
| Approval | No ticket, user cannot explain | Change ticket, documented migration |

### Common False Positives

- Backup and endpoint-sync agents (Veeam, Azure Backup, OneDrive Known Folder Move)
- Developers pushing large container images or artifacts (Docker registries, Git LFS, package feeds)
- Video conferencing and screen sharing
- Approved data migrations and vendor SFTP exchanges
- Log shippers and EDR telemetry uploads
- Security tools uploading samples to sandboxes

### Common Beginner Mistakes

- Trusting a destination because it belongs to a well-known cloud provider; attackers use personal buckets on the same services.
- Asking the user directly first when insider threat is possible, which can tip them off.
- Looking for byte counts in `DeviceNetworkEvents`, which does not record them; use proxy, firewall, or cloud logs instead.
- Isolating or remediating before collecting an investigation package and logs, which loses evidence.
- Judging on volume alone without checking for staging, tooling, and approvals.

---

## 7. Response Checklist

Flow: **1. Validate data and destination → 2. Scope users, files, and hosts → 3. If confirmed, contain and preserve.**

### Validate and Scope

- [ ] Confirm exfiltration: volume, content, method (process, protocol)
- [ ] Confirm destination: IP/domain, cloud service, owner
- [ ] Identify affected users, data/files involved, and all impacted hosts
- [ ] Hunt the destination and hash across the estate (sections 3.2, 4.5)
- [ ] Define the time range and related activity (initial access, persistence)

### Contain

- [ ] Isolate the host in Defender (Device page → Isolate device), or block the destination per process
- [ ] Block the IP/domain/URL with Defender Indicators, proxy, and firewall
- [ ] Block the exfil tool hash (Indicators → File hashes → Block and remediate)
- [ ] Disable the account and revoke sessions (Entra ID: revoke sign-in sessions), if compromise or insider confirmed
- [ ] Revoke cloud sharing links and OAuth app grants used for the transfer
- [ ] Request takedown or provider-side action for the external storage, if applicable

### Preserve Evidence

- [ ] Collect an investigation package in Defender before remediation
- [ ] Preserve endpoint, network, proxy, firewall, DNS, cloud, and SIEM logs for the time window
- [ ] Export Advanced Hunting and Splunk results with timestamps and query text
- [ ] Capture memory / disk image if legal or HR action is possible
- [ ] Keep hashes of the staged archive and record chain of custody

### Eradicate

- [ ] Remove exfil tools, scripts, scheduled tasks, and persistence
- [ ] Rotate exposed secrets, API keys, and credentials found in the stolen data
- [ ] Reset passwords and re-register MFA for affected accounts
- [ ] Patch or close the initial access vector

### Recover

- [ ] Release the host from isolation after clean scans, or reimage
- [ ] Restore user access with least privilege
- [ ] Notify data owners, legal, privacy, and HR; assess regulatory notification
- [ ] Document root cause and lessons learned

### Monitor

- [ ] Tune egress detections: rules, allow/deny lists, thresholds per baseline
- [ ] Create custom detection rules from the queries above
- [ ] Watch the destination, hash, and user for 30 days
- [ ] Enable or tighten DLP policies and CASB controls for personal cloud uploads

---

## 8. Quick Reference

| Step | Defender XDR | Splunk | Key question |
|---|---|---|---|
| Who / what sent it | `DeviceNetworkEvents` by account and process | `index=proxy` stats by host user | Which process and user? |
| How much | Connection counts / CloudAppEvents | `sum(bytes_out)`, `bin span=30m` | Above baseline? |
| Staging | `DeviceFileEvents` archives | Sysmon EventCode=11 | Archive before transfer? |
| Tooling | `DeviceProcessEvents` command lines | Sysmon EventCode=1 | rclone/curl/PowerShell? |
| Destination | Prevalence across devices | DNS, firewall, proxy pivots | New or trusted? |
| Physical | `DeviceEvents` UsbDriveMounted | - | USB in parallel? |
| Respond | Isolate, indicators, investigation package | Timeline, verify scope | Contained and preserved? |

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|---|---|
| [Network Security Monitoring: SOC Analyst Tutorial](https://www.youtube.com/watch?v=y_mHZ-yfFXw) | Fundamentals of monitoring network traffic as a SOC analyst |
| [Incident Response Series: Suspicious DNS Traffic](https://www.youtube.com/watch?v=hyBMaS19Ktk) | Investigating suspicious DNS activity, useful for the destination pivot |
| [Wireshark Crash Course: SOC Analyst Tutorial](https://www.youtube.com/watch?v=hzR6XpeBHd4) | Using Wireshark to inspect packets and network conversations |
| [Splunk for Security Analysts: DNS Log Analysis](https://www.youtube.com/watch?v=OXFkbSxhntc) | Analyzing DNS logs in Splunk |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|---|---|
| [Proxy Log Analysis](https://app.haxcamp.com/lab/proxy-log-analysis) | Tie web traffic and uploads to specific users |
| [Firewall Log Analysis](https://app.haxcamp.com/lab/firewall-log-analysis) | Read session logs, NAT translations and threat signatures |
| [Detecting Command-and-Control (C2) Traffic](https://app.haxcamp.com/lab/detecting-command-and-control-c2-traffic) | Detect hidden attacker communication channels |
| [DNS Log Analysis Using Splunk](https://app.haxcamp.com/lab/dns-log-analysis) | Detect advanced threat techniques in DNS logs |
| [TLS Log Analysis Using Splunk](https://app.haxcamp.com/lab/tls-log-analysis-using-splunk) | Uncover malicious behaviour in encrypted traffic |
| [Data Exfiltration (cloud scenario)](https://app.haxcamp.com/lab/data-exfiltration) | Investigate data exfiltration in a cloud environment |

### Official Documentation

- [MITRE ATT&CK: Exfiltration Tactic (TA0010)](https://attack.mitre.org/tactics/TA0010/)
- [MITRE ATT&CK: T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [MITRE ATT&CK: T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560/)
- [Microsoft Defender XDR: Advanced Hunting Overview](https://learn.microsoft.com/defender-xdr/advanced-hunting-overview)
- [Microsoft Defender XDR: DeviceNetworkEvents Table](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [Microsoft Defender XDR: DeviceFileEvents Table](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicefileevents-table)
- [Microsoft Defender for Endpoint: Take Response Actions on a Device](https://learn.microsoft.com/defender-endpoint/respond-machine-alerts)
- [Splunk CIM: Network Traffic Data Model](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- [Splunk CIM: Web Data Model](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- [Microsoft Sysinternals: Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
