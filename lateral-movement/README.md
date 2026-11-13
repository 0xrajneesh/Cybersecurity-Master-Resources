# Lateral Movement: SOC Investigation Playbook

How to detect, investigate, and respond when one host suddenly accesses another, using Microsoft Defender XDR, Splunk, and threat intelligence.

> **Level:** Beginner to Intermediate · **Time:** ~45 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to spot a suspicious host-to-host hop, how to trace logon → admin share → remote service in KQL and SPL, how to decide true positive vs benign and contain it
>
> **Prerequisites:** basic Windows Security event logs (4624, 7045) and KQL/SPL syntax

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

1. Identify the account, source host, and destination host from the alert.
2. Check the account's privilege level: standard user, server admin, or domain/tier-0 admin.
3. Check the logon type and authentication package (Network / RDP / NewCredentials; NTLM vs Kerberos).
4. Look for a new service (7045 / 4697) or an `ADMIN$` file write on the target within minutes of the logon.
5. Check for an approved change ticket or maintenance window covering this time, host, and account.
6. Ask whether the source host has ever reached this target before, and whether peers do.
7. Check the source host for other alerts in the last 7 days.

**Escalate immediately if:** the account is privileged or the target is a domain controller, a random-named service or binary was dropped via an admin share, or the source is hopping to multiple hosts with no change ticket.

---

## 1. What This Alert Means

A lateral movement alert fires when an identity authenticated on one host (Host A) uses that foothold to reach and act on another host (Host B). The classic Windows pattern is:

```text
New logon (Host A -> Host B)  ->  SMB admin share (ADMIN$ / C$)  ->  Remote service / process
```

This is the mechanic behind PsExec, Impacket `psexec.py`/`smbexec.py`/`wmiexec.py`, Cobalt Strike `jump psexec`, and many ransomware deployment scripts: copy a binary to `\\target\ADMIN$`, then register and start a service (or WMI process) that runs it.

**Why Attackers Do It**

- The initially compromised host (phishing victim, exposed service) rarely holds the data or privileges they need.
- Moving to servers, jump hosts, and domain controllers lets them harvest more credentials (LSASS, cached hashes, Kerberos tickets).
- Reaching many hosts is the precondition for mass impact: ransomware deployment, data staging, backup destruction.
- Using valid accounts and built-in protocols (SMB, RDP, WinRM, WMI) blends in with normal administration.

**MITRE ATT&CK Mapping**

| Tactic | Technique ID | Name | Typical evidence |
|---|---|---|---|
| Lateral Movement | T1021 | Remote Services | Network/remote logons to new hosts |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | 4624 LogonType 10, port 3389 |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | 5140/5145 on `ADMIN$`, `C$`, `IPC$` |
| Lateral Movement | T1021.006 | Remote Services: Windows Remote Management | `wsmprovhost.exe`, port 5985/5986 |
| Lateral Movement | T1570 | Lateral Tool Transfer | File written to admin share, then executed |
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | NTLM network logons from unusual sources |
| Lateral Movement | T1550.003 | Use Alternate Authentication Material: Pass the Ticket | Kerberos anomalies, ticket reuse |
| Execution | T1569.002 | System Services: Service Execution | 7045 / 4697 new service, `services.exe` child |
| Persistence | T1543.003 | Create or Modify System Process: Windows Service | Service left installed after use |
| Execution | T1047 | Windows Management Instrumentation | `WmiPrvSE.exe` spawning `cmd.exe` |
| Defense Evasion / Persistence / Privilege Escalation / Initial Access | T1078 | Valid Accounts | Legitimate credentials used from new source |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Often precedes or follows the hop |

### Key Terms

| Term | Meaning |
|---|---|
| Lateral movement | An attacker using one compromised host to reach and control other hosts in the network. |
| Admin share (`ADMIN$`, `C$`) | Hidden Windows shares that give administrators remote access to a host's system folder and drives. |
| Logon type | A number in event 4624 showing how a user logged on, such as 3 for network or 10 for RDP. |
| PsExec | A Microsoft Sysinternals tool that runs commands on remote hosts by copying a service binary over SMB; attackers abuse it too. |
| Pass-the-hash | Authenticating with a stolen NTLM password hash instead of the actual password. |
| NTLM / Kerberos | The two main Windows authentication protocols; Kerberos is the domain default, NTLM is older and easier to abuse. |
| Jump host / PAW | A dedicated, hardened machine administrators use to manage servers, so admin logons should come only from it. |
| Blast radius | The set of hosts, accounts, and data an attacker can reach from a compromised position. |

---

## 2. Alert Triage

**Sample alert:** `jdoe` on `WS-2847` authenticates to `SRV-APP-01`, then accesses `\\SRV-APP-01\ADMIN$`; unusual time, new source host. Status: **Suspicious (not confirmed)**.

Two things made it stand out:

- **Unusual time** - outside the user's normal working hours or outside any change window.
- **New source host** - `WS-2847` has never (or rarely) authenticated to `SRV-APP-01` before.

### Triage Checklist

- [ ] **Account privilege** - Is `jdoe` a standard user, local admin, server admin, or domain/tier-0 admin? Does the account legitimately need admin rights on the target? Is it a service account being used interactively?
- [ ] **Source / destination** - Which host initiated (hostname, IP, owner, OS, role)? Which host received it (server role, criticality, data held)? Is the source itself already compromised (other alerts in the last 7 days)?
- [ ] **Logon type** - 3 (Network: SMB/WMI/PsExec), 10 (RemoteInteractive: RDP), 9 (NewCredentials: `runas /netonly`, often seen with pass-the-hash tooling), 2 (Interactive). Authentication package NTLM vs Kerberos.
- [ ] **Change window** - Is there an approved change, maintenance, patching, or deployment ticket covering this time, host, and account?
- [ ] **Service creation** - Was a new service installed on the target (7045 / 4697) shortly after the logon? Random name? Binary in `ADMIN$` / `C:\Windows\` / `Temp`?
- [ ] **Peer baseline** - Do peers in the same team/role ever access this server? Does `jdoe` normally use this source host?

### Key Fields to Collect

| Field | Example | Why it matters |
|---|---|---|
| Account (UPN / SAM / SID) | `CONTOSO\jdoe` | Scope identity, privilege, other sessions |
| Source host / IP | `WS-2847` / `10.10.20.15` | Where the attacker is operating from |
| Destination host / IP | `SRV-APP-01` | What was reached, criticality |
| Logon type | 3 / 10 / 9 | Protocol and technique hint |
| Auth package | NTLM / Kerberos | NTLM from a workstation to a server can indicate pass-the-hash |
| Logon ID | `0x3E7A12` | Correlate logon to later actions on the same session |
| Share name / path | `\\*\ADMIN$`, `RelativeTargetName` | Tool transfer evidence |
| Service name / binary | `ServiceName`, `ServiceFileName` | Remote execution and persistence |
| Process tree on target | `services.exe` → `abc.exe` → `cmd.exe` | What actually ran |
| First seen / last seen | timestamps (UTC) | Timeline and dwell time |
| Related alerts | Defender incident ID | Is this part of a larger chain |

---

## 3. Investigation in Microsoft Defender XDR

Run these in **Advanced Hunting** ([security.microsoft.com](https://security.microsoft.com) → Hunting). Replace placeholders such as `<AccountName>`, `<DeviceName>`, `<SourceDevice>`. Schemas evolve; confirm column names in the schema pane of your tenant.

> Note: in `DeviceLogonEvents`, `LogonType` is a string (`Network`, `RemoteInteractive`, `Interactive`, `NewCredentials`, ...), not the numeric Windows value.

### 3.1 Trace Successful Remote Logons for an Account (Core Query, Extended)

Purpose: find every device where the account logged on remotely and where the connection came from.

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where AccountName =~ "<AccountName>"
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive", "NewCredentials")
| project Timestamp, DeviceName, RemoteDeviceName, RemoteIP, LogonType,
          AccountDomain, Protocol, IsLocalAdmin, LogonId
| order by Timestamp desc
```

**What to look for:** logons to servers the account does not normally use, `NewCredentials` logons, or `IsLocalAdmin` true on many hosts are suspicious. Consistent logons from the user's own device or a known jump host are normal.

### 3.2 New Source → Destination Pairs (First-Seen Baseline)

Purpose: surface account/source/destination combinations seen in the last day but never in the prior 30 days (the "new source host" signal).

```kql
let lookback = 30d;
let recent = 1d;
let Baseline = DeviceLogonEvents
    | where Timestamp between (ago(lookback) .. ago(recent))
    | where ActionType == "LogonSuccess" and LogonType in ("Network", "RemoteInteractive")
    | distinct AccountName, RemoteDeviceName, DeviceName;
DeviceLogonEvents
| where Timestamp > ago(recent)
| where ActionType == "LogonSuccess" and LogonType in ("Network", "RemoteInteractive")
| where isnotempty(RemoteDeviceName)
| join kind=leftanti Baseline on AccountName, RemoteDeviceName, DeviceName
| summarize FirstSeen = min(Timestamp), Logons = count(), Targets = make_set(DeviceName)
    by AccountName, RemoteDeviceName
| order by array_length(Targets) desc
```

**What to look for:** a new pair with many `Targets` (one source fanning out to several hosts) is highly suspicious. A single new pair explained by a new laptop or a change ticket is usually benign.

### 3.3 Outbound SMB/RDP/WinRM Connections from the Source

Purpose: confirm the network path from the source to the destination and see which other hosts the source touched.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<SourceDevice>"
| where ActionType == "ConnectionSuccess"
| where RemotePort in (445, 135, 3389, 5985, 5986)
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Ports = make_set(RemotePort), Processes = make_set(InitiatingProcessFileName)
    by RemoteIP, RemoteUrl
| order by Connections desc
```

**What to look for:** a workstation reaching many internal hosts on 445/135/5985, or connections made by unusual processes, is suspicious. A few connections to file servers or domain controllers are normal.

### 3.4 Remote Service Creation on the Target

Purpose: detect the "remote service / process" step (PsExec-style execution, T1569.002).

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<DeviceName>"
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName),
         ServiceAccount = tostring(parse_json(AdditionalFields).ServiceAccount),
         ServiceStartType = tostring(parse_json(AdditionalFields).ServiceStartType)
| project Timestamp, DeviceName, ServiceName, FolderPath, FileName,
          ServiceAccount, ServiceStartType, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

**What to look for:** random or short service names, `PSEXESVC`, or binaries in `C:\Windows\`, `ADMIN$`, or `Temp` are suspicious. Known agents and installers with signed binaries in `Program Files` are normal.

### 3.5 Process Execution Spawned by Remote Execution Parents

Purpose: see what actually ran on the destination via services, WMI, or WinRM.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<DeviceName>"
| where InitiatingProcessFileName in~ ("services.exe", "wmiprvse.exe", "wsmprovhost.exe", "psexesvc.exe")
| where FileName !in~ ("svchost.exe", "msiexec.exe", "TrustedInstaller.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

**What to look for:** `cmd.exe` or `powershell.exe` with encoded commands, unknown binaries, or discovery commands (`whoami`, `net group`) are suspicious. Known agent updates and patching processes are normal.

### 3.6 Files Dropped via Admin Share

Purpose: find executables/scripts written to the target over SMB (lateral tool transfer, T1570).

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<DeviceName>"
| where ActionType in ("FileCreated", "FileModified")
| where isnotempty(RequestSourceIP) or InitiatingProcessFileName =~ "System"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
     or FileName endswith ".bat" or FileName endswith ".vbs"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          RequestAccountName, RequestSourceIP, ShareName
| order by Timestamp desc
```

**What to look for:** executables or scripts written to `ADMIN$`/`C$` from a workstation IP shortly before a service install are suspicious. Writes from known deployment servers (SCCM, Intune) are normal.

### 3.7 Identity View: NTLM / Kerberos Activity in Defender for Identity

Purpose: check domain-controller-side authentication for the account (pass-the-hash / pass-the-ticket hints).

```kql
IdentityLogonEvents
| where Timestamp > ago(7d)
| where AccountName =~ "<AccountName>"
| summarize Attempts = count(), Failures = countif(ActionType == "LogonFailed"),
            Protocols = make_set(Protocol), Targets = make_set(DestinationDeviceName)
    by DeviceName, IPAddress, LogonType
| order by Attempts desc
```

**What to look for:** NTLM from a workstation to many targets, or bursts of failures followed by a success, is suspicious. Kerberos logons from the user's usual device are normal.

> Correlate across tables: join on `DeviceName` + time window, or on `LogonId` between `DeviceLogonEvents` and `DeviceProcessEvents` (`InitiatingProcessLogonId`) to tie a specific session to the processes it launched.

---

## 4. Investigation in Splunk

Goal: **map the source-to-target path** - logon (4624) → share access (5140/5145) → service install (7045).

> Index, sourcetype, and field names vary per environment. With the Splunk Add-on for Microsoft Windows, Security events are typically `sourcetype=WinEventLog:Security` (or `XmlWinEventLog:Security`) and the logon type field may be `Logon_Type` instead of `LogonType`. Verify field mappings and that you have permission to search Security, System, and SMBServer logs.

### 4.1 Network Logons by Account and Destination (Core Query)

Purpose: who logged on over the network, from where, to which host.

```spl
index=wineventlog EventCode=4624 LogonType=3
| stats count values(WorkstationName) as src_workstations values(IpAddress) as src_ips
    by TargetUserName ComputerName
| sort - count
```

**What to look for:** one user account logging on to many servers, or from IPs that belong to user workstations, is suspicious. Service accounts and admins connecting from known management hosts are normal.

### 4.2 First-Seen Source → Destination Pairs

Purpose: highlight logons from a source never used by this account against this host in the baseline window.

```spl
index=wineventlog EventCode=4624 (LogonType=3 OR LogonType=10) earliest=-30d
| eval src=coalesce(WorkstationName, IpAddress)
| stats min(_time) as first_seen max(_time) as last_seen count by TargetUserName src ComputerName
| where first_seen >= relative_time(now(), "-24h")
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

**What to look for:** every row is a pair first seen in the last 24 hours; pairs reaching servers or many hosts are suspicious. Pairs explained by a new device or change ticket are benign.

### 4.3 Admin Share Access

Purpose: detect access to `ADMIN$`, `C$`, `IPC$` and files written there.

```spl
index=wineventlog (EventCode=5140 OR EventCode=5145)
    (ShareName="*\\ADMIN$" OR ShareName="*\\C$" OR ShareName="*\\IPC$")
| table _time ComputerName SubjectUserName IpAddress ShareName RelativeTargetName AccessMask
| sort _time
```

**What to look for:** `.exe`, `.dll`, or `.bat` files in `RelativeTargetName` on `ADMIN$`/`C$` from a workstation IP are suspicious. `IPC$` access on its own is very common and usually normal.

### 4.4 New Service Installation

Purpose: find remote service creation (System log 7045; Security 4697 if auditing enabled).

```spl
index=wineventlog ((source="WinEventLog:System" EventCode=7045) OR EventCode=4697)
| eval svc_path=coalesce(ServiceFileName, Service_File_Name, ImagePath)
| table _time ComputerName ServiceName svc_path ServiceType StartType SubjectUserName
| sort _time
```

**What to look for:** random service names or `svc_path` pointing to `ADMIN$`, `Temp`, or `cmd.exe /c` are suspicious. Known vendor services with paths in `Program Files` are normal.

### 4.5 Correlate the Full Sequence on One Target

Purpose: chain logon → share access → service install for the same host within a short window.

```spl
index=wineventlog (EventCode=4624 LogonType=3) OR EventCode=5140 OR EventCode=5145 OR EventCode=7045
    ComputerName="<DeviceName>*"
| eval stage=case(EventCode=4624,"1_logon", EventCode=5140 OR EventCode=5145,"2_share", EventCode=7045,"3_service")
| eval user=coalesce(TargetUserName, SubjectUserName)
| bin _time span=10m
| stats values(stage) as stages values(user) as users values(IpAddress) as src_ips
    values(ShareName) as shares values(ServiceName) as services by _time ComputerName
| where mvcount(stages) >= 2
```

**What to look for:** a 10-minute bucket containing all three stages (logon, share, service) is a strong PsExec-style signal. Logon plus share only, from a known file-share client, is usually normal.

### 4.6 Sysmon: Processes Spawned by Remote Execution Parents

Purpose: see what ran on the target (Sysmon EventCode 1 = process create).

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    host="<DeviceName>"
    (ParentImage="*\\services.exe" OR ParentImage="*\\WmiPrvSE.exe" OR ParentImage="*\\wsmprovhost.exe")
| table _time host User ParentImage Image CommandLine Hashes
| sort _time
```

**What to look for:** shells, scripting engines, or unknown binaries spawned by `services.exe` or `WmiPrvSE.exe` are suspicious. Expected service binaries and management agents are normal.

### 4.7 Sysmon: Outbound Lateral Protocols from the Source

Purpose: list hosts the source contacted over SMB/RPC/RDP/WinRM (Sysmon EventCode 3 = network connection).

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
    host="<SourceDevice>" DestinationPort IN (445, 135, 3389, 5985, 5986)
| stats count min(_time) as first_seen values(Image) as processes by DestinationIp DestinationPort
| convert ctime(first_seen)
| sort - count
```

**What to look for:** a workstation reaching many internal IPs on 445/5985, or via unusual processes, is suspicious. Connections to file servers and domain controllers only are normal.

> Visualize the path: feed `src → ComputerName` pairs from 4.1/4.2 into a Network Diagram or Sankey visualization to see the end-to-end hop chain.

---

## 5. Threat Intelligence Enrichment

Core rule: **separate external indicators from internal movement.**

| Indicator type | Enrich? | How to treat it |
|---|---|---|
| External source IP (e.g. `203.0.113.10` hitting VPN) | Yes | Reputation, ASN, geolocation, actor/TTP links, correlate with timeline |
| File hash (e.g. service binary `5f2e...a9c3`) | Yes | Look up hash, then check execution, parent process, host impact |
| Domain / URL contacted by dropped tool | Yes | Reputation, registration age, sandbox reports |
| Internal host/IP (e.g. `10.10.20.15`) | No (context only) | Not a public IOC. Validate asset, owner, user identity, related activity |

### Workflow: Correlate → Enrich → Scope → Corroborate

1. **Correlate** - link the indicator to the relevant events and behavior (which logon, which process, which file).
2. **Enrich** - add external intel only where relevant:
   - **VirusTotal** - hash/IP/domain/URL detections, first-submission date, behavior and relations.
   - **MalwareBazaar** - known malware samples and family tags for hashes.
   - **AbuseIPDB** - abuse reports and confidence score for external IPs.
   - **AlienVault OTX** - pulses linking indicators to campaigns/actors.
   - **URLScan.io** - screenshots and DOM/requests for suspicious URLs.
   - **Microsoft Defender Threat Intelligence / file and IP pages in Defender XDR** - prevalence in your org and Microsoft verdicts.
3. **Scope** - determine affected assets, users, and time range (rerun section 3/4 queries with the indicator).
4. **Corroborate** - validate with asset inventory (host exists, in scope, expected role), identity (who actually used it), and intel confidence (high / medium / low).

### Interpreting Verdicts

- **Known malicious, high confidence** (multiple engines, family tag, recent reports) - treat as TP evidence; escalate.
- **Suspicious / low detections** - not conclusive; weigh with behavior (service install, odd parent, unusual time).
- **Clean / unknown** - absence of intel is not innocence. Custom or renamed tools (e.g. renamed PsExec, Impacket) often have no reputation. Check signer, prevalence in your org, and behavior.
- **Legitimate dual-use tool** (signed Sysinternals PsExec) - the tool is benign; the question is whether the use was authorized.

---

## 6. Verdict: True Positive vs Benign

| Signal | Leans true positive | Leans benign |
|---|---|---|
| Timing | Night/weekend, no change ticket | Inside approved change window |
| Source host | Never-before-seen workstation, user's normal device is elsewhere | Known admin jump host / PAW |
| Account | Standard user suddenly with admin rights, or admin account from workstation | Designated admin account used as normal |
| Logon | NTLM type 3 from workstation, type 9 `NewCredentials`, burst to many hosts | Kerberos from management server, consistent pattern |
| Share access | `ADMIN$` write of random-named `.exe` | Software deployment share used by SCCM/Intune |
| Service | Random service name, binary in `ADMIN$`/Temp, deleted after run | Known agent/installer service, signed binary |
| Follow-on | Credential dumping, discovery (`net group`, `nltest`), more hops | No further activity, ticket explains it |
| Peer baseline | No peers access this server | Same-team admins access it routinely |
| Intel | Hash/IP known malicious | Signed, high prevalence, no reports |

### Common False Positives

- IT administrators using PsExec, PowerShell remoting, or RDP for support.
- Software deployment and patching (SCCM/ConfigMgr, Intune, PDQ, WSUS-driven tasks) creating services remotely.
- Vulnerability scanners and asset discovery tools authenticating to many hosts.
- Backup and monitoring agents (service accounts) using SMB admin shares.
- Helpdesk remote-assist tools and new jump hosts not yet in the baseline.
- Users legitimately getting a new laptop (new source host for the same account).

When benign: document the justification (ticket number, owner confirmation), and tune with a narrow exclusion (specific account + source + destination), not a blanket one.

### Common Beginner Mistakes

- Closing the alert because PsExec is a signed Microsoft tool; the real question is whether the use was authorized.
- Treating an internal IP like `10.10.20.15` as an IOC and looking it up on VirusTotal instead of checking the asset owner.
- Investigating only the destination host and never asking how the source host was compromised.
- Treating `IPC$` access as suspicious on its own; it is extremely common.
- Confusing Windows numeric logon types (3, 10) with the string values in `DeviceLogonEvents` (`Network`, `RemoteInteractive`).

---

## 7. Response Checklist

Goal: **contain the compromised path** - close the blast radius, secure access, restore a trusted state.

### Contain

- [ ] Confirm the source account and host (who and where the hop started).
- [ ] Identify all affected targets and any privileged credentials exposed on them.
- [ ] Isolate the compromised endpoint(s) in Defender (Isolate device) if evidence supports it.
- [ ] Disable the account or mark it compromised in Entra ID / Defender for Identity; revoke sessions and Kerberos tickets (reset password twice for privileged accounts where needed).
- [ ] Block malicious hashes / external IPs / domains via Defender indicators and firewall/proxy.
- [ ] Temporarily restrict SMB/RDP/WinRM from workstations to servers if spread is active.

### Eradicate

- [ ] Remove malicious services (`sc delete <ServiceName>`) and their binaries on every target.
- [ ] Remove other persistence: scheduled tasks, Run keys, WMI subscriptions, new local admins.
- [ ] Run full AV/EDR scans; remediate or reimage hosts where integrity cannot be trusted.
- [ ] Review and clean admin shares and dropped tools (`ADMIN$`, `C$`, Temp folders).

### Recover

- [ ] Rotate credentials for the compromised account and any privileged/service accounts used on affected hosts (consider KRBTGT rotation if domain admin exposure).
- [ ] Rotate local administrator passwords (Windows LAPS).
- [ ] Release hosts from isolation only after validation; restore from known-good backups if needed.
- [ ] Review share and service permissions; remove unneeded admin rights.

### Preserve Evidence

- [ ] Collect an investigation package from Defender for affected devices before reimaging.
- [ ] Export relevant Advanced Hunting and Splunk results with timestamps (UTC).
- [ ] Preserve copies of dropped binaries (hash, file) in a secure evidence store.
- [ ] Capture memory where credential theft is suspected.
- [ ] Record the full timeline: initial access, each hop, actions, containment times.

### Monitor

- [ ] Watch the account and affected hosts for 30 days (new logons, service installs, re-infection).
- [ ] Add detections for the observed TTPs (first-seen pairs, remote service creation, admin share writes).
- [ ] Harden: tiered admin model, PAWs, restrict local admin, disable NTLM where feasible, enable SMB signing, block workstation-to-workstation SMB.
- [ ] Hold a lessons-learned review and update this playbook.

---

## 8. Quick Reference

| Item | Value |
|---|---|
| Network logon | 4624, LogonType 3 (MDE: `Network`) |
| RDP logon | 4624, LogonType 10 (MDE: `RemoteInteractive`) |
| Explicit credentials logon | 4648; LogonType 9 `NewCredentials` |
| Failed logon | 4625 |
| Share accessed / file on share checked | 5140 / 5145 |
| Service installed | 7045 (System), 4697 (Security) |
| Scheduled task created | 4698 |
| Sysmon process / network | EventCode 1 / 3 |
| Lateral ports | 445 SMB, 135 RPC, 3389 RDP, 5985/5986 WinRM |
| Remote exec parents | `services.exe`, `WmiPrvSE.exe`, `wsmprovhost.exe` |
| MDE tables | `DeviceLogonEvents`, `DeviceNetworkEvents`, `DeviceEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `IdentityLogonEvents` |
| Key ATT&CK | T1021.001, T1021.002, T1021.006, T1570, T1569.002, T1550.002 |
| Flow | Detect → Investigate → Respond |

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|---|---|
| [Windows Security Event Analysis](https://www.youtube.com/watch?v=aaAvlNgF2AU) | Reading and interpreting Windows Security events such as logons and service installs. |
| [Windows Security Monitoring Crash Course](https://www.youtube.com/watch?v=a_PzlNyWzjo) | A fast introduction to monitoring Windows hosts with Security event logs. |
| [How I Responded: Suspicious Activity Detected on Multiple Devices](https://www.youtube.com/watch?v=Vm9UERA-_5I) | A walkthrough of responding to suspicious activity that spans multiple devices. |
| [Threat Hunting Crash Course](https://www.youtube.com/watch?v=5OuPcohUfvY) | Fundamentals of proactively hunting for attacker activity. |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|---|---|
| [Detecting SMB Lateral Movement Activity](https://app.haxcamp.com/lab/detecting-smb-lateral-movement-activity) | Identify SMB authentication attempts and lateral movement in Wireshark |
| [SMB Security Analysis](https://app.haxcamp.com/lab/smb-security-analysis) | From a routine file share to a full network compromise |
| [AD Privileged Activity Auditor](https://app.haxcamp.com/lab/ad-privileged-activity-auditor) | Classify AD privileged-activity alerts and enrich source IPs |
| [Windows Security Log Monitoring](https://app.haxcamp.com/lab/introduction-to-windows-security-monitoring) | Investigate Windows Security events with Event Viewer and Splunk |
| [Threat Hunting for Windows](https://app.haxcamp.com/lab/threat-hunting-for-windows) | Hunt for attacker activity on Windows endpoints |
| [Active Directory Fundamentals](https://app.haxcamp.com/lab/active-directory-fundamentals) | AD structure, objects, authentication and authorisation |

### Official Documentation

- [MITRE ATT&CK: Lateral Movement Tactic (TA0008)](https://attack.mitre.org/tactics/TA0008/)
- [MITRE ATT&CK: Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
- [MITRE ATT&CK: SMB/Windows Admin Shares (T1021.002)](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: Service Execution (T1569.002)](https://attack.mitre.org/techniques/T1569/002/)
- [Microsoft: Advanced Hunting Overview](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [Microsoft: DeviceLogonEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
- [Microsoft: Event 4624 (An Account Was Successfully Logged On)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft: Event 5145 (Detailed File Share)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145)
- [Microsoft: Take Response Actions on a Device](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- [Microsoft: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk: Splunk Add-on for Microsoft Windows](https://docs.splunk.com/Documentation/WindowsAddOn/latest/User/AbouttheSplunkAdd-onforWindows)
- [Splunk: Search Reference (stats)](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
