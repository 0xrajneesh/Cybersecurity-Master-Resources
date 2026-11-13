# Suspicious Remote Access: SOC Investigation Playbook

A practitioner playbook for triaging, investigating, and responding to unexpected RDP, VPN, and remote sessions with Microsoft Defender XDR, Splunk, and threat intelligence.

> **Level:** Beginner to Intermediate · **Time:** ~55 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to triage an unexpected RDP or VPN session, how to reconstruct session activity with KQL and SPL, how to reach a verdict and contain a compromised account
>
> **Prerequisites:** Basic Windows logon events (4624/4625, logon types) and KQL/SPL syntax

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

1. Read the alert: which account, which host, which source IP, and what time.
2. Check the source IP: corporate egress or known vendor, or hosting/VPN/Tor/residential and never seen before?
3. Check the account type: a service account (e.g. `svc-admin`) doing an interactive RDP logon (type 10) is a red flag on its own.
4. Look for a change ticket or maintenance window covering this host, account, and time.
5. Check for many failed logons (4625) from the same source just before the success.
6. Glance at the first minutes of the session: new admins, tool downloads, new services, or PowerShell.
7. Confirm with the user or account owner through an out-of-band channel (phone).

**Escalate immediately if:** the source has bad reputation or unapproved anonymization, brute force preceded the success, or a privileged change happened within minutes of logon.

---

## 1. What This Alert Means

A "Suspicious Remote Access" alert fires when a remote session (usually RDP, sometimes VPN, SSH, or a third-party remote tool) is established in a way that deviates from the baseline: an unfamiliar external source, an unusual time, a new source device, or an account that should not be logging on interactively at all. The alert is **suspicious, not confirmed**. Your job is to decide whether it is an admin doing legitimate work or an adversary using valid access.

Typical attack path:

```text
External source (203.0.113.77) --RDP--> Endpoint (remote session) --> Defender / Splunk / TI
```

### Why Attackers Use Remote Access

- **It blends in.** RDP and VPN are legitimate admin channels. Using stolen valid credentials over them produces "normal-looking" logons rather than malware alerts.
- **Initial access.** Internet-exposed RDP (TCP 3389), VPN portals, and remote gateways are prime targets for password spraying, brute force, and credentials bought from infostealer logs or initial access brokers.
- **Interactive control.** A full desktop lets the operator run tools, disable defenses, browse file shares, and stage data manually.
- **Lateral movement.** After the first foothold, attackers RDP from host to host using harvested admin or service account credentials. This is a common precursor to ransomware deployment.
- **Persistence.** Creating local admins, enabling RDP, or installing remote access software (AnyDesk, ScreenConnect, etc.) keeps the door open.

### MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|---|---|---|
| T1133 | External Remote Services | VPN / RDP gateway used as the entry point |
| T1078 | Valid Accounts | Stolen or abused legitimate credentials |
| T1078.002 | Valid Accounts: Domain Accounts | Domain user / service accounts such as `svc-admin` |
| T1078.003 | Valid Accounts: Local Accounts | Local administrator reuse |
| T1021.001 | Remote Services: Remote Desktop Protocol | RDP logon to the target host |
| T1563.002 | Remote Service Session Hijacking: RDP Hijacking | Taking over an existing RDP session (e.g., `tscon`) |
| T1110 | Brute Force (incl. T1110.003 Password Spraying) | Repeated 4625 failures before a success |
| T1219 | Remote Access Software | AnyDesk, TeamViewer, ScreenConnect installed for persistence |
| T1098 | Account Manipulation | Adding the account to privileged groups |
| T1136.001 | Create Account: Local Account | New local user created during the session |
| T1105 | Ingress Tool Transfer | Tools downloaded during the session |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell launched in the session |

### Key Terms

| Term | Meaning |
|---|---|
| RDP | Remote Desktop Protocol, the built-in Windows way to control a computer's desktop over the network (TCP 3389). |
| Logon type 10 (RemoteInteractive) | The Windows logon type recorded when someone signs in through RDP. |
| Logon type 3 (Network) | A non-interactive logon such as accessing a file share; normal for service and monitoring accounts. |
| Service account | An account used by applications or scheduled jobs, not by a person; it should rarely log on interactively. |
| Password spraying | Trying a few common passwords against many accounts to avoid lockouts. |
| ASN | Autonomous System Number, identifying the organization that owns an IP range (ISP, hosting provider, company). |
| MFA fatigue | Flooding a user with MFA push prompts until they approve one by mistake. |
| Jump host | A hardened server that admins connect through to reach other systems. |

---

## 2. Alert Triage

**Key question: What made this remote session risky?**

Example alert:

| Field | Value |
|---|---|
| Status | Suspicious (not confirmed) |
| Account | `svc-admin` |
| Host | `SRV-APP-01` |
| Protocol | RDP from unfamiliar source `198.51.100.28` |
| Timing | Outside the maintenance window |
| Source device | New (never seen for this account) |

### Session Timeline to Reconstruct

| Time | Stage | What to confirm |
|---|---|---|
| 10:14:32 | VPN / RDP authentication | Which gateway, which user, MFA prompt and result |
| 10:15:07 | Session start | Logon type 10 (RemoteInteractive), source IP and workstation name |
| 10:17:26 | Privileged action | What was done: group change, service install, tool execution, data access |

A privileged action **under three minutes** after logon is a strong signal of an operator with a plan rather than a human doing routine checks.

### Investigation Checklist

- [ ] **Source IP / ASN** - Is it a corporate egress, known vendor, residential ISP, hosting provider, VPN or Tor exit?
- [ ] **VPN** (tunnel, user, time) - Did a VPN session exist for this user, from which public IP, and does the assigned internal IP match the RDP source?
- [ ] **MFA** (challenge and result) - Was MFA required, which method, was it approved, denied, or bypassed? Repeated pushes suggest MFA fatigue.
- [ ] **Account privilege** (e.g., admin, service) - Service accounts should rarely, if ever, perform interactive RDP logons.
- [ ] **Approved maintenance** (window and change ticket) - Is there a change record covering this host, account, and time?
- [ ] **Session activity** (commands, access, changes) - Processes, files, network connections, and configuration changes during the session.

### Key Fields to Collect

| Field | Defender XDR column | Windows / Splunk field |
|---|---|---|
| Time of logon | `Timestamp` | `_time` |
| Target host | `DeviceName` | `ComputerName` / `host` |
| Account | `AccountName`, `AccountDomain`, `AccountSid` | `TargetUserName`, `TargetDomainName` |
| Logon type | `LogonType` (`RemoteInteractive`) | `LogonType` (10 = RemoteInteractive, 3 = Network, 7 = Unlock/reconnect) |
| Source IP | `RemoteIP` | `IpAddress` |
| Source workstation | `RemoteDeviceName` | `WorkstationName` |
| Outcome | `ActionType` (`LogonSuccess` / `LogonFailed`) | `EventCode` 4624 / 4625 |
| Failure reason | `FailureReason` | `Status`, `SubStatus` |
| Logon session | `LogonId` | `TargetLogonId` |
| Admin rights | `IsLocalAdmin` | Group membership lookup |

---

## 3. Investigation in Microsoft Defender XDR

**Investigate remote logons with Microsoft Defender XDR. Run KQL, confirm your tenant's schema and action names, then pivot to a device timeline and identity events.**

### 3.0 Confirm Schema and Action Names for Your Tenant

Table and action names can vary with schema versions and connected data sources. Verify before trusting a query that returns zero rows.

```kql
DeviceLogonEvents
| getschema
```

**What to look for:** Confirm that columns used later (`LogonType`, `RemoteIP`, `IsLocalAdmin`, `LogonId`) exist; a missing column means a later query must be adjusted.

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| summarize count() by ActionType, LogonType
```

**What to look for:** Confirm the exact `ActionType` and `LogonType` values (e.g. `RemoteInteractive`, `LogonSuccess`) before filtering on them; a value missing here explains a later query returning zero rows.

### 3.1 Remote Logon Successes (Core Query, Hardened)

Purpose: list successful RDP logons, with the source, so you can spot unfamiliar IPs and devices.

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType =~ "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, AccountDomain, AccountName, RemoteIP,
          RemoteIPType, RemoteDeviceName, LogonType, IsLocalAdmin, LogonId
| order by Timestamp desc
```

**What to look for:** the same account (`j.doe`) logging on to `WS-0137` from `203.0.113.24` / `WIN-ADMIN01` twice is a pattern to verify; a service account (`svc-backup`) doing RemoteInteractive logons is a red flag on its own.

### 3.2 New Source for This Account (First Seen in 30 Days)

Purpose: flag RDP sources that the account has never used before, matching the "new source device" signal.

```kql
let lookback = 30d;
let recent = 1d;
let baseline = DeviceLogonEvents
    | where Timestamp between (ago(lookback) .. ago(recent))
    | where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"
    | distinct AccountName, RemoteIP;
DeviceLogonEvents
| where Timestamp > ago(recent)
| where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"
| join kind=leftanti baseline on AccountName, RemoteIP
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteIPType, RemoteDeviceName
```

**What to look for:** Every row is a source the account has not used in the baseline window; a public `RemoteIPType` or unknown `RemoteDeviceName` is more suspicious than a new address from a known VPN pool.

### 3.3 Failed Then Successful Logons (Brute Force / Spraying)

Purpose: detect many failures from one source followed by a success, which indicates guessed credentials.

```kql
DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType in ("RemoteInteractive", "Network")
| where isnotempty(RemoteIP)
| summarize Failures = countif(ActionType == "LogonFailed"),
            Successes = countif(ActionType == "LogonSuccess"),
            Accounts = make_set(AccountName, 50),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by RemoteIP, DeviceName
| where Failures >= 10 and Successes > 0
| order by Failures desc
```

**What to look for:** Many failures then a success from one `RemoteIP` suggests guessed credentials, and many names in `Accounts` points to spraying; a few failures from a known admin host are usually typos.

### 3.4 Pivot: Device Timeline Around the Logon (Process Activity)

Purpose: see what ran on the host shortly after the logon (example: `powershell.exe` at 09:42, `tool.exe` downloaded at 09:45).

```kql
let device = "<DeviceName>";
let account = "<AccountName>";
let logonTime = datetime(<yyyy-MM-ddTHH:mm:ssZ>);
DeviceProcessEvents
| where Timestamp between (logonTime .. (logonTime + 2h))
| where DeviceName =~ device
| where AccountName =~ account
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, SHA256, ProcessIntegrityLevel
| order by Timestamp asc
```

**What to look for:** Recon (`whoami`, `net user`, `nltest`), encoded PowerShell, downloads, or remote access tools are suspicious; expected admin consoles and patching tools fit routine maintenance.

### 3.5 Files Written and Outbound Connections During the Session

Purpose: scope file drops and network activity (downloads, C2, exfiltration) in the session window.

```kql
let device = "<DeviceName>";
let logonTime = datetime(<yyyy-MM-ddTHH:mm:ssZ>);
union
( DeviceFileEvents
  | where Timestamp between (logonTime .. (logonTime + 2h))
  | where DeviceName =~ device
  | where ActionType in ("FileCreated", "FileRenamed")
  | where FolderPath has_any (@"\Users\", @"\Temp\", @"\ProgramData\")
  | project Timestamp, Source = "File", Detail = FolderPath, SHA256,
            InitiatingProcessFileName, FileOriginUrl ),
( DeviceNetworkEvents
  | where Timestamp between (logonTime .. (logonTime + 2h))
  | where DeviceName =~ device
  | where RemoteIPType == "Public"
  | project Timestamp, Source = "Network",
            Detail = strcat(RemoteIP, ":", RemotePort, " ", RemoteUrl),
            SHA256 = InitiatingProcessSHA256, InitiatingProcessFileName,
            FileOriginUrl = "" )
| order by Timestamp asc
```

**What to look for:** Executables or archives dropped in user, Temp, or ProgramData folders (especially with a `FileOriginUrl`) and connections to unfamiliar public IPs are suspicious; traffic to known update or vendor services is normal.

### 3.6 Privileged Changes: Local Group Additions and New Accounts

Purpose: catch the "privileged action" stage (example: user added to local Administrators at 09:46).

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<DeviceName>"
| where ActionType in ("UserAccountAddedToLocalGroup", "UserAccountCreated",
                       "UserAccountDeleted", "UserAccountModified")
| project Timestamp, DeviceName, ActionType, AccountName, AccountSid,
          InitiatingProcessAccountName, AdditionalFields
| order by Timestamp desc
```

**What to look for:** Accounts created or added to local groups during the remote session with no change ticket are a strong compromise signal; changes made by your provisioning tooling are normal.

### 3.7 Pivot: Identity Events for the Account

Purpose: see the account across devices and services (on-prem AD via Defender for Identity, and Entra ID sign-ins such as the Exchange Online sign-in at 10:02).

```kql
let upn = "<user@contoso.com>";
let sam = "<samAccountName>";
union
( IdentityLogonEvents
  | where Timestamp > ago(7d)
  | where AccountUpn =~ upn or AccountName =~ sam
  | project Timestamp, Source = "AD/Identity", ActionType, LogonType, Protocol,
            DeviceName, IPAddress, Application, FailureReason ),
( AADSignInEventsBeta
  | where Timestamp > ago(7d)
  | where AccountUpn =~ upn
  | project Timestamp, Source = "EntraID", ActionType = tostring(ErrorCode),
            LogonType = LogonType, Protocol = ClientAppUsed,
            DeviceName, IPAddress, Application, FailureReason = tostring(RiskLevelDuringSignIn) )
| order by Timestamp desc
```

**What to look for:** The same account authenticating from the suspicious IP elsewhere, touching many devices, or cloud sign-ins with elevated risk are suspicious; activity only from the user's usual devices and locations is normal.

Note: `AADSignInEventsBeta` requires Entra ID P2 licensing; in some tenants the equivalent data is in `EntraIdSignInEvents` or the Sentinel `SigninLogs` table. `ErrorCode` 0 means success.

In the portal, complete the pivots visually: **Devices > `<DeviceName>` > Timeline** and **Identities > `<user>` > Activity / Alerts / Risk**.

---

## 4. Investigation in Splunk

**Correlate remote sessions with activity. Use Splunk to link successful or failed remote logons, then pivot to process/service and VPN events for context.**

> Index, sourcetype, and field names vary per environment (Splunk Add-on for Microsoft Windows, Sysmon add-on, VPN vendor add-ons, CIM data models). Treat `index=wineventlog`, `index=sysmon`, `index=vpn` below as placeholders and confirm with `| metadata type=sourcetypes index=<index>`.

Reference event IDs:

| Source | EventCode | Meaning |
|---|---|---|
| Security | 4624 / 4625 | Logon success / failure (LogonType 10 = RDP) |
| Security | 4648 | Logon with explicit credentials |
| Security | 4672 | Special privileges assigned to new logon |
| Security | 4688 | Process creation (needs audit policy; command line needs extra GPO) |
| Security | 4720 / 4732 | User account created / member added to local group |
| Security | 4778 / 4779 | Session reconnected / disconnected (RDP) |
| System | 7045 / 7036 | Service installed / service state change |
| TerminalServices-LocalSessionManager/Operational | 21 / 24 / 25 | Session logon / disconnect / reconnect |
| TerminalServices-RemoteConnectionManager/Operational | 1149 | RDP network authentication succeeded |
| Sysmon | 1 / 3 / 11 | Process create / network connection / file create |

### 4.1 Successful and Failed Remote Logons (Core Query, Refined)

Purpose: summarize RDP outcomes per user and host with source IPs.

```spl
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
    (Logon_Type=10 OR LogonType=10)
| eval src=coalesce(IpAddress, Source_Network_Address, src_ip)
| stats count values(src) AS src_ips values(Logon_Type) AS logon_types
        min(_time) AS first_seen max(_time) AS last_seen
        by TargetUserName ComputerName EventCode
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

**What to look for:** Unfamiliar or external IPs in `src_ips`, service accounts in `TargetUserName`, or high 4625 counts are suspicious; named admins from known jump hosts are normal.

### 4.2 Failures Followed by Success from the Same Source

Purpose: identify brute force or password spraying that ended in a valid logon.

```spl
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
    (Logon_Type=10 OR Logon_Type=3)
| eval src=coalesce(IpAddress, Source_Network_Address)
| where isnotnull(src) AND src!="-" AND src!="127.0.0.1"
| stats count(eval(EventCode=4625)) AS failures count(eval(EventCode=4624)) AS successes
        dc(TargetUserName) AS users values(TargetUserName) AS accounts
        by src ComputerName
| where failures>=10 AND successes>0
| sort - failures
```

**What to look for:** A source with many failures and at least one success needs immediate review; a high `users` count indicates spraying across accounts.

### 4.3 First-Time Source for an Account

Purpose: surface the "new source device / unfamiliar source" condition.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10 earliest=-30d
| eval src=coalesce(IpAddress, Source_Network_Address)
| stats min(_time) AS first_seen max(_time) AS last_seen count by TargetUserName src WorkstationName
| where first_seen >= relative_time(now(), "-24h")
| convert ctime(first_seen) ctime(last_seen)
```

**What to look for:** Each row is a source first seen for that account in the last 24 hours; check it against travel, new devices, or VPN changes before calling it malicious.

### 4.4 Pivot: Process Events in the Session (4688 and Sysmon 1)

Purpose: list what the user executed after logon on the target host.

```spl
(index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688)
OR (index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
host="<ComputerName>" earliest="<MM/DD/YYYY:HH:MM:SS>" latest="<MM/DD/YYYY:HH:MM:SS>"
| eval user=coalesce(SubjectUserName, User), process=coalesce(New_Process_Name, Image),
       cmd=coalesce(Process_Command_Line, CommandLine), parent=coalesce(Creator_Process_Name, ParentImage)
| search user="*<username>*"
| table _time host user parent process cmd
| sort _time
```

**What to look for:** Recon commands, PowerShell with encoded or download arguments, and new remote tools are suspicious; routine admin tools matching the change ticket are normal.

### 4.5 Pivot: Services, Accounts, and Group Changes

Purpose: detect persistence and privilege escalation performed during the session.

```spl
(index=wineventlog sourcetype="WinEventLog:System" (EventCode=7045 OR EventCode=7036))
OR (index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732 OR EventCode=4728 OR EventCode=4672))
host="<ComputerName>" earliest=-24h
| table _time host EventCode SubjectUserName TargetUserName Service_Name Service_File_Name Group_Name Message
| sort _time
```

**What to look for:** New services (7045) with binaries in user or Temp paths, new accounts (4720), and group additions (4728/4732) during the session are suspicious; known agent installs during approved maintenance are normal.

Note: 7036 (service state change) is very noisy; focus on 7045 (new service) and correlate 7036 only for services named in it or tied to remote tools.

### 4.6 Pivot: VPN Logs and Correlation to RDP Source

Purpose: tie the RDP source (often an internal VPN pool address) back to the VPN user and real public IP.

```spl
index=vpn (action=success OR action=allowed OR signature="*connect*") user="<username>" earliest=-24h
| table _time user src_ip assigned_ip dest vendor_action signature
| sort _time
```

**What to look for:** A VPN session from the user's usual public IP is normal; an unfamiliar `src_ip` or no VPN session at all before the RDP logon is suspicious.

Then correlate:

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10 TargetUserName="<username>"
| eval assigned_ip=coalesce(IpAddress, Source_Network_Address)
| join type=left assigned_ip
    [ search index=vpn user=* assigned_ip=* | fields assigned_ip user src_ip
      | rename user AS vpn_user src_ip AS vpn_public_ip ]
| table _time ComputerName TargetUserName assigned_ip vpn_user vpn_public_ip
```

**What to look for:** If `vpn_user` differs from `TargetUserName`, someone is using another person's credentials over a VPN session.

### 4.7 Cloud Follow-Up: Entra ID / Microsoft 365 Sign-Ins

Purpose: check whether the same account and IP appear in cloud sign-ins (Splunk Add-on for Microsoft Cloud Services or Microsoft Azure add-on).

```spl
index=azure sourcetype="azure:aad:signin" (userPrincipalName="<user@contoso.com>" OR ipAddress="<IP>")
| table _time userPrincipalName ipAddress appDisplayName status.errorCode
        authenticationRequirement conditionalAccessStatus location.countryOrRegion riskLevelDuringSignIn
| sort - _time
```

**What to look for:** The suspicious IP also appearing in cloud sign-ins, single-factor sign-ins, or elevated risk levels are suspicious; `status.errorCode` 0 with MFA from a known location is normal.

---

## 5. Threat Intelligence Enrichment

**Check the source, not just its location. Enrich the source IP with context, validate it, and corroborate before taking action.**

Geolocation ("Tokyo, JP") is **not enough**. Attackers rent infrastructure anywhere, and legitimate users travel and use VPNs.

### What to Enrich

| Attribute | What it tells you | Example |
|---|---|---|
| ASN | Owner and type of network: ISP, hosting, cloud, corporate | AS2516 (ISP, owner, network) |
| Reputation | Malicious / Suspicious / Clean from multiple sources | Multiple vendors flag it for RDP brute force |
| Passive DNS | Known hostnames, historical resolutions, related domains | Resolves to a VPS hostname, linked to phishing domains |
| VPN / Proxy | VPN, proxy, Tor, cloud egress (anonymization) | Commercial VPN exit node |
| Hashes (from session) | Known malware or dual-use tool | `tool.exe` SHA256 on MalwareBazaar |
| Domains / URLs | Download source of tools | `FileOriginUrl` from DeviceFileEvents |

### Tools

| Tool | Use for |
|---|---|
| VirusTotal | IP, domain, URL, hash reputation; passive DNS; relations |
| AbuseIPDB | Crowd-sourced abuse reports (brute force, scanning) and confidence score |
| AlienVault OTX | Pulses linking IOCs to campaigns |
| URLScan.io | Safe rendering of URLs found in the session |
| MalwareBazaar | Hash lookup for malware samples |
| Shodan / Censys | What the source IP exposes (open RDP, proxy, C2 panels) |
| Microsoft Defender Threat Intelligence / Defender XDR IP page | Microsoft verdicts and prevalence in your tenant |

### Special Cases

- **`198.51.100.28` is documentation-only (RFC 5737, TEST-NET-2).** It should never appear in production traffic, and you should never block it as a "real" IOC. The same applies to `192.0.2.0/24` and `203.0.113.0/24` used in examples throughout this guide. If you see these in real logs, suspect spoofed or test data.
- **Internal addresses** (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are **not useful for public reputation**. Resolve them internally: DHCP, VPN pool assignments, CMDB, and the device's own logs.

### IOC Workflow

1. **Validate** - confirm the IOC is real and relevant (correct IP, not a NAT/proxy artifact, not a documentation range).
2. **Enrich** - add ASN, reputation, passive DNS, VPN/proxy context.
3. **Corroborate** - cross-check with other evidence: logs, EDR, alerts, related IOCs.

Rate each IOC on:

- **Confidence** - how likely it is truly malicious (High / Medium / Low).
- **Freshness** - how recent and still valid the intelligence is (age, last seen). IP reputation decays quickly; cloud IPs are recycled.

### Interpreting Verdicts

| Verdict | Meaning | Action |
|---|---|---|
| Malicious, multiple sources, recent | High confidence | Treat as TP indicator, block and scope |
| Suspicious / few detections | Medium | Corroborate with session behavior before acting |
| Clean / no data | Absence of evidence, not proof of safety | Rely on internal evidence |
| Hosting / VPN / Tor, no reports | Anonymization in use | Unusual for staff admin access; escalate if unapproved |

**Verify before action.**

---

## 6. Verdict: True Positive vs Benign

| Indicator | Points to true positive | Points to benign |
|---|---|---|
| Source IP | Hosting, VPN, Tor, bad reputation, never seen | Corporate egress, known vendor, user's home ISP seen before |
| Timing | Outside maintenance window, user off-shift | Matches change ticket window |
| Account | Service account doing interactive logon | Named admin with documented duty |
| MFA | Missing, bypassed, repeated denials then approval | Successful MFA with known device |
| Preceding failures | Many 4625 from same source | None or a single typo |
| VPN correlation | VPN user differs from RDP user, or no VPN session | VPN session from user's usual IP |
| Session activity | Recon commands, new admins, tool downloads, AV tampering, new services | Expected app maintenance, patching |
| Speed | Privileged action within minutes | Normal pace |
| Other hosts | Same account/IP touching many hosts | Single expected host |

### Common False Positives

- Admins working from a new laptop, hotel, or while travelling.
- Approved third-party vendors connecting via their own VPN or jump host.
- Change work running late, outside the documented window.
- IT using corporate VPN with a new egress or cloud-based SASE IP ranges.
- Monitoring, backup, or management tools using service accounts (should be type 3, not type 10; confirm).
- Jump hosts / bastions making every admin logon appear from the same "new" internal IP.

Document the evidence for a benign verdict (ticket number, user confirmation through a separate channel) and consider tuning.

### Common Beginner Mistakes

- Treating geolocation alone as proof of compromise (or of safety) without checking ASN, reputation, and history.
- Closing an alert because the logon "succeeded normally"; valid credentials are exactly what attackers use.
- Getting zero rows from a query and assuming nothing happened, without confirming schema and field names.
- Asking a possibly compromised user to confirm over email or Teams instead of an out-of-band channel.
- Blocking documentation-range or internal IPs as if they were real external IOCs.

---

## 7. Response Checklist

**Secure the session and account.** Tool roles: **Defender = Investigate, Splunk = Scope, TI = Enrich.**

Playbook order: (1) verify session and user, (2) scope commands / files / network activity, (3) if compromise confirmed: revoke sessions, disable account temporarily, isolate target where appropriate, (4) rotate credentials, review remote access policy, monitor.

### Verify and Scope (Steps 1-2)

- [ ] Contact the user or account owner through an out-of-band channel (phone, not email/Teams from the possibly compromised account).
- [ ] Check for an approved change ticket and maintenance window.
- [ ] Scope commands, files, and network activity with the queries in sections 3 and 4.
- [ ] Identify all hosts the account and source IP touched.

### Contain (Step 3, When Compromise Is Confirmed)

- [ ] Terminate active RDP sessions on the target (`query session` / `logoff <id>` or via Defender live response).
- [ ] Revoke sessions and refresh tokens in Entra ID (Revoke sessions on the user, or `Revoke-MgUserSignInSession`).
- [ ] Disable the account temporarily (AD and Entra ID); in Defender for Identity use "Disable user" action.
- [ ] Isolate the target device in Defender for Endpoint where appropriate (consider business impact for servers like `SRV-APP-01`; selective isolation may be an option).
- [ ] Block the malicious source IP at firewall / VPN / Conditional Access (never block documentation or internal IPs blindly).
- [ ] Mark the user as compromised in Entra ID Protection if applicable.

### Preserve Evidence

- [ ] Collect an investigation package from Defender for Endpoint before reimaging.
- [ ] Export relevant logs (Security, System, TerminalServices, Sysmon, VPN) and the Advanced Hunting results.
- [ ] Record timeline: auth, session start, privileged action, with times in UTC.
- [ ] Preserve hashes and copies of dropped tools; consider memory capture for high-severity cases.
- [ ] Keep chain-of-custody notes in the incident ticket.

### Eradicate

- [ ] Remove attacker-created accounts and revert group membership changes.
- [ ] Remove installed services, scheduled tasks, and remote access software added during the session.
- [ ] Delete dropped tools and run a full AV scan; reimage if integrity cannot be assured.
- [ ] Hunt the same IOCs (IP, hash, account) across all endpoints.

### Recover (Step 4)

- [ ] Rotate credentials for the account and any credentials present on the host (service accounts, local admin via LAPS).
- [ ] Reset Kerberos tickets if domain admin was involved (krbtgt rotation is a separate, deliberate decision).
- [ ] Re-enable the account only with enforced MFA and after the user confirms control.
- [ ] Review remote access policy: no direct internet RDP, RDP only via VPN/RD Gateway with MFA, Network Level Authentication, deny interactive logon for service accounts ("Deny log on through Remote Desktop Services").
- [ ] Release device isolation after validation.

### Monitor

- [ ] Add watchlists for the account, source IP, and ASN for 30 days.
- [ ] Create or tune detections: new RDP source per account, service account type 10 logons, failures-then-success.
- [ ] Monitor for re-entry via other remote services (VPN, Citrix, remote tools).
- [ ] Hold a lessons-learned review and update this playbook.

---

## 8. Quick Reference

### Cheat Sheet

| Question | Defender XDR | Splunk | Event IDs |
|---|---|---|---|
| Who logged on via RDP? | `DeviceLogonEvents` LogonType `RemoteInteractive` | `EventCode=4624 Logon_Type=10` | 4624, 1149, 21 |
| Failed attempts? | `ActionType == "LogonFailed"` | `EventCode=4625` | 4625 |
| What ran? | `DeviceProcessEvents` | 4688 / Sysmon 1 | 4688, Sysmon 1 |
| What was dropped? | `DeviceFileEvents` | Sysmon 11 | Sysmon 11 |
| Network connections? | `DeviceNetworkEvents` | Sysmon 3, firewall/proxy | Sysmon 3 |
| Privilege changes? | `DeviceEvents` (UserAccountAddedToLocalGroup) | 4720, 4728, 4732 | 4672, 4720, 4728, 4732 |
| Services? | `DeviceEvents` (ServiceInstalled) | `WinEventLog:System` 7045 | 7045, 7036 |
| Session reconnects? | `DeviceLogonEvents` | 4778 / 4779 | 4778, 4779, 24, 25 |
| Identity / cloud? | `IdentityLogonEvents`, `AADSignInEventsBeta` | `azure:aad:signin` | - |
| Source reputation? | Defender IP page | TI lookups | VirusTotal, AbuseIPDB, OTX |

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|---|---|
| [Windows Security Event Analysis](https://www.youtube.com/watch?v=aaAvlNgF2AU) | Reading and interpreting Windows Security event logs, such as logon events |
| [Decrypting RDP Traffic Using Wireshark](https://www.youtube.com/watch?v=Njvp4mlsx-E) | Decrypting and inspecting RDP network traffic in Wireshark |
| [Practical Linux Incident Response: Unauthorized User Access](https://www.youtube.com/watch?v=5ecU1JaEbtk) | Responding to unauthorized user access on a Linux host |
| [Multiple Suspicious Activities Involving a User: Incident Response](https://www.youtube.com/watch?v=OALd2kcjpjY) | Investigating several related suspicious activities tied to one user |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|---|---|
| [Windows Security Log Monitoring](https://app.haxcamp.com/lab/introduction-to-windows-security-monitoring) | Investigate Windows Security events with Event Viewer and Splunk |
| [Firewall Log Analysis](https://app.haxcamp.com/lab/firewall-log-analysis) | Read session logs, NAT translations and threat signatures |
| [IP Reputation Checker Using n8n](https://app.haxcamp.com/lab/ip-reputation-checker-using-n8n) | Automate IP reputation lookups with AbuseIPDB |
| [IP Geo-Location Enrichment Using n8n](https://app.haxcamp.com/lab/ip-geo-location-enrichment-using-n8n) | Enrich a suspicious IP with geographic and network context |
| [Introduction to Network Security](https://app.haxcamp.com/lab/introduction-to-network-security) | Firewall rulebases and telling contained threats from live ones |
| [Threat Hunting for Windows](https://app.haxcamp.com/lab/threat-hunting-for-windows) | Hunt for attacker activity on Windows endpoints |

### Official Documentation

- [MITRE ATT&CK T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK T1133 External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1219 Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [DeviceLogonEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
- [IdentityLogonEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table)
- [Advanced hunting overview](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [Take response actions on a device](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- [Event 4624: An account was successfully logged on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Event 4625: An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Splunk Add-on for Microsoft Windows](https://docs.splunk.com/Documentation/WindowsAddOn/latest/User/AbouttheSplunkAdd-onforWindows)
- [Splunk SPL search reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [RFC 5737 (documentation IPv4 ranges)](https://www.rfc-editor.org/rfc/rfc5737)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
