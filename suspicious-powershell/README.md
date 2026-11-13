# Suspicious PowerShell Execution: SOC Investigation Playbook

A practical Detect → Investigate → Respond workflow for PowerShell alerts, with Microsoft Defender XDR KQL, Splunk SPL, threat intel enrichment, and a response checklist.

> **Level:** Beginner to Intermediate · **Time:** ~45 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to decode and judge suspicious PowerShell command lines, how to rebuild the process and network chain in KQL and SPL, how to scope and contain a confirmed PowerShell compromise
>
> **Prerequisites:** basic Windows process and event log concepts, and basic KQL/SPL syntax

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

1. Copy the full command line from the alert and decode any `-EncodedCommand` value (never run it).
2. Check the parent process: Office, browser, `mshta.exe` or `wscript.exe` is suspicious; a known management agent is usually benign.
3. Note the user and device: interactive standard user, admin, service account or SYSTEM?
4. Look for an outbound connection from PowerShell within a minute or two of launch.
5. Check for child processes (`rundll32`, `regsvr32`, `certutil`) or files dropped in `%AppData%`, `%Temp%`, `%ProgramData%`.
6. Check the incident for related alerts on the same user, device or destination.

**Escalate immediately if:** the decoded command downloads or executes remote code, tampers with AMSI/Defender, or PowerShell launched from an Office or browser parent made a successful outbound connection.

---

## 1. What This Alert Means

A "Suspicious PowerShell Execution" alert fires when an EDR or SIEM rule sees `powershell.exe` (or `pwsh.exe`) launched in a way that matches attacker tradecraft rather than normal administration. Typical triggers:

- **Obfuscation / hiding flags**: `-EncodedCommand` (`-enc`, `-e`), `-WindowStyle Hidden` (`-w hidden`), `-NoProfile` (`-nop`), `-NonInteractive`, `-ExecutionPolicy Bypass` (`-ep bypass`).
- **Download cradles**: `IEX (New-Object Net.WebClient).DownloadString(...)`, `Invoke-WebRequest`, `iwr`, `Start-BitsTransfer`, `[System.Net.WebClient]`.
- **Unusual parent process**: Office apps (`outlook.exe`, `winword.exe`, `excel.exe`), browsers, `wmiprvse.exe`, `mshta.exe`, `wscript.exe`/`cscript.exe`.
- **Suspicious follow-on children**: `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `schtasks.exe`, `net.exe`, `whoami.exe`.
- **AMSI / logging tampering**: strings like `AmsiUtils`, `amsiInitFailed`, `Set-MpPreference -DisableRealtimeMonitoring`.

**Why attackers use it:** PowerShell is signed, installed everywhere, runs code in memory (fileless), has full .NET and network access, and blends with admin activity. It is the go-to stage-2 loader after phishing (typical scenario: email opened → PowerShell launched → outbound connection).

### Example Scenario

| Time  | Event | Meaning |
|-------|-------|---------|
| 09:14 | Email opened in Outlook | Likely initial access via attachment or link |
| 09:15 | `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ...` with parent `outlook.exe` | Execution, hidden and obfuscated |
| 09:16 | Outbound connection observed | Payload download or C2 beacon |

Status at this point: **suspicious, not confirmed**. Your job is to prove or disprove it.

### MITRE ATT&CK Mapping

| Technique ID | Name | Where it shows up |
|--------------|------|-------------------|
| T1566.001 | Phishing: Spearphishing Attachment | Email opened, Office parent |
| T1566.002 | Phishing: Spearphishing Link | User clicked URL that launched script |
| T1204.002 | User Execution: Malicious File | User opened the attachment |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Core technique |
| T1027 | Obfuscated Files or Information | Encoded / obfuscated commands |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | String concatenation, tick marks, char codes |
| T1140 | Deobfuscate/Decode Files or Information | Base64 decode at runtime |
| T1564.003 | Hide Artifacts: Hidden Window | `-WindowStyle Hidden` |
| T1105 | Ingress Tool Transfer | Download cradle pulls payload |
| T1218.011 | System Binary Proxy Execution: Rundll32 | `rundll32.exe` child |
| T1562.001 | Impair Defenses: Disable or Modify Tools | AMSI bypass, Defender exclusions |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/S C2 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence |

### Key Terms

| Term | Meaning |
|------|---------|
| EncodedCommand | A PowerShell flag that accepts the script as Base64 text (UTF-16LE), often used to hide what the command does. |
| Download cradle | A one-line command that fetches code from the internet and runs it, usually in memory. |
| Fileless | Malicious code that runs in memory without writing an obvious executable to disk. |
| AMSI | Antimalware Scan Interface, the Windows feature that lets antivirus inspect scripts before they run; attackers try to disable it. |
| Script Block Logging | PowerShell logging (Event ID 4104) that records the code actually executed, after deobfuscation. |
| Parent process | The process that launched another process; an unusual parent is a strong suspicion signal. |
| LOLBin | "Living off the land" binary: a legitimate Windows tool such as `rundll32.exe` or `certutil.exe` abused by attackers. |
| C2 | Command and control: the attacker's server that infected machines contact for instructions. |

---

## 2. Alert Triage

Analyst checklist:

- [ ] **Preserve the full command line.** Copy it from the alert before anything rolls off. Decode `-EncodedCommand` (Base64 of UTF-16LE): in PowerShell `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<b64>'))`, or CyberChef "From Base64" → "Decode text (UTF-16LE)". Never run the decoded script.
- [ ] **Confirm parent process and user.** Is the parent an Office app, browser, script host, or a known management agent (SCCM, Intune, RMM)? Is the user interactive, a service account, or SYSTEM?
- [ ] **Check script block / PowerShell logs.** Event ID 4104 (Script Block Logging) shows deobfuscated code; 4103 (Module Logging); 400/600 in the classic Windows PowerShell log show host start and engine version (look for `HostVersion=2.0` downgrade).
- [ ] **Review destination IP and related alerts.** What did the process connect to right after launch? Are there other alerts on the same device, user, or destination in the incident?

Additional triage questions:

- [ ] Was there a preceding email/URL click for this user in the last hour?
- [ ] Did PowerShell spawn children (`rundll32`, `regsvr32`, `cmd`) or write files to `%AppData%`, `%Temp%`, `%ProgramData%`?
- [ ] Is this the first time this parent/child/command pattern is seen in the environment?
- [ ] Did Defender AV/AMSI block or detect anything at the same time?

### Key Fields to Collect

| Field | Example | Why it matters |
|-------|-------------------------|----------------|
| Device | WIN-10-01 | Scope, isolation target |
| User / account | jdoe | Credential exposure, mailbox pivot |
| Process | powershell.exe | Confirm binary path is `System32\WindowsPowerShell\v1.0` |
| Parent process | outlook.exe | Primary suspicion driver |
| Full command line | `-NoProfile -WindowStyle Hidden -EncodedCommand ...` | Decode for intent |
| Process SHA256 | of child payloads | Enrichment, hunting |
| Timestamps | 09:14 / 09:15 / 09:16 | Build timeline |
| Remote IP / URL / domain | outbound connection | C2 identification |
| Files created | DLLs, scripts in user profile | Payload and persistence |
| Email metadata | Sender, subject, NetworkMessageId | Find other recipients |
| Related alerts / incident ID | | Correlate and avoid duplicate work |

---

## 3. Investigation in Microsoft Defender XDR

Run in **Microsoft Defender portal → Hunting → Advanced hunting**. Replace placeholders such as `<DeviceName>`, `<AccountName>`, `<RemoteIP>`. Adjust the time window to cover at least 1 hour before the first alert.

### 3.1 PowerShell Executions With Suspicious Flags (Core Query, Extended)

Purpose: list PowerShell launches with the parent, user, and command line, highlighting encoded, hidden, or download-cradle usage.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-w hidden", "-WindowStyle Hidden",
        "-nop", "bypass", "DownloadString", "DownloadFile", "Invoke-WebRequest", "iwr", "IEX", "FromBase64String")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ProcessCommandLine, SHA256, ProcessId
| order by Timestamp desc
```

**What to look for:** Encoded, hidden or download-cradle flags combined with an Office, browser or script-host parent are suspicious; the same flags from a known management agent path are usually benign.

### 3.2 Office or Browser Spawning PowerShell

Purpose: catch the common phishing pattern (`outlook.exe → powershell.exe`) across all devices.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe")
| where InitiatingProcessFileName in~ ("outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe",
        "msedge.exe", "chrome.exe", "firefox.exe")
| summarize Count = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Commands = make_set(ProcessCommandLine, 10)
            by DeviceName, AccountName, InitiatingProcessFileName, FileName
| order by LastSeen desc
```

**What to look for:** Office or browser processes launching a script interpreter are rare in most environments; a low count on a single device with hidden or encoded commands deserves investigation.

### 3.3 Full Process Tree on the Device (Children of PowerShell)

Purpose: reconstruct the chain `outlook.exe → powershell.exe → rundll32.exe` and see what ran next.

```kql
let device = "<DeviceName>";
let start = datetime(<YYYY-MM-DD HH:MM>) - 30m;
let stop  = datetime(<YYYY-MM-DD HH:MM>) + 2h;
DeviceProcessEvents
| where DeviceName =~ device and Timestamp between (start .. stop)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe")
     or FileName in~ ("powershell.exe", "pwsh.exe")
| project Timestamp, InitiatingProcessParentFileName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, FolderPath, SHA256, AccountName
| order by Timestamp asc
```

**What to look for:** Children such as `rundll32`, `regsvr32`, `certutil` or recon commands (`whoami`, `net`) after PowerShell suggest a live intrusion; binaries running from user-writable folders are a red flag.

### 3.4 Network Connections Made by PowerShell

Purpose: identify the 09:16 outbound destination and any C2 beaconing.

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName =~ "<DeviceName>"
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "rundll32.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl, ActionType
| order by Timestamp asc
```

**What to look for:** Connections to raw IPs, newly seen domains or hosting providers seconds after launch are suspicious; repeated connections at regular intervals suggest C2 beaconing.

### 3.5 Files Dropped by PowerShell and Decoded Script Content

Purpose: find payloads written to disk and, where available, AMSI/script content captured by Defender.

```kql
union
( DeviceFileEvents
  | where Timestamp > ago(24h) and DeviceName =~ "<DeviceName>"
  | where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
  | where ActionType in ("FileCreated", "FileModified")
  | project Timestamp, Source = "File", ActionType, Detail = FolderPath, SHA256 ),
( DeviceEvents
  | where Timestamp > ago(24h) and DeviceName =~ "<DeviceName>"
  | where ActionType == "PowerShellCommand"
  | project Timestamp, Source = "PSCommand", ActionType,
            Detail = tostring(parse_json(AdditionalFields).Command), SHA256 = "" )
| order by Timestamp asc
```

**What to look for:** DLLs, EXEs or scripts written to `%AppData%`, `%Temp%` or `%ProgramData%` are suspicious; commands such as `Invoke-Expression` or `DownloadString` in the PSCommand rows confirm script intent.

### 3.6 Email That Preceded the Execution

Purpose: tie the alert to the delivering message and find every other recipient.

```kql
let user = "<UserPrincipalName>";
EmailEvents
| where Timestamp > ago(2d)
| where RecipientEmailAddress =~ user
| join kind=leftouter (EmailAttachmentInfo | project NetworkMessageId, FileName, SHA256) on NetworkMessageId
| join kind=leftouter (UrlClickEvents | project NetworkMessageId, Url, ClickTime = Timestamp, ActionType) on NetworkMessageId
| project Timestamp, SenderFromAddress, Subject, DeliveryAction, ThreatTypes,
          FileName, SHA256, Url, ClickTime, NetworkMessageId
| order by Timestamp desc
```

**What to look for:** A message with an attachment or clicked URL shortly before the PowerShell launch is the likely delivery vector; note its NetworkMessageId and sender for scoping.

Then find other recipients of the same campaign:

```kql
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "<SenderAddress>" or Subject == "<Subject>"
| summarize Recipients = make_set(RecipientEmailAddress), Count = count() by SenderFromAddress, Subject
```

**What to look for:** Many internal recipients of the same external sender or subject indicates a campaign; check every recipient for the same execution pattern.

### 3.7 Account Activity After Execution (Credential Exposure)

Purpose: check whether the user's credentials were used elsewhere (lateral movement or cloud sign-ins).

```kql
let user = "<AccountName>";
DeviceLogonEvents
| where Timestamp > ago(24h)
| where AccountName =~ user
| summarize Logons = count(), Devices = make_set(DeviceName), LogonTypes = make_set(LogonType),
            RemoteIPs = make_set(RemoteIP) by ActionType
```

**What to look for:** New devices, remote logon types or unfamiliar RemoteIPs after the alert time suggest stolen credentials; logons only to the user's own workstation are normal.

Analyst guidance: always check parent process, command line, user, device, and timestamp together. If confirmed, **isolate the device, collect an investigation package, and review related alerts** in the incident.

---

## 4. Investigation in Splunk

> Index and sourcetype names vary per environment. Examples assume `index=wineventlog` / `index=sysmon` with the Splunk Add-on for Microsoft Windows and Sysmon add-on. Field names below are those extracted by those add-ons; if you use the CIM `Endpoint.Processes` data model, map to `process_name`, `parent_process_name`, `process`, `user`, `dest`.

Note on the Security log query: `EventCode=4688` only includes the command line if "Include command line in process creation events" is enabled via GPO. In the native Security log the fields are `New_Process_Name`, `Creator_Process_Name`, and `Process_Command_Line`, so `process_name` and `parent_process` work only with CIM normalization.

### 4.1 PowerShell Process Creation by Host and User (Security Log)

Purpose: count PowerShell launches and their parents per host and user.

```spl
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4688
    (New_Process_Name="*\\powershell.exe" OR New_Process_Name="*\\pwsh.exe")
| stats count values(Creator_Process_Name) AS parent_process values(Process_Command_Line) AS cmd by host, Account_Name
| sort - count
```

**What to look for:** PowerShell launched by `WINWORD.EXE`, `OUTLOOK.EXE` or a browser is suspicious; launches by `explorer.exe` or known management agents are usually normal.

### 4.2 Sysmon: Suspicious PowerShell Flags and Office Parents

Purpose: higher-fidelity process creation (Sysmon Event ID 1) with hashes and parent command line.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
    (CommandLine="*-enc*" OR CommandLine="*hidden*" OR CommandLine="*DownloadString*"
     OR CommandLine="*IEX*" OR CommandLine="*bypass*"
     OR ParentImage="*\\outlook.exe" OR ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe")
| table _time host User ParentImage ParentCommandLine Image CommandLine Hashes ProcessGuid
| sort _time
```

**What to look for:** Office parents or encoded/hidden flags are high-signal; use `Hashes` and `ProcessGuid` to pivot to child processes and network events.

### 4.3 Script Block Logging (Event ID 4104)

Purpose: read the decoded script content and catch download cradles or AMSI bypasses.

```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    host="<host>"
| search ScriptBlockText="*DownloadString*" OR ScriptBlockText="*FromBase64String*"
     OR ScriptBlockText="*Invoke-Expression*" OR ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*Net.WebClient*"
| table _time host ScriptBlockId Path ScriptBlockText
| sort _time
```

**What to look for:** Download cradles, `AmsiUtils` references or heavy Base64 decoding in script blocks are strongly suspicious; signed admin module code with readable function names is usually benign.

### 4.4 Network Connections From PowerShell (Sysmon Event ID 3)

Purpose: find outbound destinations (the 09:16 connection) and other hosts talking to them.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
    (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\rundll32.exe")
| stats count min(_time) AS first_seen max(_time) AS last_seen values(DestinationPort) AS ports
        values(DestinationHostname) AS dest_hosts by host User Image DestinationIp
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

**What to look for:** Public destinations contacted by PowerShell or `rundll32` with no business purpose are suspicious; a high count over a long span may indicate beaconing.

### 4.5 Spread: Same Destination Across Proxy/Firewall Logs

Purpose: identify every host that contacted the suspicious IP or domain (scope).

```spl
(index=proxy OR index=firewall) (dest_ip="<RemoteIP>" OR url="*<domain>*" OR dest="<domain>")
| stats count min(_time) AS first_seen max(_time) AS last_seen values(user) AS users
        values(action) AS actions by src_ip
| convert ctime(first_seen) ctime(last_seen)
| sort first_seen
```

**What to look for:** Each `src_ip` is a potentially affected host; allowed (not blocked) actions mean the connection likely succeeded.

### 4.6 Pivot on User: Logons After Execution

Purpose: pivot on host and user to find related logons, looking for new logon types or hosts.

```spl
index=wineventlog sourcetype="XmlWinEventLog:Security" (EventCode=4624 OR EventCode=4625 OR EventCode=4648)
    Account_Name="<user>"
| stats count values(Logon_Type) AS logon_types values(Source_Network_Address) AS src_ips by host EventCode
| sort - count
```

**What to look for:** Failed logons (4625), explicit-credential use (4648) or logons on unfamiliar hosts after the alert suggest credential misuse; routine interactive logons on the user's own machine are normal.

### 4.7 Persistence Created Around the Alert Time

Purpose: catch scheduled tasks (4698), new services (7045), and Run-key writes (Sysmon 13).

```spl
(index=wineventlog (EventCode=4698 OR EventCode=7045)) OR
(index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*")
    host="<host>"
| table _time host EventCode Task_Name Service_Name ImagePath TargetObject Details
| sort _time
```

**What to look for:** Tasks, services or Run keys pointing to PowerShell, scripts or binaries in user-writable folders are likely persistence; entries created by known installers are usually benign.

Key point: **validate the time window and data model before treating missing results as absence of activity.** Confirm the relevant logs are actually collected for that host (e.g. `| tstats count where index=* host="<host>" by sourcetype`) before concluding "nothing happened".

---

## 5. Threat Intelligence Enrichment

Approach: "Enrich indicators. Keep context." Follow the IOC lifecycle: **Extract → Enrich → Validate → Hunt → Respond.**

### What to Extract

- Decoded script: URLs, domains, IPs, file paths, user agents.
- File hashes (SHA256) of PowerShell children and dropped files.
- Remote IPs/domains from network events.
- Email sender, sending IP, attachment hashes, URLs.

### Where to Enrich

| Indicator | Sources | What to look at |
|-----------|---------|-----------------|
| File hash | VirusTotal, MalwareBazaar, Defender file page (prevalence) | Detection ratio, family name, first seen, sandbox behaviour, internal prevalence |
| IP | AbuseIPDB, VirusTotal, AlienVault OTX, WHOIS/ASN | Abuse score, ASN (hosting vs ISP), recent reports, geolocation |
| Domain | VirusTotal, URLScan, passive DNS, WHOIS | Domain age, registrar, resolution history, categorization |
| URL | URLScan.io, VirusTotal | Screenshot, redirects, final payload, phishing kit indicators |

Do not upload sensitive internal files to public sandboxes; prefer hash lookups and an internal sandbox.

### Reading Verdicts

| Example indicator | Enrichment | Confidence | Analyst action |
|-------------------|------------|------------|----------------|
| `suspicious-login.example` | Passive DNS + URL reputation | Medium | Search proxy/DNS logs for other hosts |
| `203.0.113.44` | IP reputation + ASN | Low | Documentation-only TEST-NET range (RFC 5737); do not block |
| `a3f5...9c21` (hash) | Malware sandbox + internal prevalence | High | Hunt endpoints; quarantine only if corroborated |

- **Malicious, multiple reputable vendors, recent**: strong supporting evidence; hunt and block.
- **Clean / unknown**: not proof of safety; new infrastructure is often unrated. Rely on behaviour.
- **Shared hosting / CDN IP**: blocking may cause business impact; block the domain/URL instead.

Analyst guidance: check **source, last-seen time, confidence, and whether the indicator appears in your environment**. An IOC hit alone is not proof of compromise.

---

## 6. Verdict: True Positive vs Benign

| Indicator | Leans true positive | Leans benign |
|-----------|---------------------|--------------|
| Parent process | Office app, browser, `mshta`, `wscript` | SCCM/Intune agent, RMM tool, `explorer.exe` by IT admin |
| Command line | Encoded + hidden + download cradle | Signed script path, readable command |
| User | Standard user, unusual hours | Known admin or service account doing documented task |
| Network | New/rare domain, raw IP, hosting ASN | Microsoft, internal repo, known vendor update URL |
| Children | `rundll32`, `regsvr32`, `certutil`, recon commands | None or expected tooling |
| Files | DLL/EXE/script in `%AppData%`, `%Temp%` | Logs or config in expected paths |
| Prevalence | Single host, first seen | Many hosts, long history |
| Script block (4104) | AMSI bypass, reflection, shellcode loaders | Admin module functions |

### Common False Positives

- Endpoint management (SCCM/ConfigMgr, Intune Management Extension, Tanium, RMM tools) using `-ExecutionPolicy Bypass` or encoded commands.
- Software installers and updaters, Chocolatey/winget wrappers.
- Security tools and vulnerability scanners.
- Login scripts and GPO scripts.
- Developer tooling (VS Code, build pipelines).
- Office add-ins that legitimately invoke PowerShell (rare; verify vendor and signature).

Tune with exclusions on **parent path + signer + command pattern**, never on `powershell.exe` alone.

### Common Beginner Mistakes

- Closing the alert because the IP or hash is "clean" on VirusTotal; new attacker infrastructure is often unrated.
- Running the decoded script in a live PowerShell session instead of only reading it.
- Excluding `powershell.exe` entirely to reduce noise, which blinds the detection.
- Treating empty search results as proof of no activity without confirming the logs (4104, Sysmon, 4688 command line) are collected for that host.
- Forgetting to scope beyond the alerting device: other recipients of the same email may also have run the payload.

---

## 7. Response Checklist

Flow: Validate → Scope → Contain → Recover and improve.

### Validate

- [ ] Confirm process chain, command line, user, and device timeline.
- [ ] Decode the command and review 4104 script block content.
- [ ] Confirm whether the outbound connection succeeded and whether a payload executed.

### Scope

- [ ] Hunt for the same command, hash, account, or destination across endpoints and SIEM (queries 3.2, 3.4, 4.5).
- [ ] Find all recipients of the phishing email and who clicked or opened it.
- [ ] Check other alerts for the user and device in the last 7 days.

### Contain (If Confirmed Malicious)

- [ ] Isolate the device in Defender for Endpoint (full or selective isolation).
- [ ] Disable or reset the affected user's credentials; revoke sessions and refresh tokens in Entra ID.
- [ ] Block hashes, domains, URLs, and IPs (Defender indicators, proxy, firewall, email).
- [ ] Soft-delete or purge the phishing email from all mailboxes.
- [ ] Restrict app execution if the payload is still running.

### Preserve Evidence

- [ ] Collect the Defender investigation package before remediation.
- [ ] Export the alert, process tree, decoded script, and query results to the case.
- [ ] Capture memory if fileless activity or in-memory payloads are suspected.
- [ ] Preserve the original email (.eml) and attachment hash.
- [ ] Record a UTC timeline of all actions taken.

### Eradicate

- [ ] Remove persistence: scheduled tasks, services, Run keys, WMI subscriptions, startup folder items.
- [ ] Delete or quarantine dropped payloads; run a full AV scan.
- [ ] Remove any Defender exclusions the attacker added and revert any tampered settings.
- [ ] Reimage if integrity of the host cannot be guaranteed.

### Recover

- [ ] Release device from isolation only after validation scans are clean.
- [ ] Restore user access with a new password and MFA re-registration if needed.
- [ ] Confirm business applications work normally.

### Monitor and Improve

- [ ] Watch the device, user, and IOCs for 7-14 days.
- [ ] Tune the detection (add exclusions for confirmed benign tools only).
- [ ] Enable/verify Script Block Logging, Module Logging, AMSI, and command-line auditing for 4688.
- [ ] Consider ASR rules: "Block all Office applications from creating child processes" and "Block execution of potentially obfuscated scripts".
- [ ] Consider Constrained Language Mode / WDAC for standard users.
- [ ] Document lessons learned and update this playbook.

---

## 8. Quick Reference

### Cheat Sheet

| Need | Defender XDR (KQL) | Splunk (SPL / Event ID) |
|------|--------------------|-------------------------|
| PowerShell process launches | `DeviceProcessEvents` where `FileName in~ ("powershell.exe","pwsh.exe")` | Security 4688, Sysmon 1 |
| Decoded script content | `DeviceEvents` `ActionType == "PowerShellCommand"` | PowerShell/Operational 4104 |
| Network connections | `DeviceNetworkEvents` | Sysmon 3, proxy, firewall |
| Files dropped | `DeviceFileEvents` | Sysmon 11 |
| Registry persistence | `DeviceRegistryEvents` | Sysmon 13 |
| Scheduled tasks / services | `DeviceEvents` (`ScheduledTaskCreated`), `DeviceProcessEvents` (`schtasks.exe`) | 4698, 7045 |
| Logons | `DeviceLogonEvents`, `IdentityLogonEvents` | 4624, 4625, 4648 |
| Phishing source | `EmailEvents`, `EmailAttachmentInfo`, `UrlClickEvents` | O365 message trace / mail gateway logs |
| Decode `-enc` | `base64_decode_tostring()` (note UTF-16LE) | CyberChef / PowerShell `[Text.Encoding]::Unicode` |

Key flags to watch: `-enc`, `-e`, `-w hidden`, `-nop`, `-ep bypass`, `-noni`, `IEX`, `DownloadString`, `FromBase64String`, `-version 2`.

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|-------|----------------|
| [SOC Stories: Suspicious PowerShell Alert](https://www.youtube.com/watch?v=LNI8SnlJv0s) | A walkthrough of handling a suspicious PowerShell alert from an analyst's perspective. |
| [Log Analysis Basics: Windows PowerShell Logs](https://www.youtube.com/watch?v=u-lzvHJvte4) | Fundamentals of reading Windows PowerShell logs. |
| [Incident Response Series: Possible LOLBins](https://www.youtube.com/watch?v=UYeSOTQ0ziY) | Responding to possible abuse of living-off-the-land binaries. |
| [Windows Security Monitoring Crash Course](https://www.youtube.com/watch?v=a_PzlNyWzjo) | An introduction to monitoring Windows security events. |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|-----|------------------------|
| [PowerShell Operational Log](https://app.haxcamp.com/lab/powershell-operational-log) | Investigate PowerShell activity and obfuscated commands with Event Viewer and Splunk |
| [Sysmon Log](https://app.haxcamp.com/lab/sysmon-log) | Detect suspicious process creation with Sysmon |
| [Windows Security Log Monitoring](https://app.haxcamp.com/lab/introduction-to-windows-security-monitoring) | Investigate Windows Security events with Event Viewer and Splunk |
| [Ransomware Pre-Encryption Detection Using Splunk](https://app.haxcamp.com/lab/ransomware-pre-encryption-detection-using-splunk) | Correlate Windows, PowerShell and file-share logs to stop ransomware early |
| [Threat Hunting for Windows](https://app.haxcamp.com/lab/threat-hunting-for-windows) | Hunt for attacker activity on Windows endpoints |

### Official Documentation

- [MITRE ATT&CK T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Microsoft: Advanced Hunting Overview](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [Microsoft: Advanced Hunting Schema Tables](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Microsoft: about_Logging_Windows (Script Block Logging)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Microsoft: Attack Surface Reduction Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft: Take Response Actions on a Device](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- [Splunk: Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Splunk: CIM Endpoint Data Model](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
