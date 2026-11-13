# Suspicious Office Child Process - SOC Investigation Playbook

A practical Detect → Investigate → Respond guide for alerts where Word, Excel, Outlook or another Office app launches a shell, script host or LOLBin.

> **Level:** Beginner to Intermediate · **Time:** ~50 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to rebuild an Office-to-shell process tree, how to decode and judge suspicious command lines, how to scope and contain a macro-based phishing infection
>
> **Prerequisites:** basic Windows process concepts, Windows/Sysmon event logs and KQL/SPL syntax

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

1. Confirm the parent is a genuine Office binary (`winword.exe`, `excel.exe`, `outlook.exe`...) running from `Program Files`.
2. Identify the child process and read its full command line; flag `-enc`, `-w hidden`, `IEX`, URLs or Base64 blobs.
3. Find the document that triggered it (parent command line) and where it came from (email, web download, share).
4. Check for follow-on activity within minutes: outbound connections, dropped `.dll`/`.exe`/scripts, grandchild processes.
5. Look up the hashes and any destination domain/IP in threat intelligence.
6. Ask whether the user or a known business macro/add-in explains the behavior.
7. Check whether other hosts or users show the same pattern (campaign).

**Escalate immediately if:** the child runs an encoded or download command, connects to a public IP/rare domain, drops an unsigned payload, or the same lure is seen on multiple hosts.

---

## 1. What This Alert Means

**"Office launched PowerShell? Start here."**

The alert fires when an Office process (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `msaccess.exe`, `mspub.exe`, `onenote.exe`) is the **parent** of a process that Office normally has no reason to start, such as:

| Child process | Why attackers use it |
|---|---|
| `powershell.exe` / `pwsh.exe` | Download-and-execute, in-memory loaders, encoded payloads |
| `cmd.exe` | Chaining commands (`whoami`, `certutil`, `bitsadmin`) |
| `wscript.exe` / `cscript.exe` | Running dropped `.vbs` / `.js` / `.jse` payloads |
| `mshta.exe` | Executing remote or local `.hta` content |
| `rundll32.exe` / `regsvr32.exe` | Loading a dropped DLL (common for IcedID, Qakbot-style loaders) |
| `certutil.exe` / `bitsadmin.exe` / `curl.exe` | Downloading the next stage |
| `schtasks.exe` / `reg.exe` | Establishing persistence |

**Typical attack chain**

1. User receives a phishing email with an attachment or link (Word/Excel document, sometimes inside a ZIP, ISO or OneNote file).
2. User opens the file and enables content (macro), or the document abuses a vulnerability or embedded object.
3. VBA/XLM macro or exploit spawns a shell with an obfuscated command line (`-nop -w hidden -enc ...`).
4. The shell downloads a second stage (DLL/EXE/script), runs it (often via `rundll32.exe`), and the payload beacons out to C2.

**Why attackers do it:** Office documents are trusted and delivered easily by email; macros give code execution as the user; using built-in binaries (LOLBins) blends in with normal Windows activity and avoids dropping obvious malware first.

### MITRE ATT&CK Mapping

| Tactic | Technique | Name |
|---|---|---|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment |
| Initial Access | T1566.002 | Phishing: Spearphishing Link |
| Execution | T1204.002 | User Execution: Malicious File |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic |
| Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information |
| Defense Evasion | T1218.005 | System Binary Proxy Execution: Mshta |
| Defense Evasion | T1218.011 | System Binary Proxy Execution: Rundll32 |
| Command and Control | T1105 | Ingress Tool Transfer |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| Persistence | T1137 | Office Application Startup |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task |

### Key Terms

| Term | Meaning |
|---|---|
| Parent / child process | The process that starts another process is the parent; the one it starts is the child. |
| LOLBin | "Living off the land" binary: a legitimate built-in Windows tool (like `rundll32.exe` or `certutil.exe`) that attackers abuse to avoid dropping obvious malware. |
| Macro (VBA/XLM) | Code embedded in an Office document that can run commands when the user enables content. |
| Encoded command | A PowerShell command passed as Base64 text (`-EncodedCommand`) so its real content is hidden at a glance. |
| Mark-of-the-Web (MOTW) | A tag Windows adds to files downloaded from the internet, recording where they came from. |
| C2 (Command and Control) | The attacker's server that infected machines contact for instructions or further payloads. |
| ASR rule | An Attack Surface Reduction rule in Microsoft Defender that blocks risky behaviors such as Office creating child processes. |
| Prevalence | How many machines in your organization (or globally) have seen a file; low prevalence is a warning sign. |

---

## 2. Alert Triage

**"What made the process chain unusual?"**

Office apps rarely need to spawn shells. That is unusual and worth a closer look, but **unusual is not the same as malicious**. Treat the alert as *suspicious (not confirmed)* until context says otherwise.

Example:

```text
winword.exe -> powershell.exe -> rundll32.exe
User: jdoe   Host: WS-2847
Command line: powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand QAB...

10:24:03  Document opened (WinWord)
10:24:16  Shell spawned (PowerShell)        <- 13 s after open: macro on open
10:24:41  Outbound connection (egress)      <- 25 s later: likely second-stage download
```

### Analyst Checks

- [ ] **Parent process** - who started it? Is the parent really the signed Office binary from `C:\Program Files\Microsoft Office\...`? What started the Office process (explorer.exe after a user double-click, outlook.exe opening an attachment)?
- [ ] **Signed status** - is the parent a trusted, Microsoft-signed build? Is the child the genuine system binary from `System32`/`SysWOW64`, or a renamed copy?
- [ ] **Command line** - what is it doing? Look for `-enc`/`-EncodedCommand`, `-w hidden`, `-nop`, `IEX`, `DownloadString`, `Invoke-WebRequest`, `FromBase64String`, `http(s)://`, `certutil -urlcache`, `\AppData\`, `\Temp\`, `\Public\`.
- [ ] **File origin** - where did the document come from? Email attachment, web download (Mark-of-the-Web / `FileOriginUrl`), USB, file share, Teams/SharePoint?
- [ ] **User intent** - was it expected? Does the user run approved macros/add-ins for their job? Did they report opening an unexpected invoice/CV/shipping notice?
- [ ] **Follow-on activity** - any network connection, file writes, grandchild processes, persistence, or logons from this host after the spawn?
- [ ] **Scope** - is this one host or the same pattern on many hosts/users at once (campaign)?

### Key Fields to Collect

| Field | Example | Why it matters |
|---|---|---|
| Timestamp (UTC) | 10:24:16 | Anchor for the timeline |
| Device name / ID | WS-2847 | Pivot for all host queries |
| User / UPN | jdoe | Pivot for email, sign-ins, other hosts |
| Parent process + path + command line | winword.exe `"...\Invoice_4471.docm"` | Reveals the triggering document |
| Child process + path | powershell.exe | Shell type and location |
| Child command line (decoded) | `IEX (New-Object Net.WebClient)...` | Intent of the activity |
| SHA-256 of child, grandchild, and document | 9f64a7...b2e5 | TI lookups and fleet prevalence |
| Signer / certificate status | Microsoft Corporation / Unsigned | Trust of binary |
| Document origin | Email sender, URL, share path | Initial access vector |
| Remote IP / domain / port | 192.0.2.123:443 | C2 or download infra |
| Files created by the chain | `C:\Users\Public\x.dll` | Payloads to collect and block |
| Integrity level / token elevation | Medium | Privilege of the attacker |

---

## 3. Investigation in Microsoft Defender XDR

**"Trace the parent and child."** Trace process lineage, validate the signer, and review the command line. Run these in **Advanced Hunting** (Defender portal → Hunting → Advanced hunting). Replace `<DeviceName>`, `<AccountName>`, `<SHA256>` etc.

### 3.1 Office Apps Spawning Shells and LOLBins (Core Query, Extended)

Purpose: find every Office → shell/script-host execution, with full command lines and hashes.

```kql
let OfficeApps = dynamic(["winword.exe","excel.exe","powerpnt.exe","outlook.exe","msaccess.exe","mspub.exe","onenote.exe"]);
let Suspicious = dynamic(["powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe",
                          "rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","schtasks.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (OfficeApps)
| where FileName in~ (Suspicious)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, FolderPath, ProcessCommandLine, SHA256, ProcessIntegrityLevel, ReportId
| order by Timestamp desc
```

**What to look for:** Hidden, encoded or download-style command lines and children running from user-writable paths are suspicious; a readable command tied to a known business macro or add-in is usually benign.

### 3.2 Full Process Tree Around the Alert (Parent, Child, Grandchildren)

Purpose: rebuild lineage on the host in a window around the alert, including what the shell launched next.

```kql
let Host = "<DeviceName>";
let AlertTime = datetime(<YYYY-MM-DD HH:MM:SS>);
DeviceProcessEvents
| where DeviceName =~ Host
| where Timestamp between ((AlertTime - 10m) .. (AlertTime + 60m))
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe","powershell.exe","cmd.exe",
                                       "wscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
     or InitiatingProcessParentFileName in~ ("winword.exe","excel.exe","outlook.exe")
| project Timestamp, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, SHA256, AccountName
| order by Timestamp asc
```

**What to look for:** A shell followed within seconds by `rundll32`/`regsvr32` or another download tool is a classic infection chain; a single short-lived child with no grandchildren is less concerning.

To decode a PowerShell `-EncodedCommand` (UTF-16LE Base64) in KQL:

```kql
DeviceProcessEvents
| where DeviceName =~ "<DeviceName>" and FileName in~ ("powershell.exe","pwsh.exe")
| extend Enc = extract(@"(?i)-e(nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{20,})", 2, ProcessCommandLine)
| where isnotempty(Enc)
| extend Decoded = replace_string(base64_decode_tostring(Enc), "\u0000", "")
| project Timestamp, DeviceName, ProcessCommandLine, Decoded
```

**What to look for:** Decoded text containing `IEX`, `DownloadString`, `Net.WebClient` or URLs indicates a download-and-execute loader; a readable IT admin script with a clear purpose is typically benign.

### 3.3 Validate the Signer of Parent, Child and Dropped Files

Purpose: confirm the Office binary is a genuine Microsoft build and check whether payloads are unsigned.

```kql
DeviceProcessEvents
| where DeviceName =~ "<DeviceName>" and Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| summarize by ParentSHA1 = InitiatingProcessSHA1, ChildSHA1 = SHA1, InitiatingProcessFolderPath, FolderPath, FileName
| join kind=leftouter (DeviceFileCertificateInfo | summarize arg_max(Timestamp, *) by SHA1
    | project SHA1, ChildSigner = Signer, ChildIsSigned = IsSigned, ChildIsTrusted = IsTrusted) on $left.ChildSHA1 == $right.SHA1
| join kind=leftouter (DeviceFileCertificateInfo | summarize arg_max(Timestamp, *) by SHA1
    | project SHA1, ParentSigner = Signer, ParentIsTrusted = IsTrusted) on $left.ParentSHA1 == $right.SHA1
| project InitiatingProcessFolderPath, ParentSigner, ParentIsTrusted, FileName, FolderPath, ChildSigner, ChildIsSigned, ChildIsTrusted
```

**What to look for:** Trusted Microsoft signers on both parent and child are normal; an untrusted or unsigned parent, or a child that is not a genuine Microsoft binary, is a strong red flag.

Red flags: Office running from outside `Program Files`, a "powershell.exe" outside `System32`/`SysWOW64`, or unsigned / untrusted payloads.

### 3.4 Document Origin: Email Attachment and Download Source

Purpose: answer "where did the file come from?" via Mark-of-the-Web and email telemetry.

```kql
let User = "<AccountName>";
DeviceFileEvents
| where DeviceName =~ "<DeviceName>" and Timestamp > ago(3d)
| where FileName matches regex @"(?i)\.(docm?|xlsm?|xlsb|xls|pptm|rtf|one|iso|zip|lnk)$"
| project Timestamp, ActionType, FileName, FolderPath, SHA256, FileOriginUrl, FileOriginReferrerUrl,
          InitiatingProcessFileName
| order by Timestamp desc
```

**What to look for:** A macro-enabled document or archive with an external `FileOriginUrl`, created shortly before the alert, points to the delivery vector; files from internal shares or templates are lower risk.

```kql
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where RecipientEmailAddress =~ "<UserUPN>" or SHA256 == "<DocumentSHA256>"
| join kind=inner (EmailEvents | project NetworkMessageId, Subject, SenderFromAddress, SenderIPv4,
                   DeliveryAction, DeliveryLocation, ThreatTypes) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderIPv4, RecipientEmailAddress, Subject, FileName, SHA256,
          DeliveryAction, ThreatTypes, NetworkMessageId
```

**What to look for:** An external sender, a delivered (not blocked) message and several recipients of the same attachment suggest a phishing campaign; an internal sender with an expected business subject is usually benign.

### 3.5 Child Activity: Network Egress From the Chain

Purpose: find the outbound connection from the timeline (download or C2).

```kql
DeviceNetworkEvents
| where DeviceName =~ "<DeviceName>"
| where Timestamp between (datetime(<AlertTime>) - 5m .. datetime(<AlertTime>) + 2h)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powershell.exe","pwsh.exe","cmd.exe",
                                       "mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","certutil.exe")
| where RemoteIPType == "Public"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```

**What to look for:** Connections to raw public IPs or rare/new domains seconds after the shell spawned are suspicious; traffic only to Microsoft or known vendor endpoints is normal.

### 3.6 Dropped Files and Persistence

Purpose: identify payloads written by the chain and any autorun created.

```kql
let Host = "<DeviceName>";
union
 (DeviceFileEvents
  | where DeviceName =~ Host and Timestamp > ago(1d) and ActionType == "FileCreated"
  | where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powershell.exe","cmd.exe","mshta.exe","certutil.exe","wscript.exe")
  | where FileName matches regex @"(?i)\.(exe|dll|ps1|vbs|js|hta|bat|lnk|dat)$"
  | project Timestamp, Type = "File", InitiatingProcessFileName, Detail = FolderPath, SHA256),
 (DeviceRegistryEvents
  | where DeviceName =~ Host and Timestamp > ago(1d)
  | where RegistryKey has_any (@"\CurrentVersion\Run", @"\Office\", @"\Winlogon")
  | project Timestamp, Type = "Registry", InitiatingProcessFileName, Detail = strcat(RegistryKey, " = ", RegistryValueData), SHA256 = ""),
 (DeviceProcessEvents
  | where DeviceName =~ Host and Timestamp > ago(1d) and FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
  | project Timestamp, Type = "SchedTask", InitiatingProcessFileName, Detail = ProcessCommandLine, SHA256)
| order by Timestamp asc
```

**What to look for:** Executables, DLLs or scripts written to `AppData`, `Temp` or `Public`, and new Run keys or scheduled tasks created by the chain, indicate payload staging and persistence; an empty result is a good sign.

### 3.7 Scope: Same Hash or Pattern Across the Fleet

Purpose: check prevalence and whether other users were hit by the same campaign.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 == "<SHA256>" or InitiatingProcessSHA256 == "<SHA256>"
     or (InitiatingProcessFileName in~ ("winword.exe","excel.exe") and ProcessCommandLine has "<UniqueStringFromCmdline>")
| summarize Hosts = dcount(DeviceName), Users = make_set(AccountName, 50), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by FileName, SHA256
```

**What to look for:** A hash or command pattern seen on several hosts or users in a short window suggests a campaign; a hash seen on only one host may be targeted or new and still needs review.

Tip: the built-in `FileProfile()` function (`| invoke FileProfile(SHA256, 1000)`) adds `GlobalPrevalence`, `Signer`, and `IsCertificateValid`.

---

## 4. Investigation in Splunk

**"Hunt for Office-to-shell behavior."** Detect Office apps spawning shells, then pivot to network and file events.

> Index, sourcetype and field names vary per environment (`parent_process`, `ParentImage`, `pprocess`, `parent`). The examples use Sysmon (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), Windows Security 4688, and the CIM Endpoint data model. Adjust to your add-ons.

### 4.1 Office Spawning Shells (CIM / Data Model)

Purpose: the core query, using normalized CIM fields so it works across EDR sources.

```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime
    values(Processes.process) as process_command_line
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","msaccess.exe","mspub.exe","onenote.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe")
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

**What to look for:** Rare parent/child pairs on a few hosts with download or encoded command lines are suspicious; high-count pairs across many hosts often trace back to a known business macro or add-in.

### 4.2 Sysmon Event ID 1 (Process Creation) With Hashes

Purpose: raw Sysmon version with parent command line (reveals the document path) and hashes.

```spl
index=<sysmon_index> sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe" OR ParentImage="*\\outlook.exe")
  (Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe")
| rex field=Hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| table _time host User ParentImage ParentCommandLine Image CommandLine sha256 ProcessGuid
| sort - _time
```

**What to look for:** A `ParentCommandLine` pointing to a document in `Downloads`, `Temp` or an Outlook cache folder plus an obfuscated child `CommandLine` is suspicious; readable commands from documents on known business shares are usually benign.

### 4.3 Windows Security 4688 (No Sysmon)

Purpose: same detection from native process auditing. Requires "Include command line in process creation events" enabled.

```spl
index=<wineventlog_index> sourcetype="WinEventLog:Security" EventCode=4688
  (Creator_Process_Name="*\\winword.exe" OR Creator_Process_Name="*\\excel.exe" OR Creator_Process_Name="*\\outlook.exe")
  (New_Process_Name="*\\powershell.exe" OR New_Process_Name="*\\cmd.exe" OR New_Process_Name="*\\mshta.exe" OR New_Process_Name="*\\wscript.exe" OR New_Process_Name="*\\rundll32.exe")
| table _time host Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
```

**What to look for:** Encoded, hidden or download commands are suspicious; if `Process_Command_Line` is empty, command-line auditing is not enabled and you should pivot to EDR data.

### 4.4 Pivot: Network Events From the Chain (Sysmon ID 3 and 22)

Purpose: find outbound connections and DNS lookups (C2 beacons, downloads) from the spawned processes.

```spl
index=<sysmon_index> sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="<host>"
  (EventCode=3 OR EventCode=22)
  (Image="*\\powershell.exe" OR Image="*\\rundll32.exe" OR Image="*\\mshta.exe" OR Image="*\\winword.exe" OR Image="*\\excel.exe" OR Image="*\\regsvr32.exe")
  earliest=<alert_time-5m> latest=<alert_time+2h>
| eval dest=coalesce(DestinationHostname, DestinationIp, QueryName)
| stats count min(_time) as first max(_time) as last values(DestinationPort) as ports values(QueryResults) as resolved by Image dest
| convert ctime(first) ctime(last)
| sort first
```

**What to look for:** DNS lookups or connections to unfamiliar domains or raw IPs shortly after the alert suggest a download or C2; traffic only to Microsoft or known vendor destinations is normal.

### 4.5 Pivot: File Events (Dropped Payloads, Sysmon ID 11)

Purpose: identify files written by Office or the shell (scripts, DLLs, EXEs).

```spl
index=<sysmon_index> sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 host="<host>"
  (Image="*\\winword.exe" OR Image="*\\excel.exe" OR Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\certutil.exe" OR Image="*\\mshta.exe")
  (TargetFilename="*.exe" OR TargetFilename="*.dll" OR TargetFilename="*.ps1" OR TargetFilename="*.vbs" OR TargetFilename="*.js" OR TargetFilename="*.hta" OR TargetFilename="*.bat")
| table _time Image TargetFilename
```

**What to look for:** Office or a shell writing `.exe`, `.dll`, `.ps1`, `.vbs` or `.hta` files to user-writable folders is a strong sign of payload staging; Office writing its own temp files is normal.

### 4.6 Proxy / Firewall: Who Else Talked to the Destination

Purpose: scope the destination across the organization ("who, when, how often").

```spl
index=<proxy_index> (dest="<domain>" OR dest_ip="<ip>" OR url="*<domain>*")
| stats count min(_time) as first max(_time) as last values(user) as users values(http_user_agent) as user_agents values(url) as urls by src
| convert ctime(first) ctime(last)
| sort - count
```

**What to look for:** Additional internal sources contacting the same rare destination are candidate victims to investigate; a popular destination contacted by many hosts over months is likely legitimate.

### 4.7 Email: Who Received the Same Lure (O365 Message Trace)

Purpose: find other recipients of the document. Field names depend on the Splunk Add-on for Microsoft Office 365 / message trace input.

```spl
index=<o365_index> sourcetype="ms:o365:reporting:messagetrace" (SenderAddress="<sender>" OR Subject="<subject>")
| stats count values(RecipientAddress) as recipients values(Status) as status by SenderAddress Subject
```

**What to look for:** Multiple recipients of the same external sender or subject indicate a campaign and define the email purge scope; a single recipient narrows it.

---

## 5. Threat Intelligence Enrichment

**"Check the file and destination."** Assess the file and where it connects: reputation, signer, prevalence, and more.

### Workflow

1. **Collect hash** - SHA-256 of the document, the child/grandchild processes, and any dropped files.
2. **Enrich** - reputation, signer, prevalence, destination info.
3. **Hunt internally** - same hash, process pattern, connections, other hosts (sections 3.7, 4.6).
4. **Corroborate** - combine TI with internal evidence (EDR, logs, proxy, DNS) before concluding.

### What to Check

| Indicator | Check | Where |
|---|---|---|
| Hash reputation | Known good / bad / unknown; AV detections; malware family tags | VirusTotal, MalwareBazaar, Defender file page, AlienVault OTX |
| Signer | Digital signature, publisher, certificate validity/revocation | `DeviceFileCertificateInfo`, `FileProfile()`, Sigcheck, VirusTotal "Details" tab |
| File prevalence | Seen on many hosts or only a few; first seen date (global and org) | Defender file page (org/global prevalence), query 3.7 |
| Domain / IP reputation | Threat categories, malware/C2 association, domain age, hosting ASN | VirusTotal, AbuseIPDB, URLScan.io, AlienVault OTX, WHOIS |
| URL content | What the URL served (payload, redirect, phishing page) | URLScan.io (use private scans for sensitive URLs) |
| Proxy / DNS matches | Whether the domain/IP appears in proxy or DNS logs: who, when, how often | Splunk 4.4 / 4.6, `DeviceNetworkEvents` |
| Macro / document | Embedded VBA, auto-exec triggers, URLs | Sandbox (detonation), `olevba` in an isolated analysis VM |

### Example Lookup (Docs Only)

| Field | Value | Interpretation |
|---|---|---|
| Hash (SHA-256) | 9f64a747e1c3...b2e5 | No public detections yet |
| Signer | Unsigned | Suspicious for a file launched by a shell |
| File prevalence | Uncommon (2 hosts) | Not standard software |
| Domain | example.com | Placeholder |
| IP | 192.0.2.123 | TEST-NET placeholder |
| Domain/IP reputation | Unknown / Not listed | Absence of evidence, not evidence of absence |
| Proxy/DNS matches | 2 events, last 24h | Confirms actual egress |

### What Verdicts Mean

- **Known malicious** (multiple reputable engines, family tag, listed C2): strong signal; move to containment once internal evidence aligns.
- **Unknown / not listed**: common for fresh campaigns and targeted payloads. Rely on behavior (encoded command, unsigned DLL via rundll32, new domain).
- **Known good** (Microsoft/vendor-signed, high prevalence): lowers risk, but signed LOLBins are still abused; judge the command line.
- **Do not upload** sensitive internal documents to public services; search by hash first.

> Alert if unsigned or uncommon, but do not assume it is malicious.

---

## 6. Verdict: True Positive vs Benign

| Indicator | Leans true positive | Leans benign |
|---|---|---|
| Document origin | External email, newly registered sender domain, web download with MOTW | Internal template, trusted share, known business workflow |
| Command line | `-enc`, `-w hidden`, `IEX`, `DownloadString`, Base64 blobs, URLs | Clear, readable script path under an IT-managed location |
| Child behavior | Downloads files, spawns `rundll32`/`regsvr32`, writes to `AppData`/`Public`/`Temp` | Exits quickly, no network or file writes |
| Network | Connections to rare/new domains or raw IPs shortly after open | Connections only to Microsoft/known vendor endpoints |
| Signer / prevalence | Unsigned, low-prevalence payloads | Signed by known vendor, seen across the fleet |
| Scope | Same lure hitting several users at once | One user, recurring daily, matches job role |
| User statement | "I did not expect that file" / enabled content on prompt | Uses a known macro-enabled tool |
| Persistence | Run keys, scheduled tasks, startup folder entries created | None |

### Common False Positives

- Finance/reporting macros (Excel VBA) that call `cmd.exe` or PowerShell to export, copy or print.
- Third-party Office add-ins (DMS, e-signature, CRM, PDF tools) spawning helper processes.
- Outlook launching `cmd.exe`/browsers when users click links or open certain attachments.
- IT-deployed templates or login scripts that run from Office.
- Office repair, update, or Click-to-Run actions (usually `OfficeClickToRun.exe`, not winword.exe).
- Red team / phishing simulation exercises (confirm with the owner before closing).

Document the business justification and tune with a narrow exclusion (exact path + hash + signer + command line), never a blanket "winword.exe → powershell.exe" exclusion.

### Common Beginner Mistakes

- Closing the alert because the child (`powershell.exe`, `rundll32.exe`) is Microsoft-signed; LOLBins are signed, so judge the command line instead.
- Not decoding `-EncodedCommand` payloads before deciding on a verdict.
- Stopping at the child process and missing grandchildren, network connections and dropped files.
- Uploading a sensitive internal document to a public sandbox instead of searching by hash first.
- Investigating only one host when the same email may have reached many users.

---

## 7. Response Checklist

**"Contain only after context."** Validate chain and document source, scope across the SIEM, isolate if malicious is confirmed while preserving evidence, then block indicators, remove persistence, and tune controls.

### Validate and Scope (Before Acting)

- [ ] Validate the chain: parent, child, command line and document source confirmed (sections 2-3).
- [ ] Scope hash / user / host / destination across the SIEM and EDR (3.7, 4.6, 4.7).
- [ ] Identify all recipients of the same email and all hosts that opened the document.
- [ ] Raise severity and open an incident if any malicious indicator is confirmed.

### Contain

- [ ] Isolate the endpoint in Defender (full or selective isolation) if malicious is confirmed.
- [ ] Stop and quarantine the malicious files / processes (Defender "Stop and quarantine file").
- [ ] Revoke the user's sessions and reset credentials if credential theft or post-exploitation is suspected.
- [ ] Soft-delete / purge the phishing email from all mailboxes (Defender Threat Explorer / email remediation).
- [ ] Block sender, domain and URL in Tenant Allow/Block List.

### Preserve Evidence

- [ ] Collect an investigation package from Defender before remediation.
- [ ] Capture memory if the payload may be fileless (in-memory PowerShell loader).
- [ ] Preserve the original document, email (.eml with headers), dropped payloads and decoded commands.
- [ ] Export the relevant Advanced Hunting and Splunk results with timestamps (UTC) to the case.

### Eradicate

- [ ] Block indicators: file hashes (Defender custom indicators), domains/IPs/URLs (proxy, firewall, Defender network protection).
- [ ] Remove persistence: Run keys, scheduled tasks, startup folder items, Office add-ins/templates.
- [ ] Delete dropped payloads and run a full AV scan; reimage if integrity is in doubt.
- [ ] Check for lateral movement and credential use from the host (`DeviceLogonEvents`, `IdentityLogonEvents`, sign-in logs).

### Recover

- [ ] Release from isolation after a clean scan and validated eradication.
- [ ] Restore user access with new credentials and MFA verified.
- [ ] Confirm business applications (legit macros/add-ins) work as expected.

### Monitor and Reduce Future Risk (Tune Controls)

- [ ] Enable ASR rule "Block all Office applications from creating child processes" (audit first, then block).
- [ ] Enable ASR rules "Block Office applications from creating executable content" and "Block Win32 API calls from Office macros".
- [ ] Block macros in files from the internet (Mark-of-the-Web policy) and allow only signed/trusted-location macros.
- [ ] Enable PowerShell Script Block Logging and Constrained Language Mode where possible.
- [ ] Add a watchlist for the hash/domain/IP and a 14-30 day hunt for re-occurrence.
- [ ] Document root cause, timeline, verdict and tuning decisions; feed lessons into user awareness training.

---

## 8. Quick Reference

### Cheat Sheet

| Step | Defender XDR | Splunk | Look for |
|---|---|---|---|
| Detect | `DeviceProcessEvents` where `InitiatingProcessFileName` is Office | `Endpoint.Processes` / Sysmon 1 / 4688 | Office → shell / LOLBin |
| Lineage | `InitiatingProcessParentFileName`, query 3.2 | `ParentImage`, `ProcessGuid` / `ParentProcessGuid` | Grandchildren (`rundll32`, `regsvr32`) |
| Command line | `ProcessCommandLine`, `base64_decode_tostring()` | `CommandLine`, `Process_Command_Line` | `-enc`, `-w hidden`, `IEX`, URLs |
| Signer | `DeviceFileCertificateInfo`, `FileProfile()` | `Signature` / `SignatureStatus` (Sysmon 7) | Unsigned / untrusted |
| Origin | `DeviceFileEvents.FileOriginUrl`, `EmailAttachmentInfo` | O365 message trace, proxy | Sender, URL, MOTW |
| Network | `DeviceNetworkEvents` | Sysmon 3 / 22, proxy, firewall | Rare domains, raw IPs |
| Files | `DeviceFileEvents` | Sysmon 11 | `.dll/.exe/.ps1` in user-writable paths |
| Persistence | `DeviceRegistryEvents`, schtasks | Sysmon 12/13, 4698 | Run keys, tasks |
| Contain | Isolate device, stop & quarantine, indicators | Correlate scope | Confirmed malicious only |

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|---|---|
| [Windows Sysmon Events Analysis](https://www.youtube.com/watch?v=C_EfES2Ae1M) | Reading and analysing Sysmon events on Windows, such as the process creation data used in this guide |
| [Incident Response Series: Possible LOLBins](https://www.youtube.com/watch?v=UYeSOTQ0ziY) | Investigating possible abuse of built-in Windows binaries (LOLBins) |
| [SOC Stories: Suspicious PowerShell Alert](https://www.youtube.com/watch?v=LNI8SnlJv0s) | Working through a suspicious PowerShell alert from a SOC analyst's perspective |
| [Email Incident Response Masterclass](https://www.youtube.com/watch?v=Ne4kEw-zQUk) | Responding to email-borne incidents, the usual delivery route for malicious documents |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|---|---|
| [Email Attachment Analysis](https://app.haxcamp.com/lab/email-attachment-analysis) | Analyse malicious PDFs and Office macros, extract hashes and IOCs |
| [Sysmon Log](https://app.haxcamp.com/lab/sysmon-log) | Detect suspicious process creation with Sysmon in Event Viewer and Splunk |
| [PowerShell Operational Log](https://app.haxcamp.com/lab/powershell-operational-log) | Investigate PowerShell activity and obfuscated commands |
| [Malware Alert Triage](https://app.haxcamp.com/lab/malware-alert-triage) | Analyse an endpoint alert for a suspicious file |
| [Threat Hunting for Windows](https://app.haxcamp.com/lab/threat-hunting-for-windows) | Hunt for attacker activity on Windows endpoints |

### Official Documentation

- [MITRE ATT&CK: Phishing: Spearphishing Attachment (T1566.001)](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK: User Execution: Malicious File (T1204.002)](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: System Binary Proxy Execution (T1218)](https://attack.mitre.org/techniques/T1218/)
- [Microsoft: Advanced hunting schema reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Microsoft: DeviceProcessEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Microsoft: Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft: Take response actions on a device](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- [Microsoft: Macros from the internet are blocked by default](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked)
- [Microsoft Sysinternals: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk: Endpoint data model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- [Splunk Security Content: detections library](https://research.splunk.com/)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
