# Credential Dumping (LSASS Access): SOC Investigation Playbook

How to detect, investigate and respond to a process that accessed LSASS memory, using Microsoft Defender XDR, Splunk and threat intelligence.

> **Level:** Beginner to Intermediate · **Time:** ~45 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to validate an LSASS access alert, how to hunt dump tools and dump files in KQL and SPL, how to scope and contain credential theft
>
> **Prerequisites:** basic Windows process and Security event logs, and basic KQL/SPL syntax

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

1. Open the alert and note the host, user, accessing process and the exact time of LSASS access.
2. Check the parent process: Office apps, browsers or script hosts launching a dump tool are a red flag.
3. Read the command line for `-ma lsass`, `MiniDump`, `comsvcs` or `sekurlsa`, and note any output path in `%TEMP%`, `C:\Users\Public` or `C:\ProgramData`.
4. Verify the binary's signer and path, and whether `OriginalFileName` differs from the file name (renamed tool).
5. Check whether a `.dmp` file was written and whether the host made new SMB/RDP/WinRM connections afterwards.
6. Look for an approved change ticket or support case that explains the activity.

**Escalate immediately if:** the dump tool was launched by an Office app, browser or script host, no change ticket exists, or the exposed accounts show new network logons on other hosts.

---

## 1. What This Alert Means

The Local Security Authority Subsystem Service (`lsass.exe`) enforces security policy on Windows and holds authentication material in memory: NTLM hashes, Kerberos tickets and keys, and (on older or misconfigured systems) cleartext credentials through providers such as WDigest. A process that opens a handle to LSASS with memory-read rights, or writes a dump of LSASS to disk, may be harvesting those credentials.

**Why attackers do it**

- One compromised workstation becomes many compromised accounts: any user or admin who has logged on interactively may leave reusable material in memory.
- Hashes and tickets enable **pass-the-hash** and **pass-the-ticket** without cracking passwords.
- Harvested privileged credentials drive **lateral movement** toward servers and domain controllers.
- Dumping is often done with signed, legitimate tools (ProcDump, `comsvcs.dll` via `rundll32.exe`, Task Manager) to blend in ("living off the land").

**Common techniques seen in this alert**

| Technique | Example command or artifact |
|---|---|
| Sysinternals ProcDump | `procdump.exe -accepteula -ma lsass.exe out.dmp` |
| comsvcs.dll MiniDump | `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\temp\l.dmp full` |
| Mimikatz in-memory | `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"` |
| Task Manager "Create dump file" | `lsass.DMP` written under `%TEMP%` by `taskmgr.exe` |
| Custom / BOF dumpers | Direct `OpenProcess`/`MiniDumpWriteDump` calls, often from unsigned or renamed binaries |

**MITRE ATT&CK mapping**

| ID | Name | Relevance |
|---|---|---|
| T1003 | OS Credential Dumping | Parent technique |
| T1003.001 | OS Credential Dumping: LSASS Memory | Core behaviour of this alert |
| T1218.011 | System Binary Proxy Execution: Rundll32 | `comsvcs.dll` MiniDump variant |
| T1566.001 | Phishing: Spearphishing Attachment | Office document as initial access (winword.exe parent) |
| T1204.002 | User Execution: Malicious File | User opened the document |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Typical use of dumped NTLM hashes |
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | Typical use of dumped Kerberos tickets |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral movement with stolen credentials |
| T1078 | Valid Accounts | Follow-on use of harvested accounts |

### Key Terms

| Term | Meaning |
|---|---|
| LSASS | The Windows process (`lsass.exe`) that handles logons and keeps credential material in memory. |
| NTLM hash | A stored form of a user's password that can be reused to authenticate without knowing the password. |
| Pass-the-hash / pass-the-ticket | Logging on to other systems with stolen hashes or Kerberos tickets instead of a password. |
| Access mask | A number such as `0x1010` describing which rights a process requested when it opened another process. |
| Dump file (`.dmp`) | A file containing a copy of a process's memory; an LSASS dump holds credentials. |
| Living off the land | Using legitimate, often signed, built-in or admin tools to avoid detection. |
| Prevalence | How many devices in your environment have seen a file or behaviour; rare usually means riskier. |

---

## 2. Alert Triage

**Example scenario:** a detection flagged possible credential dumping. `procdump.exe` accessed LSASS on host `WS-2847`, user `jdoe`, launched by `winword.exe`. Status: **suspicious, not confirmed**.

| Time | Process | Meaning |
|---|---|---|
| 10:24:10 | `winword.exe` | Parent process (unusual for an admin tool) |
| 10:24:18 | `procdump.exe` | Tool started |
| 10:24:21 | `lsass.exe` | LSASS memory accessed (credential-dumping behaviour) |

An eight-second gap between Word and ProcDump, and Word as a parent, strongly suggest a macro or exploit chain rather than an admin troubleshooting session.

Remember that legitimate tools such as ProcDump are used by administrators to capture LSASS for diagnostics, so validate before you escalate.

### Validation Checklist

- [ ] **Signer** - Is the binary signed, and is the publisher trusted (e.g. Microsoft Corporation for Sysinternals)? Is the signature valid and not revoked? Is it running from an expected path?
- [ ] **Command line** - Does it match a legitimate, approved use? Look for `-ma lsass`, `MiniDump`, `sekurlsa`, output paths in `%TEMP%`, `C:\Users\Public`, `C:\ProgramData`.
- [ ] **User** - Is the account an authorized admin for this activity, on this host, at this time?
- [ ] **Parent** - Is the launch chain expected? Office apps, browsers, script hosts (`wscript`, `mshta`, `powershell`) launching dump tools is not.
- [ ] **Process access** - Did it actually open `lsass.exe` with memory-read rights? Was a dump file written?
- [ ] **Change ticket** - Is there a related, approved maintenance or troubleshooting ticket?

### Key Fields to Collect

| Field | Example | Why it matters |
|---|---|---|
| Hostname / Device ID | `WS-2847` | Scope and isolation target |
| User / logon ID | `CORP\jdoe` | Whose session ran the tool; whose credentials are in memory |
| Accessing process + path | `C:\Users\jdoe\AppData\Local\Temp\procdump.exe` | Unusual paths suggest dropped tooling |
| Process command line | `procdump.exe -accepteula -ma lsass.exe` | Intent and output location |
| Parent / grandparent process | `winword.exe` → `explorer.exe` | Initial access vector |
| SHA-256, signer, version info | Microsoft Corporation | Reputation and renaming detection |
| Granted access mask | `0x1010`, `0x1410`, `0x1FFFFF` | Read rights on LSASS |
| Dump file path / hash | `C:\Windows\Temp\l.dmp` | Exfil target, evidence |
| Logged-on accounts on host | Admins, service accounts | Credentials potentially exposed |
| Network connections after dump | SMB, RDP, WinRM, external IPs | Exfiltration or lateral movement |

---

## 3. Investigation in Microsoft Defender XDR

Run in **Hunting > Advanced hunting**. Replace placeholders like `<DeviceName>` and adjust the time window. Hunt on **behaviour** (LSASS access, dump files), not only file names: tools are renamed easily.

Investigation guidance:

- **Inspect the device timeline** - review the full process tree and preceding/follow-on activity.
- **Process access alerts** - check related alerts (e.g. "Suspicious access to LSASS service", credential dumping behaviour).
- **Signer** - verify the file's digital signature and publisher.
- **Prevalence** - assess how common the file and behaviour are across your environment (rare = higher risk).

### 3.1 Known Dump Tools and LSASS Command Lines

Purpose: find well-known dumping patterns by name and command line (core query, extended).

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("procdump.exe", "procdump64.exe", "rundll32.exe", "mimikatz.exe")
    or ProcessVersionInfoOriginalFileName in~ ("procdump", "procdump.exe", "mimikatz.exe")
| where ProcessCommandLine has_any ("lsass", "sekurlsa", "comsvcs", "MiniDump", "-ma ")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

**What to look for:** a dump tool or `rundll32.exe comsvcs.dll MiniDump` whose parent is a user application (Office, browser, script host) or that runs from a user-writable path is suspicious; runs from an admin console that match a ticket are usually benign.

`ProcessVersionInfoOriginalFileName` catches renamed copies of ProcDump.

### 3.2 Behaviour-Based: Processes Opening LSASS

Purpose: list processes that opened a handle to LSASS, regardless of their name. `OpenProcessApiCall` events are sampled, so absence is not proof of innocence.

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "MsSense.exe", "svchost.exe", "csrss.exe", "wininit.exe")
| summarize Count = count(), Devices = dcount(DeviceName), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| order by Devices asc
```

**What to look for:** accessors seen on only one or two devices, running from user or temp folders, or with an unknown hash deserve review; security agents and management tools seen across many devices are normally expected.

Low `Devices` counts surface rare accessors (prevalence check).

### 3.3 Full Process Tree on the Affected Host

Purpose: rebuild the chain around the alert (what launched Word, what Word launched, what ran afterwards).

```kql
let host = "<DeviceName>";
let alertTime = datetime(<YYYY-MM-DD HH:MM:SS>);
DeviceProcessEvents
| where DeviceName =~ host
| where Timestamp between ((alertTime - 30m) .. (alertTime + 2h))
| project Timestamp, AccountName, InitiatingProcessParentFileName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, SHA256, ProcessIntegrityLevel
| order by Timestamp asc
```

**What to look for:** Office or browser processes spawning `cmd`, `powershell` or dump tools, followed by discovery, archiving or remote-execution commands, indicate an attack chain; a clean admin session has a short, explainable tree.

### 3.4 Dump Files Written to Disk

Purpose: find LSASS dumps or any `.dmp` file created by unexpected processes.

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".dmp" or FileName has "lsass"
| where InitiatingProcessFileName !in~ ("WerFault.exe", "WerFaultSecure.exe")
| project Timestamp, DeviceName, FolderPath, FileName, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

**What to look for:** large `.dmp` files or LSASS-named files in temp, public or ProgramData folders created by tools such as `procdump`, `rundll32` or `taskmgr` are suspicious; application crash dumps in their expected folders are usually normal.

### 3.5 Signer and Prevalence of the Tool

Purpose: confirm signer and how many devices have run this exact hash.

```kql
let hash = "<SHA256>";
DeviceFileCertificateInfo
| where SHA1 in ((DeviceProcessEvents | where SHA256 == hash | distinct SHA1))
| distinct SHA1, Signer, Issuer, IsSigned, IsTrusted, CertificateSerialNumber
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(30d) and SHA256 == hash
    | summarize Devices = dcount(DeviceName), Users = dcount(AccountName), FirstSeen = min(Timestamp) by SHA1
  ) on SHA1
```

**What to look for:** unsigned or untrusted results, or a hash seen on very few devices, raise risk; a trusted Microsoft signature only proves the tool is genuine, not that its use was legitimate.

`invoke FileProfile()` can also be used to add global prevalence and signer info: `DeviceProcessEvents | where SHA256 == "<SHA256>" | take 1 | invoke FileProfile(SHA1)`.

### 3.6 Follow-On Logons and Lateral Movement

Purpose: after the dump time, find network/remote logons by the exposed account(s) and remote-admin connections from the host.

```kql
let user = "<AccountName>";
let alertTime = datetime(<YYYY-MM-DD HH:MM:SS>);
DeviceLogonEvents
| where Timestamp between (alertTime .. (alertTime + 24h))
| where AccountName =~ user
| where LogonType in ("Network", "RemoteInteractive", "NewCredentials")
| summarize Logons = count(), FirstLogon = min(Timestamp) by DeviceName, LogonType, RemoteIP, ActionType
| order by FirstLogon asc
```

**What to look for:** new network, RDP or `NewCredentials` logons by the exposed account on hosts it does not normally use, soon after the dump, suggest credential reuse; routine logons to the user's usual servers are expected.

```kql
DeviceNetworkEvents
| where DeviceName =~ "<DeviceName>"
| where Timestamp > datetime(<YYYY-MM-DD HH:MM:SS>)
| where RemotePort in (135, 445, 3389, 5985, 5986) or RemoteIPType == "Public"
| project Timestamp, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, ActionType
| order by Timestamp asc
```

**What to look for:** SMB, RPC, RDP or WinRM connections to many internal hosts, or public IP connections from unusual processes after the dump, point to lateral movement or exfiltration; browser traffic to known sites is normal.

### 3.7 Identity-Side View (Defender for Identity)

Purpose: detect use of stolen material against domain controllers (NTLM/Kerberos from unusual sources).

```kql
IdentityLogonEvents
| where Timestamp > ago(2d)
| where AccountName =~ "<AccountName>"
| summarize Attempts = count(), Failures = countif(ActionType == "LogonFailed"),
            Targets = make_set(DestinationDeviceName, 20)
    by DeviceName, IPAddress, Protocol, LogonType
| order by Attempts desc
```

**What to look for:** NTLM authentication from unexpected source devices or IPs, bursts of failures, or many distinct targets for one account are suspicious; consistent logons from the user's own workstation are expected.

---

## 4. Investigation in Splunk

Index, sourcetype and field names **vary per environment**. Examples below assume Sysmon via the Splunk Add-on for Sysmon (`sourcetype=XmlWinEventLog` with `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`) and Windows Security logs (`WinEventLog:Security` or `XmlWinEventLog:Security`). Validate field mapping first:

| Generic field | Sysmon field | Security log / CIM field |
|---|---|---|
| `process_name` | `Image` | `New_Process_Name` / `process_name` |
| `process_command_line` | `CommandLine` | `Process_Command_Line` / `process` |
| `user` | `User` | `Account_Name` / `user` |
| `parent_process` | `ParentImage` | `Creator_Process_Name` / `parent_process_name` |
| `host` | `Computer` | `ComputerName` / `dest` |

### 4.1 Core Query: Dump Tools Targeting LSASS (EDR / CIM Data)

Purpose: group suspicious command lines by host.

```spl
index=endpoint (process_name="procdump.exe" OR process_name="procdump64.exe" OR process_name="rundll32.exe")
| search process_command_line="*lsass*" OR process_command_line="*MiniDump*" OR process_command_line="*comsvcs*"
| stats values(user) AS user values(parent_process) AS parent values(process_command_line) AS cmd min(_time) AS first_seen by host
| convert ctime(first_seen)
| sort host
```

**What to look for:** hosts where the command line references LSASS or `MiniDump` and the parent is a user application are suspicious; documented admin hosts with a matching ticket are usually benign.

### 4.2 Sysmon Event ID 10: Process Access to LSASS

Purpose: behaviour-based detection of any process opening LSASS with read rights.

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
    TargetImage="*\\lsass.exe"
    (GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1438" OR GrantedAccess="0x143a" OR GrantedAccess="0x1fffff")
    NOT SourceImage IN ("*\\MsMpEng.exe", "*\\MsSense.exe", "*\\csrss.exe", "*\\wininit.exe")
| stats count min(_time) AS first_seen values(GrantedAccess) AS access values(CallTrace) AS calltrace by Computer, SourceImage, SourceUser
| convert ctime(first_seen)
| sort - count
```

**What to look for:** rare `SourceImage` values from user or temp paths, or read-capable access masks from unexpected tools, are suspicious; known security and system processes repeating across many hosts are usually normal.

A `CallTrace` containing `dbghelp.dll` or `dbgcore.dll` indicates `MiniDumpWriteDump`; `UNKNOWN` frames suggest injected code.

### 4.3 Sysmon Event ID 1: Process Tree on the Host

Purpose: rebuild the winword → procdump chain and what followed.

```spl
index=sysmon EventCode=1 Computer="<host>" earliest="<MM/DD/YYYY:HH:MM:SS>" latest=+2h
| table _time, User, ParentImage, ParentCommandLine, Image, CommandLine, Hashes, IntegrityLevel
| sort _time
```

**What to look for:** a parent such as `winword.exe` or `mshta.exe` launching a dump tool, followed by discovery or remote-execution commands, indicates an attack chain; a short admin session with a matching ticket is usually benign.

### 4.4 Sysmon Event ID 11: Dump Files Created

Purpose: find `.dmp` files and LSASS-named files written by unexpected processes.

```spl
index=sysmon EventCode=11 (TargetFilename="*.dmp" OR TargetFilename="*lsass*")
    NOT Image IN ("*\\WerFault.exe", "*\\WerFaultSecure.exe")
| table _time, Computer, User, Image, TargetFilename
| sort - _time
```

**What to look for:** `.dmp` or LSASS-named files written to temp, public or ProgramData folders by tools like `procdump`, `rundll32` or `taskmgr` are suspicious; application crash dumps in expected locations are normal.

### 4.5 Pivot: New Logons After the Access Attempt

Purpose: find accounts that logged on with explicit credentials or over the network after the dump (EventCode 4624 logon types 3/9/10, 4648 explicit credentials, 4672 special privileges).

```spl
index=wineventlog source="WinEventLog:Security" (EventCode=4624 OR EventCode=4648 OR EventCode=4672)
    earliest="<MM/DD/YYYY:HH:MM:SS>" latest=+24h
| eval logon_type=coalesce(Logon_Type, LogonType)
| where EventCode!=4624 OR logon_type IN ("3", "9", "10")
| stats count min(_time) AS first_seen values(EventCode) AS events values(logon_type) AS logon_types values(Source_Network_Address) AS src_ip by Account_Name, ComputerName
| convert ctime(first_seen)
| sort first_seen
```

**What to look for:** exposed accounts appearing with type 3/9/10 logons, 4648 explicit-credential use or 4672 privileged logons on new hosts after the dump are suspicious; expected service or admin activity on usual hosts is normal.

Logon type 9 (`NewCredentials`) with `seclogo` authentication package is a common pass-the-hash indicator.

### 4.6 Pivot: Lateral Movement to Other Hosts

Purpose: find remote execution from the affected host (services 7045, scheduled tasks 4698, admin share logons 5140, PsExec-style activity).

```spl
(index=wineventlog (source="WinEventLog:System" EventCode=7045) OR (source="WinEventLog:Security" (EventCode=4698 OR EventCode=5140)))
    OR (index=sysmon EventCode=3 Image="*" Computer="<host>" (DestinationPort=445 OR DestinationPort=3389 OR DestinationPort=5985 OR DestinationPort=135))
    earliest="<MM/DD/YYYY:HH:MM:SS>" latest=+24h
| eval detail=coalesce(Service_File_Name, Task_Name, Share_Name, DestinationIp.":".DestinationPort)
| stats count values(detail) AS detail values(EventCode) AS events by host, source
| sort - count
```

**What to look for:** new services, scheduled tasks or admin share access on other hosts shortly after the dump, or the affected host connecting to many peers on 445/3389/5985, indicate lateral movement; scheduled patching or management tooling is usually benign.

---

## 5. Threat Intelligence Enrichment

**Enrich the tool, verify the behaviour.** Threat intel informs file reputation, but memory-access context decides the case. A Microsoft-signed ProcDump will be "clean" on every reputation service and still be the weapon.

Workflow: **Hash → Enrich → Hunt → Corroborate.**

| Observable | Where to check | What to look for |
|---|---|---|
| SHA-256 of the tool | VirusTotal, MalwareBazaar, Defender file page | Detection ratio, first seen, signer, known names, sandbox behaviour |
| Signer / certificate | Defender `DeviceFileCertificateInfo`, VirusTotal "Details" | Valid chain, trusted publisher, not revoked or stolen |
| Dropping document | VirusTotal, MalwareBazaar, email logs (`EmailAttachmentInfo`) | Macro-enabled docs, known lure families |
| Destination IPs | AbuseIPDB, AlienVault OTX, VirusTotal | Abuse reports, hosting ASN, C2 associations |
| Domains / URLs | URLScan.io, VirusTotal, OTX | Newly registered domains, phishing pages, payload hosting |

**Example (illustrative, not a real hash):** signer Example Corp. (code signing), internal prevalence 1,248 endpoints, reputation Good → recommended action is still **verify behaviour**: review context, memory access and observed actions.

**Interpreting verdicts**

- **Malicious / known hack tool** (e.g. Mimikatz hash): strong signal, but confirm the execution actually happened and succeeded.
- **Clean / good reputation**: says nothing about intent. Legitimate tools dump LSASS just as well.
- **Unknown / no results**: common for custom or recompiled tooling. Treat rarity as risk.
- Always **verify the intelligence source and freshness** (last analysis date, who submitted, whether the report is stale).
- **Check internal prevalence**: how many endpoints have this hash, and how many ran it against LSASS.

> **Never classify solely on tool name.** Renamed binaries hide malicious tools; signed admin tools hide malicious intent.

Do not upload internal documents or dump files to public services; search by hash instead.

---

## 6. Verdict: True Positive vs Benign

| Indicator | Likely true positive | Likely benign |
|---|---|---|
| Parent process | Office app, browser, `mshta`, `wscript`, `powershell` from user context | `cmd.exe`/`powershell.exe` from an admin console, management agent |
| Path | `%TEMP%`, `Downloads`, `C:\Users\Public`, `C:\ProgramData` | Approved tools share, `C:\Program Files\...` |
| Signer | Unsigned, invalid, or mismatched OriginalFileName | Valid Microsoft or approved vendor signature |
| User | Standard user, unexpected account, off-hours | Named admin, matches change ticket |
| Command line | `-ma lsass`, `MiniDump <pid> ... full`, `sekurlsa::` | Documented diagnostic procedure with vendor case |
| Dump file | Written then deleted, compressed, or copied off host | Uploaded to vendor via approved channel |
| Follow-on activity | New network logons, PTH, admin share access, service creation | None |
| Prevalence | Rare (1-2 hosts) | Widespread, consistent, expected |
| Change ticket | None | Approved and matches time and host |

### Common Beginner Mistakes

- Closing the alert because ProcDump or `rundll32.exe` is Microsoft-signed; signed tools are commonly abused.
- Searching only by tool name and missing renamed binaries; always check `OriginalFileName` and LSASS access behaviour.
- Treating a missing `OpenProcessApiCall` event as proof nothing happened; those events are sampled.
- Scoping only the alerting user instead of every account with a session on the host.
- Deleting dump files or tools before collecting evidence.

**Common false positives**

- Administrators capturing LSASS dumps for Microsoft support cases.
- Windows Error Reporting (`WerFault.exe`) after an LSASS crash.
- Security products (AV, EDR, DLP, vulnerability scanners) reading LSASS.
- Password managers / SSO agents and some backup or monitoring agents.
- Authorized red team or penetration test (confirm with the engagement contact and scope).

In the example scenario (`winword.exe` → `procdump.exe` → LSASS on `WS-2847`, no ticket), treat as a **true positive until proven otherwise**.

---

## 7. Response Checklist

Order: **validate malicious access → scope endpoint/user/other hosts → if confirmed, contain and cut access → preserve evidence, remove persistence, monitor.**

### Validate and Scope

- [ ] Confirm LSASS was actually accessed (Defender `OpenProcessApiCall`, Sysmon 10) and whether a dump file was created.
- [ ] List every account with a session on the host at dump time (all are potentially exposed).
- [ ] Hunt the hash, command line and dump-file patterns across all endpoints.
- [ ] Identify other hosts the exposed accounts logged on to after the dump.
- [ ] Find the initial access vector (email with attachment, download, exploit).

### Contain

- [ ] Isolate the endpoint in Defender (Device page > Isolate device); prefer selective isolation if you need Outlook/Teams for comms.
- [ ] Disable or reset compromised accounts; prioritize privileged and service accounts.
- [ ] Revoke active sessions and refresh tokens (Entra ID "Revoke sessions") and sign out of cloud apps.
- [ ] If a domain admin or DC-level credential was exposed, plan a double `krbtgt` reset per Microsoft guidance.
- [ ] Block the malicious hash / document via Defender indicators; block C2 IPs/domains on proxy and firewall.
- [ ] Quarantine the phishing email from other mailboxes.

### Eradicate

- [ ] Remove persistence: scheduled tasks, services, Run keys, startup folder, WMI subscriptions.
- [ ] Delete dropped tools and dump files (after evidence is collected).
- [ ] Run a full antivirus scan and review remaining alerts on the host.
- [ ] Rebuild the host if integrity cannot be guaranteed.

### Recover

- [ ] Return the device to service only after re-scan and monitoring period.
- [ ] Re-enable accounts with new credentials and MFA verified.
- [ ] Harden: enable LSA Protection (RunAsPPL), Credential Guard, ASR rule "Block credential stealing from the Windows local security authority subsystem", disable WDigest, restrict Office macros, add privileged users to Protected Users.

### Preserve Evidence

- [ ] Collect an investigation package from Defender before cleanup.
- [ ] Preserve logs (Defender timeline export, Sysmon, Security, System) and extend retention for the incident.
- [ ] Acquire memory and the dump file / tool binary with hashes and chain of custody.
- [ ] Save the original email and attachment.
- [ ] Record timeline, IOCs and decisions in the case.

### Monitor

- [ ] Alert on any logon by the affected accounts for 30 days.
- [ ] Watch for reuse of the hash, command-line patterns and C2 indicators.
- [ ] Monitor for pass-the-hash/ticket patterns (logon type 9, unusual NTLM, Defender for Identity alerts).
- [ ] Hold a lessons-learned review and turn hunts into scheduled detections.

**Tools:** Defender (response actions), Splunk (scope), threat intelligence (context).

---

## 8. Quick Reference

| Question | Defender XDR | Splunk / Windows |
|---|---|---|
| Who opened LSASS? | `DeviceEvents` `ActionType == "OpenProcessApiCall"`, `FileName =~ "lsass.exe"` | Sysmon EventCode 10, `TargetImage=*\lsass.exe` |
| Which tool / command? | `DeviceProcessEvents` | Sysmon 1, Security 4688 |
| Dump written? | `DeviceFileEvents` `.dmp` | Sysmon 11 |
| Signed / prevalent? | `DeviceFileCertificateInfo`, `FileProfile()` | Sysmon `Hashes` + TI lookup |
| Credentials reused? | `DeviceLogonEvents`, `IdentityLogonEvents` | Security 4624 (types 3/9/10), 4648, 4672 |
| Lateral movement? | `DeviceNetworkEvents` ports 445/3389/5985 | System 7045, Security 4698, 5140, Sysmon 3 |
| Suspicious access masks | - | `0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1FFFFF` |
| Key MITRE ID | T1003.001 | T1003.001 |

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|---|---|
| [Windows Sysmon Events Analysis](https://www.youtube.com/watch?v=C_EfES2Ae1M) | Reading and analysing Sysmon events on Windows. |
| [Windows Security Monitoring Crash Course](https://www.youtube.com/watch?v=a_PzlNyWzjo) | A fast introduction to monitoring Windows security logs. |
| [Introduction to DFIR: Digital Forensics & Incident Response](https://www.youtube.com/watch?v=QEgcS4hheZA) | The basics of digital forensics and incident response. |
| [Threat Hunting Crash Course](https://www.youtube.com/watch?v=5OuPcohUfvY) | A quick introduction to proactive threat hunting. |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|---|---|
| [Sysmon Log](https://app.haxcamp.com/lab/sysmon-log) | Use Event Viewer and Splunk to detect suspicious process creation and other Sysmon telemetry |
| [Introduction to EDR](https://app.haxcamp.com/lab/introduction-to-edr) | How EDR records device activity; query endpoints with Velociraptor |
| [EDR & Digital Forensics and Incident Response (DFIR)](https://app.haxcamp.com/lab/edr-and-dfir) | Use EDR and forensic evidence to work out what happened on a host |
| [Process Enumeration with Volatility 3](https://app.haxcamp.com/lab/process-enumeration-with-volatility-3) | Enumerate and analyse running processes from a Windows memory image |
| [Threat Hunting for Windows](https://app.haxcamp.com/lab/threat-hunting-for-windows) | Hunt for attacker activity on Windows endpoints |
| [Active Directory Fundamentals](https://app.haxcamp.com/lab/active-directory-fundamentals) | AD structure, objects, authentication and authorisation |

### Official Documentation

- [MITRE ATT&CK T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK T1550.002: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Microsoft Defender XDR Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Configure Added LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Attack Surface Reduction Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Take Response Actions on a Device](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- [Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk Add-on for Sysmon](https://docs.splunk.com/Documentation/AddOns/released/MSSysmon/About)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
