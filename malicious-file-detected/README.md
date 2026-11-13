# Malicious File Detected - SOC Investigation Playbook

A practical, step-by-step workflow to triage, investigate, and respond to a suspicious or malicious file alert using Microsoft Defender XDR, Splunk, and threat intelligence.

> **Level:** Beginner to Intermediate · **Time:** ~50 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to tell if a flagged file actually ran, how to scope it across the estate by hash, how to decide and act on a verdict
>
> **Prerequisites:** basic Windows process and event log concepts, and beginner KQL/SPL syntax

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

1. Open the alert and note the file name, SHA-256, host, user, and detection name.
2. Check the remediation status: was the file actually quarantined or removed, or did remediation fail?
3. Decide if it was detected on write or after execution (look for `wscript.exe`, `cscript.exe`, `mshta.exe` or similar launching it).
4. Find the origin: download URL, email attachment, USB, or a parent process that dropped it.
5. Check prevalence: how many devices in your environment have the same hash?
6. Look up the hash in Defender's file page and at least one other intel source.
7. Check the device for other alerts on the same host or user in the last 7 days.

**Escalate immediately if:** the file executed and spawned PowerShell/LOLBins, made outbound connections, created persistence, remediation failed, or the same hash is on multiple hosts or a privileged user's device.

---

## 1. What This Alert Means

A "malicious file detected" alert fires when an endpoint security product (for example Microsoft Defender Antivirus / Defender for Endpoint) flags a file as malicious or suspicious, based on signatures, machine-learning models, cloud reputation, or behavior. Often the product has already **blocked or quarantined** the file, but that does not end the investigation. The questions that matter are:

- **Did it run?** Detection on write is very different from detection after execution.
- **Where did it come from?** Browser download, email attachment, USB, network share, or dropped by another process.
- **Is it anywhere else?** The same hash on other hosts means a campaign, not an isolated event.
- **Did anything follow?** Child processes, network connections, persistence, credential access.

### Example Scenario (Illustrative)

| Field | Value |
|---|---|
| File | `invoice_update.js` |
| Host | `WS-2847` |
| User | `jdoe` |
| Delivery | Browser download |
| Status | Suspicious, not confirmed; quarantined by Defender |
| Timeline | Download 10:14:27 → Write 10:14:29 → Detection 10:14:35 → Quarantine 10:14:36 |

A `.js` file named like a business document is a classic initial-access lure. On Windows, double-clicking a `.js` file runs it with **Windows Script Host** (`wscript.exe`), not a browser, giving the script full access to COM objects, the file system, and the network. Typical payloads download a second stage (loader, RAT, infostealer) or establish persistence.

### Why Attackers Use Malicious Files

- Users are trained to open invoices, shipping notices, and HR documents.
- Script files (`.js`, `.vbs`, `.hta`, `.wsf`), shortcuts (`.lnk`), archives (`.zip`, `.iso`, `.img`) and Office documents with macros bypass many mail and web filters.
- Commodity loaders (for example SocGholish-style fake browser updates, which deliver `.js` files) give the attacker a reliable first foothold that is then sold or used for ransomware.

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Name | Relevance |
|---|---|---|---|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | File arrived as an email attachment |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Email link led to the download |
| Initial Access | T1189 | Drive-by Compromise | Compromised / malicious site served the file |
| Execution | T1204.002 | User Execution: Malicious File | User opened the file |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | `.js` run via `wscript.exe` / `cscript.exe` |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Common second step launched by the script |
| Command and Control | T1105 | Ingress Tool Transfer | Script downloads a second-stage payload |
| Defense Evasion | T1027 | Obfuscated Files or Information | Obfuscated script content |
| Defense Evasion | T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | Delivery via ISO/archive to drop MOTW |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Run key or Startup folder entry |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Scheduled task created by the payload |

### Key Terms

| Term | Meaning |
|---|---|
| SHA-256 hash | A unique fingerprint of a file's contents, used to find the same file anywhere and look it up in threat intel. |
| Quarantine | The antivirus moves the file to a protected location so it cannot run; it is not deleted until remediation completes. |
| Windows Script Host | The Windows component (`wscript.exe` / `cscript.exe`) that runs `.js` and `.vbs` scripts outside a browser. |
| Prevalence | How many devices (in your org or worldwide) have seen the file; rare files deserve more suspicion. |
| LOLBins | "Living off the land" binaries: legitimate Windows tools like `mshta.exe` or `rundll32.exe` abused by attackers. |
| Mark-of-the-Web (MOTW) | A tag Windows adds to downloaded files so security features treat them as untrusted. |
| Second stage | The follow-up payload (loader, RAT, infostealer) that a first malicious file downloads and runs. |
| Persistence | Any mechanism (Run key, Startup folder, scheduled task) that makes malware survive a reboot or logoff. |

---

## 2. Alert Triage

Goal of triage: in 5-10 minutes, decide whether this is an isolated blocked file or a possible compromise that needs escalation.

### Investigation Checklist

- [ ] **Hash** - Get the file hash (SHA-256 preferred; also SHA-1/MD5 for older intel sources).
- [ ] **Path / Source** - Confirm where the file came from: URL, email attachment, download folder, removable media, share.
- [ ] **Signer** - Check the digital signature and publisher (if any). Scripts are normally unsigned; an unsigned executable claiming to be a known vendor is a red flag.
- [ ] **Prevalence** - How common is the file? (Defender file page / TI, VirusTotal, Splunk across the estate.)
- [ ] **Process tree** - Which process downloaded / created the file, and did anything execute it?
- [ ] **Quarantine status** - Confirm Defender actually quarantined or removed it and that it cannot run (check remediation status, not just the detection).

### Additional Triage Questions

- [ ] Was the detection at **write time** or **after execution** (behavior / AMSI detection)?
- [ ] Is the user privileged (local admin, IT admin, executive)?
- [ ] Is the host a workstation, server, or jump box?
- [ ] Are there other alerts on the same host/user in the last 7 days?
- [ ] Did the user report anything (pop-ups, "document did not open")?

### Key Fields to Collect

| Field | Example | Where to find it |
|---|---|---|
| File name | `invoice_update.js` | Alert, `DeviceFileEvents.FileName` |
| Full path | `C:\Users\jdoe\Downloads\` | `FolderPath` |
| SHA-256 | `9f3a4e2b...d1c9e7` | `SHA256`, file page |
| Host | `WS-2847` | `DeviceName` |
| User | `jdoe` | `InitiatingProcessAccountName` / `AccountName` |
| Origin URL / referrer | `https://<domain>/...` | `FileOriginUrl`, `FileOriginReferrerUrl` |
| Creating process | `chrome.exe` | `InitiatingProcessFileName` |
| Executing process | `wscript.exe` | `DeviceProcessEvents` |
| Detection name / threat family | e.g. `Trojan:JS/...` | Alert details, `DeviceEvents` AntivirusDetection |
| Remediation status | Quarantined / Removed / Failed | Alert, Action center |
| First / last seen | timestamps | Alert, file profile |
| Signer / publisher | Unsigned | File page, `DeviceFileCertificateInfo` |

---

## 3. Investigation in Microsoft Defender XDR

Run these in **Microsoft Defender portal > Hunting > Advanced hunting**. Replace placeholders such as `<DeviceName>`, `<SHA256>`, `<FileName>` and adjust the time window. Advanced hunting keeps 30 days of data by default.

### 3.1 Trace File Creation and Execution (Core Query, Extended)

Purpose: find when the file was written, by which process, from which URL, and whether it was executed.

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName =~ "<FileName>"          // e.g. "invoice_update.js"
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileOriginUrl, FileOriginReferrerUrl
| order by Timestamp desc
```

**What to look for:** Read the results as a sequence: `FileCreated` by `chrome.exe` / `msedge.exe` / `outlook.exe` shows delivery; `FileOriginUrl` and `FileOriginReferrerUrl` show where it was downloaded from.

### 3.2 Did It Execute? Process Tree Around the File

Purpose: confirm whether the file was launched (for a `.js`, typically by `wscript.exe` or `cscript.exe`) and what it spawned.

```kql
let target = "<FileName>";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<DeviceName>"
| where ProcessCommandLine has target
     or InitiatingProcessCommandLine has target
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessParentFileName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

**What to look for:** No rows means the file was probably never launched. Red flags: `wscript.exe` spawning `powershell.exe`, `cmd.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `curl.exe`, or `bitsadmin.exe`.

### 3.3 Defender Detections and Remediation Status

Purpose: confirm the antivirus verdict, threat name, and whether remediation succeeded.

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusDetection"
| where SHA256 == "<SHA256>" or FileName =~ "<FileName>"
| extend AF = parse_json(AdditionalFields)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
          ThreatName = tostring(AF.ThreatName),
          WasRemediated = tostring(AF.WasRemediated),
          InitiatingProcessFileName
| order by Timestamp desc
```

**What to look for:** `WasRemediated` should be `true` on every row; a `false` or missing value means the file may still be present. Also review the alert's **Action center** entry; a detection with failed remediation is effectively an active file.

### 3.4 Prevalence: Every Device With the Same Hash

Purpose: scope the blast radius across the estate and pull global reputation with `FileProfile()`.

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "<SHA256>"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Devices = dcount(DeviceName), DeviceList = make_set(DeviceName, 100),
            Users = make_set(InitiatingProcessAccountName, 100)
          by SHA256, FileName
| invoke FileProfile(SHA256, 1000)
| project FileName, SHA256, FirstSeen, LastSeen, Devices, DeviceList, Users,
          GlobalPrevalence, GlobalFirstSeen, Signer, IsCertificateValid
```

**What to look for:** One device suggests an isolated event; several devices means a campaign to scope. Low global prevalence plus no signer on a file pretending to be a document is highly suspicious.

### 3.5 Network Activity After the File Was Written / Run

Purpose: detect second-stage downloads or C2 from the script host or its children.

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(<StartTime>) .. datetime(<EndTime>))
| where DeviceName =~ "<DeviceName>"
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","powershell.exe",
        "mshta.exe","rundll32.exe","regsvr32.exe","curl.exe","bitsadmin.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, ActionType
| order by Timestamp asc
```

**What to look for:** Any outbound connection from `wscript.exe`/`cscript.exe` is suspicious, especially to rare domains, raw IPs, or file-sharing sites shortly after the file was written; no rows is a good sign.

### 3.6 Persistence Check on the Affected Device

Purpose: look for Run keys, Startup folder drops, and scheduled tasks created around the incident.

```kql
let host = "<DeviceName>";
let start = datetime(<StartTime>);
union
( DeviceRegistryEvents
  | where DeviceName =~ host and Timestamp > start
  | where RegistryKey has @"\CurrentVersion\Run"
  | project Timestamp, Type = "Registry", Detail = strcat(RegistryKey, " = ", RegistryValueData),
            InitiatingProcessFileName ),
( DeviceFileEvents
  | where DeviceName =~ host and Timestamp > start
  | where FolderPath has @"\Start Menu\Programs\Startup"
  | project Timestamp, Type = "StartupFolder", Detail = FolderPath, InitiatingProcessFileName ),
( DeviceEvents
  | where DeviceName =~ host and Timestamp > start
  | where ActionType == "ScheduledTaskCreated"
  | project Timestamp, Type = "ScheduledTask", Detail = tostring(AdditionalFields),
            InitiatingProcessFileName )
| order by Timestamp asc
```

**What to look for:** Entries created by `wscript.exe`, `powershell.exe` or other script hosts, or pointing to files in user-writable folders (`AppData`, `Temp`, `Downloads`), are suspicious; entries from known installers or IT tools are usually normal.

### 3.7 Email Delivery Path (If It Arrived as an Attachment or Link)

Purpose: find the delivering email and other recipients so the message can be purged.

```kql
EmailAttachmentInfo
| where Timestamp > ago(14d)
| where SHA256 == "<SHA256>" or FileName =~ "<FileName>"
| join kind=inner (EmailEvents | project NetworkMessageId, Subject, SenderFromAddress,
                   DeliveryAction, DeliveryLocation) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject,
          FileName, SHA256, DeliveryAction, DeliveryLocation, NetworkMessageId
```

**What to look for:** Multiple recipients or an external, unfamiliar sender point to a phishing campaign; `DeliveryLocation` tells you whether it reached inboxes or junk. For link-based delivery, pivot the origin domain in `UrlClickEvents` (`Url`, `AccountUpn`, `ActionType`, `IsClickedThrough`).

### Defender Portal Pivots

| Pivot | What to do |
|---|---|
| Check hash | Open the file page: detection name, global prevalence, signer, VirusTotal ratio, devices observed. |
| File origin | Use `FileOriginUrl` / referrer and the alert story to find Downloads / email / browser source. |
| Parent | Identify the parent process (for example `chrome.exe`) that created the file and the process that launched it (`wscript.exe`). |
| Device timeline | Filter the device timeline to +/- 30 minutes: download → create → execute → network → persistence. |
| Quarantine | Take action → Stop and Quarantine File (all devices), or add an indicator to block the hash. |

---

## 4. Investigation in Splunk

> Index, sourcetype and field names vary per environment. The examples assume Sysmon (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), Windows Security logs, and a proxy feed. If you use the Splunk CIM, prefer the `Endpoint` and `Web` data models with `tstats`. Normalize fields first (see 4.6).

### 4.1 Hunt the File Name / Hash (Core Query)

Purpose: summarize every host, user, and path associated with the file.

```spl
index=endpoint file_name="invoice_update.js"
| stats count values(host) as host values(user) as user values(file_path) as file_path values(action) as action by sha256
| sort - count
```

**What to look for:** More than one `sha256` for the same name, or many hosts and users, means the lure is spreading; `action` values other than blocked/quarantined need follow-up.

### 4.2 Find Every Host With the Same SHA-256 (Sysmon)

Purpose: hash-based scoping. Sysmon EventCode 1 (process create) and 15 (FileCreateStreamHash, often written for downloads with Zone.Identifier) carry a `Hashes` field when hashing is enabled.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=15)
    Hashes="*SHA256=<SHA256>*"
| rex field=Hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| stats min(_time) as first_seen max(_time) as last_seen dc(host) as host_count values(host) as hosts values(User) as users values(Image) as images values(TargetFilename) as files by sha256
| convert ctime(first_seen) ctime(last_seen)
```

**What to look for:** `host_count` above 1 means scope beyond the original device; any EventCode 1 hit means the hash ran as a process, not just landed on disk.

### 4.3 File Creation (Sysmon EventCode 11)

Purpose: who wrote the file and where.

```spl
index=sysmon EventCode=11 TargetFilename="*\\invoice_update.js"
| table _time host User Image TargetFilename
| sort _time
```

**What to look for:** A browser or `outlook.exe` as `Image` indicates download or attachment delivery; a script host or unknown binary writing the file suggests it was dropped by something already running.

### 4.4 Execution and Child Processes (Sysmon EventCode 1)

Purpose: confirm execution via the script host and list what it spawned.

```spl
index=sysmon EventCode=1 host="<host>"
    (CommandLine="*invoice_update.js*" OR ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe")
| table _time host User ParentImage ParentCommandLine Image CommandLine Hashes
| sort _time
```

**What to look for:** `wscript.exe`/`cscript.exe` running the file confirms execution; children such as `powershell.exe`, `cmd.exe` or `rundll32.exe` with encoded or download commands are strong compromise indicators.

If Sysmon is not deployed, use Windows Security EventCode 4688 (process creation, requires command-line auditing): fields `New_Process_Name`, `Process_Command_Line`, `Creator_Process_Name`.

### 4.5 Correlate Download (Proxy / DNS) With Execution

Purpose: link the DNS lookup and proxy download to the endpoint execution to see the full chain.

```spl
index=proxy url="*invoice_update.js*"
| table _time src_ip user url dest http_method status bytes_in http_user_agent
```

**What to look for:** A successful (`200`) download from an unfamiliar or newly seen domain confirms the delivery source; other users fetching the same URL widen the scope.

```spl
index=sysmon EventCode=22 host="<host>" QueryName="<domain>"
| table _time host Image QueryName QueryResults
```

**What to look for:** Lookups by a browser just before the download are expected; lookups by `wscript.exe` or `powershell.exe` suggest the script is reaching out on its own.

```spl
index=sysmon EventCode=3 host="<host>"
    (Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\powershell.exe")
| stats count values(DestinationIp) as dest_ip values(DestinationPort) as dest_port values(DestinationHostname) as dest_host by Image
```

**What to look for:** Script hosts rarely need network access, so any connection from `wscript.exe`/`cscript.exe` is suspicious; PowerShell connecting to rare external IPs right after execution suggests a second-stage download or C2.

### 4.6 Normalize Field Names Across Sources

Purpose: unify endpoint, proxy and DNS fields so you can pivot reliably by `host`, `user`, `file_path`, `file_name`, `sha256`, `action`.

```spl
(index=sysmon OR index=proxy OR index=dns) "<SHA256_or_FileName>"
| eval host=coalesce(dest, hostname, Computer, host),
       user=coalesce(user, username, User, account),
       file_path=coalesce(file_path, filepath, path, TargetFilename),
       file_name=coalesce(file_name, filename, name),
       sha256=coalesce(sha256, file_hash, hash),
       action=coalesce(action, event_type, activity)
| table _time index sourcetype host user file_path file_name sha256 action
| sort _time
```

**What to look for:** Empty normalized columns mean a source uses a field name not in the `coalesce()` list; add it so the timeline across indexes reads cleanly.

| Source field (varies) | Normalized field |
|---|---|
| dest / hostname / computer | `host` |
| username / user / account | `user` |
| filepath / path / file_path | `file_path` |
| file_name / filename / name | `file_name` |
| hash / sha256 / file_hash | `sha256` |
| event_type / action / activity | `action` |

### 4.7 Defender AV Events in Splunk

Purpose: confirm detection and remediation from the Windows Defender operational log (1116 = malware detected, 1117 = action taken to protect the system).

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational" (EventCode=1116 OR EventCode=1117)
| table _time host EventCode Threat_Name Path Action_Name Detection_User
```

**What to look for:** Every 1116 should be followed by a 1117 with a quarantine or remove action; a 1116 without a matching 1117 means the threat may not have been remediated.

### Hunt and Correlate: Key Takeaways

- **Hunt by hash** - pivot on SHA-256 to find every host with the same file.
- **Correlate the chain** - DNS (resolution) → proxy (download) → endpoint (write and execute), joined by time, host and hash.
- **Normalize fields** - consistent names make correlation searches reusable.

---

## 5. Threat Intelligence Enrichment

"Reputation helps. Context decides." Combine multiple sources with what you see in your own environment.

### What to Check

| Indicator | Sources | What you are looking for |
|---|---|---|
| SHA-256 | VirusTotal, MalwareBazaar, Defender file page / Threat analytics, AlienVault OTX | Detection ratio, family name, first submission date, sandbox behavior, related samples |
| Domain | VirusTotal, URLScan.io, OTX, WHOIS | Domain age, hosting, categorization, other malicious URLs on the domain |
| URL | URLScan.io, VirusTotal, URLhaus | Page screenshot, redirects, served files, known campaign |
| IP | AbuseIPDB, VirusTotal, OTX, Shodan | Abuse reports, ASN/hosting provider, known C2 infrastructure |
| Signer certificate | File page, VirusTotal "Signature info" | Valid / revoked / self-signed, known abused certificates |

### Checklist

- [ ] **Check trusted intel** - at least two reputable sources, not just one AV verdict.
- [ ] **Check in a sandbox** - detonate in an approved sandbox (Defender deep analysis, your org's sandbox, or existing public reports). Do not upload sensitive internal files to public services without approval; searching by hash is safe.
- [ ] **Check internal prevalence** - how many of your hosts have it (queries 3.4 / 4.2).
- [ ] **Check the signer** - code-signing certificate, publisher, validity.

### Interpreting Verdicts

| Result | Meaning | Action |
|---|---|---|
| Many engines detect, named family | Known malware | Treat as true positive, scope and respond |
| Few engines, generic names | Possibly malicious, or grayware / heuristic FP | Investigate behavior and context |
| Zero detections | Clean **or** new / targeted | Do not treat as clean; rely on behavior and prevalence |
| Hash not found at all | Never seen publicly - unique or targeted | Higher suspicion for unsigned scripts / executables |
| Valid signature from known vendor, high prevalence | Likely legitimate | Validate path and parent before closing |

Example: SHA-256 `a3f5...9c21`, VirusTotal confidence High, internal prevalence Low (3 hosts) → **Investigate**. Hash reputation may be absent or new; don't treat no hits as clean. **Validate before action.**

---

## 6. Verdict: True Positive vs Benign

| Indicator | Likely true positive | Likely benign |
|---|---|---|
| File type vs name | Script / executable posing as document (`invoice_update.js`, `report.pdf.exe`) | Type matches purpose |
| Origin | Unknown / newly registered domain, phishing email, file-sharing site | Corporate software portal, known vendor |
| Signer | Unsigned or invalid / revoked certificate | Valid signature from expected publisher |
| Prevalence | Rare globally and internally | Widespread in org, known application |
| Execution | Run by `wscript.exe` / `mshta.exe`, spawned PowerShell or LOLBins | Not executed, or executed by expected installer |
| Network | Connections to rare domains / IPs after execution | None, or only to vendor update servers |
| Persistence | New Run key, Startup item, scheduled task | None |
| TI | Multiple sources, named family | Clean across sources plus clean behavior |

### Common False Positives

- Admin / IT scripts (`.js`, `.vbs`, `.ps1`) used for deployment or login.
- Developer tools and packages (Node.js modules, build scripts, test files with EICAR-like strings).
- Penetration testing / red team tools and security research downloads.
- Software cracks, key generators, and adware/PUA (still a policy violation, but not targeted compromise).
- Packed or obfuscated legitimate installers flagged by heuristics.
- Archive scanning of backup or quarantine folders.

Document the rationale for every benign closure and, if appropriate, tune with a scoped exclusion or allow indicator (never a broad folder exclusion).

### Common Beginner Mistakes

- Closing the alert because the file was "quarantined" without checking whether it executed before detection.
- Treating zero VirusTotal detections as proof the file is clean.
- Investigating only the one host in the alert instead of searching the hash across the estate.
- Uploading a sensitive internal file to a public sandbox instead of searching by hash.
- Adding a broad folder or process exclusion to silence a false positive instead of a scoped, hash-based allow indicator.

---

## 7. Response Checklist

Principle: **Contain the file. Scope the impact.** Confirm verdict, search hash across endpoints, isolate only if execution / compromise is confirmed, then remove artifacts, investigate persistence, restore, and tune allow/block controls.

### Contain

- [ ] Confirm the verdict and that Defender quarantine / remediation **succeeded** on the affected host.
- [ ] Search the hash across all endpoints (3.4, 4.2) and quarantine everywhere: Defender file page → **Stop and Quarantine File**.
- [ ] Add a **Block** indicator for the SHA-256 (Settings → Endpoints → Indicators) and block the origin URL / domain (Defender indicators, proxy, DNS filter).
- [ ] **Isolate the device only if execution or compromise is confirmed** (child processes, C2 traffic, persistence).
- [ ] If credentials may be exposed (infostealer behavior): reset the user's password and revoke sessions / refresh tokens.
- [ ] Purge the delivering email from all mailboxes (Threat Explorer / soft delete) and block the sender.

### Eradicate

- [ ] Remove the artifact and any dropped second-stage files.
- [ ] Remove persistence: Run keys, Startup folder items, scheduled tasks, services, WMI subscriptions.
- [ ] Run a full antivirus scan on affected devices.
- [ ] Consider changing default file association for `.js` / `.vbs` / `.hta` to Notepad, or restrict Windows Script Host via policy.

### Recover

- [ ] Release device from isolation after clean verification.
- [ ] Reimage if compromise depth is uncertain or the payload was a RAT / loader that ran.
- [ ] Confirm the user can work normally; release false-positive files from quarantine only after validation.
- [ ] Tune allow / block controls (indicators, ASR rules such as "Block JavaScript or VBScript from launching downloaded executable content").

### Preserve Evidence

- [ ] Collect an investigation package from Defender before remediation if execution is suspected.
- [ ] Export relevant hunting results, device timeline, and Splunk searches to the case.
- [ ] Retain a copy of the sample (Defender "Download file" / quarantine) in a secure, password-protected archive.
- [ ] Record all IOCs: hashes, URLs, domains, IPs, file paths, registry keys, task names.
- [ ] Write a timeline: download → write → execution → detection → quarantine → response actions.

### Monitor

- [ ] Create a custom detection or Splunk alert for the hash, domain, and behavior (for example `wscript.exe` launching from Downloads).
- [ ] Watch the user and host for 7-14 days for new alerts, unusual sign-ins, or outbound traffic.
- [ ] Share IOCs with your TI platform / ISAC.
- [ ] Brief the user on the lure; feed into awareness training.
- [ ] Hold a short lessons-learned: what control stopped it, what would have stopped it earlier.

---

## 8. Quick Reference

### Cheat Sheet

| Step | Defender XDR | Splunk | Intel |
|---|---|---|---|
| Creation | `DeviceFileEvents` (`FileCreated`, `FileOriginUrl`) | Sysmon 11 / 15 | - |
| Execution | `DeviceProcessEvents` | Sysmon 1, Security 4688 | Sandbox report |
| Detection | `DeviceEvents` `AntivirusDetection`, alert | Defender 1116 / 1117 | AV verdicts |
| Prevalence | `DeviceFileEvents` by `SHA256` + `FileProfile()` | `stats dc(host) by sha256` | VT, MalwareBazaar, OTX |
| Download source | `FileOriginUrl`, `DeviceNetworkEvents` | Proxy, Sysmon 22 (DNS), 3 (network) | URLScan, VT, AbuseIPDB |
| Persistence | `DeviceRegistryEvents`, `ScheduledTaskCreated` | Sysmon 12/13 (registry), Security 4698 (task) | - |
| Email | `EmailAttachmentInfo`, `EmailEvents`, `UrlClickEvents` | O365 / mail logs | Sender / domain rep |
| Contain | Stop and Quarantine File, Block indicator, Isolate | Scope searches | Block IOCs |

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|---|---|
| [Respond to a Suspicious File Incident in 13 Minutes](https://www.youtube.com/watch?v=eVyuQRIEAhg) | A quick end-to-end response to a suspicious file alert. |
| [Malware Analysis Basics with Real-World Tools](https://www.youtube.com/watch?v=wJEuQPG_FGI) | Introductory malware analysis using common real-world tools. |
| [Hands-on with ANY.RUN: Malware Analysis for SOC Analysts](https://www.youtube.com/watch?v=xaIzf6kXHTI) | Detonating and analysing samples in the ANY.RUN interactive sandbox. |
| [How I Handled WannaCry Ransomware Alerts on EDR](https://www.youtube.com/watch?v=rku3JkbQrHg) | Working real ransomware alerts in an EDR console. |
| [Wazuh + n8n + VirusTotal: Real-Time Threat Detection Workflow](https://www.youtube.com/watch?v=XZW4A5tOBjc) | Automating file and hash reputation checks with Wazuh, n8n and VirusTotal. |
| [YARA for Security Analysts: Crash Course](https://www.youtube.com/watch?v=LQnfjwAgCnE) | Writing and using YARA rules to identify malicious files. |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|---|---|
| [Malware Alert Triage](https://app.haxcamp.com/lab/malware-alert-triage) | Analyse an endpoint alert for a suspicious file, look up its hash, decide on the endpoint |
| [Windows Defender Log](https://app.haxcamp.com/lab/windows-defender-log) | Read and interpret Microsoft Defender event logs |
| [AI Malware Hash Investigator Using n8n](https://app.haxcamp.com/lab/ai-malware-hash-investigator-using-n8n) | Automate malware hash triage with VirusTotal |
| [File Hash Reputation Checker Using n8n](https://app.haxcamp.com/lab/file-hash-reputation-checker-using-n8n) | Check suspicious hashes against VirusTotal |
| [AI Malware Sandbox Report Summarizer Using n8n](https://app.haxcamp.com/lab/ai-malware-sandbox-report-summarizer-using-n8n) | Hash a sample and pull MalwareBazaar intelligence |
| [Introduction to EDR](https://app.haxcamp.com/lab/introduction-to-edr) | How EDR records device activity |

### Official Documentation

- [MITRE ATT&CK T1204.002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1059.007: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Advanced Hunting Overview](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [DeviceFileEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [FileProfile() Function](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function)
- [Take Response Actions on a File](https://learn.microsoft.com/en-us/defender-endpoint/respond-file-alerts)
- [Create Indicators for Files](https://learn.microsoft.com/en-us/defender-endpoint/indicator-file)
- [Attack Surface Reduction Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft Defender Antivirus Event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk CIM Endpoint Data Model](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- [Splunk stats Command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
