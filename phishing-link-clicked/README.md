# Phishing Link Clicked - SOC Investigation Playbook

A practitioner playbook for working out what happened after a user clicked a link in a phishing email, covering the click, the account and the endpoint, using Microsoft Defender XDR, Splunk and threat intelligence.

> **Level:** Beginner to Intermediate · **Time:** ~45 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to rebuild the click-to-activity chain, how to scope a phishing campaign across users, how to decide and act on a verdict
>
> **Prerequisites:** basic email header concepts, Windows process basics and KQL/SPL syntax

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

1. Open the alert and note the user, the clicked URL, the click time (UTC) and the `NetworkMessageId`.
2. Check the click verdict: was it `ClickAllowed`, `ClickBlocked`, or clicked through a warning (`IsClickedThrough`)?
3. Rule out a phishing simulation or a link-scanner pre-fetch (check sender/IP against the simulation allow list).
4. Look up the URL and domain reputation passively (never browse to it directly) and note the domain age.
5. Check the user's sign-ins in the 24 hours after the click for new IPs, countries or risky sessions.
6. Check the user's device for PowerShell, script hosts or downloads started by the browser or Outlook right after the click.
7. Count how many other users received or clicked the same message.

**Escalate immediately if:** a successful sign-in from an unfamiliar IP/country follows the click, a browser or Outlook spawns PowerShell or a script host, or new inbox/forwarding rules appear on the mailbox.

---

## 1. What This Alert Means

A user received a message (usually email, sometimes Teams or another chat tool), clicked a link in it, and that click was recorded by Safe Links, a proxy or an endpoint sensor. The alert itself only proves the **click**. Your job is to rebuild the **click-to-activity chain** and find out how far the attack got:

```text
Message delivered -> URL clicked -> Sign-in (attempt) -> Endpoint process (e.g. powershell.exe)
```

Each step tells you how serious the incident is:

| Stage reached | What it usually means | Severity |
|---|---|---|
| Message delivered, no click | Exposure only | Low |
| URL clicked, blocked by Safe Links or proxy | Attempt stopped | Low-Medium |
| URL clicked and allowed / clicked through | User reached the attacker page | Medium |
| Credentials entered / suspicious sign-in follows | Possible account compromise (credential theft or AiTM) | High |
| Process execution on endpoint (PowerShell, script host, LOLBin) | Possible malware delivery / initial access on host | High-Critical |

**Why attackers do it**
- **Credential harvesting**: a fake Microsoft 365 / VPN / SSO login page collects usernames, passwords and sometimes MFA codes.
- **Adversary-in-the-Middle (AiTM)**: reverse-proxy kits (e.g. Evilginx-style) steal the **session cookie**, which gets around standard MFA.
- **Payload delivery**: the link downloads an archive, ISO, LNK, HTA or script that launches `powershell.exe`, `mshta.exe`, `wscript.exe` and so on.
- **Foothold for follow-on attacks**: mailbox access enables BEC, internal phishing, inbox rules and data theft.

**MITRE ATT&CK mapping**

| Technique ID | Name | Where it shows up |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | The delivered message |
| T1204.001 | User Execution: Malicious Link | The click |
| T1056.003 | Input Capture: Web Portal Capture | Fake login page |
| T1557 | Adversary-in-the-Middle | AiTM proxy login pages |
| T1539 | Steal Web Session Cookie | Session token theft via AiTM |
| T1078.004 | Valid Accounts: Cloud Accounts | Attacker sign-in with stolen creds |
| T1059.001 | Command and Scripting Interpreter: PowerShell | `powershell.exe` after the click |
| T1027 | Obfuscated Files or Information | `powershell -enc` encoded commands |
| T1105 | Ingress Tool Transfer | Second-stage download |
| T1114.003 | Email Collection: Email Forwarding Rule | Post-compromise mailbox rules |

### Key Terms

| Term | Plain-English meaning |
|---|---|
| Safe Links | A Defender for Office 365 feature that rewrites email links and checks them at click time. |
| NetworkMessageId | A unique ID Microsoft 365 gives each email, used to tie a click back to the original message. |
| AiTM (Adversary-in-the-Middle) | A fake login page that sits between the user and the real site and steals the session cookie, bypassing standard MFA. |
| SPF / DKIM / DMARC | Email authentication checks that show whether a sender is allowed to send for the domain it claims. |
| LOLBin | A legitimate Windows tool (e.g. `mshta.exe`, `certutil.exe`) abused by attackers to run or download code. |
| ZAP (Zero-hour Auto Purge) | A Microsoft 365 feature that removes already-delivered emails once they are found to be malicious. |
| Refresh token | A long-lived credential that keeps a user signed in; revoking it forces sign-out everywhere. |
| BEC (Business Email Compromise) | Fraud carried out from, or by impersonating, a real business mailbox, often after credential theft. |

---

## 2. Alert Triage

**Starting point: "Suspicious - not confirmed."** Do not close or escalate until you have worked through the checklist below.

### Investigation Checklist

- [ ] **Message headers**: sender (From vs envelope MailFrom vs Reply-To), delivery path (Received hops, sending IP), authentication results (SPF, DKIM, DMARC, composite auth).
- [ ] **URL**: the full URL including query string, the redirect chain (shorteners, open redirects, Safe Links wrapping), reputation of domain and IP.
- [ ] **Click verdict**: was the click allowed, blocked, or clicked through a warning page? Malicious / suspicious / benign verdict from Safe Links or the proxy.
- [ ] **User sign-ins**: time relative to the click, result (success/failure/MFA interrupted), location / IP / ASN, user agent, risk level.
- [ ] **Endpoint timeline**: processes after the click, parent/child relationships (browser → PowerShell is a red flag), user context, files written, network connections.
- [ ] **Report scope**: affected user(s), every recipient of the same message/campaign, time window, impact (credentials, data, host).

### Key Fields to Collect

| Field | Example | Why it matters |
|---|---|---|
| User / UPN | `jdoe@contoso.com` | Pivot key for identity and mail |
| NetworkMessageId / Internet Message-ID | `4f6b9e3d-...` / `<abc123@...>` | Ties the click to the original email |
| Sender (From / MailFrom / Reply-To) | `phish@bad.com` | Spoofing, lookalike domain, campaign pivot |
| Subject | `Invoice update` | Campaign pivot |
| Sender IP | `203.0.113.10` | Infrastructure reputation |
| Full URL + final landing URL | `https://evil-example.com/login` | TI lookup, blocking |
| Click time (UTC) | `2025-01-23 14:52:37Z` | Anchor for the timeline |
| Click action / IsClickedThrough | `ClickAllowed` / `true` | Did the user actually reach the page |
| Device name / IP | `WS-102` | Endpoint pivot |
| Sign-in IP / country / app / result | `198.51.100.7`, `NL`, `OfficeHome`, success | Credential compromise indicator |
| Suspicious process + command line | `powershell.exe -enc ...` | Execution indicator |

---

## 3. Investigation in Microsoft Defender XDR

Run these in **Advanced Hunting** (Microsoft Defender portal > Hunting). Replace placeholders such as `<UserUpn>`, `<DeviceName>`, `<NetworkMessageId>`, `<Domain>`.

> Note: table availability depends on licensing. `UrlClickEvents` needs Defender for Office 365 Safe Links; `AADSignInEventsBeta` needs Defender for Identity/Entra ID P2 data (newer tenants also have `EntraIdSignInEvents`). In `UrlClickEvents`, real `ActionType` values are `ClickAllowed`, `ClickBlocked`, `ClickBlockedByTenantPolicy`, `UrlScanInProgress` and `UrlErrorPage`, so expect those and not plain "Clicked"/"Blocked".

### 3.1 Find the User's URL Clicks

Purpose: list every Safe Links click for the user and highlight click-throughs past a warning.

```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<UserUpn>"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, Workload,
          IPAddress, ThreatTypes, DetectionMethods, NetworkMessageId
| order by Timestamp desc
```

**What to look for:** `ClickAllowed` or `IsClickedThrough == true` means the user reached the page; `ClickBlocked` with no further clicks usually means the attempt was stopped.

### 3.2 Pivot on NetworkMessageId to the Original Email

Purpose: get sender, authentication, delivery and detection details for the message behind the click.

```kql
let msgId = "<NetworkMessageId>";
EmailEvents
| where Timestamp > ago(30d)
| where NetworkMessageId == msgId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderMailFromAddress,
          SenderDisplayName, SenderIPv4, Subject, AuthenticationDetails,
          DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods,
          ConfidenceLevel, InternetMessageId
| join kind=leftouter (
    EmailUrlInfo
    | where NetworkMessageId == msgId
    | summarize Urls = make_set(Url), UrlDomains = make_set(UrlDomain) by NetworkMessageId
  ) on NetworkMessageId
```

**What to look for:** failed SPF/DKIM/DMARC in `AuthenticationDetails`, a From/MailFrom mismatch or a lookalike sender domain are suspicious; passing authentication from a known partner domain points toward benign.

Check `EmailPostDeliveryEvents` for the same `NetworkMessageId` to see whether ZAP or an admin has already removed it.

### 3.3 Scope the Campaign: Who Else Received or Clicked It

Purpose: find every recipient of messages that contain the malicious domain and whether they clicked.

```kql
let badDomain = "<Domain>";
let msgs = EmailUrlInfo
    | where Timestamp > ago(14d)
    | where UrlDomain has badDomain
    | distinct NetworkMessageId;
EmailEvents
| where Timestamp > ago(14d)
| where NetworkMessageId in (msgs)
| project NetworkMessageId, Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, DeliveryLocation
| join kind=leftouter (
    UrlClickEvents
    | where Timestamp > ago(14d)
    | where NetworkMessageId in (msgs)
    | summarize Clicks = count(), ClickedThrough = countif(IsClickedThrough), LastClick = max(Timestamp) by NetworkMessageId, AccountUpn
  ) on NetworkMessageId
| order by Clicks desc
```

**What to look for:** many recipients from one sender or subject indicates a campaign; any row with `ClickedThrough > 0` is another user who needs the same investigation.

### 3.4 Sign-Ins After the Click (Credential Compromise Check)

Purpose: find sign-ins in the hours after the click from new IPs, countries or risky sessions.

```kql
let user = "<UserUpn>";
let clickTime = datetime(<YYYY-MM-DDTHH:MM:SSZ>);
AADSignInEventsBeta
| where Timestamp between (clickTime - 1h .. clickTime + 24h)
| where AccountUpn =~ user
| project Timestamp, AccountUpn, Application, LogonType, ErrorCode, IPAddress, Country, City,
          UserAgent, RiskLevelDuringSignIn, RiskLevelAggregated, ConditionalAccessStatus,
          AuthenticationRequirement, DeviceName, IsManaged
| order by Timestamp asc
```

**What to look for:** red flags are `ErrorCode == 0` (success) from an unfamiliar IP/ASN shortly after the click; `AuthenticationRequirement == "singleFactorAuthentication"` from unmanaged devices; elevated `RiskLevelDuringSignIn`; hosting-provider IPs.

### 3.5 Endpoint: Browser-Spawned or Suspicious Processes After the Click

Purpose: find PowerShell, script hosts or LOLBins started around the click on the user's device.

```kql
let device = "<DeviceName>";
let clickTime = datetime(<YYYY-MM-DDTHH:MM:SSZ>);
DeviceProcessEvents
| where Timestamp between (clickTime - 5m .. clickTime + 2h)
| where DeviceName =~ device
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","msiexec.exe","certutil.exe","bitsadmin.exe")
   or InitiatingProcessFileName in~ ("msedge.exe","chrome.exe","firefox.exe","outlook.exe","explorer.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

**What to look for:** a browser or Outlook launching PowerShell, `mshta.exe` or a script host, especially with encoded or download commands, is suspicious; normal browser child processes (renderer or update processes) are expected noise.

### 3.6 Endpoint: Downloads and Network Connections to the Phishing Infrastructure

Purpose: confirm whether the device contacted the domain and whether any file was written from the browser.

```kql
let device = "<DeviceName>";
let badDomain = "<Domain>";
union
( DeviceNetworkEvents
  | where Timestamp > ago(7d) and DeviceName =~ device
  | where RemoteUrl has badDomain
  | project Timestamp, DeviceName, Source = "Network", InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, Detail = ActionType ),
( DeviceFileEvents
  | where Timestamp > ago(7d) and DeviceName =~ device
  | where ActionType == "FileCreated"
  | where FileOriginUrl has badDomain or FileOriginReferrerUrl has badDomain
  | project Timestamp, DeviceName, Source = "File", InitiatingProcessFileName, RemoteUrl = FileOriginUrl, Detail = strcat(FolderPath, " | ", SHA256) )
| order by Timestamp asc
```

**What to look for:** network rows confirm the device reached the domain; any file row (especially archives, ISO, LNK, HTA or scripts) means a payload landed and should be checked for execution in 3.5.

### 3.7 Post-Compromise Mailbox Activity

Purpose: detect inbox rules, forwarding or mass mail access by the account after the sign-in.

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where AccountDisplayName has "<UserDisplayName>" or tostring(RawEventData.UserId) =~ "<UserUpn>"
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox","MailItemsAccessed","Send")
| project Timestamp, ActionType, IPAddress, CountryCode, ISP, UserAgent, RawEventData
| order by Timestamp desc
```

**What to look for:** new inbox or forwarding rules (especially ones that move or delete mail) or `MailItemsAccessed` from an IP that matches the suspicious sign-in are strong compromise signs; activity only from the user's usual IPs is normal.

**Build the End-to-End Story:** pair the email (3.2) and click (3.1) with the user timeline (3.4, 3.7) and the device timeline (3.5, 3.6). The device page in the portal and its Timeline tab show the same information visually.

---

## 4. Investigation in Splunk

Splunk is your **correlation layer** across email, identity, endpoint and network. The `index` and `sourcetype` names below are common defaults (Sysmon via Splunk Add-on for Sysmon, Microsoft Cloud Services / Microsoft 365 add-ons). **They vary by environment**, so adjust them and prefer CIM data models (`Email`, `Authentication`, `Endpoint`, `Web`) where they are populated.

### 4.1 Email-to-Endpoint Correlation

Purpose: link the suspicious email to the user and to PowerShell activity on their host within a time window.

```spl
index=email user="jdoe" (url=* OR action="clicked") earliest=-24h
| stats values(url) as url values(sender) as sender values(subject) as subject min(_time) as first_click by message_id user
| join type=left user
    [ search index=endpoint process_name="powershell.exe" earliest=-24h
      | stats values(host) as host values(process_command_line) as process_command_line min(_time) as first_ps by user ]
| where isnull(first_ps) OR (first_ps >= first_click AND first_ps <= first_click + 7200)
| table user message_id sender subject url host process_command_line
```

**What to look for:** rows where `process_command_line` is populated show PowerShell within two hours of the click and need review; rows with an empty host/command line mean no PowerShell was seen.

Avoid broad joins in production: always filter by user and time first, normalize the user key (`jdoe` vs `jdoe@contoso.com` vs `CONTOSO\jdoe`) with `eval`, and use a time window.

### 4.2 Sysmon Process Creation (EventCode 1) from Browser or Office Parents

Purpose: detect PowerShell or script hosts spawned by a browser or Outlook.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host="<DeviceName>"
    (ParentImage="*\\msedge.exe" OR ParentImage="*\\chrome.exe" OR ParentImage="*\\firefox.exe" OR ParentImage="*\\outlook.exe" OR ParentImage="*\\explorer.exe")
    (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\mshta.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\cmd.exe")
| eval encoded=if(match(CommandLine, "(?i)\s-(e|enc|encodedcommand)\s"), "yes", "no")
| table _time host User ParentImage Image CommandLine encoded Hashes
| sort _time
```

**What to look for:** `encoded=yes` or a browser/Outlook parent launching a script host is highly suspicious; `explorer.exe` launching `cmd.exe` alone can be normal user activity, so check the command line.

### 4.3 Sysmon DNS (EventCode 22) and Network (EventCode 3) to the Phishing Domain

Purpose: confirm which hosts resolved or connected to the domain, and which process did it.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    ((EventCode=22 QueryName="*<Domain>*") OR (EventCode=3 DestinationHostname="*<Domain>*"))
| eval dest=coalesce(QueryName, DestinationHostname)
| stats min(_time) as first_seen max(_time) as last_seen values(Image) as process values(DestinationIp) as dest_ip count by host dest
| convert ctime(first_seen) ctime(last_seen)
```

**What to look for:** a browser process resolving the domain matches the click; a non-browser process (PowerShell, `rundll32.exe`) contacting it suggests a payload is calling back.

### 4.4 Proxy / Web Gateway: Who Visited the URL

Purpose: scope every user and host that reached the domain, and whether the proxy allowed it.

```spl
index=proxy (url="*<Domain>*" OR dest="*<Domain>*") earliest=-7d
| stats min(_time) as first_seen max(_time) as last_seen values(url) as urls values(action) as action values(http_method) as methods count by user src
| convert ctime(first_seen) ctime(last_seen)
| sort first_seen
```

**What to look for:** a `POST` to the phishing domain strongly suggests that credentials were submitted.

### 4.5 Entra ID (Azure AD) Sign-Ins After the Click

Purpose: find successful or risky sign-ins from new locations soon after the click.

```spl
index=azure sourcetype="azure:aad:signin" userPrincipalName="<UserUpn>" earliest=-24h
| eval result=if('status.errorCode'==0, "success", "failure")
| table _time userPrincipalName appDisplayName ipAddress location.countryOrRegion location.city result status.errorCode riskLevelDuringSignIn conditionalAccessStatus userAgent
| sort _time
```

**What to look for:** a `success` result from a new country, IP or user agent soon after the click is suspicious; failures alone may just be the attacker testing a wrong password.

(The sourcetype may be `ms:aad:signin`, `azure:monitor:aad` or similar, depending on the add-on.)

### 4.6 Windows Security Logons on the Endpoint

Purpose: check for new logons (4624), failed logons (4625) or explicit-credential use (4648) on the host after the click.

```spl
index=wineventlog sourcetype="WinEventLog:Security" host="<DeviceName>" (EventCode=4624 OR EventCode=4648 OR EventCode=4625)
| table _time host EventCode Account_Name Logon_Type Source_Network_Address Process_Name
| sort _time
```

**What to look for:** 4648 explicit-credential use or network/remote logons from unexpected sources after the click are suspicious; interactive logons by the user at normal hours are expected.

### 4.7 Office 365 Mailbox Rules After Compromise

Purpose: detect forwarding or deletion rules created by the attacker.

```spl
index=o365 sourcetype="o365:management:activity" Workload=Exchange (Operation="New-InboxRule" OR Operation="Set-InboxRule" OR Operation="UpdateInboxRules" OR Operation="Set-Mailbox") UserId="<UserUpn>"
| table _time UserId Operation ClientIP Parameters{}.Name Parameters{}.Value
| sort - _time
```

**What to look for:** rules that forward externally, delete mail or move it to obscure folders (e.g. RSS Feeds), created from an unfamiliar `ClientIP`, indicate attacker persistence.

---

## 5. Threat Intelligence Enrichment

**Validate the URL and domain before you act.** Two rules first:
- **Do not open the suspicious link directly** from your workstation. Use sandboxes and passive lookups.
- **Reputation is context, not proof.** Always weigh it against the message and tenant evidence.

| Check | What to look at | Tools |
|---|---|---|
| Reputation | Vendor detections, categories, community comments | VirusTotal, Microsoft Defender TI, AlienVault OTX, Cisco Talos |
| Certificate / registration | Domain age (newly registered is a red flag), registrar, WHOIS privacy, certificate issue date, cert SANs | WHOIS/RDAP, crt.sh, VirusTotal |
| Redirects | Full redirect chain, final landing page, brand impersonation, cloaking | URLScan.io, sandbox detonation |
| Passive DNS | Historical IPs, co-hosted domains, fast-flux | VirusTotal Relations, Defender TI, OTX |
| Proxy logs | Who else accessed the domain, POST requests, downloads | Splunk proxy index, `DeviceNetworkEvents` |
| IP reputation | Hosting/VPS/anonymizer ASN, abuse reports | AbuseIPDB, VirusTotal, GreyNoise |
| File hashes | Known malware family, first seen, sandbox behaviour | VirusTotal, MalwareBazaar, Hybrid Analysis |

**Interpreting Verdicts**

| Result | Meaning | Action |
|---|---|---|
| Multiple reputable engines malicious, domain under 30 days old, brand-impersonating login page | High confidence malicious | Block and contain |
| 0-2 detections, but young domain or credential form | Suspicious; TI may simply not have caught up yet | Treat by tenant evidence; sandbox it |
| Clean, long-established, legitimate business | Likely benign, but check for compromised legit site / open redirect | Validate redirect chain |
| Hash unknown everywhere | Not proof of safety; could be unique/polymorphic | Rely on behaviour (process tree) |

**Verify before action.** Record IOCs (URL, domain, IPs, hashes, sender) in the ticket together with the source and timestamp of each lookup.

---

## 6. Verdict: True Positive vs Benign

| Indicator | Points to true positive | Points to benign |
|---|---|---|
| Sender authentication | SPF/DKIM/DMARC fail, lookalike domain, mismatched Reply-To | Passes, known partner domain |
| URL / domain | Newly registered, credential form, brand impersonation, TI hits | Established domain, matches business context |
| Click result | `ClickAllowed` + `IsClickedThrough = true`, proxy allowed, POST seen | `ClickBlocked`, no follow-up traffic |
| Sign-ins | Success from new IP/country/ASN soon after click, risky session, new MFA method | Only normal locations and devices |
| Endpoint | Browser/Outlook spawns PowerShell, encoded command, download + execution | No new processes, file only in Downloads, untouched |
| Mailbox | New inbox/forwarding rules, mass send, MailItemsAccessed from new IP | None |
| Scope | Same message to many users, other clicks | Single legitimate email |

**Common False Positives**
- Security-awareness phishing simulations (Attack Simulation Training, KnowBe4 and similar). Check sender/IP against the simulation allow list.
- Safe Links or sandbox detonation "clicks" and pre-fetch by link scanners, which is not a human click.
- Marketing / newsletter links with tracking redirectors flagged as suspicious.
- Legitimate SaaS login pages on new domains (new vendor onboarding).
- Admin or IT scripts running `powershell.exe` around the same time, not related to the click.

**Classify:** True Positive (compromise confirmed), True Positive (attempt blocked / no impact), Benign True Positive (simulation), or False Positive. Document the evidence for each conclusion.

### Common Beginner Mistakes

- Closing the alert because Safe Links blocked one click, without checking for other clicks, other recipients or a click-through.
- Opening the suspicious URL directly in a workstation browser instead of using a sandbox or passive lookup.
- Treating a clean VirusTotal result as proof of safety for a newly registered domain.
- Skipping sign-in and mailbox checks: AiTM attacks can leave no trace on the endpoint.
- Isolating the device or resetting the password before collecting evidence and scoping the campaign.

---

## 7. Response Checklist

Tool roles: **Defender** investigates and responds (purge, block, revoke, isolate). **Splunk** correlates across email, identity, endpoint and network. **TI** adds reputation, TTPs and related IOCs.

### Contain
- [ ] **Purge / quarantine matching emails**: Defender > Explorer / Advanced Hunting > Take action > Soft/Hard delete or move to quarantine for every recipient of the campaign (match by sender, subject, URL domain, NetworkMessageId).
- [ ] **Block the URL/domain after validation**: add to Tenant Allow/Block List (URLs and sender), Defender for Endpoint custom indicators (URL/domain/IP), and the web proxy / firewall / DNS filter.
- [ ] Block the sender address/domain and sending IP if the source is not a legitimate compromised partner.
- [ ] **Revoke sessions if compromised**: revoke refresh tokens (Entra ID "Revoke sessions" / `Revoke-MgUserSignInSession`), then reset the password.
- [ ] Require MFA re-registration if attacker-added MFA methods are found; enforce MFA / Conditional Access if missing.
- [ ] **Isolate the endpoint only if malicious execution is confirmed** (Defender for Endpoint > Isolate device). Avoid isolating on a click alone.
- [ ] Temporarily disable the account if active attacker use is ongoing.

### Eradicate
- [ ] Remove attacker inbox rules, forwarding, delegated permissions and malicious OAuth app consents.
- [ ] Remove dropped files and persistence (scheduled tasks, Run keys, services) found in the device timeline; run a full AV scan.
- [ ] Block file hashes (Defender indicators) for any payloads.
- [ ] Reimage the host if the extent of compromise cannot be determined confidently.

### Recover
- [ ] Release the device from isolation once it is clean; confirm sensor health.
- [ ] Re-enable the account with a new password and verified MFA methods.
- [ ] Notify the user, explain what happened and what to watch for; notify any internal/external contacts who received follow-on phishing from the account.

### Preserve Evidence
- [ ] Export the original message (.eml) with headers, and the click events, sign-in logs and device timeline.
- [ ] Collect an investigation package from Defender for Endpoint before reimaging.
- [ ] Record all IOCs, query results, timestamps (UTC) and actions taken in the ticket.

### Monitor
- [ ] **Hunt other recipients and clicks** (queries 3.3, 4.4) and validate full scope.
- [ ] Watch the user's sign-ins and mailbox activity for 7-14 days.
- [ ] **Tune detections**: turn hunting queries into custom detection rules / Splunk correlation searches; tune sensors and Safe Links policies.
- [ ] Feed lessons into awareness training and reporting-button adoption.

---

## 8. Quick Reference

### Cheat Sheet

| Question | Defender XDR | Splunk |
|---|---|---|
| Did the user click, and was it allowed? | `UrlClickEvents` (ActionType, IsClickedThrough) | `index=proxy`, email gateway logs |
| What was the email? | `EmailEvents`, `EmailUrlInfo`, `EmailPostDeliveryEvents` | `index=email` / CIM `Email` |
| Who else got it / clicked? | `EmailUrlInfo` + `EmailEvents` + `UrlClickEvents` | `index=email`, `index=proxy` by domain |
| Were credentials used? | `AADSignInEventsBeta`, `IdentityLogonEvents` | `azure:aad:signin`, CIM `Authentication` |
| Did anything execute? | `DeviceProcessEvents` | Sysmon EventCode 1 |
| Network / download? | `DeviceNetworkEvents`, `DeviceFileEvents` | Sysmon EventCode 3, 22, 11; proxy |
| Mailbox abuse? | `CloudAppEvents` | `o365:management:activity` |
| Host logons? | `DeviceLogonEvents` | Security 4624 / 4625 / 4648 |

**Golden rule:** Detect → Investigate → Respond. Verify before action, and scope before you close.

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|---|---|
| [Introduction to Phishing Analysis and Email Security](https://www.youtube.com/watch?v=gIWNbME4H0s) | An introduction to phishing analysis and the basics of email security. |
| [Email Incident Response Masterclass](https://www.youtube.com/watch?v=Ne4kEw-zQUk) | Responding to email-based security incidents from start to finish. |
| [Phishing Analysis with a Real Email Sample](https://www.youtube.com/watch?v=vK0Vc7wRVEg) | A hands-on analysis of a real phishing email sample. |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|---|---|
| [Phishing Fundamentals](https://app.haxcamp.com/lab/phishing-fundamentals) | How phishing emails are built and what headers reveal |
| [Phishing Alert Triage](https://app.haxcamp.com/lab/phishing-alert-triage) | Triage a user-reported phishing email and enrich IOCs |
| [Email and URL Analysis](https://app.haxcamp.com/lab/email-and-url-analysis) | Forensic header reading and suspicious URL investigation |
| [Phishing Investigation in Splunk](https://app.haxcamp.com/lab/phishing-investigation-in-splunk) | Find recipients, then correlate proxy logs to detect URL clicks |
| [Advanced Phishing Scenarios](https://app.haxcamp.com/lab/advanced-phishing-scenarios) | BEC, OAuth consent phishing and QR code attacks |
| [Proxy Log Analysis](https://app.haxcamp.com/lab/proxy-log-analysis) | Read URL categories and tie web activity to users |

### Official Documentation

- [Microsoft: Advanced Hunting Schema - UrlClickEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table)
- [Microsoft: Advanced Hunting Schema - EmailEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)
- [Microsoft: Advanced Hunting Schema - AADSignInEventsBeta](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table)
- [Microsoft: Safe Links in Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)
- [Microsoft: Phishing Investigation Playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing)
- [Microsoft: Remediate Malicious Email](https://learn.microsoft.com/en-us/defender-office-365/remediate-malicious-email-delivered-office-365)
- [MITRE ATT&CK T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK T1204.001 - Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
- [MITRE ATT&CK T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [Splunk: Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- [Splunk Add-on for Sysmon](https://docs.splunk.com/Documentation/AddOns/released/MSSysmon/About)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
