# Multiple Failed Logins (Brute Force / Password Spray) - SOC Investigation Playbook

A practitioner workflow to Detect, Investigate and Respond to a burst of failed sign-ins that ends in a success, using Microsoft Defender XDR, Splunk and threat intelligence.

> **Level:** Beginner to Intermediate · **Time:** ~45 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to tell brute force from password spraying, how to confirm a failures-then-success sequence, how to decide whether to contain or close
>
> **Prerequisites:** basic Windows Security event logs, Entra ID sign-in concepts and KQL/SPL syntax

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

1. Note the account, source IP, target host and the exact timestamps of the first failure, last failure and the success (with time zone).
2. Check whether the source IP is internal, corporate VPN/egress, or external, and run a quick reputation lookup.
3. Count the distinct accounts the source targeted: one account suggests guessing, many suggests spraying.
4. Read the failure reasons (bad password, unknown user, locked out, MFA denied).
5. Check the MFA outcome of the successful sign-in: passed, failed, or not required.
6. Look for related alerts on the same user or IP (unfamiliar sign-in properties, impossible travel, inbox rules).
7. Ask whether the user recently changed their password or has a known service or app with stale credentials.

**Escalate immediately if:** a success followed the failures without MFA (or via legacy auth), the account is privileged, or post-access activity (inbox rules, MFA changes, odd processes) is present.

---

## 1. What This Alert Means

A "multiple failed logins" alert fires when an identity provider (Entra ID, Active Directory, VPN, web app) records many failed sign-ins in a short window. The real concern is the pattern: **many failures, then a success, from the same source**. That can mean someone guessed the password.

Three main attack shapes:

| Pattern | What it looks like | Typical goal |
|---|---|---|
| **Brute force / password guessing** | One account, many passwords, from one or a few IPs, over a short time | Get into a specific, known account |
| **Password spraying** | Many accounts, one or a few common passwords (`Winter2025!`), slow and spread out to avoid lockout | Find any weak account in the tenant |
| **Credential stuffing** | Many accounts, username/password pairs from earlier breaches | Use passwords people reuse across sites |

**Why attackers do it:** it is cheap, scripted, and works wherever there is no MFA, a weak password policy, or legacy authentication (IMAP/POP/SMTP AUTH, basic auth, NTLM) exposed to the internet. One valid account gives initial access for phishing from inside, data theft from mailboxes, or lateral movement.

### MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|---|---|---|
| T1110 | Brute Force | Parent technique |
| T1110.001 | Brute Force: Password Guessing | Many passwords against one account |
| T1110.003 | Brute Force: Password Spraying | One password against many accounts |
| T1110.004 | Brute Force: Credential Stuffing | Breached credential pairs |
| T1078 | Valid Accounts | The success after the failures |
| T1078.004 | Valid Accounts: Cloud Accounts | Entra ID / Microsoft 365 takeover |
| T1133 | External Remote Services | VPN / RDP gateways used as the target |
| T1021.001 | Remote Services: Remote Desktop Protocol | Interactive session on the endpoint after access |

### Key Terms

| Term | Meaning |
|---|---|
| Password spraying | Trying one or a few common passwords against many accounts to stay under lockout limits. |
| Credential stuffing | Replaying username/password pairs leaked from other breaches. |
| Legacy authentication | Older protocols (IMAP, POP, SMTP AUTH, basic auth) that cannot enforce MFA. |
| MFA | Multi-factor authentication: a second proof of identity beyond the password. |
| Conditional Access | Entra ID policies that allow, block or require MFA based on user, location, device and risk. |
| Smart lockout | Entra ID feature that locks out attackers while trying to keep the real user able to sign in. |
| ASN | Autonomous System Number: identifies the network (ISP or hosting provider) that owns an IP. |
| Logon type | Windows code for how a logon happened, e.g. 2 interactive, 3 network, 10 RDP. |

---

## 2. Alert Triage

Example scenario (documentation values only):

| Item | Value |
|---|---|
| Account | `jdoe` |
| Source | `203.0.113.25` (TEST-NET-3, RFC 5737 documentation range) |
| Activity | 18 failed sign-ins in 4 minutes, then 1 success from the same source |
| Target | `WIN-10-01` |
| Failed attempts | 2025-01-14 10:02:11 to 10:06:03 |
| Successful sign-in | 2025-01-14 10:06:27 |
| Endpoint session | 2025-01-14 10:06:34 |

Status at this point: **Suspicious, not confirmed.** A success after failures is also exactly what a user who forgot their password looks like.

### Triage Checklist

- [ ] **Preserve timestamps** for the whole sequence (first failure, last failure, success, session start - e.g. 10:02:11 to 10:06:34). Record the time zone (UTC vs local).
- [ ] **Check the account and source** (`jdoe`, `203.0.113.25`): is the account privileged, a service account, disabled, or recently created? Is the IP internal, VPN, a corporate egress, or external?
- [ ] **Compare against the baseline**: usual sign-in hours, countries, devices, apps and how often this user fails.
- [ ] **Review the MFA outcome**: was MFA prompted, passed, failed, or not required (bypassed by a trusted location, legacy protocol or excluded policy)?
- [ ] **Review related alerts**: other failed-login alerts, unfamiliar sign-in properties, atypical travel, new device, impossible travel, or mailbox rule alerts for the same user or IP.
- [ ] Count how many **distinct accounts** the source targeted (1 = guessing, many = spraying).
- [ ] Note the **failure reasons** (bad password vs unknown user vs locked out vs MFA denied).

### Key Fields to Collect

| Field | Why it matters | Where (examples) |
|---|---|---|
| Username / UPN | Who is targeted | `UserPrincipalName`, `AccountUpn`, `TargetUserName` |
| Source IP | Who is attacking | `IPAddress`, `RemoteIP`, `IpAddress`, `src_ip` |
| Result / error code | Why it failed | `ResultType`, `ErrorCode`, Windows `Status`/`SubStatus` |
| Logon type | Network (3), RDP (10), interactive (2) | `LogonType` |
| Application / resource | What was accessed | `AppDisplayName`, `Application` |
| Client app / protocol | Legacy auth vs modern | `ClientAppUsed` |
| Device name / ID | Where the session landed | `DeviceName`, `WorkstationName` |
| MFA detail | Was the second factor satisfied | `AuthenticationRequirement`, `AuthenticationDetails` |
| Conditional Access result | Was a policy applied | `ConditionalAccessStatus` |
| Geo / ASN | Location context | `Country`, `City`, `AutonomousSystemNumber` (Sentinel `LocationDetails`) |
| User agent | Scripted tools often show odd agents | `UserAgent` |

Useful Entra ID error codes: `50126` invalid username or password, `50053` account locked (smart lockout) or sign-in blocked, `50057` account disabled, `50055` password expired, `50074`/`50076` strong authentication (MFA) required, `500121` MFA failed or denied, `0` success.

Useful Windows Security event IDs: `4625` failed logon, `4624` successful logon, `4740` account locked out, `4771` Kerberos pre-auth failed, `4776` NTLM credential validation.

---

## 3. Investigation in Microsoft Defender XDR

Goal: **validate the identity risk**. Confirm the failure/success sequence, inspect IP, app, device and MFA, correlate with identity risk, and correlate with the endpoint timeline.

> Table notes: `SigninLogs` / `AADRiskyUsers` are Microsoft Sentinel tables and appear in Defender Advanced Hunting only when Sentinel is connected to the unified portal. In `SigninLogs`, `ResultType` is a **string** (`"0"`). `AADSignInEventsBeta` is the native Defender XDR table (requires Defender for Cloud Apps / Entra ID P2 licensing), where `ErrorCode` is an integer. Advanced Hunting keeps 30 days of data.

### 3.1 Confirm the Failure/Success Sequence (Sentinel SigninLogs)

Purpose: rebuild the per-user timeline, including MFA and Conditional Access details.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "<user@contoso.com>"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription,
          AppDisplayName, ClientAppUsed, AuthenticationRequirement,
          ConditionalAccessStatus, Location = tostring(LocationDetails.countryOrRegion),
          UserAgent, RiskLevelDuringSignIn
| order by TimeGenerated asc
```

**What to look for:** Normal is a few failures spread over time, then a success with MFA from a known location. Suspicious is a tight burst of `50126` failures followed by `0`, with MFA not required or from a new country or IP.

### 3.2 Failures Followed by Success from the Same IP (AADSignInEventsBeta)

Purpose: find sources with a burst of failures that ended in a successful sign-in for the same account.

```kql
let window = 1h;
let threshold = 10;
AADSignInEventsBeta
| where Timestamp > ago(1d)
| summarize Failures = countif(ErrorCode != 0),
            Successes = countif(ErrorCode == 0),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Apps = make_set(Application, 10),
            ErrorCodes = make_set(ErrorCode, 10)
            by AccountUpn, IPAddress, bin(Timestamp, window)
| where Failures >= threshold and Successes > 0
| order by Failures desc
```

**What to look for:** Rows from external IPs with high failure counts and a success are the strongest signal; corporate egress IPs here often point to stale saved credentials.

### 3.3 Detect Password Spray Across Accounts

Purpose: one IP failing against many distinct accounts with invalid-password errors (50126) is a spray, not a forgetful user.

```kql
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 50126
| summarize TargetedAccounts = dcount(AccountUpn),
            Attempts = count(),
            SampleAccounts = make_set(AccountUpn, 20),
            Countries = make_set(Country, 5)
            by IPAddress
| where TargetedAccounts >= 5
| order by TargetedAccounts desc
```

**What to look for:** An IP hitting 5 or more distinct accounts with invalid passwords is a spray; shared corporate NAT or proxy IPs can also appear, so confirm the source before blocking.

### 3.4 Inspect IP, App, Device and MFA for the Successful Sign-In

Purpose: check whether the success used a known device, which app, and whether MFA was really satisfied.

```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<user@contoso.com>" and ErrorCode == 0
| project Timestamp, AccountUpn, IPAddress, Country, City, Application, ClientAppUsed,
          DeviceName, IsManaged, IsCompliant, AuthenticationRequirement,
          ConditionalAccessStatus, RiskLevelDuringSignIn, UserAgent
| order by Timestamp desc
```

**What to look for:** Suspicious signs are an unmanaged or non-compliant device, a legacy `ClientAppUsed`, MFA not required, or an unusual country and user agent. A managed, compliant device with MFA satisfied points to the real user.

### 3.5 Correlate with On-Prem Identity and Endpoint Logons

Purpose: tie the cloud sequence to AD (Defender for Identity) and to logons on the target device (`WIN-10-01`), such as RDP (LogonType `RemoteInteractive`) from the suspicious IP.

```kql
let ip = "<SourceIP>";
let user = "<SamAccountName>";
union
  (IdentityLogonEvents
   | where Timestamp > ago(7d)
   | where IPAddress == ip or AccountName =~ user
   | project Timestamp, Source = "Identity", ActionType, AccountName, IPAddress,
             DeviceName, LogonType, Protocol, FailureReason),
  (DeviceLogonEvents
   | where Timestamp > ago(7d)
   | where RemoteIP == ip or AccountName =~ user
   | project Timestamp, Source = "Endpoint", ActionType, AccountName, IPAddress = RemoteIP,
             DeviceName, LogonType, Protocol, FailureReason)
| order by Timestamp asc
```

**What to look for:** The same IP showing up in both identity and endpoint logons, especially `RemoteInteractive` (RDP) successes on the target device right after the cloud success, is a strong takeover signal. No endpoint logons narrows the scope to the cloud.

### 3.6 Endpoint Timeline After the Successful Logon

Purpose: see what ran on the device in the first hour after the session started (recon, credential dumping, persistence).

```kql
let device = "<DeviceName>";
let start = datetime(<2025-01-14T10:06:00Z>);
DeviceProcessEvents
| where DeviceName =~ device
| where Timestamp between (start .. (start + 1h))
| where AccountName =~ "<SamAccountName>"
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, SHA256
| order by Timestamp asc
```

**What to look for:** Discovery commands (`whoami`, `net user`, `nltest`), credential tools, encoded PowerShell or new scheduled tasks and services are suspicious. The user's usual apps such as Outlook, browsers and Teams are normal.

### 3.7 Post-Access Cloud Activity and Identity Risk

Purpose: correlate with identity risk and look for typical takeover actions (inbox rules, MFA method changes, OAuth consent).

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where AccountDisplayName has "<UserDisplayName>" or IPAddress == "<SourceIP>"
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
                       "Update user.", "Consent to application.",
                       "User registered security info")
| project Timestamp, ActionType, AccountDisplayName, IPAddress, CountryCode, Application,
          RawEventData
| order by Timestamp desc
```

**What to look for:** Any inbox rule, MFA method registration or OAuth consent from the attacker IP, or shortly after the suspicious sign-in, strongly suggests account takeover. Actions from the user's normal device and IP are usually benign.

Also open the user's page under **Assets > Identities** to see Entra ID Protection risk level, risky sign-ins and the identity timeline.

---

## 4. Investigation in Splunk

Goal: **find the pattern across accounts**, then pivot the source IP into success events, VPN, MFA and endpoint logs.

> Note: index names, sourcetypes and field names (`src_ip` vs `src` vs `IpAddress`) vary by environment and add-on (CIM, Splunk Add-on for Microsoft Windows, Microsoft Azure / Microsoft 365 add-ons). Validate in your own instance and set the time range before drawing conclusions.

### 4.1 High-Volume Failure Pattern by Source (Core Query)

Purpose: find sources with 10 or more failures and which users they hit.

```spl
index=auth action=failure
| stats count values(user) as users dc(user) as user_count by src_ip
| where count >= 10
| sort -count
```

**What to look for:** High counts against many users from one external `src_ip` indicate an attack; one user with repeated failures from an internal IP usually points to a stale credential.

### 4.2 Windows Failed Logons (4625) with Reasons

Purpose: on-prem view of failures, with logon type and status codes (0xC000006A bad password, 0xC0000064 unknown user, 0xC0000234 locked out).

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| stats count min(_time) as first max(_time) as last
        values(TargetUserName) as users dc(TargetUserName) as user_count
        values(Logon_Type) as logon_types values(Sub_Status) as sub_status
        by IpAddress, ComputerName
| where count >= 10
| convert ctime(first) ctime(last)
| sort -count
```

**What to look for:** `0xC0000064` (unknown user) across many names suggests enumeration or spraying, and Logon_Type 10 from external IPs suggests RDP brute force. Repeated `0xC000006A` on one account from one internal host is often a stale password.

### 4.3 Failures Followed by a Success from the Same Source

Purpose: reproduce the alert logic: many 4625 then a 4624 for the same user and IP within a window.

```spl
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| eval outcome=if(EventCode=4624, "success", "failure")
| bin _time span=10m
| stats count(eval(outcome="failure")) as failures
        count(eval(outcome="success")) as successes
        min(_time) as window_start
        by _time, TargetUserName, IpAddress
| where failures >= 10 AND successes >= 1
```

**What to look for:** Any result means the alert logic reproduced; treat external sources with a success as a likely compromise until MFA and post-logon activity prove otherwise.

### 4.4 Password Spray in Entra ID / Azure AD Sign-Ins

Purpose: one IP, many users, error 50126. Field names follow the Splunk Add-on for Microsoft Cloud Services / Azure sign-in JSON.

```spl
index=azure sourcetype="azure:monitor:aad" category=SignInLogs properties.status.errorCode=50126
| rename properties.userPrincipalName as user, properties.ipAddress as src_ip
| stats dc(user) as targeted_users count values(user) as users by src_ip
| where targeted_users >= 5
| sort -targeted_users
```

**What to look for:** Many distinct users with `50126` from one IP is a spray; next, check whether any of those users also have a successful sign-in from the same IP.

### 4.5 Pivot the Source IP Across Success, VPN, MFA and Endpoint Data

Purpose: build the full picture of everything the source touched.

```spl
(index=auth OR index=vpn OR index=mfa OR index=wineventlog OR index=azure) "<SourceIP>"
| eval source_type=sourcetype
| stats count min(_time) as first max(_time) as last
        values(action) as actions values(user) as users values(EventCode) as event_codes
        by index, source_type
| convert ctime(first) ctime(last)
| sort first
```

**What to look for:** The source appearing in success events, VPN connections or endpoint logs (not just failures) is suspicious. Activity limited to failures means the attack likely did not get in.

### 4.6 Endpoint Activity After the Logon (Sysmon)

Purpose: process creation (Sysmon Event ID 1) on the target host after the successful logon.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  host="<DeviceName>" User="*<SamAccountName>*"
  earliest="01/14/2025:10:06:00" latest="01/14/2025:11:06:00"
| table _time, host, User, ParentImage, Image, CommandLine, Hashes
| sort _time
```

**What to look for:** Recon, credential dumping, remote access tools or persistence shortly after the logon are suspicious. Routine user applications and system processes are normal.

### 4.7 Lockouts Tied to the Attack

Purpose: lockouts (4740) show scope and user impact; many lockouts in a short span suggest a spray tuned badly or a brute force.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4740
| stats count values(TargetUserName) as locked_accounts by Caller_Computer_Name
| sort -count
```

**What to look for:** Many accounts locked from the same caller computer suggests a spray or brute force; a single repeated lockout usually points to a device with an old saved password.

---

## 5. Threat Intelligence Enrichment

Key question: **is the source address meaningful?** Enrich the source IP to understand its context and whether it is a real, actionable threat.

### What to Check

| Check | What to look for | Tools |
|---|---|---|
| **IP format and reputation** | Valid public IP? Not private (RFC 1918), not a documentation range (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Abuse reports and detections | AbuseIPDB, VirusTotal, AlienVault OTX, GreyNoise, Microsoft Defender Threat Intelligence |
| **ASN** | Residential ISP vs cloud/hosting provider (attack infra often lives on VPS hosting) | WHOIS / RDAP, ipinfo, Team Cymru IP-to-ASN |
| **Geolocation** | Country, region, ISP compared to the user's baseline | Sign-in log location data, ipinfo, MaxMind |
| **Passive DNS** | Historical domains resolving to the IP; shared or dedicated infra | VirusTotal Relations, AlienVault OTX, SecurityTrails |
| **VPN / proxy context** | Hosting, anonymizer, Tor exit node, commercial VPN, residential proxy | Tor Project exit list, GreyNoise, IP intel feeds |

If the investigation finds files or URLs on the endpoint (section 3.6), check hashes in **VirusTotal** and **MalwareBazaar**, and URLs/domains in **URLScan.io** and VirusTotal.

### IOC Workflow

1. **Validate** - is it a real, routable indicator? (The example `203.0.113.25` is a TEST-NET reserved documentation address, not a real threat IOC. Do not block based on it.)
2. **Enrich** - reputation, ASN, geo, passive DNS, proxy context.
3. **Search** - hunt the indicator in your own logs (sections 3 and 4) for other users and earlier activity.
4. **Corroborate** - combine with internal evidence before acting.

### Reading Verdicts

| Result | Meaning | Action |
|---|---|---|
| Many recent abuse reports for brute force / SSH / RDP | Known scanning or attack infra | Strong supporting evidence; block after validating no business use |
| Clean, residential ISP in user's home country | Could be the user | Confirm with the user |
| Hosting/VPS or Tor exit, no history | Anonymized, unknown | Treat as suspicious, rely on internal evidence |
| Known corporate VPN / egress / partner range | Benign infra | Look for an internal cause (bad saved credential) |

> Reputation is context, not proof; confidence and freshness matter. A clean IP can still be an attacker, and a "malicious" IP may have been reassigned. **Verify before action.**

---

## 6. Verdict: True Positive vs Benign

| Indicator | Points to true positive | Points to benign |
|---|---|---|
| Accounts targeted | Many accounts from one IP (spray) | Only the user's own account |
| Source | Hosting/VPN/Tor, foreign country, bad reputation | Corporate network, user's home ISP |
| Failure reasons | Bad password across many users, unknown usernames | Expired password, same old password repeated |
| MFA | MFA not required, legacy auth, or MFA fatigue (many denies then approve) | MFA prompted and passed on a known device |
| Timing | Scripted, regular intervals, off-hours | Working hours, human pace |
| User agent / client | Scripting libraries, legacy protocols (IMAP, SMTP AUTH) | Normal browser / Outlook client |
| After success | New inbox rules, MFA method added, OAuth consent, odd processes | Normal work activity |
| User confirmation | User denies the activity | User confirms they mistyped / changed password |

### Common False Positives

- User recently changed password and an old one is still saved on a phone, mapped drive or Outlook profile.
- Service accounts or scheduled tasks with stale credentials.
- Misconfigured apps or scripts looping on bad credentials.
- Penetration tests or authorised security scans (verify the ticket).
- Shared NAT / proxy egress IPs making many users look like one source.
- Users typing username formats wrong (`jdoe` vs `jdoe@contoso.com`).

### Common Beginner Mistakes

- Closing the alert because the IP looks "clean" without checking internal evidence such as the MFA outcome and post-access activity.
- Looking only at the alerted user and missing that the same IP sprayed many other accounts.
- Assuming MFA protected the account without checking whether MFA was actually required or bypassed through legacy auth.
- Mixing time zones (UTC vs local) when lining up sign-in, Windows and endpoint events.
- Blocking an IP that turns out to be shared corporate NAT, VPN or partner infrastructure.

---

## 7. Response Checklist

Flow: **validate sequence and MFA → scope users, source, apps, devices → contain confirmed account takeover → recover and improve.**

### Validate and Scope

- [ ] Confirm failure/success sequence and MFA outcome (sections 3.1, 3.4).
- [ ] List all users targeted by the source and which had a success (3.3, 4.4).
- [ ] List all apps, devices and sessions touched by the source and compromised account(s).

### Contain (Only for Confirmed or Highly Likely Takeover)

- [ ] Revoke all sessions / refresh tokens for the user (Entra ID "Revoke sessions" or `Revoke-MgUserSignInSession`).
- [ ] Reset the password and require re-registration of MFA if MFA methods were changed.
- [ ] Mark the user as compromised in Entra ID Protection (raises user risk for risk-based policies).
- [ ] Temporarily disable the account if active misuse is ongoing.
- [ ] Apply Conditional Access: block the source location/IP (named location) after validation, require MFA, block legacy authentication.
- [ ] Isolate the endpoint in Defender for Endpoint if malicious activity followed the logon.
- [ ] Block the IP at firewall/VPN only after confirming it is real and not shared business infra.

### Eradicate

- [ ] Remove malicious inbox rules, forwarding and mail delegations.
- [ ] Remove attacker-registered MFA methods and devices.
- [ ] Revoke suspicious OAuth app consents.
- [ ] Remove persistence or tools found on the endpoint.

### Recover

- [ ] Restore account access with a new strong password and verified MFA.
- [ ] Notify the user and their manager; explain what happened and what to watch for.
- [ ] Check for phishing sent from the account and notify recipients if needed.

### Preserve Evidence

- [ ] Export sign-in logs, Windows events and query results with timestamps (UTC) before retention expires.
- [ ] Record the source IP enrichment results with date checked.
- [ ] Collect an investigation package from the endpoint if it was involved.
- [ ] Document the timeline and decisions in the incident ticket.

### Monitor and Improve

- [ ] Watch the user and source IP for 7 to 14 days for re-entry.
- [ ] Tune thresholds (count, window, distinct users) to cut noise from known service accounts.
- [ ] Enforce MFA for all users, block legacy auth, enable Entra smart lockout and banned password lists.
- [ ] Turn successful queries into scheduled detections / custom detection rules.

---

## 8. Quick Reference

| Need | Defender XDR | Splunk / Windows |
|---|---|---|
| Cloud sign-in failures | `AADSignInEventsBeta` `ErrorCode != 0`, `SigninLogs` `ResultType != "0"` | Azure sign-in logs `errorCode` |
| Bad password | Error `50126` | 4625 Sub_Status `0xC000006A` |
| Unknown user | Error `50034` | 4625 Sub_Status `0xC0000064` |
| Lockout | Error `50053` | Event `4740` |
| MFA failed / denied | Error `500121` | MFA provider logs |
| Success | `ErrorCode == 0` | Event `4624` |
| On-prem AD auth | `IdentityLogonEvents` | `4771` (Kerberos), `4776` (NTLM) |
| Device logons | `DeviceLogonEvents` | `4624` / `4625` with Logon_Type |
| Post-logon processes | `DeviceProcessEvents` | Sysmon Event ID 1 |
| Post-access cloud actions | `CloudAppEvents` | O365 Management Activity logs |
| Spray signal | `dcount(AccountUpn)` by IP | `dc(user)` by src_ip |

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|---|---|
| [Detect and Respond: SSH Brute-Force Attack Using Splunk](https://www.youtube.com/watch?v=ZTqu4aLFoPg) | Detecting an SSH brute-force attack in Splunk and responding to it. |
| [SSH Brute Force Attack Detection Using Wazuh](https://www.youtube.com/watch?v=1cO81wmebZo) | Using Wazuh to detect brute-force attempts against SSH. |
| [Log Analysis Basics: Windows Security Logs](https://www.youtube.com/watch?v=ea7f_M2ExVE) | Fundamentals of reading Windows Security event logs. |
| [SSH Log Analysis Using Splunk](https://www.youtube.com/watch?v=uD3vbbj7DBQ) | Searching and analysing SSH authentication logs in Splunk. |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|---|---|
| [Brute Force Attack Triage](https://app.haxcamp.com/lab/brute-force-attack-triage) | Identify brute force from failed logins, enrich the IP, decide to block or escalate |
| [SSH Log Analysis Using Splunk](https://app.haxcamp.com/lab/ssh-log-analysis) | Investigate failed login patterns and attack behaviour in SSH logs |
| [SSH Log Analysis Using Wazuh](https://app.haxcamp.com/lab/ssh-log-analysis-using-wazuh) | Detect brute force, enumeration and password spraying in SSH logs |
| [Windows Security Log Monitoring](https://app.haxcamp.com/lab/introduction-to-windows-security-monitoring) | Investigate Windows Security events with Event Viewer and Splunk |
| [Brute-Force Attack Enrichment Using n8n](https://app.haxcamp.com/lab/brute-force-attack-enrichment-using-n8n) | Enrich a brute-force alert with AbuseIPDB reputation and a risk score |
| [Authentication and Identity Fundamentals](https://app.haxcamp.com/lab/authentication-and-identity-fundamentals) | How identity is proven and the threats that target credentials |

### Official Documentation

- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1110.003: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [Microsoft: Password Spray Investigation Playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray)
- [Microsoft: Advanced Hunting Schema Reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Microsoft: Entra ID Authentication Error Codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- [Microsoft: Entra Smart Lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [Microsoft: Event 4625 - An Account Failed to Log On](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Splunk: Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Splunk Security Content (Detections)](https://research.splunk.com/)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
