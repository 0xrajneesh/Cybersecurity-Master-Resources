# Impossible Travel: SOC Investigation Playbook

How to triage, investigate, and respond to an "impossible travel" sign-in alert using Microsoft Defender XDR, Splunk, and threat intelligence.

> **Level:** Beginner to Intermediate · **Time:** ~45 min read · **Tools:** Microsoft Defender XDR, Splunk, Threat Intelligence
>
> **You will learn:** how to prove or disprove impossible travel with data, how to separate VPN/proxy noise from account takeover, how to contain a compromised cloud account
>
> **Prerequisites:** basic understanding of Entra ID sign-ins and KQL/SPL syntax

All IPs, users, and hostnames in this guide (for example `203.0.113.10`, `198.51.100.23`, `jdoe@contoso.com`) are documentation examples (RFC 5737 / Microsoft sample tenant), never real IOCs.

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

1. Normalize both sign-in timestamps to UTC and recompute the distance and speed yourself.
2. Check whether each sign-in **succeeded** (error code 0) or was only an attempt.
3. Look up the IP/ASN of both sign-ins: corporate egress, VPN, mobile carrier, or hosting/VPS?
4. Compare the device ID, OS, and browser with the user's normal baseline.
5. Check the MFA detail: interactive MFA with a known method, or "satisfied by claim in token" from a new IP?
6. Look for post-sign-in activity: new inbox rules, MFA method changes, OAuth consents, mass downloads.
7. Check for recent related alerts on the user (phishing click, risky user, MFA fatigue).

**Escalate immediately if:** the suspicious sign-in succeeded from an unknown device or hosting/anonymizer IP and is followed by inbox rule creation, MFA changes, or the same session ID appearing from two distant IPs.

---

## 1. What This Alert Means

An **impossible travel** alert fires when the same identity authenticates from two geographic locations that are too far apart to be reached in the elapsed time. Example: New York at 09:14 and Singapore at 11:27 on the same day, roughly 15,300 km in 2h 13m. That implies a travel speed of about 6,900 km/h, which no commercial flight can achieve.

Common sources of this detection:

| Source | Detection name |
|---|---|
| Microsoft Defender for Cloud Apps | Impossible travel (anomaly detection policy) |
| Microsoft Entra ID Protection | Atypical travel (offline risk detection), Impossible travel (MDCA-sourced) |
| Splunk ES / ESCU | Geographically improbable access / custom `iplocation` + `haversine` style searches |

### Why Attackers Trigger It

- **Stolen credentials** (phishing, infostealer logs, password spray, credential stuffing) are used from attacker infrastructure while the real user is still working from home or the office.
- **Session / token theft** (adversary-in-the-middle phishing kits such as reverse-proxy kits, stolen browser cookies) lets an attacker replay a valid session from another country. MFA often shows as "succeeded" because the user completed it on the phishing proxy.
- **Attacker anonymization**: VPS, residential proxies, and commercial VPNs place the attacker's sign-in in an unexpected location.

### MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|---|---|---|
| T1078 | Valid Accounts | Attacker signs in with legitimate credentials |
| T1078.004 | Valid Accounts: Cloud Accounts | Entra ID / Microsoft 365 account abuse |
| T1110.003 | Brute Force: Password Spraying | Common precursor to the foreign sign-in |
| T1110.004 | Brute Force: Credential Stuffing | Reused leaked passwords |
| T1566.002 | Phishing: Spearphishing Link | Credential / AiTM phishing that leads to the sign-in |
| T1557 | Adversary-in-the-Middle | AiTM proxy capturing session cookies |
| T1539 | Steal Web Session Cookie | Session cookie theft for replay |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Replaying the stolen cookie |
| T1621 | Multi-Factor Authentication Request Generation | MFA fatigue / push bombing |
| T1090 | Proxy | Attacker routes through VPN/proxy infrastructure |
| T1114.003 | Email Collection: Email Forwarding Rule | Common post-compromise persistence in M365 |
| T1098 | Account Manipulation | Adding MFA methods, app credentials, roles |

### Key Terms

| Term | Meaning |
|---|---|
| UPN | User Principal Name, the sign-in name of an account in the form `user@domain.com`. |
| ASN | Autonomous System Number, an ID for the network (ISP, hosting provider, carrier) that owns an IP range. |
| AiTM | Adversary-in-the-Middle, a phishing proxy that sits between the user and the real login page and steals the session cookie after MFA. |
| Token replay | Reusing a stolen session token or cookie so the attacker is treated as already signed in, without needing the password or MFA again. |
| Conditional Access (CA) | Entra ID policies that allow, block, or require MFA for a sign-in based on user, device, location, and risk. |
| Geo-IP | A database lookup that estimates a physical location from an IP address; it can be wrong. |
| Egress IP | The public IP address an organization's or VPN's traffic leaves from, which is what cloud services see. |
| Haversine formula | A formula that calculates the great-circle distance between two latitude/longitude points. |

---

## 2. Alert Triage

Two sign-ins from distant locations minutes apart look suspicious, but **location signals can be misleading**. Before escalating, answer the analyst checklist.

### Why Location Can Lie

| Factor | What happens |
|---|---|
| VPN | Corporate or personal VPN egresses in another city or country |
| Proxy | Cloud proxy / SWG (e.g., Zscaler, Netskope) or relay masks the real location |
| Mobile carrier | Traffic egresses from a carrier or regional gateway far from the user |
| Stale geo-IP | IP-to-location databases are outdated or wrong, especially for reassigned ranges |
| Cloud / IPv6 | Cloud-hosted apps and IPv6 ranges geolocate to the provider's registered HQ |

### Analyst Checklist

- [ ] **Verify timestamps / timezones**: normalize both events to UTC. Confirm the alert is not comparing local time to UTC.
- [ ] **Check IP / ASN**: is either IP a known corporate egress, VPN concentrator, SWG, mobile carrier, or hosting/VPS provider?
- [ ] **Confirm device (new or known)**: same device ID / Entra device ID as normal? Managed and compliant? New OS or browser?
- [ ] **Review session (activity and state)**: what did each session do afterwards (mailbox access, file downloads, rule creation)? Is it still active?
- [ ] **Validate MFA (result and method)**: was MFA required, satisfied, by which method, or satisfied by token claim from a prior session?
- [ ] **Consider travel context**: recent or planned travel, HR/travel system, user's manager, out-of-office notes.
- [ ] Check whether the user had other alerts in the last 7-30 days (phishing click, risky user, MFA fatigue).

### Key Fields to Collect

| Field | Example | Why it matters |
|---|---|---|
| User / UPN | `jdoe@contoso.com` | Scope and pivot key |
| Sign-in 1 time (UTC), IP, location | 09:12 UTC, `203.0.113.18`, Mumbai | Baseline / expected sign-in |
| Sign-in 2 time (UTC), IP, location | 09:34 UTC, `198.51.100.42`, London | Suspicious sign-in |
| ASN / ISP of each IP | AS64496 | Hosting vs. residential vs. carrier |
| Device ID / OS / browser / user agent | Windows 11, new device | New device is a strong signal |
| Application / resource | Office 365 Exchange Online | What the session reached |
| Authentication requirement / MFA detail | multiFactorAuthentication, satisfied by claim | Token replay indicator |
| Conditional Access status | success / failure / notApplied | Was a policy bypassed? |
| Risk level / risk state | high, atRisk | Entra ID Protection opinion |
| Session ID / correlation ID | `<SessionId>` | Ties later activity to the sign-in |
| Result / error code | 0 (success), 50126 (bad password), 50074 (MFA required) | Success vs. attempt |

---

## 3. Investigation in Microsoft Defender XDR

Goal: **validate the sign-in context.** For each event inspect Device ID, auth details (protocol: OIDC, WS-Fed, legacy), risk state, MFA, and session.

> Note: many examples use the `SigninLogs` table, which is available in Advanced Hunting only when Microsoft Sentinel is connected to the Defender portal (it uses `TimeGenerated`). Natively, Defender XDR exposes Entra sign-ins in `AADSignInEventsBeta` (requires Defender for Cloud Apps / Entra ID P2 licensing), which uses `Timestamp`. Both are shown below.

### 3.1 Sign-In Timeline for the User (Sentinel `SigninLogs`)

Purpose: reproduce the core query with the fields needed to judge device, auth method, MFA, risk, and CA.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "<UserPrincipalName>"
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion),
         DeviceId = tostring(DeviceDetail.deviceId), OS = tostring(DeviceDetail.operatingSystem),
         Browser = tostring(DeviceDetail.browser), IsCompliant = tostring(DeviceDetail.isCompliant)
| project TimeGenerated, IPAddress, City, Country, AutonomousSystemNumber, AppDisplayName,
          ClientAppUsed, DeviceId, OS, Browser, IsCompliant, ResultType, ResultDescription,
          AuthenticationRequirement, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskState,
          SessionId, CorrelationId, UserAgent
| order by TimeGenerated desc
```

**What to look for:** Successful sign-ins (`ResultType` 0) from a new country, with a non-compliant or empty `DeviceId`, or with `RiskLevelDuringSignIn` medium/high are suspicious; sign-ins that share the user's usual device, browser, and ASN are normal.

### 3.2 Sign-In Timeline in Native Advanced Hunting (`AADSignInEventsBeta`)

Purpose: same view without Sentinel, including managed/compliant state and session ID.

```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<UserPrincipalName>"
| project Timestamp, IPAddress, Country, City, Latitude, Longitude, Application, ResourceDisplayName,
          LogonType, ClientAppUsed, DeviceName, AadDeviceId, OSPlatform, DeviceTrustType, IsManaged,
          IsCompliant, ErrorCode, AuthenticationRequirement, ConditionalAccessStatus,
          RiskLevelDuringSignIn, RiskState, SessionId, UserAgent
| order by Timestamp asc
```

**What to look for:** A sign-in with `IsManaged`/`IsCompliant` false or an empty `AadDeviceId` right next to a normal managed-device sign-in is suspicious; the same `SessionId` on two distant IPs points to token replay.

### 3.3 Calculate Travel Speed Between Consecutive Successful Sign-Ins

Purpose: confirm the "impossible" claim with numbers instead of trusting the alert.

```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<UserPrincipalName>" and ErrorCode == 0
| where isnotempty(Latitude) and isnotempty(Longitude)
| project Timestamp, IPAddress, Country, City, Lat = todouble(Latitude), Lon = todouble(Longitude), AadDeviceId, Application
| order by Timestamp asc
| extend PrevTime = prev(Timestamp), PrevIP = prev(IPAddress), PrevCity = prev(City),
         PrevLat = prev(Lat), PrevLon = prev(Lon)
| where isnotnull(PrevTime) and PrevIP != IPAddress
| extend DistanceKm = round(geo_distance_2points(PrevLon, PrevLat, Lon, Lat) / 1000, 0),
         Hours = datetime_diff('second', Timestamp, PrevTime) / 3600.0
| extend SpeedKmh = iff(Hours > 0, round(DistanceKm / Hours, 0), real(null))
| where SpeedKmh > 1000 or (Hours == 0 and DistanceKm > 100)
| project PrevTime, PrevIP, PrevCity, Timestamp, IPAddress, City, DistanceKm, Hours, SpeedKmh, AadDeviceId, Application
```

**What to look for:** Every row is a pair of successful sign-ins faster than 1,000 km/h; it is most suspicious when the two rows have different `AadDeviceId` values, and likely benign when one IP is a known VPN or proxy egress.

### 3.4 Everyone Else Using the Suspicious IP

Purpose: scope. A single IP signing into many accounts suggests spray / AiTM infrastructure; many users on the same IP with clean history suggests a corporate VPN or proxy egress.

```kql
let SuspiciousIP = "<SuspiciousIP>";
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where IPAddress == SuspiciousIP
| summarize Attempts = count(), Successes = countif(ErrorCode == 0),
            Users = make_set(AccountUpn, 50), Apps = make_set(Application, 20),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by IPAddress, Country
```

**What to look for:** Many failed attempts across many users with few successes suggests spraying or attacker infrastructure; many users succeeding consistently over weeks usually means a shared corporate or VPN egress.

### 3.5 Post-Sign-In Cloud Activity from the Suspicious Session

Purpose: review what the session did (mailbox rules, MFA changes, file downloads, consent grants).

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where AccountDisplayName has "<UserDisplayName>" or tostring(RawEventData.UserId) =~ "<UserPrincipalName>"
| where IPAddress == "<SuspiciousIP>"
    or ActionType in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox",
                       "Add-MailboxPermission", "Update user.", "Consent to application.",
                       "Add app role assignment grant to user.", "FileDownloaded", "MailItemsAccessed")
| project Timestamp, Application, ActionType, IPAddress, CountryCode, City, ISP,
          IsAnonymousProxy, ActivityObjects, RawEventData
| order by Timestamp asc
```

**What to look for:** Inbox rule creation, mailbox permission changes, app consents, or bulk `FileDownloaded`/`MailItemsAccessed` from the suspicious IP (especially with `IsAnonymousProxy` true) indicate compromise; ordinary activity from the user's usual IP is normal.

### 3.6 Did the User Click a Phishing Link Before the Sign-In?

Purpose: find the likely credential-theft vector (T1566.002 / AiTM).

```kql
let User = "<UserPrincipalName>";
let AlertTime = datetime(<AlertTimeUTC>);
UrlClickEvents
| where Timestamp between ((AlertTime - 3d) .. AlertTime)
| where AccountUpn =~ User
| project Timestamp, Url, ActionType, IsClickedThrough, NetworkMessageId, IPAddress
| join kind=leftouter (
    EmailEvents
    | where Timestamp between ((AlertTime - 4d) .. AlertTime)
    | where RecipientEmailAddress =~ User
    | project NetworkMessageId, SenderFromAddress, SenderIPv4, Subject, ThreatTypes, DeliveryAction
  ) on NetworkMessageId
| order by Timestamp desc
```

**What to look for:** A clicked-through URL (`IsClickedThrough` true) shortly before the alert, especially from a message with `ThreatTypes` set or pointing to a lookalike login page, is the likely credential-theft vector; no clicks means check other vectors (spray, infostealer).

### 3.7 Endpoint Pivot: Interactive Logons on the User's Known Device

Purpose: if the user was actively logged on to their corporate device at home at the time of the foreign sign-in, the foreign session is almost certainly not them.

```kql
DeviceLogonEvents
| where Timestamp between (datetime(<AlertTimeUTC>) - 2h .. datetime(<AlertTimeUTC>) + 2h)
| where AccountName =~ "<SamAccountName>"
| where LogonType in ("Interactive", "RemoteInteractive", "Unlock", "CachedInteractive")
| project Timestamp, DeviceName, LogonType, ActionType, RemoteIP, RemoteIPType, IsLocalAdmin
| order by Timestamp asc
```

**What to look for:** An interactive or unlock logon on the user's home device within minutes of the foreign sign-in strongly suggests the foreign session is not the user; no device activity at all is inconclusive.

What to look for per event:

| Check | Field(s) | Red flag |
|---|---|---|
| Device ID | `AadDeviceId`, `DeviceDetail.deviceId`, `IsManaged` | Empty or never-seen device ID, unmanaged |
| Auth details | `ClientAppUsed`, `LogonType`, `UserAgent` | Legacy auth (IMAP/POP/SMTP), unusual UA (python-requests, headless) |
| Risk state | `RiskLevelDuringSignIn`, `RiskState` | medium/high, atRisk / confirmedCompromised |
| MFA | `AuthenticationRequirement`, `AuthenticationDetails` | singleFactor on sensitive app, MFA "satisfied by claim in token" from new IP |
| Session | `SessionId` | Same session ID used from two distant IPs (token replay) |

---

## 4. Investigation in Splunk

Goal: **track the user across sign-ins**, then pivot successful sign-ins to endpoint and VPN logs.

> Index and sourcetype names vary per environment. Examples below assume the Splunk Add-on for Microsoft Cloud Services / Microsoft Office 365 (`sourcetype=azure:monitor:aad`, `o365:management:activity`), Windows Security logs (`WinEventLog:Security`), and a generic VPN index. Validate field mappings and time zones (UTC vs. local) before drawing conclusions, and never infer impossible travel from IP geo alone.

### 4.1 User Sign-In Timeline (Core Query, CIM Authentication)

Purpose: list where, from what device, and with what result the user authenticated.

```spl
index=identity user="jdoe" earliest=-7d
| iplocation src_ip
| stats values(src_ip) as src_ip values(City) as city values(Country) as country values(dest) as app values(action) as action by _time, user
| sort _time
```

**What to look for:** Successful sign-ins from cities or countries the user never uses, especially minutes after a normal sign-in, are suspicious; repeated locations matching the user's office or home are normal.

### 4.2 Entra ID Sign-Ins with MFA, CA, and Device Detail

Purpose: same as KQL 3.1, from Entra sign-in logs ingested into Splunk.

```spl
index=azure sourcetype="azure:monitor:aad" category=SignInLogs properties.userPrincipalName="<UserPrincipalName>" earliest=-7d
| rename properties.* as *
| table _time userPrincipalName ipAddress location.city location.countryOrRegion appDisplayName clientAppUsed
        deviceDetail.deviceId deviceDetail.operatingSystem deviceDetail.browser status.errorCode
        authenticationRequirement conditionalAccessStatus riskLevelDuringSignIn riskState correlationId
| sort _time
```

**What to look for:** A risky sign-in with an unknown `deviceDetail.deviceId`, a legacy `clientAppUsed`, or `conditionalAccessStatus` of notApplied is suspicious; consistent device and browser values match the user's baseline.

### 4.3 Compute Travel Speed Between Consecutive Sign-Ins

Purpose: calculate distance and speed with `iplocation` and the haversine formula.

```spl
index=azure sourcetype="azure:monitor:aad" category=SignInLogs properties.userPrincipalName="<UserPrincipalName>" properties.status.errorCode=0 earliest=-7d
| rename properties.ipAddress as src_ip
| iplocation src_ip
| sort 0 _time
| streamstats current=f window=1 last(_time) as prev_time last(src_ip) as prev_ip last(lat) as prev_lat last(lon) as prev_lon last(City) as prev_city
| where isnotnull(prev_ip) AND src_ip!=prev_ip
| eval rlat1=prev_lat*pi()/180, rlat2=lat*pi()/180, dlat=(lat-prev_lat)*pi()/180, dlon=(lon-prev_lon)*pi()/180
| eval a=pow(sin(dlat/2),2)+cos(rlat1)*cos(rlat2)*pow(sin(dlon/2),2)
| eval distance_km=round(6371*2*atan2(sqrt(a),sqrt(1-a)),0)
| eval hours=(_time-prev_time)/3600, speed_kmh=if(hours>0, round(distance_km/hours,0), null())
| where speed_kmh>1000
| table prev_time prev_ip prev_city _time src_ip City distance_km hours speed_kmh
```

**What to look for:** Each row is a pair of successful sign-ins faster than 1,000 km/h; treat it as suspicious unless one IP belongs to a known VPN, proxy, or mobile carrier egress.

### 4.4 Pivot to Endpoint Logs (Windows Logons on the User's Device)

Purpose: correlate device, logon, and process activity. Event 4624 = successful logon, 4625 = failed logon, 4648 = logon with explicit credentials.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4624, 4625, 4648) user="jdoe" earliest=-24h
| eval logon_type=Logon_Type
| table _time host EventCode logon_type src_ip user Workstation_Name Process_Name
| sort _time
```

**What to look for:** Successful 4624 interactive logons on the user's workstation at the same time as the foreign cloud sign-in suggest the real user was at home; bursts of 4625 or unexpected 4648 events deserve a closer look.

Optional process context from Sysmon (Event ID 1 = process creation) on the same host:

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host="<DeviceName>" User="*jdoe*" earliest=-24h
| table _time host User ParentImage Image CommandLine
| sort _time
```

**What to look for:** Unusual processes (scripting engines, archive tools, remote access software) launched around the alert time are suspicious; normal Office and browser activity is expected.

### 4.5 Pivot to VPN Logs

Purpose: confirm whether the user had a remote-access session and from which public IP. A VPN session from the user's home city at the same time as a foreign cloud sign-in strongly supports compromise; a VPN egress in the foreign city supports a benign explanation.

```spl
index=vpn user="jdoe" earliest=-24h
| iplocation src_ip
| table _time user src_ip City Country assigned_ip action session_id duration
| sort _time
```

**What to look for:** A VPN session from the user's home city during the foreign cloud sign-in supports compromise; a VPN egress in the foreign city explains the alert as benign.

### 4.6 Post-Compromise Activity in Microsoft 365

Purpose: hunt for persistence and data access from the suspicious IP.

```spl
index=o365 sourcetype="o365:management:activity" UserId="<UserPrincipalName>" earliest=-7d
| search ClientIP="<SuspiciousIP>*" OR Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox","Add-MailboxPermission","Consent to application.","Update user.","FileDownloaded","MailItemsAccessed")
| table _time Operation Workload ClientIP ObjectId Parameters{}.Name Parameters{}.Value
| sort _time
```

**What to look for:** New inbox rules that forward, delete, or move mail, new mailbox permissions, app consents, or bulk downloads from the suspicious `ClientIP` indicate compromise; routine operations from known IPs are normal.

---

## 5. Threat Intelligence Enrichment

**Check the IP, then check the user.** Enrich every production IP with trusted intel, passive DNS, ASN, and VPN/proxy context.

> Example: `203.0.113.10` / AS64496 are reserved documentation values (RFC 5737 TEST-NET-3, RFC 5398). They are never real IOCs: do not action them.

### What to Check

| Indicator | Check | Tools |
|---|---|---|
| IP | Reputation, abuse reports, open ports, first/last seen | VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, Shodan |
| ASN / owner | Hosting/VPS vs. ISP vs. mobile carrier; organization | WHOIS / RDAP, bgp.he.net, IPinfo |
| VPN / proxy / Tor | Anonymizer, residential proxy, Tor exit node | IPinfo privacy data, Spur, Tor exit list, Defender `IsAnonymousProxy` |
| Passive DNS | Historical resolutions, domains hosted on the IP (AiTM lookalike domains) | VirusTotal Relations, RiskIQ / Defender TI, SecurityTrails |
| Phishing URL / domain | Redirect chain, screenshot, login-page brand impersonation | URLScan.io, VirusTotal |
| File hash (if a payload was involved) | Malware family, first-seen | VirusTotal, MalwareBazaar |

### IOC Lifecycle

1. **Validate**: is the indicator real and well-formed (not RFC 1918, RFC 5737, or your own egress)?
2. **Enrich**: add reputation, ASN, geo, passive DNS, anonymizer context.
3. **Compare**: against the user's baseline (normal IPs, ASNs, devices) and against your org's known egress list.
4. **Corroborate**: confirm with independent evidence (session activity, device, user statement) before acting.

### Interpreting Verdicts

| Result | Meaning | Action |
|---|---|---|
| Multiple vendors / reports flag IP as malicious, hosting ASN | Strong supporting evidence | Combine with session evidence; likely TP |
| Commercial VPN / residential proxy | Anonymized, but users use VPNs too | Ask the user; check whether VPN use is allowed |
| Mobile carrier / clean ISP in user's country | Likely legitimate geo-IP drift | Lean benign if device and MFA match |
| No data / unknown | Absence of evidence is not evidence of absence | Rely on behavioral evidence |

Reputation and geolocation are **not proof** of malicious intent, identity, or attribution. **Verify before action.**

---

## 6. Verdict: True Positive vs Benign

| Signal | Points to true positive | Points to benign |
|---|---|---|
| Device | New, unregistered, unmanaged device | Known Entra-joined / compliant device ID |
| IP / ASN | Hosting/VPS, Tor, residential proxy, flagged IP | Corporate egress, known VPN, mobile carrier |
| MFA | Satisfied by token claim from new IP, MFA fatigue prompts, new MFA method registered | Interactive MFA with user's known method on known device |
| Session | Same `SessionId` from two distant IPs; inbox rules, mass downloads, consent grants | Normal app usage consistent with role |
| User agent | Scripted / unusual UA, legacy protocol | Same browser/OS as baseline |
| Precursors | Phishing click, password spray failures before success | None |
| User statement | User denies the sign-in | User confirms travel or VPN use |
| Endpoint | User actively logged on at home device at same time | Device offline / user travelling with it |

### Common False Positives

- Corporate VPN, SASE, or secure web gateway egress in another region.
- Mobile carriers routing through distant gateways.
- Stale or inaccurate geo-IP data (newly reassigned ranges, IPv6).
- Cloud-hosted VDI / Azure Virtual Desktop / Citrix in another region.
- Shared or service accounts used by teams in multiple countries.
- Legitimate travel where the user stayed signed in on one device while a second device synced from home.

### Common Beginner Mistakes

- Trusting the alert's distance and timing without normalizing timestamps to UTC and recomputing the speed.
- Treating geo-IP location as proof, without checking whether the IP belongs to a VPN, proxy, or mobile carrier.
- Assuming "MFA succeeded" means the user is safe, when AiTM token replay can satisfy MFA by claim.
- Closing the alert after the user confirms travel, without checking post-sign-in activity such as inbox rules or MFA changes.
- Resetting the password but forgetting to revoke sessions and refresh tokens, leaving the attacker's session alive.

---

## 7. Response Checklist

Respond to **confirmed** account compromise: validate sign-in/session, scope account/device/apps, revoke sessions and reset credentials if confirmed, enforce MFA/Conditional Access and monitor.

### Contain

- [ ] Validate the suspicious sign-in and session (sections 3-4) and document the verdict.
- [ ] Confirm with the user out-of-band (phone/Teams call, not email to the possibly compromised mailbox).
- [ ] Revoke refresh tokens and sessions (Entra ID: "Revoke sessions" / `Revoke-MgUserSignInSession`).
- [ ] Reset the password (or disable the account temporarily if active misuse is ongoing).
- [ ] Mark the user as compromised in Entra ID Protection ("Confirm user compromised").
- [ ] Block the malicious IP(s) via a Conditional Access named location or network controls.
- [ ] Isolate the endpoint in Defender for Endpoint if device involvement is suspected.

### Eradicate

- [ ] Remove attacker-registered MFA methods and review authentication methods.
- [ ] Remove malicious inbox rules, forwarding (`ForwardingSmtpAddress`), and mailbox delegations.
- [ ] Revoke suspicious OAuth app consents and service principal credentials.
- [ ] Remove any role assignments or group memberships added by the attacker.
- [ ] Purge related phishing emails from all mailboxes (Defender for Office 365 Threat Explorer).

### Recover

- [ ] Re-enable the account with new credentials and re-register MFA under verification.
- [ ] Restore deleted or modified mailbox items / files if needed.
- [ ] Notify affected internal or external parties if emails were sent from the account.

### Preserve Evidence

- [ ] Export sign-in logs, audit logs, and Unified Audit Log entries for the incident window.
- [ ] Record IPs, session IDs, correlation IDs, user agents, and timestamps (UTC) in the case.
- [ ] Collect an investigation package from the endpoint if it was isolated.
- [ ] Preserve phishing email samples (headers, URLs) for TI sharing.

### Monitor

- [ ] Enforce phishing-resistant MFA (FIDO2 / Windows Hello / passkeys) and Conditional Access requiring compliant devices.
- [ ] Block legacy authentication tenant-wide.
- [ ] Enable sign-in risk and user risk policies in Entra ID Protection.
- [ ] Add a watchlist / detection for the IOCs and the user for 30 days.
- [ ] Tune the detection: add known VPN/egress ranges as trusted locations to reduce false positives.

---

## 8. Quick Reference

### Cheat Sheet

| Step | Defender XDR | Splunk | Key question |
|---|---|---|---|
| Timeline | `AADSignInEventsBeta` / `SigninLogs` | `sourcetype=azure:monitor:aad` | Where and when did the user sign in? |
| Speed check | `geo_distance_2points()` | `iplocation` + haversine | Is the travel actually impossible? |
| IP scope | `AADSignInEventsBeta` by `IPAddress` | `stats dc(user) by src_ip` | Who else uses this IP? |
| Session activity | `CloudAppEvents` | `o365:management:activity` | What did the session do? |
| Vector | `UrlClickEvents` + `EmailEvents` | Email / proxy logs | How were credentials stolen? |
| Endpoint | `DeviceLogonEvents` | `EventCode=4624` / Sysmon 1 | Was the real user on their device? |
| VPN | n/a (ingest VPN logs) | `index=vpn` | Does VPN explain the location? |
| TI | Defender TI, `IsAnonymousProxy` | TI lookups | Hosting, VPN, Tor, flagged? |
| Response | Revoke sessions, reset, CA | Notable event workflow | Contained and hardened? |

---

## 9. Practice and Learn More

### Watch: Video Walkthroughs

| Video | What it covers |
|---|---|
| [SOC L1 Triage: SOC Analyst Guide](https://www.youtube.com/watch?v=X537D_K3_zQ) | How an L1 analyst approaches and triages incoming alerts |
| [Authentication Types (Mock Interview)](https://www.youtube.com/watch?v=mLJMt6OGsys) | Authentication methods explained in an interview-style format |
| [Threat Intelligence Crash Course](https://www.youtube.com/watch?v=WAkDp7yxHJo) | Fundamentals of threat intelligence and how analysts use it |
| [Splunk SPL Query Masterclass](https://www.youtube.com/watch?v=tfA8shtJ8ew) | Writing and understanding Splunk SPL queries |

### Practice: Hands-on Labs on HaxCamp

| Lab | What you will practice |
|---|---|
| [Authentication and Identity Fundamentals](https://app.haxcamp.com/lab/authentication-and-identity-fundamentals) | How identity is proven and controlled, and the threats that target credentials and accounts |
| [Identity & Access Basics](https://app.haxcamp.com/lab/identity-and-access-basics) | Right people, right access, from first sign-in to the day they leave |
| [IP Geo-Location Enrichment Using n8n](https://app.haxcamp.com/lab/ip-geo-location-enrichment-using-n8n) | Enrich a suspicious IP with geographic and network context |
| [AWS Account Compromise](https://app.haxcamp.com/lab/aws-account-compromise) | Investigate a compromised cloud account |
| [Alert Triage Fundamentals](https://app.haxcamp.com/lab/alert-triage-fundamentals) | Work out what fired and decide whether to close or escalate |
| [IOC Investigation](https://app.haxcamp.com/lab/ioc-investigation) | From a single indicator to a full attacker infrastructure map |

### Official Documentation

- [Microsoft Defender XDR Advanced Hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [AADSignInEventsBeta table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table)
- [CloudAppEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table)
- [Defender for Cloud Apps anomaly detection policies (Impossible travel)](https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy)
- [Entra ID Protection risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- [Revoke user access in Entra ID](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access)
- [Microsoft incident response playbooks](https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks)
- [MITRE ATT&CK T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [Splunk `iplocation` command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Iplocation)
- [Splunk `streamstats` command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Streamstats)

---

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [HaxCamp Projects](https://app.haxcamp.com/projects) · [Learning Paths](https://app.haxcamp.com/learning-paths)
