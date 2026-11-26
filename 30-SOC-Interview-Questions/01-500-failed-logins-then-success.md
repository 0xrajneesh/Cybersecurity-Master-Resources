# Q1. 500 Failed Logins, Then a Success

> **Difficulty:** Beginner · **Topic:** Authentication Attacks · **Asked for:** SOC L1 / L2

## The Question

> "You see 500 failed logins from one IP, followed by a successful login. What do you do?"

## The Trap Answer

Most candidates fire back with **"Block the IP."** It sounds decisive, and it is the first thing any firewall admin would do.

It fails because the attacker is **already in**. Blocking the IP stops new attempts from that address, but it does nothing about the session that is live right now, the password that is now known, or whatever the attacker did in the minutes after logging in. Blocking first can also destroy your visibility into what they do next. The interviewer wants to hear you investigate, scope and contain, in that order.

## The Strong Answer, Step by Step

### 1. Confirm the pattern in the SIEM
Do not trust the alert title. Pull the raw events and build a timeline.
- **Event ID 4625** (failed logon) followed by **Event ID 4624** (successful logon)
- Same **source IP** and same **target account**?
- Check the **logon type**: **10 = RemoteInteractive (RDP)**, **3 = Network**, **2 = Interactive**
- Note the exact time of the first failure, the success, and the gap between them

### 2. Decide: brute force or password spraying
The shape of the failures tells you what kind of attack it was.
- **Brute force:** one account, hundreds of attempts
- **Password spraying:** many accounts, one or two attempts each
- Spraying means **more than one account** may be compromised, so your scope just got wider

### 3. Check the IP
Find out who is on the other end.
- Reputation in **VirusTotal** and **AbuseIPDB**
- **Geolocation and ASN**: residential ISP, cloud hosting, or a known bad provider?
- Is it a **VPN exit node or Tor**?
- Does this user **ever** log in from this location? Compare with their normal history

### 4. Check the host and cloud apps after the login
The success is the start of the story, not the end.
- In **EDR**, look at activity on the host after the 4624:
  - **Encoded PowerShell** (`-EncodedCommand`)
  - **New scheduled tasks** (Event ID **4698**)
  - **LSASS access** (credential dumping)
- In cloud apps (for example **Microsoft Entra ID / Microsoft 365**):
  - **New MFA devices** registered
  - **Inbox forwarding rules** created

### 5. Call the user
One question saves hours: **"Was this you?"**
- Use a known phone number or a separate channel, not email on a possibly compromised account
- If they say no, or cannot be reached, treat it as **confirmed compromise**

### 6. Contain
Order matters. Kill the attacker's access before you touch the IP.
- **Disable the account** and **revoke active sessions / tokens**
- **Reset the password** (and force MFA re-registration if a device was added)
- **Isolate the host** in EDR if anything malicious ran
- **Then block the IP** at the firewall or conditional access
- **Escalate** to L2 / incident response with your timeline

### 7. Hunt that IP across the environment
Finally, assume this was not the only target.
- Search the IP across **all accounts** for the last **30 days**
- Look for other 4624s, VPN logins, and cloud sign-ins from the same IP or ASN

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Confirm the pattern and build a timeline | SIEM, Event IDs 4625 / 4624, logon type |
| 2 | Brute force vs password spraying | SIEM: accounts per source IP |
| 3 | Check the IP | VirusTotal, AbuseIPDB, geo / ASN, VPN / Tor lists |
| 4 | Check post-login activity | EDR (PowerShell, 4698, LSASS), Entra ID / M365 logs |
| 5 | Verify with the user | Phone or separate channel |
| 6 | Contain, then block | Disable account, revoke sessions, reset, isolate, firewall |
| 7 | Hunt the IP for 30 days | SIEM search across all accounts |

## What the Interviewer Is Really Testing

They want to see that you know **which tool answers which question**: the SIEM for the pattern, threat intel for the IP, EDR for the host, and cloud logs for identity. They also want to hear **who to call before you act**, because verifying with the user and escalating with evidence is what separates an analyst from a firewall rule.

## Follow-Up Questions to Expect

- **How would you tell RDP from a network logon?** *Logon type in Event 4624: 10 is RDP, 3 is network.*
- **What if the IP is a known corporate VPN?** *Then the attacker may be inside or using stolen VPN creds; check the VPN logs for the real source.*
- **Why not block the IP first?** *It does not end the live session or reset the stolen password; contain the account first.*

## One-Line Answer to Memorize

> "I confirm the 4625-to-4624 pattern, check the IP and what happened after the login, verify with the user, contain the account and host before blocking the IP, then hunt that IP across every account."

---

[← All 30 questions](README.md) · [Next: Q2](02-user-clicked-phishing-link.md)
