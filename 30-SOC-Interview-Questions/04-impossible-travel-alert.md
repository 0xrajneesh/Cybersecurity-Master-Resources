# Q4. Impossible Travel for a Senior Executive

> **Difficulty:** Beginner · **Topic:** Identity and Cloud · **Asked for:** SOC L1 / L2

## The Question

> "You get an impossible travel alert for a senior executive. What do you do?"

## The Trap Answer

The typical answer is **"Lock the account immediately."** It feels safe because executives are high-value targets.

It fails because impossible travel is **one of the noisiest alerts in any SOC**. VPNs, mobile carriers, and cloud proxies routinely make a user look like they are in two countries at once. Locking a CEO out before a board meeting over a VPN exit node damages trust in the SOC. The strong answer verifies fast and acts hard only when the evidence says so.

## The Strong Answer, Step by Step

### 1. Read both sign-ins in detail
The alert is two data points. Look at both.
- In **Microsoft Entra ID sign-in logs** (or Okta, Google Workspace): IP, location, time, **user agent**, device
- Was **MFA satisfied**, and by which method?
- Is the device **compliant / managed** or unknown?

### 2. Rule out the usual false positives
Most of these alerts have a boring explanation.
- Is one IP a **corporate VPN**, **cloud proxy** or **mobile carrier** egress?
- Does the executive have **travel** on their calendar (ask their assistant)?
- Are both sign-ins from the **same device** and the same browser?

### 3. Check the IP reputation
- **VirusTotal**, **AbuseIPDB**, ASN lookup
- Hosting provider, **VPN service**, or **Tor** exit? Attackers love these

### 4. Check what the session did
A stolen session shows itself in behaviour.
- **Unified Audit Log** in Microsoft 365: mailbox access, file downloads, sharing links
- **New inbox rules** or forwarding
- **New MFA methods** or app consent grants (OAuth)

### 5. Verify with the executive
Use a channel the attacker cannot control.
- Call them, or go through their **executive assistant**
- Ask simply: **"Were you signing in from this location at this time?"**

### 6. Contain if it is not them
Executives get priority handling, but containment is the same.
- **Revoke sessions** and **reset the password**
- Remove rogue **MFA methods** and malicious **OAuth apps**
- Remove malicious **inbox rules**
- **Escalate immediately**: executive compromise can lead to **business email compromise (BEC)** and wire fraud

### 7. Tune and document
- If it was a known VPN, add it as a **named / trusted location** to reduce noise
- Record the outcome so the next analyst moves faster

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Compare both sign-ins | Entra ID sign-in logs: IP, device, MFA, user agent |
| 2 | Rule out VPN / travel | VPN egress list, calendar, assistant |
| 3 | Check IP reputation | VirusTotal, AbuseIPDB, ASN |
| 4 | Review session activity | M365 Unified Audit Log, inbox rules, OAuth consents |
| 5 | Verify with the exec | Phone or executive assistant |
| 6 | Contain | Revoke, reset, remove rules and MFA, escalate |
| 7 | Tune | Named locations, ticket notes |

## What the Interviewer Is Really Testing

They want to see you **separate signal from noise** without being reckless, and that you understand **business impact**: an executive account is both a high-value target and a person you cannot casually lock out. Balance speed with verification.

## Follow-Up Questions to Expect

- **MFA was passed on the second sign-in. Is it safe?** *No; token theft and MFA fatigue bypass MFA, so check device and session behaviour.*
- **What is BEC?** *An attacker uses a real mailbox to trick staff into paying invoices or sending data.*
- **How do you reduce false positives long term?** *Trusted locations, compliant device policies, and tuning on known VPN ranges.*

## One-Line Answer to Memorize

> "I compare both sign-ins, rule out VPN and travel, check what the session did, verify with the executive, and if it is not them I revoke, reset and escalate as a possible BEC."

---

[← All 30 questions](README.md) · [Previous: Q3](03-encoded-powershell-alert.md) · [Next: Q5](05-ransomware-note-on-file-server.md)
