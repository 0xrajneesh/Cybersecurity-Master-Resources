# Q14. User Approved an MFA Push They Did Not Start

> **Difficulty:** Intermediate · **Topic:** Identity / MFA · **Asked for:** SOC L1 / L2

## The Question

> "A user approved an MFA push they did not start. How do you respond?"

## The Trap Answer

**"MFA protected us. I would remind the user to be careful next time."**

It did the opposite. A push only appears after the **correct password** was entered, so the attacker already has the password. The user approving it handed over a **valid authenticated session**. This is **MFA fatigue** or **push bombing**, MITRE **T1621 (Multi-Factor Authentication Request Generation)**, and it was used in several high-profile breaches.

Treat it as a **confirmed account compromise**. Awareness training comes later; containment comes now.

## The Strong Answer, Step by Step

### 1. Treat it as a live compromise
- Password is known to the attacker, and they now hold a session
- Time matters: every minute the session lives, they can read mail, files and add persistence

### 2. Contain the identity first
- **Revoke all sessions and refresh tokens** (Entra ID "Revoke sessions" or `Revoke-MgUserSignInSession`)
- **Reset the password**
- **Temporarily disable** the account if the business allows it
- Review **registered MFA methods** and remove any the attacker added

### 3. Read the sign-in logs
- **Entra ID sign-in logs** (or Okta System Log): many MFA denied or timed-out attempts, then one success
- Source **IP, country, ASN, device, user agent**
- Which **application** was accessed: Outlook, SharePoint, VPN, Azure portal?

### 4. Check what the attacker did after login
- **Unified Audit Log**: inbox rules (**New-InboxRule**), file downloads (**FileDownloaded**), sharing links
- New **MFA device registration**, **OAuth app consent**, password changes
- If VPN was the target: internal network activity from the VPN IP, then **EDR** on any hosts touched

### 5. Talk to the user
- Ask how many prompts they received and when
- Did anyone call or message them pretending to be IT? Attackers often pair push bombing with a **vishing** call
- Where might the password have leaked? Reuse, phishing, an **infostealer** on a personal device

### 6. Escalate and hunt
- Escalate to L2/IR with the timeline
- Search for the same IP against **other users**; push bombing campaigns often target several accounts

### 7. Recommend the fix
- **Number matching** in Microsoft Authenticator (now enforced by Microsoft) and additional context in the prompt
- **Phishing-resistant MFA** such as **FIDO2 security keys** for privileged users
- **Conditional Access** policies and alerts for repeated MFA denials

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Treat as compromise | Password known, session issued |
| 2 | Contain identity | Revoke sessions, reset password, review MFA methods |
| 3 | Review sign-ins | Entra ID / Okta logs, denied then approved |
| 4 | Check post-login activity | Unified Audit Log, EDR |
| 5 | Interview user | Prompt count, vishing call, password source |
| 6 | Escalate and hunt | Same IP across all users |
| 7 | Harden | Number matching, FIDO2, Conditional Access |

## What the Interviewer Is Really Testing

They want to know you understand that **MFA approval means the password is already compromised** and that you prioritise **session revocation** over user education. Recommending number matching or phishing-resistant MFA shows you think beyond the single ticket.

## Follow-Up Questions to Expect

- **Why is a password reset alone not enough?** *The attacker's existing session and refresh tokens remain valid until revoked.*
- **What is number matching?** *The user must type a number shown on the login screen into the app, so blind approvals fail.*
- **What would you alert on to catch this earlier?** *Multiple MFA denials or timeouts for one user in a short window, then a success from a new IP.*

## One-Line Answer to Memorize

> "An approved push means the attacker has the password and a session, so I revoke sessions, reset the password, review MFA methods, check what they did, and push for number matching or FIDO2."

---

[← All 30 questions](README.md) · [Previous: Q13](13-inbox-forwarding-rule.md) · [Next: Q15](15-crypto-miner-high-cpu.md)
