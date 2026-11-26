# Q13. New Inbox Rule Forwarding to an External Address

> **Difficulty:** Intermediate · **Topic:** Email / Cloud (Microsoft 365) · **Asked for:** SOC L1 / L2

## The Question

> "A user's mailbox has a new rule forwarding all email to an external address. What now?"

## The Trap Answer

**"I would delete the rule and tell the user not to do that."**

Deleting the rule removes the symptom, not the attacker. Users rarely create rules that forward everything to a Gmail address. This is a textbook sign of **Business Email Compromise (BEC)**: the attacker already has access and wants to keep reading mail even after a password reset. MITRE maps it to **T1114.003 (Email Collection: Email Forwarding Rule)**.

If you only delete the rule, the attacker's session token may still be valid, and they may have created a second hidden rule that moves replies to RSS Feeds or Archive so the user never sees them (**T1564.008, Email Hiding Rules**).

## The Strong Answer, Step by Step

### 1. Confirm who created the rule and from where
- **Microsoft 365 Unified Audit Log**: operations **New-InboxRule**, **Set-InboxRule**, **UpdateInboxRules**
- Also check mailbox-level forwarding: **Set-Mailbox** with `ForwardingSmtpAddress`
- Note the **ClientIP**, user agent and timestamp

### 2. Inspect the rule itself
The details tell you the attacker's goal.
- Forward all mail, or only mail with keywords like **"invoice", "payment", "wire", "bank"**?
- Does it **delete** or **mark as read** or move to an obscure folder?
- Pull every rule on the mailbox: `Get-InboxRule -Mailbox user@domain`

### 3. Review the sign-in logs
- **Entra ID (Azure AD) sign-in logs** around the rule creation time
- Unfamiliar IP, country, ASN, or a suspicious user agent
- Was **MFA** satisfied? A pass from a new location can mean an **AiTM phishing** proxy stole the session cookie

### 4. Find the initial access
- Search the user's mailbox for a recent **phishing email** with a credential harvesting link
- Check **Defender for Office 365** or your email gateway for clicked URLs

### 5. Contain
Order matters here.
- **Revoke all sessions / refresh tokens** so stolen cookies stop working
- **Reset the password** and re-register or review **MFA methods** (attackers often add their own)
- **Remove the malicious rules** and any mailbox forwarding
- Block the external address and the sign-in IP

### 6. Assess the damage
- What mail was forwarded? Use the **message trace** to list emails sent to the external address
- Did the attacker **send email** from the account? Look for internal phishing or fake invoice emails to customers
- Any **OAuth app consents** granted during the session?

### 7. Notify and escalate
- Escalate to L2/IR; possible **data exposure** may need legal or privacy review
- Warn finance and any contacts who received fraudulent mail

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Who created the rule | Unified Audit Log: New-InboxRule, Set-Mailbox |
| 2 | Inspect the rule | Get-InboxRule, keywords, delete/move actions |
| 3 | Review sign-ins | Entra ID sign-in logs, IP, MFA status |
| 4 | Find initial access | Email gateway, Defender for Office 365 |
| 5 | Contain | Revoke sessions, reset password, review MFA, remove rules |
| 6 | Assess damage | Message trace, sent items, OAuth consents |
| 7 | Escalate and notify | IR, legal, finance |

## What the Interviewer Is Really Testing

They want you to recognise **BEC indicators** immediately and know that **session revocation comes before or with the password reset**. Cleaning up without understanding how the attacker got in is the mistake they are screening for.

## Follow-Up Questions to Expect

- **Why revoke sessions if you already reset the password?** *Existing refresh tokens and stolen session cookies can stay valid until revoked.*
- **How would you detect this automatically?** *Alert on New-InboxRule or Set-Mailbox forwarding to external domains in the audit log.*
- **What is AiTM phishing?** *An adversary-in-the-middle proxy that relays the real login page and steals the session cookie after MFA.*

## One-Line Answer to Memorize

> "An external forwarding rule means likely BEC, so I check the audit and sign-in logs, revoke sessions, reset the password and MFA, remove the rules, then use message trace to see what was leaked."

---

[← All 30 questions](README.md) · [Previous: Q12](12-rdp-from-internet-ip.md) · [Next: Q14](14-mfa-fatigue-push-approved.md)
