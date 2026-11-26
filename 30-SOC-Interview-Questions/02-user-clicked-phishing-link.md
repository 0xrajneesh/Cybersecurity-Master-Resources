# Q2. A User Clicked a Phishing Link

> **Difficulty:** Beginner · **Topic:** Phishing Response · **Asked for:** SOC L1 / L2

## The Question

> "A user tells you they clicked a link in a suspicious email. Walk me through your response."

## The Trap Answer

The common answer is **"Tell them to change their password and delete the email."** It is quick, it sounds safe, and it closes the ticket.

It fails because you have no idea what the link actually did. It might have been a credential harvesting page, a drive-by download, or nothing at all. And if one person got the email, **dozens of others probably did too**. Resetting one password while the same email sits in 200 inboxes is not a response.

## The Strong Answer, Step by Step

### 1. Thank the user and get the facts
Reporting fast is good behaviour. Reward it, then ask precise questions.
- **When** did they click, and on which device?
- Did they **enter credentials** on the page?
- Did anything **download or open**?
- Ask them to **forward the email as an attachment** (keeps the headers) and not delete it

### 2. Analyse the email and the link
Work out what you are dealing with before you act.
- Check the **headers**: sender, Return-Path, **SPF / DKIM / DMARC** results
- Extract the URL and detonate it safely in **urlscan.io**, **ANY.RUN** or **Joe Sandbox**
- Check domain age and reputation in **VirusTotal**
- Is it a **fake login page** or a **file download**?

### 3. Check the user's identity
If credentials were entered, assume they are already being used.
- In **Microsoft Entra ID sign-in logs**, look for sign-ins from new IPs or countries after the click
- Look for **new MFA methods** registered
- Look for **new inbox rules** (forwarding or deleting mail)

### 4. Check the endpoint
If anything downloaded, the problem is on the host too.
- In **EDR**, review process activity on the device around the click time
- Browser spawning unusual children, files in **Downloads** or **%TEMP%**, new **scheduled tasks**
- Look for outbound connections to the phishing domain or new IPs

### 5. Scope the campaign
One reporter usually means many recipients.
- Search mail logs for the same **sender, subject or URL** (for example **Message Trace** or **Threat Explorer** in Microsoft Defender for Office 365)
- Find who else **received** it and who else **clicked** (proxy or URL click logs)

### 6. Contain
Act on what the evidence showed.
- **Purge the email** from all mailboxes
- **Block** the sender domain and URL at the mail gateway and proxy
- If creds were entered: **reset password, revoke sessions**, remove rogue MFA devices
- If malware ran: **isolate the host** in EDR and escalate

### 7. Document and close the loop
- Record IOCs: sender, URLs, domains, hashes
- Tell the user what happened and what you did

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Get the facts from the user | Time, device, creds entered?, email as attachment |
| 2 | Analyse email and URL | Headers, SPF/DKIM/DMARC, urlscan.io, ANY.RUN, VirusTotal |
| 3 | Check identity | Entra ID sign-in logs, MFA methods, inbox rules |
| 4 | Check endpoint | EDR process tree, downloads, network connections |
| 5 | Scope the campaign | Message Trace / Threat Explorer, proxy logs |
| 6 | Contain | Purge, block, reset, revoke, isolate |
| 7 | Document | IOC list, ticket notes, user feedback |

## What the Interviewer Is Really Testing

They want to see you **figure out what the link actually did** before choosing a fix, and that you **scope beyond one user**. A good phishing response treats the reporter as the first signal of a campaign, not the whole incident.

## Follow-Up Questions to Expect

- **The user entered their password but has MFA. Are we safe?** *Not necessarily; adversary-in-the-middle kits steal session tokens, so revoke sessions anyway.*
- **How do you safely open the link?** *Never on your workstation; use a sandbox like urlscan.io or ANY.RUN.*
- **What if 40 people clicked?** *Prioritise those who entered creds or downloaded files, then purge and reset in bulk.*

## One-Line Answer to Memorize

> "I find out what the link did, check the user's sign-ins and device, scope everyone who got the email, then purge, block and reset based on the evidence."

---

[← All 30 questions](README.md) · [Previous: Q1](01-500-failed-logins-then-success.md) · [Next: Q3](03-encoded-powershell-alert.md)
