# Q26. Phishing Email Header Analysis

> **Difficulty:** Intermediate · **Topic:** Email Security · **Asked for:** SOC L1 / L2

## The Question

> "How do you analyse a phishing email's headers? What do SPF, DKIM and DMARC tell you?"

## The Trap Answer

**"I check the From address. If it looks like the real company, it is fine."** The display name and From address are the easiest things in an email to fake.

The second trap is **"If SPF, DKIM and DMARC all pass, it is safe."** Attackers register their own lookalike domains and set up perfect authentication. A pass only proves the email came from the domain it claims, not that the domain is trustworthy.

## The Strong Answer, Step by Step

### 1. Get the full raw headers
- Outlook: **File → Properties → Internet headers**, or the message source
- Gmail: **Show original**
- Paste into **MXToolbox Header Analyzer** or **Google Admin Toolbox Messageheader** to read hops cleanly
- Never click links or open attachments while doing this

### 2. Compare the sender fields
- **From**: what the user sees
- **Return-Path** (envelope sender): where bounces go, used by SPF
- **Reply-To**: where replies go; a mismatch to a free webmail address is a **classic BEC sign**
- Lookalike domains: **micros0ft-support.com**, extra hyphens, different TLD

### 3. Read the Received chain bottom to top
- The **lowest Received header** is closest to the true origin
- Note the **originating IP** and the first external mail server
- Check that IP in **AbuseIPDB**, **VirusTotal**, and against the sender's expected mail provider

### 4. Interpret SPF
**Sender Policy Framework**: is this sending IP allowed to send for the Return-Path domain?
- Look for `spf=pass` / `spf=fail` / `softfail` in **Authentication-Results**
- SPF checks the **envelope** domain, not the visible From

### 5. Interpret DKIM
**DomainKeys Identified Mail**: a cryptographic signature proving the message was signed by the domain in **d=** and not altered in transit.
- `dkim=pass header.d=example.com`
- Check that **d=** matches the From domain

### 6. Interpret DMARC
**Domain-based Message Authentication, Reporting and Conformance** ties it together.
- Passes only if SPF or DKIM passes **and aligns** with the visible From domain
- Domain policy: **p=none** (monitor), **p=quarantine**, **p=reject**
- `dmarc=fail` on a From of a real brand is a **strong spoofing signal**

### 7. Check the content and scope
- Detonate URLs and attachments in a **sandbox** (Any.Run, Joe Sandbox, URLScan.io)
- Search the mail gateway for the **same sender, subject or URL** across all mailboxes
- Purge, block the sender / domain, and check who **clicked**

## Quick Reference

| Check | What it proves | What it does not prove |
|---|---|---|
| From / Reply-To | What the user sees and replies to | Anything; easily forged |
| Received chain | The path and origin IP | Intent |
| SPF | Sending IP is authorised for envelope domain | That the visible From is genuine |
| DKIM | Message signed by d= domain and unaltered | That the domain is trustworthy |
| DMARC | SPF / DKIM align with visible From | That a lookalike domain is safe |
| Sandbox + scope | Payload behaviour and blast radius | Root cause on endpoints |

## What the Interviewer Is Really Testing

Whether you can **read headers methodically** and whether you understand that **authentication results prove origin, not safety**.

## Follow-Up Questions to Expect

- SPF passes but DMARC fails. Why? *The envelope domain passed SPF but does not align with the visible From domain, which points to spoofing.*
- What is a lookalike domain? *A domain built to resemble a real one, such as rn instead of m, which can pass all authentication checks.*
- After confirming phishing, what next? *Scope recipients, purge the email, block indicators, and check for clicks and credential entry.*

## One-Line Answer to Memorize

> "I pull the raw headers, compare From, Return-Path and Reply-To, trace the Received chain to the origin IP, then read SPF, DKIM and DMARC, remembering that a pass proves where it came from, not that it is safe."

---

[← All 30 questions](README.md) · [Previous: Q25](25-splunk-query-brute-force.md) · [Next: Q27](27-virustotal-3-detections.md)
