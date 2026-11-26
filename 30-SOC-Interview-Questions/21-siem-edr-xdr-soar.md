# Q21. SIEM vs EDR vs XDR vs SOAR

> **Difficulty:** Beginner · **Topic:** SOC Tooling · **Asked for:** SOC L1 / L2

## The Question

> "What is the difference between SIEM, EDR, XDR and SOAR?"

## The Trap Answer

**"They are all security tools that detect threats."** True, and useless. It tells the interviewer you have memorised acronyms but never thought about where each one sits in your workflow.

The real failure is not knowing **which tool answers which question**. On shift, you open the SIEM to see *what happened across the environment*, the EDR to see *what happened on this host*, and SOAR to *stop doing the same ten clicks by hand*. If you cannot say that, you will be slow on every alert.

## The Strong Answer, Step by Step

### 1. Define SIEM: the central log brain
A **Security Information and Event Management** platform collects, normalises and correlates logs from everything.
- Sources: **Windows Security logs**, firewalls, proxies, DNS, VPN, cloud audit logs (Entra ID, AWS CloudTrail)
- Core jobs: **correlation rules**, alerting, search, long-term **retention** for compliance
- Examples: **Splunk Enterprise Security**, **Microsoft Sentinel**, **IBM QRadar**, **Elastic Security**
- Question it answers: *"Did this IP touch anything else in the last 30 days?"*

### 2. Define EDR: deep visibility on the endpoint
**Endpoint Detection and Response** is an agent on each laptop and server recording process, file, registry and network activity.
- Sees **process trees** (winword.exe → cmd.exe → powershell.exe), command lines, hashes
- Can **isolate a host**, kill a process, quarantine a file, pull artifacts remotely
- Examples: **CrowdStrike Falcon**, **Microsoft Defender for Endpoint**, **SentinelOne**
- Question it answers: *"What did this process do after it started?"*

### 3. Define XDR: EDR stretched across more telemetry
**Extended Detection and Response** correlates endpoint, email, identity, cloud and network data, usually from one vendor's stack.
- Joins signals into one **incident** instead of five separate alerts
- Examples: **Microsoft Defender XDR**, **Palo Alto Cortex XDR**, **Trend Vision One**
- Honest caveat: XDR is partly a **marketing term**; quality depends on what it actually ingests

### 4. Define SOAR: automation and orchestration
**Security Orchestration, Automation and Response** runs **playbooks** that call other tools via APIs.
- Typical playbook: phishing email reported → extract URLs and hashes → enrich in VirusTotal → if malicious, purge from all mailboxes → open ticket
- Examples: **Splunk SOAR**, **Palo Alto Cortex XSOAR**, **Microsoft Sentinel playbooks (Logic Apps)**
- It does not detect anything on its own; it **acts on** what other tools detect

### 5. Show how they work together
Walk one alert through all four.
- EDR flags **encoded PowerShell** on a workstation
- XDR links it to a **phishing email** the user opened 3 minutes earlier
- SIEM search shows the same sender hit **12 other mailboxes**
- SOAR playbook **isolates the host**, purges the email, and creates the case

### 6. State the trade-offs
- SIEM: broad but **expensive per GB**, only as good as the logs you send
- EDR: deep but **blind** to devices without an agent (printers, IoT, unmanaged laptops)
- XDR: less tuning, but **vendor lock-in**
- SOAR: saves hours, but a bad playbook **automates mistakes at scale**

## Quick Reference

| Tool | Scope | Main job | Example products |
|---|---|---|---|
| SIEM | Whole environment (logs) | Collect, correlate, search, retain | Splunk ES, Sentinel, QRadar |
| EDR | Endpoints | Process-level visibility and host response | CrowdStrike, Defender for Endpoint, SentinelOne |
| XDR | Endpoint + email + identity + cloud | Correlate signals into incidents | Defender XDR, Cortex XDR |
| SOAR | Across tools via API | Automate enrichment and response | Splunk SOAR, Cortex XSOAR |

## What the Interviewer Is Really Testing

Whether you understand **where each tool fits in an investigation** and whether you can **pick the right tool for the question** in front of you. Bonus points for knowing that SOAR acts while the others detect.

## Follow-Up Questions to Expect

- Can EDR replace a SIEM? *No. EDR sees endpoints only; you still need firewall, identity, DNS and cloud logs correlated centrally.*
- Which SIEM have you used? *Name one, and describe a search you ran, even from a home lab with Splunk Free or Elastic.*
- What would you automate first with SOAR? *Repetitive enrichment: IP, domain and hash reputation lookups on every alert.*

## One-Line Answer to Memorize

> "SIEM correlates logs across the whole environment, EDR gives deep visibility and response on endpoints, XDR stitches endpoint, email, identity and cloud into one incident, and SOAR automates the response steps across all of them."

---

[← All 30 questions](README.md) · [Previous: Q20](20-windows-event-ids-to-know.md) · [Next: Q22](22-escalate-or-close.md)
