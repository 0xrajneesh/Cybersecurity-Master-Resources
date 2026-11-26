# Q10. A Host Calls an Unknown Domain Every 60 Seconds

> **Difficulty:** Intermediate · **Topic:** Network Detection / C2 · **Asked for:** SOC L1 / L2

## The Question

> "A host contacts an unknown domain every 60 seconds. What is happening and how do you confirm it?"

## The Trap Answer

Candidates often say **"It is malware, block the domain."** Regular check-ins sound like malware, so the answer feels safe.

It fails because plenty of legitimate software **beacons on a timer**: update checkers, telemetry, license servers, and monitoring agents. It also fails the other way: if it really is **command and control (C2)**, blocking the domain while the implant is still running just pushes it to a backup domain. You need to **prove what is beaconing** before you act.

## The Strong Answer, Step by Step

### 1. Name what you suspect
- Regular, repeating connections are called **beaconing**
- It is a classic sign of **C2**: the implant checks in for instructions
- Tools like **Cobalt Strike** and **Sliver** beacon on a configurable **sleep interval with jitter**

### 2. Investigate the domain
- **WHOIS**: a domain registered **days ago** is a red flag
- Reputation in **VirusTotal**, **urlscan.io**, and your threat intel platform
- Look for **DGA-style** random names or cheap TLDs
- Check its **DNS history** and hosting provider

### 3. Measure the pattern
- In proxy, firewall, or **Zeek** logs, check the **interval, jitter, and request size**
- Very consistent timing and small, similar request sizes suggest automation
- Note the **user agent** and URI: odd or fake browser strings are a clue
- Tools like **RITA** (Real Intelligence Threat Analytics) score beaconing in Zeek data

### 4. Find the process
Network data tells you the host. EDR tells you **what** is beaconing.
- In **EDR**, find the process owning the connection
- **Sysmon Event ID 3** (network connection) and **Event ID 22** (DNS query) map traffic to a process
- Red flags: unsigned binary, odd path (`%APPDATA%`, `%TEMP%`), or `rundll32.exe` making web requests

### 5. Look for how it got there and how it stays
- Trace the process back: what created it and when (Sysmon Event ID **1**, **11**)
- Persistence: **scheduled tasks (4698)**, **services (7045)**, **Run keys** (Sysmon Event ID **13**)

### 6. Contain and scope
- If confirmed malicious: **isolate the host** in EDR first, then **block the domain and IP**
- Hunt for **other hosts** resolving the same domain or running the same hash
- **Escalate** with the domain, process, hash and timeline

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Recognise beaconing | Regular interval, possible C2 |
| 2 | Investigate the domain | WHOIS, VirusTotal, urlscan.io, DNS history |
| 3 | Measure the pattern | Proxy / firewall / Zeek logs, RITA |
| 4 | Find the process | EDR, Sysmon Event IDs 3 and 22 |
| 5 | Trace origin and persistence | Sysmon 1, 11, 13; Event IDs 4698, 7045 |
| 6 | Contain and scope | EDR isolation, DNS / proxy block, hunt |

## What the Interviewer Is Really Testing

They want to see that you can **link network behaviour to a specific process** and that you know **legitimate software beacons too**. Proving it before you block is what makes the containment stick.

## Follow-Up Questions to Expect

- **What is jitter?** *Random variation added to the sleep interval so beacons look less regular.*
- **Which MITRE tactic is this?** *Command and Control (TA0011), for example T1071.001 Application Layer Protocol: Web Protocols.*
- **What if the traffic goes to a trusted cloud service?** *Attackers use domain fronting and cloud services for C2, so check the process, not just the domain.*

## One-Line Answer to Memorize

> "It looks like C2 beaconing, so I check the domain's age and reputation, measure the timing, find the process behind it in EDR, and isolate the host before blocking the domain."

---

[← All 30 questions](README.md) · [Previous: Q9](09-new-admin-account-at-midnight.md) · [Next: Q11](11-lsass-access-credential-dumping.md)
