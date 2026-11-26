# Q18. IOC vs IOA

> **Difficulty:** Beginner · **Topic:** Threat Intelligence / Detection · **Asked for:** SOC L1 / L2

## The Question

> "What is the difference between an IOC and an IOA? Give examples."

## The Trap Answer

**"They are basically the same thing, both are signs of an attack."**

They are related, but the difference is exactly what the interviewer is asking about. An **IOC (Indicator of Compromise)** is a piece of **evidence** that something bad already happened: a hash, an IP, a domain. An **IOA (Indicator of Attack)** describes **behaviour**: what an attacker is doing, regardless of which tool or IP they use.

Mixing them up suggests you only know how to paste hashes into VirusTotal. Modern attackers change hashes and IPs constantly; behaviour is much harder for them to change.

## The Strong Answer, Step by Step

### 1. Define IOC
- **Indicator of Compromise**: a forensic artefact showing a system **was** compromised
- **Reactive** and usually **static**
- Examples: **file hash** (SHA256), **malicious IP**, **C2 domain**, malicious URL, specific registry key, mutex name

### 2. Define IOA
- **Indicator of Attack**: a pattern of **behaviour** that shows an attack **is happening**
- **Proactive** and tool-agnostic
- Examples: **Office app spawning PowerShell**, a process reading **LSASS memory**, `vssadmin delete shadows`, many failed logins followed by a success, a new service created right after a remote logon

### 3. Give one scenario that shows both
Ransomware attack:
- **IOC**: the ransomware binary hash, the C2 IP, the ransom note filename
- **IOA**: shadow copy deletion, mass file renames, credential dumping, lateral movement with PsExec
- Change the binary and the IOC is useless; the IOA still fires

### 4. Connect it to the Pyramid of Pain
- IOCs like hashes and IPs sit at the **bottom**: trivial for attackers to change
- IOAs map to **TTPs** at the **top**: painful for attackers to change
- That is why mature detection focuses on behaviour

### 5. Show how you use each on shift
- **IOCs**: block lists, threat intel feeds (**MISP**, **AlienVault OTX**), retro-hunts in the SIEM ("did any host talk to this IP in the last 30 days?")
- **IOAs**: EDR behavioural detections, **Sigma** rules, ATT&CK-mapped SIEM correlations
- During an incident, you extract IOCs from what you find and hunt for them everywhere; you use IOAs to catch what the IOCs miss

## Quick Reference

| Aspect | IOC | IOA |
|---|---|---|
| Meaning | Evidence a compromise happened | Behaviour showing an attack in progress |
| Timing | Reactive, after the fact | Proactive, during the attack |
| Nature | Static artefact | Behaviour pattern |
| Examples | Hash, IP, domain, URL, registry key | Word spawns PowerShell, LSASS read, shadow copy deletion |
| Easy for attacker to change? | Yes | No |
| Pyramid of Pain | Bottom levels | TTPs at the top |
| Typical tools | Threat intel feeds, blocklists, MISP | EDR behaviour rules, Sigma, ATT&CK |

## What the Interviewer Is Really Testing

They want to see that you can separate **artefacts from behaviour** and understand why **behaviour-based detection** survives attacker changes. Linking it to the Pyramid of Pain shows you think about detection quality, not just lookups.

## Follow-Up Questions to Expect

- **Are IOCs still useful?** *Yes, for quick blocking and retro-hunting, but they expire fast.*
- **Give an IOA for phishing.** *A browser or Office process writing and executing a new file from the Downloads folder.*
- **Where do you get IOCs from?** *Threat intel feeds, vendor reports, ISACs and your own investigations.*

## One-Line Answer to Memorize

> "An IOC is evidence that a compromise happened, like a hash or IP, while an IOA is attacker behaviour, like Word spawning PowerShell, and IOAs are harder for attackers to change."

---

[← All 30 questions](README.md) · [Previous: Q17](17-prioritize-50-alerts.md) · [Next: Q19](19-mitre-attack-in-investigations.md)
