# Q27. 3 out of 70 on VirusTotal

> **Difficulty:** Intermediate · **Topic:** Malware Triage · **Asked for:** SOC L1 / L2

## The Question

> "A file hash shows 3 out of 70 detections on VirusTotal. Is it malicious?"

## The Trap Answer

**"Only 3 engines flagged it, so it is a false positive."** Or the opposite: **"Any detection means malicious."** Both treat the score as the answer instead of the starting point.

Low detection counts are normal for **brand-new malware**, targeted payloads and packed files that engines have not caught up with yet. They are also normal for **hacking tools, adware and unsigned admin utilities**. The number alone cannot tell you which.

## The Strong Answer, Step by Step

### 1. Say "it depends", then show what it depends on
The detection ratio is **one signal**. You need context from VirusTotal itself and from your own environment.

### 2. Look at who detected it and what they called it
- Are the 3 engines **reputable** for this file type?
- Are the labels **generic** (`Generic.ML`, `Heuristic`, `Suspicious`) or **specific** (`Trojan.AgentTesla`)?
- **PUA / HackTool / RiskWare** labels mean a dual-use tool, not necessarily an attack

### 3. Check the file's history and metadata
- **First Submission** date: submitted yesterday is more worrying than seen for 5 years
- **Digital signature**: signed by a known vendor, or unsigned / invalid?
- File names, **community comments**, and **Relations** tab (contacted domains, IPs)
- Packer or obfuscation info in the **Details** tab

### 4. Look at behaviour, not just signatures
- VirusTotal **Behavior** tab (sandbox reports)
- Detonate in **Any.Run**, **Joe Sandbox** or **Hybrid Analysis** if allowed by policy
- Do not upload **internal or sensitive files** to public services; upload the hash only when unsure

### 5. Check your own environment
- How did it arrive: **email attachment, download, USB**?
- **Parent process** in EDR: dropped by winword.exe or a browser is a red flag
- **Prevalence**: on 1 host or 500? A rare file on one host is more suspicious
- Any **network connections, persistence** (Run keys, scheduled tasks **4698**, services **7045**)?

### 6. Make the call and document it
- Malicious behaviour or suspicious delivery: **treat as malicious**, isolate and escalate
- Known legitimate software with generic heuristics: **benign**, note the evidence
- Still unclear: **escalate** with your findings and keep the host under watch

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Treat score as a signal | VirusTotal detection ratio |
| 2 | Judge engines and labels | Detection tab, label names |
| 3 | Review history and metadata | First Submission, signature, Relations |
| 4 | Check behaviour | VT Behavior, Any.Run, Joe Sandbox, Hybrid Analysis |
| 5 | Check local context | EDR parent process, prevalence, 4698, 7045 |
| 6 | Decide and document | Ticket notes, escalation |

## What the Interviewer Is Really Testing

Whether you treat threat intel scores as **evidence to weigh, not a verdict**, and whether you go back to **your own telemetry** to make the final call.

## Follow-Up Questions to Expect

- What if it is 0 out of 70? *Zero means unknown, not clean; brand-new or targeted malware often starts at zero.*
- Why not upload every suspicious file to VirusTotal? *Uploads are visible to other subscribers and may leak internal data or tip off the attacker.*
- What is a PUA? *A potentially unwanted application such as adware or a bundled toolbar, not usually an active attacker.*

## One-Line Answer to Memorize

> "Three out of seventy is not a verdict, so I check which engines and labels flagged it, its age and signature, its sandbox behaviour, and how it arrived and behaves on our host before I decide."

---

[← All 30 questions](README.md) · [Previous: Q26](26-phishing-email-header-analysis.md) · [Next: Q28](28-incident-response-lifecycle.md)
