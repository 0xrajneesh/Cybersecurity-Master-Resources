# Q17. Prioritizing 50 Open Alerts at Shift Start

> **Difficulty:** Beginner · **Topic:** SOC Operations / Triage · **Asked for:** SOC L1 / L2

## The Question

> "You start your shift with 50 open alerts. How do you prioritize them?"

## The Trap Answer

**"I would start with the oldest alert and work through them in order."**

First in, first out sounds fair, but attackers do not wait in line. The ransomware precursor at alert 47 matters far more than a low-severity policy violation from yesterday. Working by age guarantees the most dangerous alert gets the least attention.

The other trap is **"highest severity first, done."** Severity is set by the rule author, not by context. A "medium" alert on a domain controller can be more urgent than a "high" on a test VM.

## The Strong Answer, Step by Step

### 1. Read the handover first
- Check the **shift handover notes** and any open incidents already in progress
- Ask the outgoing analyst what is hot; two minutes here can save an hour

### 2. Scan the whole queue before diving in
- Spend a few minutes looking at all 50, not working the first one
- **Group duplicates**: 20 alerts from the same host or user may be one incident
- Look for **patterns**: same IP, same hash, same time window across hosts

### 3. Prioritize by severity plus context
Use a simple mental formula: **severity x asset criticality x confidence**.
- **Severity**: Critical and High first
- **Asset criticality**: domain controllers, admin accounts, executives, internet-facing servers, payment systems
- **Confidence**: high-fidelity EDR detections beat noisy generic rules

### 4. Push active-attack signals to the top
These jump the queue regardless of score.
- **Ransomware behaviour**: mass file renames, `vssadmin delete shadows`
- **Credential dumping** (LSASS access), new domain admins (**Event ID 4728 / 4732**)
- **Lateral movement** or confirmed **C2 beaconing**
- Anything that shows the attack is **still in progress**

### 5. Respect SLAs
- Check each alert's **SLA timer** in the SIEM or SOAR (Splunk ES, Sentinel, QRadar)
- Critical alerts often carry a short response SLA; do not let one breach while you work a low

### 6. Clear the easy noise quickly
- Known **false positives** with documented patterns can be closed fast with notes
- Use **SOAR playbooks** for enrichment so you spend time on judgment, not copy-paste

### 7. Escalate and communicate
- If an incident is too big to handle alone, **escalate to L2** early and keep triaging the rest
- Update ticket notes so the next shift knows where you left off

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Read handover | Shift notes, open incidents |
| 2 | Scan and group | SIEM queue, correlate host / user / IP |
| 3 | Score by context | Severity, asset criticality, confidence |
| 4 | Promote active attacks | Ransomware, LSASS, new admins, C2 |
| 5 | Watch SLAs | SIEM / SOAR timers |
| 6 | Clear known noise | Documented FPs, SOAR enrichment |
| 7 | Escalate and document | L2, ticket notes, handover |

## What the Interviewer Is Really Testing

They are checking that you can think in terms of **risk, not order of arrival**, and that you **correlate alerts into incidents** instead of treating each one in isolation. Calm, structured triage under volume is the core L1 skill.

## Follow-Up Questions to Expect

- **Two critical alerts arrive at the same time. Which first?** *The one on the more critical asset or showing active spread; escalate the other if you cannot handle both.*
- **How do you avoid alert fatigue?** *Push tuning requests for noisy rules and use automation for enrichment.*
- **What goes into a good handover note?** *Open incidents, what was done, what is pending, and who was contacted.*

## One-Line Answer to Memorize

> "I read the handover, scan and group the whole queue, then rank by severity, asset criticality and signs of an active attack, while watching SLAs and escalating early."

---

[← All 30 questions](README.md) · [Previous: Q16](16-true-false-positive-negative.md) · [Next: Q18](18-ioc-vs-ioa.md)
