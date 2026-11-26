# Q22. Escalate or Close?

> **Difficulty:** Intermediate · **Topic:** Triage · **Asked for:** SOC L1 / L2

## The Question

> "How do you decide whether to escalate an alert or close it?"

## The Trap Answer

**"If it looks bad I escalate, if it looks fine I close it."** That is a feeling, not a process. Two analysts with that answer will make two different decisions on the same alert.

Interviewers also hear the opposite trap: **"I escalate everything to be safe."** That floods L2, buries real incidents and shows you cannot own a decision. A good L1 closes confidently *with evidence* and escalates *with evidence*.

## The Strong Answer, Step by Step

### 1. Understand what the rule is detecting
Read the detection logic before you judge the alert.
- What **behaviour** does the rule look for? Which **log source**?
- Map it to a **MITRE ATT&CK** technique so you know the attacker goal
- Check the rule's **history**: is it known to be noisy?

### 2. Gather context on the entities
Every alert has a user, a host, an IP or a file. Enrich all of them.
- User: role, **privileged or not**, normal working hours, recent password reset
- Host: server or laptop, **asset criticality**, owner
- IP / domain / hash: **VirusTotal**, **AbuseIPDB**, internal threat intel

### 3. Look for a benign explanation you can prove
A false positive needs proof, not hope.
- Approved **change ticket**, known admin script, vulnerability scanner IP
- Same activity seen for months on the same host (**baseline**)
- Confirmation from the user or system owner, recorded in the ticket

### 4. Look for signs of real compromise
- Follow-on activity: **4624** after many **4625**, new service (**7045**), new scheduled task (**4698**)
- Suspicious **process trees** in EDR, outbound connections to rare domains
- Same indicator on **multiple hosts or users**

### 5. Apply the escalation criteria
Escalate when **any** of these is true:
- Evidence of **successful** malicious activity (not just an attempt)
- **Privileged account**, domain controller or crown-jewel system involved
- You **cannot rule it out** within your SLA or your access
- Your SOC runbook says this alert type always goes to L2

### 6. Close with a documented reason
- Classify: **True Positive**, **Benign True Positive**, or **False Positive**
- Write *what you checked, what you found, why you decided*
- Suggest **tuning** if the rule keeps firing on the same benign activity

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Understand the rule | Detection logic, MITRE ATT&CK |
| 2 | Enrich entities | AD / Entra ID, CMDB, VirusTotal, AbuseIPDB |
| 3 | Prove a benign cause | Change tickets, baseline, user confirmation |
| 4 | Hunt for compromise signs | SIEM search, EDR process tree, 4624 / 7045 / 4698 |
| 5 | Apply escalation criteria | SOC runbook, asset criticality, SLA |
| 6 | Close or escalate with notes | Ticketing system (ServiceNow, Jira) |

## What the Interviewer Is Really Testing

Whether you follow **an evidence-based, repeatable process** and whether you have the **judgement to own a decision** without either hiding behind escalation or closing things you have not checked.

## Follow-Up Questions to Expect

- What is a benign true positive? *The rule fired correctly on real behaviour, but the behaviour was authorised, like an admin running PsExec.*
- What do you write in an escalation? *Summary, timeline, entities, evidence, what you already did, and what you think L2 should do next.*
- What if you are unsure and the SLA is running out? *Escalate with what you have and say clearly what is still unknown.*

## One-Line Answer to Memorize

> "I understand the rule, enrich every entity, try to prove a benign cause, look for signs of success, and if it is real, privileged or unprovable, I escalate with evidence, otherwise I close with a documented reason."

---

[← All 30 questions](README.md) · [Previous: Q21](21-siem-edr-xdr-soar.md) · [Next: Q23](23-pyramid-of-pain.md)
