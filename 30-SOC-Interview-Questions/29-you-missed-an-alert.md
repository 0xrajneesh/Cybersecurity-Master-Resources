# Q29. You Closed a Real Attack as a False Positive

> **Difficulty:** Intermediate · **Topic:** Professional Judgement · **Asked for:** SOC L1 / L2

## The Question

> "You realise you closed a real attack as a false positive yesterday. What do you do?"

## The Trap Answer

**"I would quietly reopen it and fix it myself."** It sounds responsible, but hiding a mistake costs hours the attacker uses to dig in. A day-old compromise needs more people, not fewer.

The other trap is **"That would never happen, I am very careful."** Every analyst misses something eventually. The interviewer wants to hear **ownership, speed and process**, not perfection.

## The Strong Answer, Step by Step

### 1. Tell your lead immediately
- Message or call your **shift lead / L2** the moment you realise
- Short and factual: *"I closed alert X yesterday as FP. New evidence says it is real. Reopening now."*
- Speed matters more than pride: the attacker has had **24 hours**

### 2. Reopen and re-classify the case
- Reopen the original ticket, do not create a disconnected one
- Change classification to **True Positive** and raise severity as needed
- Keep your original notes; they are part of the **timeline**

### 3. Re-investigate with the full window
- Pull activity from the **original alert time to now**
- Logons (**4624**, **4625**), new services (**7045**), scheduled tasks (**4698**), new accounts (**4720**)
- EDR process trees, outbound connections, data volume
- Check whether the same indicator appears on **other hosts or users**

### 4. Contain based on what you find
- **Isolate** affected hosts via EDR
- **Disable / reset** compromised accounts and revoke sessions
- Block IOCs at firewall, proxy, email gateway
- Escalate to **incident response** if scope has grown

### 5. Find out why it was missed
Blameless root cause, focused on the process.
- Was the alert **missing context** (no user info, no asset criticality)?
- Did the playbook lack a **check** that would have caught it?
- Was it **alert fatigue** from a noisy rule?

### 6. Fix the process
- Update the **playbook** with the missing step
- Ask detection engineering to **enrich or tune** the rule
- Share the lesson in the shift handover so the **whole team** learns

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Notify lead immediately | Phone, Teams / Slack, shift lead |
| 2 | Reopen and re-classify | Ticketing system (ServiceNow, Jira) |
| 3 | Re-investigate full window | SIEM, EDR, 4624, 4720, 4698, 7045 |
| 4 | Contain | EDR isolation, account disable, IOC blocks |
| 5 | Blameless root cause | Playbook review, alert context |
| 6 | Improve process | Updated playbook, rule tuning, handover notes |

## What the Interviewer Is Really Testing

Your **integrity under pressure** and your **ability to recover a missed incident** quickly and methodically. They are checking whether you would be safe to trust with a night shift alone.

## Follow-Up Questions to Expect

- Would you be worried about getting in trouble? *Less than about the attacker; healthy SOCs run blameless reviews and value fast disclosure.*
- How do you avoid it happening again personally? *Follow the playbook fully, note what I checked, and ask for a second opinion on borderline cases.*
- What if your lead is unreachable? *Escalate to the next person in the on-call chain and start containment within my authority.*

## One-Line Answer to Memorize

> "I tell my lead straight away, reopen the case as a true positive, re-investigate everything since the alert, contain what I find, and then fix the playbook gap so nobody misses it again."

---

[← All 30 questions](README.md) · [Previous: Q28](28-incident-response-lifecycle.md) · [Next: Q30](30-tell-me-about-an-investigation.md)
