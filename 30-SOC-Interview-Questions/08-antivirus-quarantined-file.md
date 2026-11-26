# Q8. Antivirus Quarantined It. Can You Close the Ticket?

> **Difficulty:** Beginner · **Topic:** Alert Triage · **Asked for:** SOC L1 / L2

## The Question

> "Antivirus quarantined a malicious file. Can you close the ticket?"

## The Trap Answer

The tempting answer is **"Yes, the AV blocked it, so the threat is handled."** The console says *Quarantined*, so the job seems done.

It fails because **quarantine only tells you one file was caught**. It does not tell you how the file got there, whether it already ran, or whether other files that AV missed are still on the box. Attackers often drop several payloads, and the one that got caught is sometimes the noisy decoy.

## The Strong Answer, Step by Step

### 1. Say "Not yet" and explain why
- Quarantine is a **good outcome**, not a **complete investigation**
- You need to answer: **How did it arrive? Did it execute? Is anything else there?**

### 2. Confirm the detection details
- Check the AV / EDR alert: **file path, hash, detection name, action taken**
- In Microsoft Defender, look at **Event ID 1116** (malware detected) and **1117** (action taken)
- Was it caught **on write** or **on execution**? Execution means it may have already done something

### 3. Find how it arrived
- Was the parent a **browser**, **Outlook**, a **USB drive**, or another process?
- Check the **Zone.Identifier** (Mark of the Web) for the download URL
- If it came by email, find the message and **who else received it**

### 4. Check whether it ran
- Search **EDR** process telemetry for the hash or filename
- **Sysmon Event ID 1** / **Event ID 4688** for any execution
- **Prefetch** files can show if a program executed

### 5. Look for what AV missed
- Other new files in the same folder or timeframe (**Sysmon Event ID 11**)
- Network connections to suspicious domains (**Sysmon Event ID 3**)
- Persistence: **scheduled tasks (4698)**, **services (7045)**, **Run keys**

### 6. Check the hash and the family
- Look up the hash in **VirusTotal** and read the **detection names** and behaviour tab
- A family name like **Emotet** or **QakBot** implies follow-on payloads and spreading

### 7. Scope, then close with evidence
- Hunt the **hash, URL, or sender** across all endpoints and mailboxes
- Close only when you can write: arrival vector, no execution (or execution contained), no persistence, no other hosts affected

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Do not close yet | Quarantine is not an investigation |
| 2 | Confirm detection | Defender Event IDs 1116 / 1117, EDR alert |
| 3 | Find arrival vector | Parent process, Zone.Identifier, mail logs |
| 4 | Check execution | EDR, Sysmon 1, 4688, Prefetch |
| 5 | Find what AV missed | Sysmon 3 and 11, 4698, 7045 |
| 6 | Research the family | VirusTotal detections and behaviour |
| 7 | Scope and close | EDR / mail hunt, written closure notes |

## What the Interviewer Is Really Testing

They are testing **investigative curiosity** and **closure discipline**. A good analyst does not trust a single control and can explain exactly why a ticket is safe to close.

## Follow-Up Questions to Expect

- **What if it was caught before it ever ran?** *Still find the source and other recipients, then close with that documented.*
- **What does quarantine actually do?** *Moves and neutralises the file so it cannot run; it can be restored.*
- **When would you escalate?** *If it executed, has a known loader family, or appears on more than one host.*

## One-Line Answer to Memorize

> "Not yet: I confirm how the file arrived, whether it ran, what AV might have missed, and whether other hosts have it, and only then close with evidence."

---

[← All 30 questions](README.md) · [Previous: Q7](07-word-spawns-cmd.md) · [Next: Q9](09-new-admin-account-at-midnight.md)
