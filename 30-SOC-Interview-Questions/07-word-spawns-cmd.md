# Q7. Microsoft Word Launched cmd.exe

> **Difficulty:** Intermediate · **Topic:** Endpoint Investigation · **Asked for:** SOC L1 / L2

## The Question

> "Microsoft Word just launched cmd.exe. Why does that matter, and what do you check?"

## The Trap Answer

A weak answer is **"Word might have crashed, or the user ran a macro. Let me check with them."** It treats the alert as a curiosity.

It fails because **Word has almost no legitimate reason to spawn a shell**. A document opening cmd.exe or PowerShell is a classic sign of a **malicious macro or exploit**, and it is often the very first stage of a much bigger intrusion. By the time you casually ask the user, a second-stage payload could already be running.

## The Strong Answer, Step by Step

### 1. Explain why it matters
Say this out loud in the interview. It shows you understand **parent-child relationships**.
- Office apps should open documents, not run command shells
- `winword.exe -> cmd.exe` or `winword.exe -> powershell.exe` is a top initial access pattern
- Maps to **T1204.002 (User Execution: Malicious File)** and **T1059 (Command and Scripting Interpreter)**

### 2. Read the full process tree
- In **EDR**, view the whole chain: what launched Word, what cmd.exe ran, and what that launched
- Get the **full command line** (Sysmon Event ID **1** or Event ID **4688**)
- Look for `certutil`, `bitsadmin`, `mshta`, `rundll32`, `regsvr32`, or `powershell -enc`

### 3. Find the document
- Which file was open? Check EDR file events and **recent files**
- Where did it come from: email attachment, download, USB? The **Mark of the Web** (Zone.Identifier) helps
- Get the **hash** and check it in **VirusTotal**; detonate in **ANY.RUN** or **Joe Sandbox**

### 4. Follow the network activity
- Did cmd.exe or a child reach out to the internet? **Sysmon Event ID 3**, proxy logs
- Check contacted domains and IPs for reputation

### 5. Check for dropped files and persistence
- New files in `%TEMP%`, `%APPDATA%` (**Sysmon Event ID 11**)
- **Scheduled tasks** (Event ID **4698**), **services** (Event ID **7045**), **Run keys** (Sysmon Event ID **13**)

### 6. Contain and scope
- **Isolate the host** if anything malicious executed
- Find the source email and **purge it** from all mailboxes
- Hunt for the **same hash or parent-child pattern** across all endpoints
- **Escalate** with the process tree attached

### 7. Recommend prevention
- **Attack Surface Reduction (ASR)** rule: *Block all Office applications from creating child processes*
- Block macros from the internet (Microsoft now does this by default for files with Mark of the Web)

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Explain the risk | Parent-child anomaly, T1204.002, T1059 |
| 2 | Read the process tree | EDR, Sysmon 1, Event ID 4688 |
| 3 | Find the document | EDR file events, Zone.Identifier, VirusTotal, sandbox |
| 4 | Follow network | Sysmon 3, proxy logs |
| 5 | Check persistence | Sysmon 11 and 13, Event IDs 4698, 7045 |
| 6 | Contain and scope | Isolation, email purge, EDR hunt |
| 7 | Prevent | ASR rules, macro blocking |

## What the Interviewer Is Really Testing

They are checking whether you understand **process lineage as a detection signal** and whether you can **trace an alert back to its source**, the document and the email, rather than only cleaning up the endpoint.

## Follow-Up Questions to Expect

- **What other parent-child pairs are suspicious?** *excel.exe or outlook.exe spawning powershell.exe, mshta.exe, or wscript.exe.*
- **What if the user says they opened an invoice?** *That confirms the lure; find the email and everyone else who got it.*
- **What is Mark of the Web?** *A Zone.Identifier stream marking files downloaded from the internet.*

## One-Line Answer to Memorize

> "Word should never spawn a shell, so I read the full process tree, find the document and where it came from, check for network and persistence, then isolate, purge and hunt."

---

[← All 30 questions](README.md) · [Previous: Q6](06-large-outbound-transfer-at-night.md) · [Next: Q8](08-antivirus-quarantined-file.md)
