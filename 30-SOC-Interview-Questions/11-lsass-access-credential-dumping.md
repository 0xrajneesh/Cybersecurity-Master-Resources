# Q11. A Process Accessed LSASS Memory

> **Difficulty:** Intermediate · **Topic:** Endpoint / Credential Access · **Asked for:** SOC L1 / L2

## The Question

> "You get an alert for a process accessing LSASS memory. What does it mean and what do you do?"

## The Trap Answer

**"LSASS is a Windows system process, so it is probably normal. I would check if the EDR blocked it and close it."**

That answer shows you know the name but not why attackers love it. **LSASS (Local Security Authority Subsystem Service)** holds credential material for logged-on users: NTLM hashes, Kerberos tickets and, on older or misconfigured systems, even cleartext passwords. Reading its memory is the classic **credential dumping** move, MITRE **T1003.001 (OS Credential Dumping: LSASS Memory)**.

If an attacker got those credentials, a "blocked" alert does not mean the danger is over. They may already have a dump file, or they may try again with a different tool. You treat this as a **potential full credential compromise** until proven otherwise.

## The Strong Answer, Step by Step

### 1. Explain what the alert means
Say it plainly first, so the interviewer knows you understand the stakes.
- **LSASS** stores credentials of everyone logged on to that host, including admins who RDP'd in
- Dumping it lets an attacker do **pass-the-hash** or **pass-the-ticket** and move laterally
- Mapped to **MITRE ATT&CK T1003.001**

### 2. Identify the accessing process
The single most important field is *who* touched LSASS.
- **Sysmon Event ID 10 (ProcessAccess)** with `TargetImage` = `lsass.exe`
- Check `SourceImage`: `procdump.exe`, `rundll32.exe` loading **comsvcs.dll MiniDump**, `taskmgr.exe`, or an unknown binary in `C:\Users\Public` or `%TEMP%`
- Check **GrantedAccess**: values like `0x1010` or `0x1410` include **PROCESS_VM_READ**, which is what memory reading needs
- Known-good readers exist: AV/EDR agents, some backup and monitoring tools

### 3. Look at the full process tree
Context decides benign vs malicious.
- Parent and grandparent in **EDR** (CrowdStrike, Defender for Endpoint, SentinelOne)
- Command line: `procdump -ma lsass.exe`, `rundll32 comsvcs.dll, MiniDump <PID> out.dmp full`, or **Mimikatz** strings like `sekurlsa::logonpasswords`
- **Event ID 4688** / Sysmon **Event ID 1** for process creation with command line

### 4. Look for a dump file
A dump on disk means credentials may already be gone.
- **Sysmon Event ID 11 (FileCreate)** for `.dmp` files
- Check whether the file was copied, zipped or sent out (Sysmon **Event ID 3** network connections)

### 5. Find out whose credentials were exposed
This sets the blast radius.
- Who was logged on to the host? **Event ID 4624** logons, especially **logon type 2, 10** (interactive, RDP)
- Was a **domain admin** or service account session present? That changes severity immediately

### 6. Contain
Move fast once it looks malicious.
- **Isolate the host** with EDR network containment
- **Reset passwords** for every account that had a session there; for privileged accounts, coordinate with the identity team
- If a domain admin was exposed, escalate to L2/IR; a **krbtgt** double reset may come up in that discussion

### 7. Hunt for use of the stolen credentials
Assume the attacker will use them.
- Look for **4624 logon type 3** from this host to servers, **4648** explicit credential logons, unusual **4769** Kerberos service ticket requests
- Search the same tool hash and command line across all endpoints

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Explain the risk | T1003.001, LSASS holds hashes and tickets |
| 2 | Identify source process | Sysmon 10, SourceImage, GrantedAccess |
| 3 | Review process tree | EDR, 4688 / Sysmon 1 command line |
| 4 | Look for dump file | Sysmon 11 (.dmp), Sysmon 3 |
| 5 | Scope exposed accounts | 4624 logon types on the host |
| 6 | Contain | EDR isolation, password resets, escalate |
| 7 | Hunt credential use | 4624 type 3, 4648, 4769 |

## What the Interviewer Is Really Testing

They want to see that you know **why LSASS matters to an attacker** and that you think in terms of **blast radius**: whose credentials were on that box and where they could be used next. A strong candidate also knows how to separate a real dump from a noisy security tool.

## Follow-Up Questions to Expect

- **How would you prevent LSASS dumping?** *Enable Credential Guard, run LSASS as a protected process (RunAsPPL), and use the Defender ASR rule that blocks credential stealing from LSASS.*
- **What is pass-the-hash?** *Using a stolen NTLM hash to authenticate without knowing the plaintext password.*
- **The source was taskmgr.exe. Is that safe?** *Not automatically; Task Manager can create dump files too, so check who ran it and whether a .dmp was written.*

## One-Line Answer to Memorize

> "LSASS access usually means credential dumping, so I identify the source process and dump file, find whose credentials were on that host, isolate it, reset those accounts and hunt for their use elsewhere."

---

[← All 30 questions](README.md) · [Previous: Q10](10-beaconing-to-unknown-domain.md) · [Next: Q12](12-rdp-from-internet-ip.md)
