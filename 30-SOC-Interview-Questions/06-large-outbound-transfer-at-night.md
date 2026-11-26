# Q6. 8 GB Outbound at 2 AM

> **Difficulty:** Intermediate · **Topic:** Data Exfiltration · **Asked for:** SOC L1 / L2

## The Question

> "A host sends 8 GB to an external IP at 2 AM. How do you investigate?"

## The Trap Answer

Candidates often say **"That is data exfiltration, block the IP."** The time and the volume both look scary, so it seems obvious.

It fails because large night-time transfers are very often **backups, patch syncs, or cloud storage clients** doing exactly what they were scheduled to do. Blocking blind can break a real backup job. And if it is exfiltration, blocking the IP without knowing **which process and which data** leaves you unable to tell the business what was lost.

## The Strong Answer, Step by Step

### 1. Identify the destination
Who is receiving the data?
- **WHOIS / ASN** lookup: is it AWS, Azure, Google Cloud, a backup vendor, or an unknown VPS?
- Reputation in **VirusTotal**, **AbuseIPDB**
- Check the **domain** from DNS or proxy logs, not just the IP

### 2. Identify the process
Network logs say a host talked. EDR says **what** talked.
- In **EDR**, find the process that owned the connection
- **Sysmon Event ID 3** (network connection) gives process name and path
- Red flags: **rclone.exe**, **WinSCP**, **curl**, **PowerShell**, or an unsigned binary in `%TEMP%`
- Expected: your **backup agent**, **OneDrive**, **patching tool**

### 3. Compare with baseline
Normal is your best friend.
- Does this host **send large volumes every night**? Check NetFlow / firewall history
- Is there a **scheduled backup job** at 2 AM? Ask the system owner
- Is this host even supposed to talk to the internet (for example a database server)?

### 4. Check what data was touched
- File access before the transfer: **archives** (`.zip`, `.7z`, `.rar`) created in staging folders
- Sensitive share access (Event ID **5145**)
- Tools like **7-Zip** or **WinRAR** running just before the upload

### 5. Check the account
- Which user was logged in, and is a 2 AM session normal for them?
- Any **new logons** (Event ID **4624**) from unusual sources before the transfer?

### 6. Contain if malicious
- **Isolate the host** in EDR
- **Block the destination** IP / domain at firewall and proxy
- Disable the involved account and **escalate**: possible data breach means legal and privacy teams get involved

### 7. Hunt for the same pattern
- Search other hosts for connections to the same destination or ASN
- Look for the same tool hash across endpoints

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Identify destination | WHOIS, ASN, VirusTotal, DNS / proxy logs |
| 2 | Identify process | EDR, Sysmon Event ID 3 |
| 3 | Compare to baseline | NetFlow, firewall history, system owner |
| 4 | Check data staged | Archive creation, Event ID 5145 |
| 5 | Check the account | Event ID 4624, user history |
| 6 | Contain | EDR isolation, firewall block, escalation |
| 7 | Hunt | SIEM / EDR search for destination and hash |

## What the Interviewer Is Really Testing

They want to see you **tie network evidence to a process and a user**, and that you **check the baseline** before calling it an attack. Volume and timing raise suspicion; process, destination and context prove it.

## Follow-Up Questions to Expect

- **Which MITRE tactic is this?** *Exfiltration (TA0010), for example T1567 Exfiltration Over Web Service.*
- **What if the destination is Google Drive or Mega?** *Legitimate services are abused for exfil; check whether the org uses them and which account uploaded.*
- **How would you detect this automatically?** *Alert on outbound volume far above the host's baseline, and on tools like rclone.*

## One-Line Answer to Memorize

> "I identify the destination and the process behind it, compare against that host's baseline, check what data was staged, and isolate and escalate if it is not a known job."

---

[← All 30 questions](README.md) · [Previous: Q5](05-ransomware-note-on-file-server.md) · [Next: Q7](07-word-spawns-cmd.md)
