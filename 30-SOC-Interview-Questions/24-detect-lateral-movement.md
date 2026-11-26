# Q24. Detecting Lateral Movement

> **Difficulty:** Intermediate · **Topic:** Detection · **Asked for:** SOC L1 / L2

## The Question

> "What is lateral movement, and how would you detect it?"

## The Trap Answer

**"It is when an attacker moves from one computer to another, and I would look for unusual network traffic."** The definition is fine. The detection part is too vague to act on.

Lateral movement usually rides on **legitimate admin protocols**: RDP, SMB, WinRM, PsExec. "Unusual traffic" will not find it. You need to name the logs, the event IDs and the patterns that separate an attacker from a sysadmin.

## The Strong Answer, Step by Step

### 1. Define it
After initial access, the attacker uses stolen credentials or tokens to reach **other systems**, usually heading for a **domain controller**, file server or backup server.
- MITRE ATT&CK tactic **TA0008 Lateral Movement**
- Common techniques: **T1021 Remote Services** (RDP, SMB/Admin shares, WinRM), **T1550 Use Alternate Authentication Material** (Pass-the-Hash, Pass-the-Ticket), **T1570 Lateral Tool Transfer**

### 2. Watch the authentication logs
- **4624** successful logon: check **Logon Type 3** (network) and **Logon Type 10** (RDP)
- **4625** failures across many hosts from one source
- **4648** logon with explicit credentials (runas, PsExec-style use)
- **4768 / 4769** Kerberos TGT and service ticket requests on the DC
- Pattern: one account logging into **many hosts in a short window**

### 3. Watch for remote execution artifacts
- **7045** new service installed (classic **PsExec** footprint, service often named PSEXESVC)
- **4698** scheduled task created remotely
- **5140 / 5145** network share access, especially **ADMIN$** and **C$**
- WinRM: **wsmprovhost.exe** spawning commands
- WMI: **WmiPrvSE.exe** spawning cmd.exe or powershell.exe

### 4. Use EDR process trees
- Parent-child chains that cross hosts: services.exe → unknown binary right after a 4624 type 3
- Tools on disk that admins rarely use: **PsExec**, **Impacket** artifacts, **Cobalt Strike** named pipes

### 5. Baseline who talks to whom
- Workstation-to-workstation **SMB or RDP** is rare in most networks: high-value signal
- Service accounts logging in **interactively** is suspicious
- Admin accounts used **outside their usual jump host**

### 6. Respond when you find it
- Map every host the account touched (your **blast radius**)
- **Disable or reset** the account, revoke Kerberos tickets if needed
- **Isolate** affected hosts via EDR and escalate to L2 / IR

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Define and map | MITRE TA0008, T1021, T1550, T1570 |
| 2 | Review authentication | 4624 (type 3/10), 4625, 4648, 4768, 4769 |
| 3 | Find remote execution | 7045, 4698, 5140, 5145, WmiPrvSE, wsmprovhost |
| 4 | Inspect process trees | CrowdStrike, Defender for Endpoint, SentinelOne |
| 5 | Compare to baseline | SIEM stats on source-destination pairs |
| 6 | Scope and contain | EDR isolation, AD account disable, escalation |

## What the Interviewer Is Really Testing

Whether you can name **concrete log evidence** for lateral movement and whether you understand that attackers **blend in with admin activity**, so baselining matters more than signatures.

## Follow-Up Questions to Expect

- How do you spot Pass-the-Hash? *Look for 4624 Logon Type 3 with NTLM authentication from unusual sources, especially for admin accounts that normally use Kerberos.*
- Why is workstation-to-workstation traffic suspicious? *Users rarely need to RDP or SMB into a colleague's laptop; attackers do.*
- What is the first thing you scope? *Every host the compromised account logged into, and what ran there afterwards.*

## One-Line Answer to Memorize

> "Lateral movement is an attacker reusing credentials to hop between systems, and I detect it through logon types 3 and 10, new services and scheduled tasks, admin share access, and accounts touching hosts they never normally touch."

---

[← All 30 questions](README.md) · [Previous: Q23](23-pyramid-of-pain.md) · [Next: Q25](25-splunk-query-brute-force.md)
