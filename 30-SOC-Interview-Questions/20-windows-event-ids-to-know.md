# Q20. Windows Event IDs Every SOC Analyst Should Know

> **Difficulty:** Beginner · **Topic:** Windows Logging · **Asked for:** SOC L1 / L2

## The Question

> "Which Windows Event IDs should every SOC analyst know, and why?"

## The Trap Answer

**"4624 is a successful login and 4625 is a failed login."**

Correct, but that is where most candidates stop. Two IDs is not a toolkit. The interviewer wants to see that you know the events that tell an **attack story**: logons, privilege, account changes, persistence and anti-forensics.

The other weak spot is listing numbers without the **why**. "4688 is process creation" is fine; "4688 with command line logging lets me see the encoded PowerShell an attacker ran" is what gets you hired.

## The Strong Answer, Step by Step

### 1. Logon and authentication
- **4624** successful logon. Always check the **logon type**: **2** interactive, **3** network, **10** RDP
- **4625** failed logon: brute force and password spraying
- **4648** logon with explicit credentials (`runas`, some lateral movement)
- **4672** special privileges assigned: an admin-level logon
- **4740** account locked out

### 2. Kerberos and NTLM (domain controllers)
- **4768** Kerberos TGT requested
- **4769** Kerberos service ticket requested: many requests with RC4 encryption can indicate **Kerberoasting**
- **4771** Kerberos pre-authentication failed
- **4776** NTLM credential validation

### 3. Account and group changes
- **4720** user account created
- **4722** account enabled, **4725** disabled, **4726** deleted
- **4724** password reset attempt
- **4728** member added to a security-enabled **global** group (for example Domain Admins)
- **4732** member added to a security-enabled **local** group (for example Administrators)
- **4756** member added to a security-enabled **universal** group

### 4. Execution and persistence
- **4688** new process created (enable **command line auditing** to make it useful)
- **4698** scheduled task created
- **7045** new service installed (System log): common for **PsExec** and malware
- **4697** service installed (Security log)

### 5. PowerShell
- **4104** PowerShell **Script Block Logging**: shows decoded script content, a gold mine for encoded commands

### 6. Anti-forensics
- **1102** Security audit log cleared: almost always worth an immediate look
- **104** System log cleared

### 7. Add Sysmon if available
- **Sysmon 1** process create with hashes, **3** network connection, **10** process access (LSASS), **11** file create, **22** DNS query

## Quick Reference

| Event ID | Log | Meaning | Why it matters |
|---|---|---|---|
| 4624 / 4625 | Security | Logon success / failure | Brute force, logon type tells RDP vs network |
| 4648 | Security | Explicit credential logon | Lateral movement, runas |
| 4672 | Security | Special privileges assigned | Admin logon |
| 4769 | Security | Kerberos service ticket | Kerberoasting |
| 4720 | Security | User created | Backdoor accounts |
| 4728 / 4732 / 4756 | Security | Added to privileged group | Privilege escalation |
| 4688 | Security | Process created | Malicious command lines |
| 4698 / 7045 | Security / System | Scheduled task / service | Persistence, PsExec |
| 4104 | PowerShell Operational | Script block logged | Decoded PowerShell |
| 1102 | Security | Audit log cleared | Covering tracks |

## What the Interviewer Is Really Testing

They want to see that you can tie event IDs to **attacker behaviour** and that you know the **logon types** that change the meaning of 4624. Knowing what has to be **enabled** (command line auditing, script block logging) shows real-world experience.

## Follow-Up Questions to Expect

- **What logon type is RDP?** *Type 10, RemoteInteractive.*
- **Which event shows a user added to Domain Admins?** *4728, member added to a security-enabled global group.*
- **Why might 4688 not show command lines?** *"Include command line in process creation events" must be enabled via Group Policy.*

## One-Line Answer to Memorize

> "Beyond 4624 and 4625, I watch 4672 and 4728 for privilege, 4720 for new accounts, 4688, 4698 and 7045 for execution and persistence, 4104 for PowerShell, and 1102 for cleared logs."

---

[← All 30 questions](README.md) · [Previous: Q19](19-mitre-attack-in-investigations.md) · [Next: Q21](21-siem-edr-xdr-soar.md)
