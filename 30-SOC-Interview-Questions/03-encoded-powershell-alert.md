# Q3. Encoded PowerShell on a Workstation

> **Difficulty:** Intermediate · **Topic:** Endpoint Investigation · **Asked for:** SOC L1 / L2

## The Question

> "EDR alerts on an encoded PowerShell command on a workstation. How do you investigate?"

## The Trap Answer

Many candidates say **"PowerShell is malicious, isolate the machine."** Or the opposite: **"Admins use PowerShell all the time, it is probably fine."**

Both skip the actual work. Encoded commands are used by attackers to hide intent, but some legitimate management tools use them too. The command itself is the evidence, and you have not read it yet. The interviewer wants to hear you **decode, trace the parent, and follow the activity**.

## The Strong Answer, Step by Step

### 1. Decode the command
Encoded PowerShell is just **Base64 of UTF-16LE text**. Read it.
- Look for `-EncodedCommand`, `-enc`, `-e` in the command line
- Decode it in **CyberChef** (From Base64, then Decode text UTF-16LE)
- Watch for red flags: `IEX`, `Invoke-Expression`, `DownloadString`, `Net.WebClient`, `FromBase64String`, `-nop`, `-w hidden`

### 2. Check the parent process
Who launched PowerShell tells you a lot.
- **explorer.exe** may mean a user ran it; **winword.exe** or **excel.exe** means a malicious document
- **wmiprvse.exe** or **services.exe** may point to remote execution
- Your management agent (SCCM, Intune) may be legitimate, so confirm with IT

### 3. Pull the PowerShell logs
Windows records the decoded script if logging is on.
- **Event ID 4104** (Script Block Logging) in `Microsoft-Windows-PowerShell/Operational`
- **Event ID 4103** (Module Logging)
- **Sysmon Event ID 1** (process creation) or **Event ID 4688** for full command lines

### 4. Follow the network and file activity
What did the script reach out to or drop?
- **Sysmon Event ID 3** (network connection) or EDR network tab
- Check contacted domains and IPs in **VirusTotal** and **AbuseIPDB**
- **Sysmon Event ID 11** (file create): payloads in `%TEMP%`, `%APPDATA%`, `C:\ProgramData`

### 5. Look for persistence
Attackers rarely run once.
- **New scheduled tasks** (Event ID **4698**)
- **Run keys** in the registry (Sysmon Event ID **13**)
- **New services** (Event ID **7045**)

### 6. Scope and contain
- Search the **decoded command, domain, or hash** across all endpoints in the SIEM / EDR
- If malicious: **isolate the host**, kill the process, collect artifacts, **escalate**
- Check the logged-in user's account for further suspicious sign-ins

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Decode the Base64 | CyberChef, EDR command line |
| 2 | Identify the parent process | EDR process tree |
| 3 | Pull PowerShell logs | Event IDs 4104, 4103, 4688, Sysmon 1 |
| 4 | Follow network and files | Sysmon 3 and 11, VirusTotal |
| 5 | Check persistence | Event IDs 4698, 7045, Sysmon 13 |
| 6 | Scope and contain | SIEM / EDR hunt, isolation, escalation |

## What the Interviewer Is Really Testing

They want proof that you can **read the evidence rather than react to the alert name**, and that you understand **process lineage**. Decoding the command and checking the parent shows you can turn a vague alert into a clear verdict.

## Follow-Up Questions to Expect

- **What MITRE technique is this?** *T1059.001, Command and Scripting Interpreter: PowerShell; obfuscation maps to T1027.*
- **What if Script Block Logging is off?** *Rely on EDR telemetry and 4688 with command-line auditing, and recommend enabling 4104.*
- **How would you know it is legitimate?** *Known parent, signed management tool, documented change, and a decoded script that matches it.*

## One-Line Answer to Memorize

> "I decode the command, check what launched it, read the 4104 logs, follow its network and file activity, look for persistence, then scope and contain."

---

[← All 30 questions](README.md) · [Previous: Q2](02-user-clicked-phishing-link.md) · [Next: Q4](04-impossible-travel-alert.md)
