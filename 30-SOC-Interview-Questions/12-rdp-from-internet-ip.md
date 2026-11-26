# Q12. Successful RDP Login from a Public IP

> **Difficulty:** Intermediate · **Topic:** Network / Remote Access · **Asked for:** SOC L1 / L2

## The Question

> "You see a successful RDP login from a public internet IP. How do you handle it?"

## The Trap Answer

**"I would check the IP on VirusTotal, and if it is clean, it is fine."**

A clean reputation score proves almost nothing. Attackers use fresh cloud VMs and residential proxies that have no history yet. The bigger problem is the question you skipped: **why is RDP reachable from the internet at all?** Exposed RDP is one of the most common ransomware entry points, mapped to MITRE **T1133 (External Remote Services)** and **T1021.001 (Remote Desktop Protocol)**.

A successful login means someone has valid credentials and an interactive desktop on your network. That is a **potential hands-on-keyboard intrusion**, not a reputation lookup.

## The Strong Answer, Step by Step

### 1. Confirm the logon
Make sure you are reading the right event.
- **Event ID 4624** with **logon type 10 (RemoteInteractive)**, or type 3 with NLA plus a following type 10
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` **Event ID 1149** shows the source IP for the RDP auth
- `LocalSessionManager` **Event ID 21** (logon), **24** (disconnect), **25** (reconnect)

### 2. Check what came before it
Was this a lucky guess or a known password?
- **Event ID 4625** failures from the same IP before the success: brute force or spraying
- No failures at all: the attacker likely had **valid credentials** from phishing or an infostealer log

### 3. Investigate the source IP
- **AbuseIPDB**, **VirusTotal**, **Shodan**, geolocation and **ASN** (hosting provider vs ISP)
- Is it a known **VPN, Tor exit** or cloud range?
- Has this user ever logged in from this IP or country before?

### 4. Find out why RDP is exposed
This is the root cause.
- Check firewall / NAT rules and port **3389** exposure with your perimeter team or **Shodan**
- Was it a temporary vendor rule someone forgot to remove?

### 5. Check what happened during the session
Interactive sessions leave a trail.
- **EDR** process tree under that session: `cmd.exe`, `powershell.exe`, **net.exe** recon (`net group "domain admins" /domain`)
- Tools dropped: **AnyDesk**, **Advanced IP Scanner**, **Mimikatz**, **Rclone**
- **Event ID 4720** new accounts, **4698** scheduled tasks, **7045** new services, **1102** log cleared

### 6. Contact the account owner
- "Did you log in from this location at this time?"
- Confirm through a known channel, not by replying to the same compromised account

### 7. Contain and fix the exposure
- **Disable the account**, reset the password, kill the session
- **Isolate the host** if any suspicious activity is found
- **Block 3389 from the internet**; recommend RDP only behind **VPN** or a **gateway with MFA**
- Escalate to L2/IR if there was any post-login activity

### 8. Hunt wider
- Same IP against all hosts and accounts for the last **30 days**
- Other hosts with 3389 open to the internet

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Confirm RDP logon | 4624 type 10, TS 1149, LSM 21/24/25 |
| 2 | Check prior failures | 4625 from same IP |
| 3 | Investigate IP | AbuseIPDB, Shodan, ASN, user history |
| 4 | Find the exposure | Firewall rules, port 3389 |
| 5 | Review session activity | EDR, 4720, 4698, 7045, 1102 |
| 6 | Verify with user | Phone or known channel |
| 7 | Contain and close exposure | Disable account, isolate, block 3389 |
| 8 | Hunt | SIEM search, 30 days |

## What the Interviewer Is Really Testing

They want to see that you go beyond reputation checks and think about **root cause (why RDP was exposed)** and **post-login activity**. Knowing the RDP-specific logs beyond 4624 is a strong signal that you have actually done this.

## Follow-Up Questions to Expect

- **What is logon type 10 vs type 3?** *Type 10 is RemoteInteractive (RDP); type 3 is network logon such as SMB share access.*
- **The IP is clean on every reputation site. Now what?** *Reputation is not innocence; rely on user verification, history and session activity.*
- **How would you secure RDP?** *No direct internet exposure, VPN or RD Gateway with MFA, NLA enabled, account lockout policy.*

## One-Line Answer to Memorize

> "I confirm the logon type 10 and source IP, check for prior failures and session activity, verify with the user, then disable the account, isolate if needed and close port 3389 to the internet."

---

[← All 30 questions](README.md) · [Previous: Q11](11-lsass-access-credential-dumping.md) · [Next: Q13](13-inbox-forwarding-rule.md)
