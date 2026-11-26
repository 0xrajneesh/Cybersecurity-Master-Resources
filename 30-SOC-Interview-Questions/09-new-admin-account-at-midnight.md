# Q9. A New Domain Admin at Midnight

> **Difficulty:** Intermediate · **Topic:** Privilege Escalation and Persistence · **Asked for:** SOC L1 / L2

## The Question

> "A new domain admin account was created at midnight. What do you do?"

## The Trap Answer

A common answer is **"Delete the account right away."** It looks like quick, decisive containment.

It fails in two ways. If it was a legitimate emergency change, you just broke something an admin needed. And if it is an attacker, deleting it **only removes one foothold**. Someone already had the rights to create a domain admin, which means **another privileged account is compromised**. That is the account you really need to find.

## The Strong Answer, Step by Step

### 1. Confirm the events
Pull the raw logs from the domain controller security log.
- **Event ID 4720**: a user account was created
- **Event ID 4728**: member added to a security-enabled **global** group (Domain Admins is a global group)
- **Event ID 4732**: member added to a security-enabled **local** group (for example Administrators)
- **Event ID 4756**: member added to a **universal** group (for example Enterprise Admins)

### 2. Identify who did it
The **Subject** field in these events is the account that made the change.
- Which **account** created it and from which **workstation / IP**?
- Find that account's **logon** (Event ID **4624**) on the DC and its logon type

### 3. Check for an approved change
- Is there a **change ticket** or emergency request?
- Contact the **identity / AD team** using a known channel
- Midnight plus no ticket plus an unknown creator is a **strong compromise signal**

### 4. Investigate the creating account
This is the real target.
- Recent sign-ins: unusual hosts, times, or sources
- Signs of credential theft on its workstation: **LSASS access**, **Mimikatz**, **encoded PowerShell**
- Kerberos activity: **Event IDs 4768 / 4769** for unusual ticket requests

### 5. Check what the new account has done
- Logons by the new account (**4624**), especially to DCs and servers
- **GPO changes**, new **scheduled tasks** (**4698**), new **services** (**7045**)
- Other group changes or accounts created around the same time

### 6. Contain
- **Disable** (do not delete) the new account, so evidence is preserved
- **Disable or reset** the creating account and revoke its sessions
- **Isolate** the source workstation in EDR
- **Escalate** immediately: domain admin compromise is a **critical incident**

### 7. Hunt and harden
- Review **all privileged group memberships** for other unexpected members
- Plan **krbtgt password reset** with IR if Golden Ticket abuse is suspected
- Alert on every change to **Domain Admins** and **Enterprise Admins**

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Confirm the events | DC logs: 4720, 4728, 4732, 4756 |
| 2 | Identify the creator | Subject field, 4624 |
| 3 | Check for a change ticket | ITSM, AD team |
| 4 | Investigate the creator | EDR, LSASS access, 4768 / 4769 |
| 5 | Check new account activity | 4624, 4698, 7045, GPO changes |
| 6 | Contain | Disable both accounts, isolate host, escalate |
| 7 | Hunt and harden | Privileged group review, krbtgt reset plan |

## What the Interviewer Is Really Testing

They want to see that you know the **right Active Directory event IDs** and that you **follow the chain back to the account that made the change**. Finding the compromised creator matters more than removing the new account.

## Follow-Up Questions to Expect

- **Why disable instead of delete?** *Deleting destroys evidence like the SID and history; disabling stops use and keeps it.*
- **What MITRE technique is this?** *T1136.002 Create Account: Domain Account, and T1098 Account Manipulation.*
- **How do you catch this faster?** *Real-time alerts on 4728 / 4756 for Domain Admins and Enterprise Admins.*

## One-Line Answer to Memorize

> "I confirm 4720 and 4728, find who created it and from where, check for a change ticket, then disable both accounts, isolate the source and escalate as a domain compromise."

---

[← All 30 questions](README.md) · [Previous: Q8](08-antivirus-quarantined-file.md) · [Next: Q10](10-beaconing-to-unknown-domain.md)
