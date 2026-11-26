# Q5. A Ransom Note on the File Server

> **Difficulty:** Intermediate · **Topic:** Ransomware Response · **Asked for:** SOC L1 / L2

## The Question

> "A ransom note appears on a file server. What are your first steps?"

## The Trap Answer

The panic answer is **"Shut the server down and restore from backup."** It feels like the fastest way to make the problem go away.

It fails on two counts. Pulling the power **destroys memory evidence**, which can include encryption keys and the attacker's tooling. And restoring before you know how they got in means **they encrypt it again tomorrow**. By the time a ransom note appears, the attacker has usually been inside for days and has likely **stolen data** already.

## The Strong Answer, Step by Step

### 1. Declare it and escalate immediately
Ransomware is not an L1 solo job. Speed of escalation matters most.
- Raise a **critical incident** and page L2 / IR and your manager
- Start a **timeline** right now: who saw what, and when

### 2. Isolate, do not power off
Stop the spread while keeping the evidence.
- **Network-isolate** the server through **EDR** (Defender for Endpoint, CrowdStrike, SentinelOne) or by pulling it from the switch
- Leave it **powered on** so memory can be captured
- Disable the **compromised account** writing the encrypted files

### 3. Identify the scope
Find every machine that is encrypting or was touched.
- Which **user account and source host** is modifying the files? Check file share audit logs (**Event ID 5145**) and EDR
- Search for the **ransom note filename** and **new file extensions** across all endpoints
- Look for mass file renames in EDR telemetry

### 4. Protect the backups
Attackers target backups on purpose.
- Confirm backups are **offline or immutable** and not reachable from the infected network
- Look for **shadow copy deletion**: `vssadmin delete shadows`, `wmic shadowcopy delete`
- Check for backup service tampering

### 5. Find patient zero and initial access
- Trace back: phishing email, exposed **RDP**, VPN without MFA, or an unpatched edge device
- Look for precursors: **Cobalt Strike**, **PsExec**, **AdFind**, **Rclone** (data exfiltration)
- Check for new admin accounts (Event IDs **4720**, **4728**, **4732**)

### 6. Preserve evidence
- Capture **memory** and **disk images** before rebuilding
- Photograph or copy the **ransom note**; it identifies the ransomware family
- Use **ID Ransomware** to identify the variant, and check **No More Ransom** for decryptors

### 7. Recover the right way
- Eradicate the access path first, then **rebuild and restore from clean backups**
- Reset credentials, starting with **privileged accounts**
- Legal and leadership decide on notification and ransom, not the analyst

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Declare and escalate | Incident ticket, IR on-call |
| 2 | Isolate, keep powered on | EDR network containment |
| 3 | Scope the encryption | Event ID 5145, EDR, ransom note search |
| 4 | Protect backups | Immutable backups, vssadmin / wmic evidence |
| 5 | Find initial access | Mail, RDP, VPN logs; 4720 / 4728 / 4732 |
| 6 | Preserve evidence | Memory and disk images, ID Ransomware |
| 7 | Recover cleanly | Rebuild, restore, reset privileged creds |

## What the Interviewer Is Really Testing

They want to see **containment without destroying evidence**, and that you understand ransomware is the **last stage of a longer intrusion**. A calm, ordered response with fast escalation beats heroic solo work every time.

## Follow-Up Questions to Expect

- **Why not just pay?** *Not your call, no guarantee of decryption, and data may still be leaked; legal and leadership decide.*
- **What is double extortion?** *Encrypting data and also threatening to publish what was stolen.*
- **How would you detect it earlier?** *Alert on shadow copy deletion, mass file renames, and tools like Rclone or PsExec.*

## One-Line Answer to Memorize

> "I escalate immediately, isolate the server without powering it off, scope every infected host, protect the backups, and find the initial access before anything is restored."

---

[← All 30 questions](README.md) · [Previous: Q4](04-impossible-travel-alert.md) · [Next: Q6](06-large-outbound-transfer-at-night.md)
