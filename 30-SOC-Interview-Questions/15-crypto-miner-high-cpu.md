# Q15. Server at 100% CPU, Suspected Crypto Miner

> **Difficulty:** Intermediate · **Topic:** Endpoint / Linux and Windows · **Asked for:** SOC L1 / L2

## The Question

> "A server is at 100% CPU and you suspect a crypto miner. How do you investigate?"

## The Trap Answer

**"I would kill the process and restart the server."**

Killing it destroys evidence and usually does nothing. Miners are deployed with **persistence** (cron jobs, systemd services, scheduled tasks) and come right back. Worse, you never answer the real question: **how did the attacker get code execution on your server?** MITRE maps mining to **T1496 (Resource Hijacking)**, but the miner is just the payload.

The same vulnerability or stolen credential that let in a miner could let in ransomware next week. The miner is the alarm bell, not the incident.

## The Strong Answer, Step by Step

### 1. Identify the process
- Linux: `top`, `htop`, `ps auxf` to find the CPU-heavy process and its parent
- Windows: **EDR** process view, Task Manager, `Get-Process | Sort CPU -Descending`
- Note the **binary path**: miners love `/tmp`, `/var/tmp`, `/dev/shm`, or `%AppData%`
- Common names: **xmrig**, or random names and fake ones like `kworker` or `systemd-` lookalikes

### 2. Collect evidence before killing anything
- Take the **file hash** (`sha256sum`) and look it up on **VirusTotal**
- Grab the **command line**: look for `--donate-level`, `-o pool...`, `stratum+tcp://`
- If possible, take a **memory capture** or at least snapshot the VM

### 3. Check network connections
- `ss -tunap` or `netstat -anp` on Linux, Sysmon **Event ID 3** on Windows
- Connections to **mining pools** (domains with "pool" or "xmr"), often on ports like **3333, 4444, 5555, 14444**
- DNS logs and firewall logs for the same destination

### 4. Find the persistence
- Linux: `crontab -l` for every user, `/etc/cron.*`, `/etc/systemd/system/`, `~/.bashrc`, `~/.ssh/authorized_keys` (attackers add their own key)
- Windows: **Event ID 4698** scheduled task created, **7045** service installed, Run keys, WMI subscriptions

### 5. Find the initial access
This is the step most candidates skip.
- Internet-facing service with a known **CVE**? (Confluence, Log4j, unpatched web apps, exposed Docker API, Redis)
- **SSH brute force** in `/var/log/auth.log` or `/var/log/secure`
- Web server logs for odd requests just before the miner appeared
- Cloud: leaked access keys used to spin up instances

### 6. Contain
- **Isolate** the host or restrict it with security groups
- Block the pool domains and IPs at the firewall and DNS
- Then kill the process, remove persistence and rotate any credentials on the box

### 7. Recover and hunt
- Rebuild from a known-good image if root was obtained; cleaning is risky
- Hunt the same hash, pool domain and cron entries across all servers
- Patch the exploited service and escalate with a timeline

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Identify process | top, ps auxf, EDR |
| 2 | Preserve evidence | sha256sum, VirusTotal, command line, snapshot |
| 3 | Check network | ss / netstat, Sysmon 3, stratum ports |
| 4 | Find persistence | crontab, systemd, authorized_keys, 4698, 7045 |
| 5 | Find initial access | auth.log, web logs, CVE exposure |
| 6 | Contain | Isolate, block pool, then kill and clean |
| 7 | Recover and hunt | Rebuild, fleet-wide search, patch |

## What the Interviewer Is Really Testing

They want to see **evidence preservation before remediation** and a focus on **initial access**, not just the noisy symptom. Knowing where Linux persistence hides is a strong plus for any SOC that monitors servers.

## Follow-Up Questions to Expect

- **Why is a miner considered serious if it only steals CPU?** *It proves someone has code execution; the same access can deliver worse payloads.*
- **Where would you look for persistence on Linux?** *Cron, systemd units, shell profiles and authorized_keys.*
- **How do you detect miners without high CPU alerts?** *DNS and network detections for mining pool domains and stratum traffic.*

## One-Line Answer to Memorize

> "I identify and hash the process, capture its connections and persistence before killing it, then find how the attacker got in, because the miner is just the payload."

---

[← All 30 questions](README.md) · [Previous: Q14](14-mfa-fatigue-push-approved.md) · [Next: Q16](16-true-false-positive-negative.md)
