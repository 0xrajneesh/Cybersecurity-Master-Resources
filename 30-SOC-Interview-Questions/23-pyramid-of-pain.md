# Q23. The Pyramid of Pain

> **Difficulty:** Intermediate · **Topic:** Threat Intelligence · **Asked for:** SOC L1 / L2

## The Question

> "What is the Pyramid of Pain, and how does it change how you respond?"

## The Trap Answer

**"It is a pyramid of indicator types, hashes at the bottom and TTPs at the top."** Correct, and only half the answer. The interviewer asked how it *changes how you respond*.

Candidates who stop at the definition reveal that they still think blocking a hash or an IP is "done". The point of the model is that those blocks cost the attacker almost nothing, so your response has to climb higher.

## The Strong Answer, Step by Step

### 1. Define it
Created by **David Bianco** in 2013. It ranks indicators by **how much pain you cause the attacker** when you detect and deny them.
- Bottom = trivial for the attacker to change
- Top = forces the attacker to change **how they operate**

### 2. Walk the levels, bottom to top
- **Hash values**: trivial; recompile or change one byte and the hash is new
- **IP addresses**: easy; new VPS or proxy in minutes
- **Domain names**: simple; register a new domain cheaply
- **Network / host artifacts**: annoying; URI patterns, user-agent strings, registry keys, named pipes
- **Tools**: challenging; the attacker must find or build a new tool (e.g. replace **Mimikatz**)
- **TTPs**: tough; tactics, techniques and procedures, such as **credential dumping from LSASS** or **Kerberoasting**

### 3. Give an example
A phishing campaign drops a loader.
- You block the **hash**: attacker repacks it tomorrow
- You block the **C2 domain**: attacker rotates to a new one
- You detect **Office apps spawning PowerShell** (ATT&CK **T1059.001** via a phishing attachment): every variant gets caught, whatever the hash or domain

### 4. Show how it changes your response on shift
- Still block IOCs, because it is **fast and cheap** for you
- But in the ticket, ask: *"What behaviour did this attacker rely on?"*
- Recommend a **behaviour-based detection** to the detection engineering team
- Hunt for the **same technique** on other hosts, not just the same hash

### 5. Connect it to IOC vs IOA
- Bottom half = mostly **IOCs** (what was left behind)
- Top half = **IOAs and TTPs** (what the attacker is doing)
- Mature SOCs invest detection effort near the **top**

## Quick Reference

| Level | Example | Attacker pain | Your action |
|---|---|---|---|
| Hash | SHA256 of loader | Trivial | Block in EDR, but expect variants |
| IP address | C2 server IP | Easy | Block at firewall, hunt past connections |
| Domain | Phishing domain | Simple | Block at proxy / DNS |
| Network / host artifacts | Odd user-agent, registry Run key | Annoying | Write SIEM / EDR rule on the artifact |
| Tools | Mimikatz, Cobalt Strike | Challenging | Detect tool behaviour, not file name |
| TTPs | LSASS dumping, Kerberoasting | Tough | Behaviour detections mapped to ATT&CK |

## What the Interviewer Is Really Testing

Whether you understand **why indicator blocking alone is weak** and whether you think in terms of **attacker behaviour** when you write up and recommend follow-up on an incident.

## Follow-Up Questions to Expect

- Why block hashes at all if they are so weak? *They are cheap, instant and stop the exact copy already spreading.*
- Give a TTP-level detection you could write. *Alert when any non-system process opens a handle to lsass.exe with read access, via Sysmon Event ID 10.*
- Where do IOCs come from? *Your own incidents, threat intel feeds, vendor reports and ISACs.*

## One-Line Answer to Memorize

> "The Pyramid of Pain shows that blocking hashes and IPs barely slows an attacker, so I still block them fast, but I push detections up to tools and TTPs, because that is what forces the attacker to change how they work."

---

[← All 30 questions](README.md) · [Previous: Q22](22-escalate-or-close.md) · [Next: Q24](24-detect-lateral-movement.md)
