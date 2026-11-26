# Q19. Using MITRE ATT&CK During an Investigation

> **Difficulty:** Intermediate · **Topic:** Frameworks / Investigation · **Asked for:** SOC L1 / L2

## The Question

> "How do you use MITRE ATT&CK during an investigation?"

## The Trap Answer

**"MITRE ATT&CK is a framework of tactics and techniques. I would map the alert to a technique ID."**

That is a definition, not a use. Mapping an alert to **T1059.001** and stopping there is like naming a disease without treating it. The interviewer wants to hear how ATT&CK changes **what you do next**.

The real value is that ATT&CK tells you **where you are in the attack** and **what the attacker probably did before and will do after**. That turns a single alert into a hunting plan.

## The Strong Answer, Step by Step

### 1. Know the structure
- **Tactics** = the attacker's goal (the "why"), for example **TA0001 Initial Access**, **TA0006 Credential Access**, **TA0008 Lateral Movement**, **TA0010 Exfiltration**
- **Techniques and sub-techniques** = the "how", for example **T1059.001 PowerShell**, **T1003.001 LSASS Memory**
- **Procedures** = how a specific group actually did it

### 2. Map the alert to locate the attack stage
Example: EDR flags encoded PowerShell launched by Word.
- **T1566.001 Spearphishing Attachment** (Initial Access)
- **T1204.002 Malicious File** (Execution, user ran it)
- **T1059.001 PowerShell** (Execution)
- Now you know the attacker is **early** in the chain

### 3. Pivot backwards
What tactic came before this one?
- Find the phishing email, the sender, other recipients
- Check who else opened the same attachment

### 4. Pivot forwards
What tactics usually come next? Hunt for them before they hurt you.
- **Persistence**: T1053.005 Scheduled Task (**Event ID 4698**), T1547.001 Run keys
- **Credential Access**: T1003.001 LSASS access (**Sysmon Event ID 10**)
- **Discovery** and **Lateral Movement**: T1021.002 SMB/Admin Shares, **4624 logon type 3** from this host
- **Command and Control**: T1071 Application Layer Protocol beaconing

### 5. Use it to communicate
- Write the incident timeline in ATT&CK terms; L2, IR and management all understand it
- Makes reports **consistent** across analysts and shifts

### 6. Use it for threat intel and coverage
- Look up the suspected **threat group** (ATT&CK Groups pages) and check their usual techniques
- Use **ATT&CK Navigator** to visualise which techniques you detect and where the **gaps** are
- Feed gaps to detection engineering as new rule requests

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Know tactics vs techniques | ATT&CK matrix, TA / T IDs |
| 2 | Map the alert | T1566.001, T1204.002, T1059.001 |
| 3 | Pivot backwards | Email gateway, initial access artefacts |
| 4 | Pivot forwards | 4698, Sysmon 10, 4624 type 3, C2 traffic |
| 5 | Communicate | Timeline and report in ATT&CK terms |
| 6 | Threat intel and coverage | ATT&CK Groups, ATT&CK Navigator |

## What the Interviewer Is Really Testing

They want proof that you use ATT&CK as a **thinking tool to pivot backwards and forwards**, not a label. Mentioning **coverage gaps with Navigator** shows you understand how the SOC improves over time.

## Follow-Up Questions to Expect

- **What is the difference between a tactic and a technique?** *A tactic is the goal, like Credential Access; a technique is how it is achieved, like LSASS dumping.*
- **How is ATT&CK different from the Cyber Kill Chain?** *The Kill Chain is a high-level linear model; ATT&CK is a detailed, non-linear knowledge base of real techniques.*
- **What is ATT&CK Navigator?** *A web tool for layering and colouring the matrix, often used to show detection coverage.*

## One-Line Answer to Memorize

> "I map the alert to a tactic and technique to see where the attacker is, then pivot backwards to find how they got in and forwards to hunt for what they will do next."

---

[← All 30 questions](README.md) · [Previous: Q18](18-ioc-vs-ioa.md) · [Next: Q20](20-windows-event-ids-to-know.md)
