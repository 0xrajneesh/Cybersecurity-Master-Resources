# Q30. Tell Me About an Investigation You Are Proud Of

> **Difficulty:** Beginner · **Topic:** Behavioural · **Asked for:** SOC L1 / L2

## The Question

> "Tell me about an investigation you are proud of."

## The Trap Answer

**"I do not have job experience yet, so I have not done one."** That ends the conversation. Interviewers know freshers have no SOC job; they are asking whether you have **done the work anyway**.

The experienced version of the trap is a rambling story with no structure, no tools and no result. Five minutes of "and then we looked at stuff" tells them nothing about how you think.

## The Strong Answer, Step by Step

### 1. Pick the right story
- **With experience**: a real alert you triaged where your action changed the outcome
- **Without experience**: a **home lab**, **TryHackMe SOC Level 1** room, **Blue Team Labs Online** or **LetsDefend** case, **Boss of the SOC (BOTS)** Splunk dataset, or a CTF
- Choose one with a clear **trigger, investigation and conclusion**

### 2. Structure it with STAR
- **Situation**: the environment and the alert
- **Task**: what you had to find out
- **Action**: the steps and tools, in order
- **Result**: what you found, what changed, what you learned

### 3. Set the scene in two sentences
- *"In a Splunk BOTS v1 dataset, I was given an alert that a web server had been defaced."*
- *"On shift, EDR flagged encoded PowerShell on a finance laptop at 9 PM."*

### 4. Show your actions with real evidence
- Name the **tools**: Splunk, Sentinel, Wireshark, CrowdStrike, VirusTotal
- Name the **evidence**: Event IDs **4625 / 4624**, **4688** process creation, Sysmon **Event ID 1** and **3**, HTTP logs
- Show the **pivot**: *"The source IP led me to the user-agent, which led me to the scanning tool used."*

### 5. Give a concrete result
- What you **concluded** (true positive, root cause, attacker tool)
- What you **did** (contained, escalated, wrote a detection)
- A number if possible: *"cut triage time on that alert from 20 minutes to 5 with a saved search."*

### 6. Close with what you learned
- One technical lesson and one process lesson
- Shows **reflection**, which interviewers value more than the story itself

### 7. Prepare for depth
- They will drill into any step; only claim what you **actually did**
- Have your **lab write-up or GitHub notes** ready to share

## Quick Reference

| STAR part | What to say | Example evidence |
|---|---|---|
| Situation | Environment and alert | "Splunk BOTS v1, web server defacement" |
| Task | Question you had to answer | "Find how the attacker got in" |
| Action | Steps, tools, pivots | Splunk SPL, HTTP logs, 4688, Sysmon 1 / 3 |
| Result | Finding and impact | Root cause, detection written, time saved |
| Lesson | Technical and process takeaway | "Always pivot on user-agent and source IP" |

## What the Interviewer Is Really Testing

Your **structured communication** and your **genuine hands-on curiosity**. A clear lab story told well beats a vague real-job story every time.

## Follow-Up Questions to Expect

- What would you do differently now? *Name one specific step, like correlating with DNS logs earlier.*
- What was the hardest part? *Be honest: noisy data, a dead end, or a tool you had to learn on the spot.*
- Can you show me your write-up? *Have a GitHub repo or blog post link ready on your CV.*

## One-Line Answer to Memorize

> "I tell one real or lab investigation using STAR, naming the alert, the tools and Event IDs I used, the pivot that cracked it, the result, and what I learned."

---

[← All 30 questions](README.md) · [Previous: Q29](29-you-missed-an-alert.md) · [Back to the index](README.md)
