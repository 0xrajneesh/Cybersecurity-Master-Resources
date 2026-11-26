# Q16. True Positive, False Positive, True Negative, False Negative

> **Difficulty:** Beginner · **Topic:** SOC Fundamentals · **Asked for:** SOC L1 / L2

## The Question

> "Explain true positive, false positive, true negative and false negative. Which is the most dangerous?"

## The Trap Answer

**"A false positive is the most dangerous because it wastes the analyst's time."**

False positives are annoying, and too many of them cause **alert fatigue**, but they are visible. Someone looks at them. The truly dangerous outcome is the one nobody sees: the **false negative**, a real attack that produced no alert at all.

Candidates also mix up the terms by reading "positive" as "good". In detection, **positive means "the alert fired"** and **true or false means "was the alert right"**. Get that sentence straight and the rest falls into place.

## The Strong Answer, Step by Step

### 1. Define the two axes
- **Positive / Negative**: did the detection **fire**?
- **True / False**: was the detection **correct**?

### 2. Define each outcome with an example
- **True Positive (TP)**: alert fired and it is a real attack. *Brute force alert, and it really was a password spray from a Tor exit node.*
- **False Positive (FP)**: alert fired but it is benign. *"Encoded PowerShell" alert that turns out to be the SCCM admin's deployment script.*
- **True Negative (TN)**: no alert, and nothing bad happened. *Normal user logins all day, correctly ignored.*
- **False Negative (FN)**: no alert, but an attack happened. *Attacker uses stolen valid credentials over VPN and no rule catches it.*

### 3. Say which is most dangerous and why
- **False negative** is the most dangerous: the attacker operates with **zero visibility** for days or months
- False positives are a **cost** problem; false negatives are a **breach** problem

### 4. Explain the balance
- Tighten a rule and you cut FPs but risk more FNs
- Loosen it and you catch more but drown in FPs, which can hide a TP in the noise
- Too many FPs create **alert fatigue**, which indirectly creates FNs when analysts start skimming

### 5. Show how you use it on shift
- Close tickets with the **correct disposition** (TP, FP, benign true positive) so detection engineers can tune
- A **benign true positive** is worth knowing: the rule worked correctly, but the activity was authorised (for example a pentest or an admin using PsExec)
- Feed FPs back as **tuning requests**, never silently ignore a noisy rule

### 6. Show how you reduce false negatives
- **Threat hunting** for things rules do not cover
- Map detections to **MITRE ATT&CK** to spot coverage gaps
- Run **purple team** or **Atomic Red Team** tests to check that rules actually fire

## Quick Reference

| Outcome | Alert fired? | Real attack? | Example | Risk |
|---|---|---|---|---|
| True Positive | Yes | Yes | Real password spray detected | Good, act on it |
| False Positive | Yes | No | Admin script flagged as malicious | Wasted time, alert fatigue |
| True Negative | No | No | Normal logins ignored | Ideal |
| False Negative | No | Yes | Stolen VPN creds, no alert | Most dangerous, undetected breach |

## What the Interviewer Is Really Testing

Beyond the definitions, they want to see that you understand **detection trade-offs** and that you **close tickets with accurate dispositions** so the SOC can improve. Mentioning hunting or ATT&CK coverage to reduce false negatives shows maturity.

## Follow-Up Questions to Expect

- **How would you reduce false positives on a noisy rule?** *Find the common benign pattern and add a narrow, documented exclusion, not a blanket disable.*
- **What is a benign true positive?** *The rule detected exactly what it was built for, but the activity was authorised.*
- **How do you find false negatives if nothing alerts?** *Threat hunting, red/purple team tests and reviewing incidents for missed signals.*

## One-Line Answer to Memorize

> "Positive means the alert fired, true means it was right; a false negative is the most dangerous because a real attack happens with no alert at all."

---

[← All 30 questions](README.md) · [Previous: Q15](15-crypto-miner-high-cpu.md) · [Next: Q17](17-prioritize-50-alerts.md)
