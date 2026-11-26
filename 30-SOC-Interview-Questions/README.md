# 30 SOC Interview Questions

**Real SOC analyst interview questions, the trap answers that fail candidates, and the strong answers that get you hired.**

> By Rajneesh Gupta · HaxCamp

Every answer follows the same format, so you can practise it out loud:

| Section | What It Gives You |
|---|---|
| **The Trap Answer** | What most candidates say, and why it fails |
| **The Strong Answer** | A step-by-step process an interviewer wants to hear |
| **Quick Reference** | The whole answer in one table |
| **What the Interviewer Is Testing** | The skill behind the question |
| **Follow-Up Questions** | What they will ask next, with hints |
| **One-Line Answer** | A single sentence to memorise |

---

## Alert Scenarios: "What Would You Do?"

| # | Question | Level |
|---|---|---|
| 1 | [500 failed logins from one IP, then one success. What do you do?](01-500-failed-logins-then-success.md) | Beginner |
| 2 | [A user clicked a link in a suspicious email. Walk me through your response.](02-user-clicked-phishing-link.md) | Beginner |
| 3 | [EDR alerts on an encoded PowerShell command. How do you investigate?](03-encoded-powershell-alert.md) | Intermediate |
| 4 | [Impossible travel alert for a senior executive. What do you do?](04-impossible-travel-alert.md) | Beginner |
| 5 | [A ransom note appears on a file server. What are your first steps?](05-ransomware-note-on-file-server.md) | Intermediate |
| 6 | [A host sends 8 GB to an external IP at 2 AM. How do you investigate?](06-large-outbound-transfer-at-night.md) | Intermediate |
| 7 | [Microsoft Word just launched cmd.exe. Why does it matter?](07-word-spawns-cmd.md) | Intermediate |
| 8 | [Antivirus quarantined a malicious file. Can you close the ticket?](08-antivirus-quarantined-file.md) | Beginner |
| 9 | [A new domain admin account was created at midnight. What do you do?](09-new-admin-account-at-midnight.md) | Intermediate |
| 10 | [A host contacts an unknown domain every 60 seconds. What is happening?](10-beaconing-to-unknown-domain.md) | Intermediate |
| 11 | [A process accessed LSASS memory. What does it mean?](11-lsass-access-credential-dumping.md) | Advanced |
| 12 | [A successful RDP login from a public internet IP. How do you handle it?](12-rdp-from-internet-ip.md) | Beginner |
| 13 | [A mailbox rule forwards all email to an external address. What now?](13-inbox-forwarding-rule.md) | Intermediate |
| 14 | [A user approved an MFA push they did not start. How do you respond?](14-mfa-fatigue-push-approved.md) | Intermediate |
| 15 | [A server is at 100% CPU and you suspect a crypto miner.](15-crypto-miner-high-cpu.md) | Intermediate |

## SOC Concepts: "Explain This to Me"

| # | Question | Level |
|---|---|---|
| 16 | [True positive, false positive, false negative: which is most dangerous?](16-true-false-positive-negative.md) | Beginner |
| 17 | [You start your shift with 50 open alerts. How do you prioritise?](17-prioritize-50-alerts.md) | Beginner |
| 18 | [What is the difference between an IOC and an IOA?](18-ioc-vs-ioa.md) | Beginner |
| 19 | [How do you use MITRE ATT&CK during an investigation?](19-mitre-attack-in-investigations.md) | Intermediate |
| 20 | [Which Windows Event IDs should every SOC analyst know?](20-windows-event-ids-to-know.md) | Beginner |
| 21 | [SIEM vs EDR vs XDR vs SOAR: what is the difference?](21-siem-edr-xdr-soar.md) | Beginner |
| 22 | [How do you decide whether to escalate or close an alert?](22-escalate-or-close.md) | Beginner |
| 23 | [What is the Pyramid of Pain?](23-pyramid-of-pain.md) | Intermediate |
| 24 | [What is lateral movement, and how would you detect it?](24-detect-lateral-movement.md) | Intermediate |

## Hands-On: "Show Me"

| # | Question | Level |
|---|---|---|
| 25 | [Write a Splunk query to detect a brute force attack.](25-splunk-query-brute-force.md) | Intermediate |
| 26 | [How do you analyse phishing email headers? SPF, DKIM, DMARC?](26-phishing-email-header-analysis.md) | Intermediate |
| 27 | [A hash shows 3 out of 70 detections on VirusTotal. Is it malicious?](27-virustotal-3-detections.md) | Beginner |
| 28 | [Walk me through the incident response lifecycle.](28-incident-response-lifecycle.md) | Beginner |

## Behavioural: "Tell Me About a Time"

| # | Question | Level |
|---|---|---|
| 29 | [You closed a real attack as a false positive. What do you do?](29-you-missed-an-alert.md) | Beginner |
| 30 | [Tell me about an investigation you are proud of.](30-tell-me-about-an-investigation.md) | Beginner |

---

## How to Practise

1. **Read the question, then stop.** Answer it out loud before you scroll.
2. **Compare** your answer with the Strong Answer. Did you jump to the trap?
3. **Memorise the one-line answer**, then explain each step in your own words.
4. **Practise the follow-ups**, because that is where interviews are won.

## Practice and Learn More

| Resource | What You Get |
|---|---|
| [Top 20 SOC Analyst L1 Interview Questions](https://www.youtube.com/watch?v=fWJc9rPprSs) | Direct Q&A walkthrough on video |
| [This 15 Min Video Can Simplify Your SOC Interview](https://www.youtube.com/watch?v=-ONDzsdRWsI) | How to structure your answers |
| [SOC L1 Triage: SOC Analyst Guide](https://www.youtube.com/watch?v=X537D_K3_zQ) | How L1 triage works on a real shift |
| [Alert Triage Fundamentals](https://app.haxcamp.com/lab/alert-triage-fundamentals) | Hands-on lab: close or escalate real alerts |
| [What Does an L1 Analyst Actually Do?](https://app.haxcamp.com/lab/what-does-an-l1-analyst-actually-do) | Hands-on lab: manage an alert queue |
| [Triage Decision Framework](https://app.haxcamp.com/lab/triage-decision-framework) | Hands-on lab: a five-question model for every alert |

**Keep learning:** [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) · [HaxCamp Labs](https://app.haxcamp.com/labs) · [SOC Investigation Playbooks](../README.md)
