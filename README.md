# Cybersecurity Master Resources

Practical, hands-on **SOC investigation playbooks** for the security alerts analysts see every day.

Every guide follows the same flow: **Detect → Investigate → Respond**, using **Microsoft Defender XDR**, **Splunk** and **Threat Intelligence**.

## What Each Guide Includes

- **60-second triage**: the first steps to take when the alert fires
- What the alert means, key terms and the **MITRE ATT&CK** mapping
- Alert triage checklist and the key fields to collect
- Ready-to-use **Defender KQL** hunting queries, with what to look for in the results
- Ready-to-use **Splunk SPL** searches
- Threat intelligence enrichment steps
- True positive vs benign indicators and common beginner mistakes
- A full **response checklist**: contain, eradicate, recover, preserve evidence, monitor
- **Practice and learn more**: video walkthroughs and hands-on labs for the topic

## SOC Investigation Guides

| Alert | What You Will Investigate | Guide |
|-------|---------------------------|-------|
| Credential Dumping (LSASS Access) | A process reading LSASS memory to steal credentials | [Open guide](credential-dumping/README.md) |
| Impossible Travel | Sign-ins from locations too far apart to be genuine | [Open guide](impossible-travel/README.md) |
| Lateral Movement | An attacker moving from one host to another | [Open guide](lateral-movement/README.md) |
| Malicious File Detected | A suspicious or malicious file on an endpoint | [Open guide](malicious-file-detected/README.md) |
| Multiple Failed Logins | Brute force and password spray attempts | [Open guide](multiple-failed-logins/README.md) |
| Suspicious Office Child Process | Word or Excel launching shells and scripts | [Open guide](office-child-process/README.md) |
| Phishing Link Clicked | A user clicking a malicious link in an email | [Open guide](phishing-link-clicked/README.md) |
| Suspicious PowerShell Execution | Encoded, hidden or download-cradle PowerShell | [Open guide](suspicious-powershell/README.md) |
| Suspicious Remote Access | Risky RDP and remote tool sessions | [Open guide](suspicious-remote-access/README.md) |
| Unusual Data Transfer | Large or unusual outbound data (exfiltration) | [Open guide](unusual-data-transfer/README.md) |

## 30 SOC Interview Questions

Preparing for a SOC analyst interview? [**30 SOC Interview Questions**](30-SOC-Interview-Questions/README.md) covers real alert scenarios, core concepts and hands-on questions, each with the trap answer, the strong answer and a one-line answer to memorise.

## How to Use the Queries

- Replace placeholders like `<DeviceName>`, `<AccountName>` and `<IP>` with values from your alert.
- Splunk `index=` and `sourcetype=` names differ between environments, so adjust them to yours.
- Validate queries in a test environment before relying on them in production.

## Practice and Learn More

| Resource | What You Get |
|----------|--------------|
| [YouTube: Rajneesh Gupta](https://www.youtube.com/@RajneeshCyber) | Free SOC, SIEM, threat hunting and incident response tutorials |
| [HaxCamp Labs](https://app.haxcamp.com/labs) | Hands-on labs: alert triage, Splunk, Sysmon, phishing, EDR, threat intel |
| [HaxCamp Projects](https://app.haxcamp.com/projects) | Home-lab projects to build and add to your resume |
| [HaxCamp Learning Paths](https://app.haxcamp.com/learning-paths) | Structured paths from beginner to job-ready |

Recommended starting points:

- [SOC L1 Triage: SOC Analyst Guide](https://www.youtube.com/watch?v=X537D_K3_zQ) (video)
- [Splunk SPL Query Masterclass](https://www.youtube.com/watch?v=tfA8shtJ8ew) (video)
- [Alert Triage Fundamentals](https://app.haxcamp.com/lab/alert-triage-fundamentals) (lab)
- [Deep Dive with SPL](https://app.haxcamp.com/lab/deep-dive-with-spl) (lab)
- [MITRE ATT&CK Fundamentals](https://app.haxcamp.com/lab/mitre-attck-fundamentals) (lab)
