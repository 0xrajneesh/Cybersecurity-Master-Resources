# Q25. Splunk Query for Brute Force

> **Difficulty:** Intermediate · **Topic:** SIEM / SPL · **Asked for:** SOC L1 / L2

## The Question

> "Write a Splunk query to detect a brute force attack and explain it."

## The Trap Answer

**`index=* EventCode=4625`** and nothing else. It returns every failed login in the company, with no threshold, no grouping and no way to tell a typo from an attack.

The interviewer wants to see that you can **aggregate**, **threshold** and **explain each pipe**. They also want to hear that you know brute force only matters if it is followed by a **success**.

## The Strong Answer, Step by Step

### 1. Start with the right data
Windows failed logons are **Event ID 4625** in the Security log.
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
```
- Name a **specific index**; `index=*` is slow and sloppy
- Field names vary by add-on; with the Splunk Add-on for Windows you typically get **src_ip** (or Source_Network_Address) and **user**

### 2. Bucket by time and count failures
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count AS failures dc(user) AS users_tried BY _time, src_ip
| where failures > 20
```
- **bin span=5m**: groups events into 5-minute windows
- **stats count**: failures per source IP per window
- **dc(user)**: distinct accounts tried (high = **password spraying**)
- **where failures > 20**: threshold; tune it to your environment

### 3. Tell brute force from spraying
- **failures high, users_tried = 1**: brute force on one account
- **failures high, users_tried high**: password spraying across many accounts

### 4. Correlate with a success
The question that matters: *did they get in?*
```spl
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) AS failures
        count(eval(EventCode=4624)) AS successes
        values(user) AS users
        BY src_ip
| where failures > 20 AND successes > 0
```
- **count(eval(...))** counts each event type separately in one pass
- Any row returned is a **priority alert**: failures followed by a success from the same IP

### 5. Add useful context
- `| iplocation src_ip` for country and city
- Exclude known scanners or VPN gateways with a **lookup** of allowlisted IPs
- Add **Logon_Type** to see if it was RDP (10) or network (3)

### 6. Explain how you would operationalise it
- Save it as a **scheduled search** or correlation search in **Splunk ES**
- Run every 5 to 15 minutes over a matching window
- Tune the threshold after reviewing a week of results

## Quick Reference

| Step | Action | Tool / Evidence |
|---|---|---|
| 1 | Pull failed logons | EventCode=4625, specific index |
| 2 | Bucket and count | bin, stats count, dc(user) |
| 3 | Separate brute force vs spraying | users_tried value |
| 4 | Correlate with success | 4624 + 4625, count(eval()) |
| 5 | Enrich | iplocation, allowlist lookup, Logon_Type |
| 6 | Operationalise | Scheduled / correlation search in Splunk ES |

## What the Interviewer Is Really Testing

Whether you can **write SPL that aggregates and thresholds** rather than just filters, and whether you **think like an analyst** by correlating failures with a successful login.

## Follow-Up Questions to Expect

- How would you reduce false positives? *Allowlist scanners and service accounts with known bad passwords, and tune the threshold to your baseline.*
- What is the difference between stats and table? *table just displays fields; stats aggregates them into counts, distinct counts and lists.*
- How would you do this in Microsoft Sentinel? *A KQL query on SecurityEvent where EventID == 4625, summarised by IpAddress over bin(TimeGenerated, 5m).*

## One-Line Answer to Memorize

> "I search EventCode 4625, bucket it into 5-minute windows, count failures and distinct users per source IP, threshold it, and then correlate with 4624 to catch the IPs that actually got in."

---

[← All 30 questions](README.md) · [Previous: Q24](24-detect-lateral-movement.md) · [Next: Q26](26-phishing-email-header-analysis.md)
