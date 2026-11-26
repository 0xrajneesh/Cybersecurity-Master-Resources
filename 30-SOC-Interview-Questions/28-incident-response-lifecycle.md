# Q28. The Incident Response Lifecycle

> **Difficulty:** Beginner · **Topic:** Incident Response · **Asked for:** SOC L1 / L2

## The Question

> "Walk me through the incident response lifecycle with a real example."

## The Trap Answer

**"Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned."** Reciting the list is fine. Stopping there is not; the interviewer explicitly asked for an example.

Without an example, you sound like you studied for an exam, not like someone who can run a case at 3 AM. Pick one scenario and carry it through every phase.

## The Strong Answer, Step by Step

### 1. Name the framework
Two common models; know both and pick one.
- **NIST SP 800-61**: Preparation → Detection and Analysis → Containment, Eradication and Recovery → Post-Incident Activity
- **SANS PICERL**: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned
- Example used below: a **phishing email leads to a compromised mailbox**

### 2. Preparation
Everything done before the incident.
- **Playbooks** for phishing and account compromise
- Logging enabled: **Entra ID sign-in logs**, **Unified Audit Log**, EDR on endpoints
- Contacts list, escalation paths, MFA rolled out

### 3. Detection and Analysis (Identification)
- User reports a "DocuSign" email; SIEM shows a **sign-in from a new country** 10 minutes later
- Mailbox audit shows a **new inbox rule forwarding to an external address**
- Scope: search the gateway, **14 users** received it, **2 entered credentials**
- Classify severity and open the incident

### 4. Containment
Stop the bleeding, short term first.
- **Revoke sessions** and **reset passwords** for the 2 accounts
- Remove the **forwarding rules**, block the phishing domain at proxy and gateway
- **Purge** the email from all 14 mailboxes

### 5. Eradication
Remove every foothold.
- Check for **new MFA methods** registered by the attacker and remove them
- Review **OAuth app consents** granted during the session
- Confirm no further sign-ins from the attacker IPs

### 6. Recovery
- Restore normal access, confirm users can sign in with **fresh MFA**
- **Heightened monitoring** on both accounts for 30 days
- Notify affected parties if the attacker sent emails from the mailbox

### 7. Lessons Learned (Post-Incident Activity)
- Timeline review within a week: **what worked, what was slow**
- Detection gap: create an alert for **external forwarding rules**
- Push **phishing-resistant MFA** or number matching to stop repeat attacks

## Quick Reference

| Phase | Action in the example | Tool / Evidence |
|---|---|---|
| Preparation | Playbooks, logging, MFA | Runbooks, Entra ID, EDR |
| Detection and Analysis | Spot risky sign-in and rule, scope victims | SIEM, sign-in logs, Unified Audit Log |
| Containment | Revoke sessions, reset, purge, block | Entra ID, Exchange admin, mail gateway |
| Eradication | Remove MFA methods, OAuth apps | Entra ID, app consent review |
| Recovery | Restore access, monitor | SIEM watchlist |
| Lessons Learned | New detection, MFA hardening | Post-incident report |

## What the Interviewer Is Really Testing

Whether you know **the phases in order** and whether you can **apply them to a real scenario** with concrete actions, not just definitions.

## Follow-Up Questions to Expect

- Why contain before eradicating? *To stop further damage first; eradicating too early can tip off the attacker before you know the full scope.*
- What goes in a lessons learned report? *Timeline, root cause, impact, what worked, what failed, and owned action items.*
- Which phase do teams skip most? *Lessons learned, which is why the same incidents keep repeating.*

## One-Line Answer to Memorize

> "I follow NIST: prepare, detect and analyse, contain, eradicate, recover, and learn, and for a phished mailbox that means scoping victims, revoking sessions, removing attacker rules and MFA methods, restoring access, and adding a detection so it does not happen again."

---

[← All 30 questions](README.md) · [Previous: Q27](27-virustotal-3-detections.md) · [Next: Q29](29-you-missed-an-alert.md)
