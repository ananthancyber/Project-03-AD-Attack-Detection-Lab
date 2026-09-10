# Lateral Movement Investigation

## Executive Summary

This investigation documents a controlled remote authentication scenario performed during Day 12 of the Active Directory Attack & Detection Lab.

A low-privileged domain account, `bh_enum`, was used from the Kali analysis system to authenticate remotely to `WIN10-CLIENT` through SMB. The activity generated Windows Security Event ID 4624 with Logon Type 3, indicating a network-based logon.

The authentication was subsequently detected by Wazuh through:

**Rule 92657 — Successful Remote Logon Detected**

The investigation correlated the source IP, workstation, account, authentication protocol, destination endpoint, Windows event, and Wazuh alert.

The activity was intentionally generated within the controlled lab environment and was classified as expected test activity.

This exercise demonstrates the SOC workflow:

**Remote Authentication → Endpoint Telemetry → SIEM Detection → Correlation → Investigation → Assessment**

The exercise does not establish administrative access, privilege escalation, credential theft, or full host compromise.

---

# 1. Investigation Classification

| Field | Value |
|---|---|
| Investigation | Lateral Movement / Remote Authentication |
| Activity Type | Controlled Security Test |
| Severity | Medium Investigation Priority |
| Status | Closed — Lab Validation |
| Source | Kali Linux |
| Source IP | `192.168.159.129` |
| Destination | `WIN10-CLIENT` |
| Destination IP | `192.168.159.133` |
| Account | `CORP\bh_enum` |
| Protocol | SMB |
| Port | TCP/445 |
| Windows Event | 4624 |
| Logon Type | 3 — Network |
| Authentication | NTLM / NTLM V2 |
| SIEM | Wazuh |
| Detection Rule | 92657 |
| Wazuh Severity | Level 6 |
| Final Classification | Expected Controlled Activity |

---

# 2. Investigation Objective

The objective was to demonstrate how a SOC analyst can identify and investigate remote authentication activity that may represent lateral movement.

The investigation focused on:

- Establishing a pre-activity baseline.
- Validating SMB connectivity.
- Performing controlled remote authentication.
- Identifying Windows Event ID 4624.
- Analyzing Logon Type 3.
- Correlating the source IP and workstation.
- Validating Wazuh detection.
- Reviewing Rule 92657.
- Assessing whether the activity represented malicious behavior.
- Documenting the investigation using evidence-based conclusions.

---

# 3. Lab Environment

| Component | Configuration |
|---|---|
| Active Directory Domain | `CORP.LOCAL` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Attacker / Analysis System | Kali Linux |
| Kali IP | `192.168.159.129` |
| Target Endpoint | `WIN10-CLIENT` |
| Target IP | `192.168.159.133` |
| Account Used | `bh_enum` |
| Protocol | SMB |
| Destination Port | TCP/445 |
| SIEM | Wazuh |

---

# 4. Investigation Scope

The investigation covered the following activity:

**Kali**

`192.168.159.129`

↓

**SMB / TCP 445**

↓

**WIN10-CLIENT**

`192.168.159.133`

↓

**CORP\bh_enum**

↓

**Windows Event 4624**

↓

**Wazuh Rule 92657**

The investigation did not include:

- Credential dumping
- Pass-the-Hash
- Privilege escalation
- Remote command execution
- Persistence
- Administrative share abuse
- Full host compromise

This scope distinction prevents the investigation from overclaiming what the evidence actually demonstrates.

---

# 5. Pre-Activity Baseline

Before performing the controlled remote authentication, successful Windows logon activity was reviewed on WIN10-CLIENT.

This established a baseline for Event ID 4624 and provided context for subsequent authentication analysis.

### Evidence

![Windows 4624 Baseline](../screenshots/Day12/Day12-01-Windows10-4624-LateralMovement-Baseline.png)

**Evidence:** `Day12-01-Windows10-4624-LateralMovement-Baseline.png`

---

# 6. SMB Session Baseline

The existing SMB session state was checked before the controlled activity.

No active SMB sessions were returned at the time of the baseline check.

This provided a clean pre-activity state for the target endpoint.

### Evidence

![Windows SMB Session Baseline](../screenshots/Day12/Day12-02-Windows10-SMB-Session-Baseline.png)

**Evidence:** `Day12-02-Windows10-SMB-Session-Baseline.png`

---

# 7. Network Connectivity Validation

Before authentication, connectivity from Kali to the WIN10-CLIENT SMB service was validated.

The target SMB service was reachable on:

`192.168.159.133:445`

### Evidence

![Kali to Windows SMB Connectivity](../screenshots/Day12/Day12-03-Kali-to-Windows10-SMB-Connectivity-Baseline.png)

**Evidence:** `Day12-03-Kali-to-Windows10-SMB-Connectivity-Baseline.png`

The inability to receive ICMP ping responses did not prevent SMB communication because ICMP and TCP/445 are separate protocols.

The successful TCP/445 test confirmed that the required remote service was reachable.

---

# 8. Controlled Remote Authentication

A controlled SMB authentication was performed from Kali using the dedicated low-privileged `bh_enum` domain account.

The authentication targeted the SMB IPC$ service on WIN10-CLIENT.

The SMB session was successfully established.

### Evidence

![Kali SMB Remote Authentication](../screenshots/Day12/Day12-04-Kali-SMB-Remote-Authentication.png)

**Evidence:** `Day12-04-Kali-SMB-Remote-Authentication.png`

This demonstrated successful remote authentication using valid domain credentials.

---

# 9. Windows Security Event Analysis

Following the authentication, WIN10-CLIENT generated a successful logon event.

The relevant Windows Security Event ID was:

**4624 — An account was successfully logged on**

The event contained the following important characteristics:

| Field | Observed Value |
|---|---|
| Target Account | `bh_enum` |
| Domain | `CORP` |
| Logon Type | `3` |
| Authentication Package | `NTLM` |
| NTLM Version | `NTLM V2` |
| Source IP | `192.168.159.129` |
| Workstation | `KALI` |

Logon Type 3 represents a network logon and is consistent with remote network authentication such as SMB.

### Evidence

![Windows 4624 Network Logon](../screenshots/Day12/Day12-05-Windows10-4624-Lateral-Movement-Network-Logon.png)

**Evidence:** `Day12-05-Windows10-4624-Lateral-Movement-Network-Logon.png`

---

# 10. SIEM Detection

The Windows authentication telemetry was observed by Wazuh.

Wazuh generated:

**Rule 92657 — Successful Remote Logon Detected**

with:

**Level 6**

The alert contained the account, source, destination, authentication, and Windows event information required for further investigation.

### Evidence

![Wazuh Lateral Movement Alert](../screenshots/Day12/Day12-06-Wazuh-Lateral-Movement-4624-Document-Details.png)

**Evidence:** `Day12-06-Wazuh-Lateral-Movement-4624-Document-Details.png`

---

# 11. Wazuh Detection Analysis

Rule 92657 was examined to determine why the alert was generated.

Observed information included:

- Rule ID: `92657`
- Level: `6`
- Parent Rule: `92652`
- Ruleset file: `0840-win_event_channel.xml`
- Authentication-success grouping
- Windows Event Channel grouping

The detection identifies successful remote logon activity and provides context for investigating potential remote access.

### Evidence

![Wazuh Rule 92657 Detection Logic](../screenshots/Day12/Day12-07-Wazuh-Rule-92657-Detection-Logic.png)

**Evidence:** `Day12-07-Wazuh-Rule-92657-Detection-Logic.png`

Additional rule metadata was reviewed to confirm the detection's severity and ruleset information.

### Evidence

![Wazuh Rule 92657 Information](../screenshots/Day12/Day12-08-Wazuh-Rule-92657-Information.png)

**Evidence:** `Day12-08-Wazuh-Rule-92657-Information.png`

---

# 12. Evidence Correlation

The investigation correlated multiple pieces of evidence.

| Evidence | Observation |
|---|---|
| Source system | Kali |
| Source IP | `192.168.159.129` |
| Destination | `WIN10-CLIENT` |
| Destination IP | `192.168.159.133` |
| Remote service | SMB / TCP 445 |
| Account | `CORP\bh_enum` |
| Windows Event | 4624 |
| Logon Type | 3 |
| Authentication | NTLM / NTLM V2 |
| Workstation | KALI |
| SIEM Rule | 92657 |
| SIEM Severity | Level 6 |

The evidence forms a consistent chain:

**Kali → SMB → WIN10-CLIENT → bh_enum → 4624 → NTLM → Logon Type 3 → Wazuh 92657**

---

# 13. Timeline

| Sequence | Activity | Evidence |
|---|---|---|
| 1 | Windows authentication baseline reviewed | Day12-01 |
| 2 | SMB session baseline established | Day12-02 |
| 3 | SMB connectivity validated | Day12-03 |
| 4 | Controlled SMB authentication performed | Day12-04 |
| 5 | Windows 4624 network logon observed | Day12-05 |
| 6 | Wazuh detected remote logon | Day12-06 |
| 7 | Rule 92657 detection logic reviewed | Day12-07 |
| 8 | Rule metadata validated | Day12-08 |

---

# 14. Analyst Investigation

The analyst reviewed the alert using the following questions:

### Who authenticated?

`CORP\bh_enum`

### Where did the authentication originate?

`192.168.159.129`

The source system was the Kali security-testing host.

### Which workstation was associated with the authentication?

`KALI`

### Which endpoint received the authentication?

`WIN10-CLIENT`

### Which service was used?

SMB over TCP/445.

### What Windows logon type was recorded?

Logon Type 3 — Network.

### Which authentication protocol was observed?

NTLM / NTLM V2.

### Which SIEM rule detected the activity?

Wazuh Rule 92657.

---

# 15. Risk Assessment

The activity was initially relevant from a SOC perspective because successful remote authentication can be associated with lateral movement.

However, context significantly reduced the risk classification.

The investigation established that:

- The source was the controlled Kali lab system.
- The account was the designated lab `bh_enum` account.
- The authentication was intentionally generated.
- The target was the controlled WIN10-CLIENT endpoint.
- No evidence demonstrated administrative access.
- No evidence demonstrated privilege escalation.
- No evidence demonstrated credential theft.

Therefore, the activity was classified as:

**Expected Controlled Security Testing**

---

# 16. False Positive Assessment

Rule 92657 can legitimately trigger on normal remote authentication.

Potential legitimate sources include:

- IT administrators
- Help-desk personnel
- Remote support
- File-sharing activity
- System administration
- Security testing
- Automated management systems

The analyst should therefore avoid treating the alert as an automatic compromise.

Context must be evaluated before escalation.

---

# 17. Detection Quality Assessment

The detection provided useful information for SOC triage.

The most valuable fields were:

- Account
- Source IP
- Workstation
- Destination endpoint
- Logon Type
- Authentication protocol
- Windows Event ID
- Wazuh rule
- Wazuh severity

The alert therefore provides a practical starting point for investigating remote authentication.

---

# 18. Recommended SOC Investigation

If the same detection occurred in production, the analyst should:

1. Validate the account and source workstation.
2. Determine whether the remote authentication was expected.
3. Check whether the account normally accesses the target.
4. Review authentication activity before and after the event.
5. Search for additional destinations accessed by the account.
6. Review related Windows Security events.
7. Check for privilege changes or suspicious administrative activity.
8. Investigate the source endpoint if the authentication is unauthorized.
9. Contain credentials when compromise is suspected.
10. Escalate according to incident-response procedures.

---

# 19. Response Decision

For this controlled laboratory event:

**Response Required:** No

**Reason:** The authentication was intentionally generated as part of the security exercise.

For an equivalent production alert, the response decision would depend on:

- Account privilege
- Source system trust
- Destination criticality
- User behavior
- Authentication history
- Related alerts
- Business context

---

# 20. MITRE ATT&CK Relevance

### T1021.002 — SMB/Windows Admin Shares

SMB is a Windows remote-service protocol that can be involved in lateral movement.

This exercise demonstrated remote SMB authentication but did not demonstrate administrative share abuse.

### T1078 — Valid Accounts

The exercise used a valid domain account to authenticate remotely.

### T1550.002 — Pass the Hash

Pass-the-Hash is relevant to the broader Project 3 attack set and was separately demonstrated during Day 9.

Day 12 did not use Pass-the-Hash.

---

# 21. Investigation Limitations

The available evidence establishes successful remote authentication and SIEM detection.

It does not establish:

- Malicious intent
- Administrative access
- Privilege escalation
- Credential theft
- Remote command execution
- Persistence
- Full host compromise

Therefore, the investigation conclusion is intentionally limited to the activity supported by the evidence.

---

# 22. Attack-to-Detection Diagram

The Day 12 workflow is represented by the following diagram:

![Day 12 Lateral Authentication Detection Flow](../diagrams/Day12-Lateral-Movement-Detection-Flow.png)

Editable source:

`../diagrams/Day12-Lateral-Movement-Detection-Flow.drawio`

The workflow represented is:

**Remote Authentication → Windows Telemetry → Wazuh Detection → SOC Investigation**

---

# 23. Final Investigation Finding

### Finding

A controlled low-privileged domain authentication was successfully performed from Kali to WIN10-CLIENT through SMB.

### Observed Telemetry

Windows generated Event ID 4624 with:

- Logon Type 3
- NTLM authentication
- Source IP `192.168.159.129`
- Workstation `KALI`
- Account `bh_enum`

### SIEM Detection

Wazuh generated:

**Rule 92657 — Successful Remote Logon Detected**

**Severity: Level 6**

### Analyst Assessment

The event represented expected activity within the controlled cybersecurity laboratory.

### Security Conclusion

The exercise successfully demonstrated that remote Windows authentication can generate useful endpoint and SIEM telemetry suitable for SOC investigation.

---

# 24. Lessons Learned

### Remote authentication is an important detection surface

Valid credentials can be used to authenticate to remote systems, making authentication telemetry valuable to defenders.

### Event ID 4624 requires context

A successful logon alone does not establish malicious activity.

Logon Type, source IP, workstation, account, and authentication protocol provide additional investigative context.

### Detection and investigation are different

Wazuh identified the activity.

The analyst determined its significance.

### Baselines improve detection quality

The pre-activity baseline provided a reference point for interpreting the controlled authentication.

### Accurate scope matters

A professional investigation should distinguish:

**Observed remote authentication**

from:

**Confirmed lateral compromise**

This prevents overstatement and improves analytical credibility.

---

# 25. Final Case Conclusion

The Day 12 investigation successfully demonstrated the end-to-end detection and investigation of controlled remote SMB authentication.

The activity originated from:

**Kali — 192.168.159.129**

and authenticated to:

**WIN10-CLIENT — 192.168.159.133**

using:

**CORP\bh_enum**

The target generated:

**Windows Security Event ID 4624**

with:

**Logon Type 3 — Network**

and:

**NTLM / NTLM V2 authentication**

Wazuh detected the activity through:

**Rule 92657 — Successful Remote Logon Detected**

at:

**Level 6**

The investigation correlated the source, account, workstation, destination, authentication protocol, Windows event, and SIEM alert.

Because the activity was intentionally generated within the controlled lab, it was classified as expected security testing.

The investigation demonstrates the practical SOC workflow:

**Detect → Validate → Correlate → Investigate → Assess → Respond**

without overstating the evidence as proof of privilege escalation or full compromise.

---

# 26. Evidence Index

| # | Evidence | Purpose |
|---|---|---|
| 01 | [Day12-01-Windows10-4624-LateralMovement-Baseline.png](../screenshots/Day12/Day12-01-Windows10-4624-LateralMovement-Baseline.png) | Windows 4624 baseline |
| 02 | [Day12-02-Windows10-SMB-Session-Baseline.png](../screenshots/Day12/Day12-02-Windows10-SMB-Session-Baseline.png) | SMB session baseline |
| 03 | [Day12-03-Kali-to-Windows10-SMB-Connectivity-Baseline.png](../screenshots/Day12/Day12-03-Kali-to-Windows10-SMB-Connectivity-Baseline.png) | SMB connectivity validation |
| 04 | [Day12-04-Kali-SMB-Remote-Authentication.png](../screenshots/Day12/Day12-04-Kali-SMB-Remote-Authentication.png) | Controlled SMB authentication |
| 05 | [Day12-05-Windows10-4624-Lateral-Movement-Network-Logon.png](../screenshots/Day12/Day12-05-Windows10-4624-Lateral-Movement-Network-Logon.png) | Windows network logon telemetry |
| 06 | [Day12-06-Wazuh-Lateral-Movement-4624-Document-Details.png](../screenshots/Day12/Day12-06-Wazuh-Lateral-Movement-4624-Document-Details.png) | Wazuh alert correlation |
| 07 | [Day12-07-Wazuh-Rule-92657-Detection-Logic.png](../screenshots/Day12/Day12-07-Wazuh-Rule-92657-Detection-Logic.png) | Wazuh detection logic |
| 08 | [Day12-08-Wazuh-Rule-92657-Information.png](../screenshots/Day12/Day12-08-Wazuh-Rule-92657-Information.png) | Wazuh rule metadata |

---

# 27. Portfolio Significance

This investigation demonstrates practical experience with:

- Active Directory authentication
- SMB remote authentication
- Windows Security Event ID 4624
- Network Logon Type 3
- NTLM authentication
- Source IP correlation
- Workstation correlation
- Wazuh SIEM
- Detection-rule analysis
- SOC alert triage
- False-positive assessment
- Evidence-based investigation
- MITRE ATT&CK mapping
- Incident-response methodology

The strongest aspect of this investigation is the ability to connect the full security workflow:

**Controlled Attack Activity → Endpoint Telemetry → SIEM Detection → Evidence Correlation → Analyst Assessment**

This demonstrates the practical mindset expected from a junior SOC or Blue-Team analyst.