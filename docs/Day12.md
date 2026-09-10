# Day 12 — Lateral Authentication Detection & SOC Investigation

## Overview

Day 12 focused on demonstrating and detecting controlled remote authentication activity within the Active Directory lab.

The exercise simulated a low-privileged domain account authenticating remotely from the Kali analysis system to the Windows 10 endpoint over SMB. The resulting Windows Security telemetry was then validated and observed through Wazuh.

The investigation demonstrated the following workflow:

**Remote SMB Authentication → Windows Event 4624 → Network Logon Analysis → Wazuh Detection → SOC Investigation**

The exercise was intentionally limited to remote authentication and detection validation. It did not demonstrate administrative access, privilege escalation, credential extraction, or full host compromise.

---

## Objectives

The objectives of Day 12 were to:

- Understand lateral movement and remote authentication concepts.
- Establish a Windows authentication baseline.
- Establish an SMB session baseline.
- Validate connectivity between Kali and WIN10-CLIENT.
- Perform controlled remote SMB authentication using a low-privileged domain account.
- Identify the resulting Windows Security Event ID 4624.
- Analyze Logon Type 3 network authentication.
- Correlate the source IP and workstation information.
- Validate Wazuh visibility of the authentication.
- Analyze Wazuh Rule 92657.
- Establish a repeatable SOC investigation workflow.

---

# 1. Lab Environment

| Component | Configuration |
|---|---|
| Domain | `CORP.LOCAL` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Target Endpoint | `WIN10-CLIENT` |
| Target IP | `192.168.159.133` |
| Source System | Kali Linux |
| Source IP | `192.168.159.129` |
| Account Used | `bh_enum` |
| Protocol | SMB |
| Destination Port | TCP/445 |
| Windows Event | 4624 |
| Logon Type | 3 — Network |
| Authentication | NTLM / NTLM V2 |
| SIEM | Wazuh |
| Wazuh Rule | 92657 |
| Wazuh Severity | Level 6 |

---

# 2. Lateral Movement Concept

Lateral movement describes an attacker's attempt to move from one system or security context to another within an environment after obtaining or abusing access.

A common Windows example is remote authentication to another host using valid credentials.

For this controlled exercise, the activity was limited to:

**Kali**
→ **SMB / TCP 445**
→ **WIN10-CLIENT**
→ **Remote domain authentication**

The objective was to generate and investigate the authentication telemetry rather than perform privileged actions on the target.

---

# 3. Windows 4624 Baseline

Before generating the controlled authentication event, recent Windows Security Event ID 4624 activity was reviewed.

Event ID 4624 represents a successful account logon.

The baseline established that successful authentication events were already present on the endpoint before the controlled test.

### Evidence

![Windows 4624 Baseline](../screenshots/Day12/Day12-01-Windows10-4624-LateralMovement-Baseline.png)

**Evidence:** `Day12-01-Windows10-4624-LateralMovement-Baseline.png`

---

# 4. SMB Session Baseline

The existing SMB session state on WIN10-CLIENT was checked before the controlled activity.

No active SMB sessions were returned at the time of the baseline check.

This established a clean pre-activity state for the target endpoint.

### Evidence

![Windows SMB Session Baseline](../screenshots/Day12/Day12-02-Windows10-SMB-Session-Baseline.png)

**Evidence:** `Day12-02-Windows10-SMB-Session-Baseline.png`

---

# 5. Kali-to-Windows SMB Connectivity

Before performing authentication, connectivity from Kali to the target SMB service was validated.

The target was confirmed as:

`192.168.159.133:445`

TCP/445 was reachable and reported as open.

The ICMP ping test was not successful, but this did not prevent the SMB connection because ICMP and TCP/445 are separate protocols.

### Evidence

![Kali to Windows SMB Connectivity](../screenshots/Day12/Day12-03-Kali-to-Windows10-SMB-Connectivity-Baseline.png)

**Evidence:** `Day12-03-Kali-to-Windows10-SMB-Connectivity-Baseline.png`

---

# 6. Controlled SMB Remote Authentication

A controlled SMB authentication was performed from Kali using the dedicated low-privileged `bh_enum` domain account.

The authentication targeted the Windows 10 endpoint through the SMB IPC$ share.

The authentication successfully established an SMB session.

### Evidence

![Kali SMB Remote Authentication](../screenshots/Day12/Day12-04-Kali-SMB-Remote-Authentication.png)

**Evidence:** `Day12-04-Kali-SMB-Remote-Authentication.png`

This demonstrated the remote authentication component of the lateral-movement scenario.

---

# 7. Windows Security Event 4624

Following the successful SMB authentication, the Windows Security log was examined for the resulting successful logon event.

The relevant event contained the following characteristics:

- Account: `bh_enum`
- Domain: `CORP`
- Logon Type: `3`
- Authentication Package: `NTLM`
- NTLM Package: `NTLM V2`
- Source IP: `192.168.159.129`
- Workstation: `KALI`

Logon Type 3 represents a network logon and is consistent with remote network authentication such as SMB.

### Evidence

![Windows 4624 Lateral Movement Network Logon](../screenshots/Day12/Day12-05-Windows10-4624-Lateral-Movement-Network-Logon.png)

**Evidence:** `Day12-05-Windows10-4624-Lateral-Movement-Network-Logon.png`

---

# 8. Wazuh Detection

The corresponding Windows authentication telemetry was visible in Wazuh.

Wazuh generated:

**Rule 92657 — Successful Remote Logon Detected**

with:

**Severity: Level 6**

The alert contained the important authentication fields needed for SOC investigation.

### Evidence

![Wazuh Lateral Movement 4624 Details](../screenshots/Day12/Day12-06-Wazuh-Lateral-Movement-4624-Document-Details.png)

**Evidence:** `Day12-06-Wazuh-Lateral-Movement-4624-Document-Details.png`

---

# 9. Wazuh Authentication Telemetry

The Wazuh event provided the following important correlation fields:

| Field | Observed Value |
|---|---|
| Agent | `WIN10-CLIENT` |
| Agent IP | `192.168.159.133` |
| Target User | `bh_enum` |
| Target Domain | `CORP` |
| Source IP | `192.168.159.129` |
| Workstation | `KALI` |
| Event ID | `4624` |
| Logon Type | `3` |
| Authentication | `NTLM` |
| NTLM Version | `NTLM V2` |
| Logon Process | `NtLmSsp` |

This provided sufficient context to distinguish the event from a normal local interactive logon.

---

# 10. Rule 92657 Detection Logic

The Wazuh Rule 92657 definition was examined to understand why the authentication generated an alert.

The rule is associated with successful remote authentication activity and uses the Windows event telemetry to identify remote logon characteristics.

The rule details showed:

- Rule ID: `92657`
- Level: `6`
- Parent Rule: `92652`
- Group: `authentication_success`
- Group: `win_evt_channel`
- Group: `windows`

The rule description identifies successful remote logon activity and advises analysts to validate the workstation and authentication context.

### Evidence

![Wazuh Rule 92657 Detection Logic](../screenshots/Day12/Day12-07-Wazuh-Rule-92657-Detection-Logic.png)

**Evidence:** `Day12-07-Wazuh-Rule-92657-Detection-Logic.png`

---

# 11. Wazuh Rule Information

Additional Rule 92657 information confirmed:

- Rule ID: `92657`
- Severity Level: `6`
- Ruleset path: `ruleset/rules`
- Rule file: `0840-win_event_channel.xml`
- Authentication-related rule grouping
- Lateral-movement context in the rule's MITRE mapping

### Evidence

![Wazuh Rule 92657 Information](../screenshots/Day12/Day12-08-Wazuh-Rule-92657-Information.png)

**Evidence:** `Day12-08-Wazuh-Rule-92657-Information.png`

---

# 12. Attack-to-Detection Correlation

The complete activity can be represented as:

**Kali**
`192.168.159.129`

↓

**SMB / TCP 445**

↓

**WIN10-CLIENT**
`192.168.159.133`

↓

**Remote Authentication**

↓

**Windows Security Event 4624**

↓

**Logon Type 3 — Network**

↓

**NTLM / NTLM V2**

↓

**Wazuh Rule 92657**

↓

**Level 6 Successful Remote Logon Detection**

↓

**SOC Investigation**

This correlation demonstrates how an authentication activity can be traced from the source system through endpoint telemetry into the SIEM.

---

# 13. SOC Investigation Workflow

A SOC analyst receiving Rule 92657 should not automatically classify the event as malicious.

The recommended workflow is:

### 1. Validate

Confirm:

- Account
- Source IP
- Destination host
- Event ID
- Logon Type
- Authentication protocol
- Workstation

### 2. Correlate

Compare the event with:

- Known administrator activity
- Expected workstation relationships
- Recent authentication events
- Other Windows Security events
- Existing alerts

### 3. Investigate

Determine:

- Why the account authenticated remotely.
- Whether the source system is authorized.
- Whether the user normally accesses the target.
- Whether similar authentication occurred elsewhere.
- Whether suspicious activity occurred before or after the logon.

### 4. Assess

Determine whether the event represents:

- Legitimate administration
- Expected remote access
- Security testing
- Suspicious authentication
- Potential credential abuse

### 5. Respond

If unauthorized:

- Investigate the account.
- Review additional authentication activity.
- Restrict or disable compromised credentials when appropriate.
- Investigate the source host.
- Escalate according to SOC procedures.

---

# 14. False Positive Considerations

Successful remote logons are not inherently malicious.

Potential legitimate causes include:

- Remote administration
- File sharing
- IT support activity
- Domain management
- Authorized service activity
- Administrative troubleshooting

Therefore, Rule 92657 should be treated as an **investigation trigger**, not automatic proof of compromise.

Useful context includes:

- Source workstation
- Source IP
- Account role
- Authentication protocol
- Logon type
- Time of activity
- Expected administrative behavior
- Related alerts

---

# 15. Detection Assessment

The Day 12 detection demonstrates that Wazuh can provide useful visibility into successful remote Windows authentication.

The strongest detection characteristics observed were:

- Successful authentication
- Remote source
- Network Logon Type 3
- NTLM authentication
- Source IP visibility
- Workstation visibility
- Account visibility
- SIEM rule correlation

This creates a practical starting point for identifying suspicious lateral-authentication activity.

---

# 16. Limitations

This exercise intentionally demonstrates **remote authentication and detection**, not complete lateral compromise.

The evidence does not establish:

- Administrative access
- Privilege escalation
- Command execution on the target
- Credential extraction
- Persistence
- Full host compromise

The correct security conclusion is therefore:

> A controlled remote SMB authentication was successfully performed and generated observable Windows and Wazuh telemetry suitable for SOC investigation.

---

# 17. Diagram

The Day 12 attack-to-detection workflow is represented in the following architecture diagram:

![Day 12 Lateral Authentication Detection Flow](../diagrams/Day12-Lateral-Movement-Detection-Flow.png)

**Editable source:** `../diagrams/Day12-Lateral-Movement-Detection-Flow.drawio`

The diagram represents:

**Remote Authentication → Windows Telemetry → Wazuh Detection → SOC Analyst Workflow**

---

# 18. MITRE ATT&CK Relevance

The exercise is relevant to the following ATT&CK concepts:

### T1078 — Valid Accounts

The controlled exercise used a valid domain account to authenticate to a remote system.

### T1021.002 — SMB/Windows Admin Shares

The authentication occurred through SMB infrastructure. The exercise focused on the authentication component and did not demonstrate administrative share abuse.

### T1550.002 — Pass the Hash

This technique is relevant to the broader Project 3 attack set, particularly the separate Day 9 Pass-the-Hash investigation. Day 12 itself did not use a pass-the-hash technique.

The distinction is important: **Day 12 demonstrates remote authentication detection, while Day 9 demonstrates Pass-the-Hash.**

---

# 19. Key Lessons

### Remote authentication is valuable SOC telemetry

A successful remote logon can provide important information about account usage and source systems.

### Logon Type matters

Event ID 4624 alone is not enough.

Logon Type 3 provides important context indicating network-based authentication.

### Source context matters

The combination of:

`bh_enum + 192.168.159.129 + KALI + Logon Type 3 + NTLM`

provides significantly more investigative value than simply seeing a successful logon.

### SIEM alerts require investigation

Rule 92657 identifies activity worth reviewing, but the analyst must determine whether the activity is expected or suspicious.

### Detection should be evidence-driven

The strongest investigation combines:

**Attack Activity + Windows Telemetry + Source Context + SIEM Detection + Analyst Validation**

---

# 20. Day 12 Final Assessment

Day 12 successfully demonstrated a controlled remote authentication scenario from Kali to WIN10-CLIENT using a low-privileged domain account.

The activity generated Windows Security Event ID 4624 with:

- Logon Type 3
- NTLM authentication
- Source IP `192.168.159.129`
- Workstation `KALI`
- Target account `bh_enum`

Wazuh subsequently detected the activity through:

**Rule 92657 — Successful Remote Logon Detected**

at **Level 6**.

The resulting telemetry provided sufficient context for a SOC analyst to validate, correlate, investigate, assess, and respond to the activity.

The exercise therefore demonstrates the complete defensive workflow:

**Remote Authentication → Endpoint Telemetry → SIEM Detection → SOC Investigation**

while maintaining an accurate distinction between **remote authentication detection** and claims of full lateral compromise.

---

# 21. Evidence Index

| # | Evidence | Purpose |
|---|---|---|
| 01 | [Day12-01-Windows10-4624-LateralMovement-Baseline.png](../screenshots/Day12/Day12-01-Windows10-4624-LateralMovement-Baseline.png) | Windows 4624 baseline |
| 02 | [Day12-02-Windows10-SMB-Session-Baseline.png](../screenshots/Day12/Day12-02-Windows10-SMB-Session-Baseline.png) | SMB session baseline |
| 03 | [Day12-03-Kali-to-Windows10-SMB-Connectivity-Baseline.png](../screenshots/Day12/Day12-03-Kali-to-Windows10-SMB-Connectivity-Baseline.png) | SMB connectivity validation |
| 04 | [Day12-04-Kali-SMB-Remote-Authentication.png](../screenshots/Day12/Day12-04-Kali-SMB-Remote-Authentication.png) | Controlled remote authentication |
| 05 | [Day12-05-Windows10-4624-Lateral-Movement-Network-Logon.png](../screenshots/Day12/Day12-05-Windows10-4624-Lateral-Movement-Network-Logon.png) | Windows network logon telemetry |
| 06 | [Day12-06-Wazuh-Lateral-Movement-4624-Document-Details.png](../screenshots/Day12/Day12-06-Wazuh-Lateral-Movement-4624-Document-Details.png) | Wazuh event correlation |
| 07 | [Day12-07-Wazuh-Rule-92657-Detection-Logic.png](../screenshots/Day12/Day12-07-Wazuh-Rule-92657-Detection-Logic.png) | Detection logic |
| 08 | [Day12-08-Wazuh-Rule-92657-Information.png](../screenshots/Day12/Day12-08-Wazuh-Rule-92657-Information.png) | Rule metadata and severity |

---

# 22. Portfolio Significance

Day 12 demonstrates practical experience with:

- Windows authentication telemetry
- SMB remote authentication
- Active Directory domain accounts
- Windows Security Event ID 4624
- Logon Type analysis
- NTLM authentication analysis
- Source IP correlation
- Workstation correlation
- Wazuh SIEM
- Wazuh rule analysis
- SOC alert triage
- Detection validation
- False-positive assessment
- Incident investigation methodology
- MITRE ATT&CK mapping

The most important takeaway is that the project demonstrates more than performing an attack.

It demonstrates the defensive workflow:

**Generate controlled activity → collect telemetry → identify the security event → correlate context → validate SIEM detection → assess risk → determine appropriate response.**