# Detection Coverage Matrix

## Project 3 — Active Directory Attack & Detection Lab

## 1. Overview

This document provides a project-wide view of the detection and investigation coverage implemented throughout the Active Directory Attack & Detection Lab.

The matrix connects:

**Attack / Activity → Telemetry → Detection Logic → SIEM Rule → MITRE ATT&CK → Validation → Investigation**

The purpose of this document is to provide a single SOC-oriented view of the security monitoring capabilities demonstrated in the project.

> **Scope Note:** Not every activity in this project is an event-based SIEM detection. BloodHound, for example, provides identity and attack-path analysis rather than a traditional Windows event detection. Detection status is therefore described according to what was actually demonstrated and documented.

---

# 2. Detection Coverage Summary

| # | Attack / Security Activity | Primary Telemetry | Detection Focus | Wazuh Rule | MITRE ATT&CK | Validation Status | Investigation |
|---|---|---|---|---|---|---|---|
| 1 | Kerberoasting | Windows Security Event 4769 | Suspicious Kerberos service-ticket requests, including RC4 and anomalous service-account activity | Not specified in detection document | T1558.003 — Kerberoasting | Detection logic and lab telemetry validated | Completed |
| 2 | NTLM Unexpected Source | Windows Security Events 4624 + 4776 | Successful Type 3 NTLM authentication from an unexpected source with credential-validation correlation | Not specified in detection document | T1078; T1021.002 | Correlation logic and lab telemetry validated | Completed |
| 3 | AS-REP Roasting | Windows Security Event 4768 | Successful Kerberos authentication request with Pre-Authentication Type 0 | Not specified in detection document | T1558.004 — AS-REP Roasting | Detection logic and lab telemetry validated | Completed |
| 4 | Pass-the-Hash | Windows Security Events 4624 + 4776 | Suspicious remote NTLM authentication and credential-validation correlation | 92652 | T1550.002 — Pass the Hash; T1078 — Valid Accounts | Wazuh detection validated | Completed |
| 5 | DCSync | Windows Security Event 4662 | Control Access with Active Directory replication-related extended rights | 100005 | T1003.006 — DCSync | Custom rule independently validated with `wazuh-logtest`; live Rule 100005 alert not claimed | Completed |
| 6 | BloodHound Attack Path | Active Directory identity/group relationships | Identification of privilege-escalation paths through nested group membership | Not applicable | T1078 — Valid Accounts | Attack path successfully demonstrated, then removed and revalidated | Completed |
| 7 | Lateral Authentication / SMB | Windows Security Event 4624 | Successful remote network authentication using SMB/NTLM | 92657 | T1021.002 — SMB/Windows Admin Shares; T1078 — Valid Accounts | Wazuh detection validated | Completed |

---

# 3. Attack-to-Telemetry Correlation

## 3.1 Kerberoasting

**Attack:** Kerberoasting

**Primary Event:** Windows Security Event ID `4769`

**Detection Concept:**

- Identify successful Kerberos service-ticket requests.
- Examine service-account usage.
- Identify RC4 encryption (`0x17`) where relevant.
- Compare ticket activity against normal service-account behavior.
- Use request volume and account context to increase detection confidence.

**MITRE ATT&CK:**

`T1558.003 — Kerberoasting`

**Detection Status:**

Detection logic and Windows Event 4769 telemetry were demonstrated and documented.

**Investigation Status:**

Completed.

---

## 3.2 NTLM Unexpected Source

**Activity:** Unexpected NTLM Authentication

**Primary Events:**

- `4624` — Successful Logon
- `4776` — Credential Validation

**Detection Concept:**

Identify successful Type 3 NTLM authentication for a domain account when the authentication originates from an unexpected workstation or source IP.

Detection confidence increases when Event 4776 confirms successful credential validation for the same account and authentication window.

**MITRE ATT&CK:**

- `T1078 — Valid Accounts`
- `T1021.002 — SMB/Windows Admin Shares`

**Detection Status:**

Correlation logic and controlled telemetry were validated.

**Investigation Status:**

Completed.

---

## 3.3 AS-REP Roasting

**Attack:** AS-REP Roasting

**Primary Event:** Windows Security Event ID `4768`

**Key Detection Condition:**

`Pre-Authentication Type = 0`

Additional context includes:

- Successful authentication request
- Account identity
- Client IP
- Encryption type
- Baseline comparison

Event 4768 alone is not sufficient to identify AS-REP Roasting. The absence of Kerberos pre-authentication provides the more meaningful behavioral signal.

**MITRE ATT&CK:**

`T1558.004 — AS-REP Roasting`

**Detection Status:**

Detection logic and controlled Event 4768 telemetry were validated.

**Investigation Status:**

Completed.

---

## 3.4 Pass-the-Hash

**Attack:** Pass-the-Hash

**Primary Events:**

- `4624` — Successful Logon
- `4776` — Credential Validation

**Wazuh Detection Chain:**

`Rule 92651 → Rule 92652`

**Primary Wazuh Rule:**

`92652 — NTLM Remote Logon`

**Detection Concept:**

Identify suspicious remote NTLM authentication and correlate it with authentication-validation telemetry.

Relevant context includes:

- Logon Type 3
- NTLM authentication
- Source IP
- Target account
- Remote authentication
- Event 4776 correlation

**MITRE ATT&CK:**

- `T1550.002 — Pass the Hash`
- `T1078 — Valid Accounts`

**Detection Status:**

Wazuh Rule 92652 detection was validated during the controlled Pass-the-Hash exercise.

**Investigation Status:**

Completed.

---

## 3.5 DCSync

**Attack:** DCSync

**Primary Event:** Windows Security Event ID `4662`

**Detection Concept:**

Identify Active Directory operations involving:

- Control Access
- Replication-related extended rights
- Suspicious account context
- Source/system context
- Authentication context
- Deviation from the legitimate Active Directory replication baseline

**Custom Wazuh Rule:**

`100005`

**MITRE ATT&CK:**

`T1003.006 — DCSync`

**Validation Status:**

The controlled DCSync operation successfully generated Event 4662 containing replication-related directory access.

The custom Rule 100005 detection logic was independently validated using `wazuh-logtest`.

**Important Detection Qualification:**

Live Rule 100005 alert generation is **not claimed**.

This distinction is maintained to ensure that the project documentation accurately represents the validation performed.

**Investigation Status:**

Completed.

---

## 3.6 BloodHound Attack-Path Analysis

**Activity:** Active Directory Attack-Path Discovery

**Primary Data Source:**

Active Directory identity, group-membership, and relationship data.

**Detection / Analysis Concept:**

Identify potentially dangerous privilege relationships such as:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

The controlled attack path was created, collected, analyzed, and subsequently remediated.

After remediation, the attack path was no longer present.

**MITRE ATT&CK Context:**

`T1078 — Valid Accounts`

**Detection Type:**

Identity / attack-path analysis rather than traditional Windows Event/SIEM detection.

**Validation Status:**

- Baseline path: Not Found
- Controlled attack path: Successfully identified
- Remediation: Completed
- Post-remediation path: Not Found

**Investigation Status:**

Completed.

---

## 3.7 Lateral Authentication / SMB

**Activity:** Controlled Remote SMB Authentication

**Primary Event:** Windows Security Event ID `4624`

**Protocol:**

SMB over TCP/445

**Wazuh Rule:**

`92657 — Successful Remote Logon Detected`

**Severity:**

Level 6

**Detection Concept:**

Identify successful remote network authentication and provide an investigation trigger for the SOC analyst.

Relevant telemetry included:

- Account
- Source IP
- Workstation
- Destination endpoint
- Logon Type
- Authentication protocol
- Windows Event ID

Observed authentication:

- Account: `CORP\bh_enum`
- Source: `192.168.159.129`
- Target: `WIN10-CLIENT`
- Destination: `192.168.159.133`
- Logon Type: `3 — Network`
- Authentication: `NTLM / NTLM V2`
- Workstation: `KALI`

**MITRE ATT&CK Context:**

- `T1021.002 — SMB/Windows Admin Shares`
- `T1078 — Valid Accounts`

The detection documentation also contains contextual references to `T1550.002 — Pass the Hash`, but Day 12 itself used valid credentials and did **not** demonstrate Pass-the-Hash.

**Detection Status:**

Wazuh Rule 92657 was successfully validated.

**Investigation Status:**

Completed.

---

# 4. Detection Validation Matrix

| Detection | Attack Executed | Windows Telemetry Observed | Detection Logic Validated | Wazuh Alert Validated | Investigation Completed |
|---|---:|---:|---:|---:|---:|
| Kerberoasting | Yes | Yes — 4769 | Yes | Not specified | Yes |
| NTLM Unexpected Source | Yes | Yes — 4624 + 4776 | Yes | Not specified | Yes |
| AS-REP Roasting | Yes | Yes — 4768 | Yes | Not specified | Yes |
| Pass-the-Hash | Yes | Yes — 4624 + 4776 | Yes | Yes — Rule 92652 | Yes |
| DCSync | Yes | Yes — 4662 | Yes | Rule 100005 independently validated with `wazuh-logtest` | Yes |
| BloodHound | Yes | AD relationship data | Yes — attack-path analysis | Not applicable | Yes |
| Lateral Authentication | Yes | Yes — 4624 | Yes | Yes — Rule 92657 | Yes |

---

# 5. MITRE ATT&CK Coverage

| MITRE Technique | Technique Name | Project Coverage |
|---|---|---|
| T1558.003 | Kerberoasting | Demonstrated and investigated |
| T1558.004 | AS-REP Roasting | Demonstrated and investigated |
| T1550.002 | Pass the Hash | Demonstrated and investigated |
| T1003.006 | DCSync | Demonstrated and investigated |
| T1078 | Valid Accounts | Covered across authentication and attack-path scenarios |
| T1021.002 | SMB/Windows Admin Shares | Covered through remote SMB authentication |

The project therefore demonstrates coverage across:

- Credential access
- Kerberos abuse
- NTLM authentication
- Credential replay
- Active Directory replication abuse
- Valid-account abuse
- Remote authentication
- Identity-based attack-path analysis

---

# 6. Detection Engineering Principles Demonstrated

## 6.1 Event IDs Are Not Automatically Malicious

Several Windows events used in this project can occur during legitimate operations.

Examples include:

- Event 4624
- Event 4768
- Event 4769
- Event 4776
- Event 4662

The project therefore emphasizes contextual detection rather than simply alerting on the presence of an event ID.

---

## 6.2 Baseline Before Detection

The project repeatedly establishes normal activity before evaluating suspicious behavior.

This is particularly important for:

- Kerberos authentication
- NTLM authentication
- Active Directory replication
- Remote logons
- SMB sessions

Baselines provide the context required to reduce false positives.

---

## 6.3 Correlation Improves Detection Confidence

The project demonstrates correlation between multiple telemetry sources.

Examples:

**4624 + 4776**

for suspicious NTLM authentication.

**4662 + replication rights + account/source context**

for DCSync analysis.

**4768 + Pre-Authentication Type 0**

for AS-REP Roasting.

**4769 + RC4 + service-account context**

for Kerberoasting analysis.

---

# 7. False-Positive Considerations

| Detection | Potential Legitimate Activity |
|---|---|
| Event 4769 / Kerberoasting | Normal Kerberos service-ticket requests |
| Event 4768 / AS-REP Roasting | Normal Kerberos authentication requests |
| Event 4624 / NTLM | Legitimate network authentication |
| Event 4776 | Normal credential validation |
| Event 4662 / DCSync | Legitimate Active Directory operations and replication |
| Rule 92652 | Legitimate remote NTLM authentication |
| Rule 92657 | Legitimate remote logons and administration |
| BloodHound paths | Legitimate delegated permissions or approved administrative relationships |

A production SOC should therefore incorporate:

- Asset criticality
- User role
- Source workstation
- Account privilege
- Historical behavior
- Authentication frequency
- Business context
- Known administrative workflows

before escalating an alert.

---

# 8. Investigation Coverage

Every major attack scenario in the project includes an investigation component.

| Scenario | Investigation Focus |
|---|---|
| Kerberoasting | TGS request, service account, SPN, encryption, source |
| NTLM Unexpected Source | 4624/4776 correlation, account, source workstation |
| AS-REP Roasting | 4768, PreAuth Type 0, account, source, encryption |
| Pass-the-Hash | Remote NTLM authentication, 4624/4776 correlation |
| DCSync | 4662, replication rights, account context, baseline comparison |
| BloodHound | Privilege relationships, attack path, remediation |
| Lateral Authentication | SMB, 4624 Type 3, source, account, Wazuh alert |

---

# 9. Evidence Coverage

The project maintains dedicated evidence for each major scenario.

Evidence is organized under:

`/screenshots/DayXX/`

The evidence supports:

- Baseline establishment
- Attack execution
- Windows telemetry
- Wazuh telemetry
- Detection logic
- Investigation
- Remediation
- Validation

Detailed evidence indexes are maintained within the individual Day documentation and investigation reports.

---

# 10. Detection Coverage Strengths

### Strong Active Directory telemetry coverage

The project covers several high-value Windows Security events:

- `4624`
- `4662`
- `4768`
- `4769`
- `4776`

### Multi-stage detection workflow

The project demonstrates:

**Attack → Telemetry → Detection → Correlation → Investigation → Assessment**

rather than simply showing an attack tool output.

### Baseline-driven analysis

Legitimate behavior is explicitly considered before declaring activity suspicious.

### Detection validation

The project distinguishes between:

- Attack execution
- Telemetry generation
- Detection logic validation
- Live SIEM alert validation

This distinction improves the technical accuracy of the project.

### Identity-aware detection

BloodHound extends the project beyond traditional event monitoring by demonstrating how identity relationships can expose privilege-escalation paths.


---

# 11. SOC Detection Workflow

The project follows a repeatable SOC investigation model:

**1. Detect**

Identify suspicious or noteworthy telemetry.

↓

**2. Validate**

Confirm the event and determine whether the telemetry is genuine.

↓

**3. Correlate**

Connect account, source, destination, event, protocol, and related telemetry.

↓

**4. Baseline**

Compare the activity with expected behavior.

↓

**5. Investigate**

Determine whether the activity is authorized, suspicious, or malicious.

↓

**6. Assess**

Assign severity based on context and confidence.

↓

**7. Respond**

Recommend containment, credential protection, escalation, or closure.

↓

**8. Document**

Record evidence, findings, and lessons learned.

---

# 12. Overall Project Detection Maturity

| Capability | Assessment |
|---|---|
| Windows Event Collection | Strong |
| Active Directory Security Monitoring | Strong |
| Sysmon Visibility | Demonstrated |
| Wazuh SIEM Integration | Strong |
| Authentication Monitoring | Strong |
| Kerberos Monitoring | Strong |
| NTLM Monitoring | Strong |
| AD Replication Monitoring | Demonstrated |
| Identity Attack-Path Analysis | Demonstrated |
| Detection Engineering | Demonstrated |
| Baseline Analysis | Demonstrated |
| Event Correlation | Demonstrated |
| False-Positive Analysis | Demonstrated |
| Investigation Reporting | Strong |
| MITRE ATT&CK Mapping | Strong |
| Evidence Management | Strong |

---

# 13. Final Coverage Assessment

The completed project demonstrates a layered Active Directory defense model:

**Identity Layer**

→ Users, groups, privileges, and attack paths

**Authentication Layer**

→ Kerberos, NTLM, network authentication

**Endpoint Layer**

→ Windows Security Events and Sysmon

**Directory Layer**

→ Active Directory replication and object access

**SIEM Layer**

→ Wazuh ingestion and detection rules

**SOC Layer**

→ Correlation, investigation, severity assessment, and response

This layered approach demonstrates that the project is not limited to offensive attack execution.

It demonstrates the complete defensive lifecycle:

**Understand the Attack → Generate Telemetry → Detect the Behavior → Correlate Evidence → Investigate the Activity → Assess Risk → Remediate Where Applicable**

---

# 14. Portfolio Summary

The Project 3 detection coverage demonstrates practical experience with:

- Active Directory security monitoring
- Windows Security Event analysis
- Sysmon telemetry
- Wazuh SIEM
- Kerberos security
- NTLM authentication
- SMB remote authentication
- Credential-access detection
- DCSync detection
- Identity attack-path analysis
- Detection engineering
- Baseline development
- Event correlation
- False-positive analysis
- MITRE ATT&CK mapping
- SOC investigation methodology
- Evidence-based reporting

The project demonstrates a key SOC principle:

> **A security event becomes meaningful when it is placed into context.**

Rather than treating individual events as automatic indicators of compromise, the project combines telemetry, identity, source, destination, authentication behavior, baselines, and attack context to produce higher-confidence investigations.

---

# 15. Related Project Documentation

| Area | Documentation |
|---|---|
| Kerberoasting | `attacks/Kerberoasting.md` / `detections/Kerberoasting-4769.md` / `reports/Kerberoasting-Investigation.md` |
| NTLM | `attacks/NTLM-Unexpected-Source.md` / `detections/NTLM-Unexpected-Source-4624-4776.md` / `reports/NTLM-Investigation.md` |
| AS-REP Roasting | `attacks/ASREP-Roasting.md` / `detections/ASREP-Roasting-4768.md` / `reports/ASREP-Roasting-Investigation.md` |
| Pass-the-Hash | `attacks/Pass-the-Hash.md` / `detections/Pass-the-Hash-92652.md` / `reports/Pass-the-Hash-Investigation.md` |
| DCSync | `attacks/DCSync.md` / `detections/DCSync-4662.md` / `reports/DCSync-Investigation.md` |
| BloodHound | `attacks/BloodHound-Attack-Path-Analysis.md` / `detections/BloodHound-Attack-Path-Detection.md` / `reports/BloodHound-Attack-Path-Investigation.md` |
| Lateral Authentication | `attacks/Lateral-Movement-SMB.md` / `detections/Lateral-Movement-92657.md` / `reports/Lateral-Movement-Investigation.md` |

---

# 16. Final Statement

Project 3 provides end-to-end defensive visibility across multiple Active Directory attack techniques and authentication scenarios.

The strongest portfolio characteristic is the correlation between:

**Attack Activity**

→ **Windows / Active Directory Telemetry**

→ **Wazuh Detection**

→ **SOC Investigation**

→ **Evidence-Based Assessment**

The project therefore demonstrates practical Blue-Team and SOC capabilities rather than isolated penetration-testing exercises.