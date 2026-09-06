# Day 10 — DCSync Attack & Detection Engineering

## Overview

Day 10 focused on **DCSync**, an Active Directory credential-access technique that abuses directory replication functionality to request sensitive directory information from a Domain Controller.

The objective was to simulate DCSync in the controlled `CORP.LOCAL` environment, generate the associated Windows security telemetry, analyze Event ID `4662`, identify replication-related access, and develop detection logic around the observed behavior.

**MITRE ATT&CK:** T1003.006 — OS Credential Dumping: DCSync

**Tactic:** Credential Access

---

## Day 10 Objectives

- Understand the DCSync attack technique.
- Understand how Active Directory replication permissions relate to DCSync.
- Enable Directory Service Access auditing.
- Verify the effective audit policy.
- Configure auditing for replication-related rights.
- Establish a baseline for Event ID `4662`.
- Establish a legitimate replication baseline.
- Execute a controlled DCSync attack from Kali Linux.
- Confirm successful DCSync execution.
- Analyze Windows Security Event ID `4662`.
- Identify Control Access (`0x100`).
- Identify replication-related extended-right GUIDs.
- Correlate Event Viewer telemetry with raw XML.
- Develop DCSync detection logic.
- Validate the custom detection logic using Wazuh `wazuh-logtest`.
- Map the activity to MITRE ATT&CK T1003.006.

---

# 1. DCSync Theory

DCSync abuses the normal Active Directory replication mechanism.

Instead of directly accessing the Domain Controller's credential database, an attacker with sufficient replication privileges can request directory data through the same replication functionality used by Domain Controllers.

This makes DCSync particularly important for Blue Team monitoring because the underlying mechanism is legitimate Active Directory functionality.

The security problem is therefore not simply:

**"Was replication used?"**

The more important question is:

**"Who requested replication-related information, from where, and was that behavior expected?"**

---

# 2. Lab Environment

| System | Role | IP Address |
|---|---|---|
| AD-DC | Windows Server 2022 Domain Controller | `192.168.159.10` |
| WIN10-CLIENT | Domain-joined Windows endpoint | `192.168.159.133` |
| Kali Linux | Attack simulation system | `192.168.159.129` |
| Ubuntu / Wazuh | SIEM / detection platform | `192.168.159.130` |

### Active Directory Domain

`CORP.LOCAL`

---

# 3. Directory Service Access Auditing

The first stage of Day 10 was enabling Directory Service Access auditing on the Domain Controller.

This was required to generate the Windows security telemetry necessary for investigating Active Directory object access.

### Evidence

![Directory Service Access auditing enabled](../screenshots/Day10/Day10-01-ADDC-Audit-Directory-Service-Access-Success.png)

The effective audit policy was then verified using `auditpol`.

### Evidence

![Directory Service Access audit policy verification](../screenshots/Day10/Day10-02-ADDC-AuditPol-Directory-Service-Access-Success.png)

---

# 4. DCSync Replication Auditing

Targeted auditing for Active Directory replication-related rights was configured.

The purpose was to increase visibility into directory operations associated with replication functionality.

### Evidence

![DCSync replication audit rights configured](../screenshots/Day10/Day10-03-ADDC-DCSync-Audit-Rights-Configured.png)

---

# 5. Event 4662 Baseline

Before executing the attack, Windows Security Event ID `4662` activity was examined.

This baseline was important because Event 4662 can represent legitimate Active Directory operations.

A detection that simply alerts on every Event 4662 would create unnecessary noise.

### Evidence

![Event 4662 Directory Service Access baseline](../screenshots/Day10/Day10-04-ADDC-Event4662-Directory-Service-Access-Baseline.png)

---

# 6. Replication Control Access Baseline

Replication-related Control Access activity was reviewed to understand expected Active Directory behavior.

### Evidence

![Replication Control Access baseline](../screenshots/Day10/Day10-05-ADDC-4662-Replication-Control-Access-Baseline.png)

This established the need for contextual detection rather than treating all replication-related events as malicious.

---

# 7. Legitimate Replication XML Baseline

The underlying XML representation of legitimate replication-related telemetry was also reviewed.

### Evidence

![Legitimate replication XML baseline](../screenshots/Day10/Day10-06-ADDC-4662-Legitimate-Replication-Baseline-XML.png)

Reviewing the raw XML helped identify the underlying fields that could later be used for detection engineering and SIEM correlation.

---

# 8. DCSync Attack Simulation

A controlled DCSync attack was executed from the Kali Linux attacker system.

### Attack Source

`192.168.159.129`

### Target

`AD-DC — 192.168.159.10`

### Tool

Impacket `secretsdump`

### Target Account

`Administrator`

The attack successfully used the DRSUAPI replication mechanism to request credential-related directory information from the Domain Controller.

### Evidence

![Successful DCSync execution](../screenshots/Day10/Day10-07-Kali-DCSync-SecretsDump-Success.png)

> **Security note:** This evidence may contain credential hashes or cryptographic key material. Any public GitHub version must have sensitive values redacted.

---

# 9. Windows Event 4662 Detection Telemetry

Following the DCSync operation, the Domain Controller generated Windows Security Event ID `4662`.

The observed event contained:

- Event ID `4662`
- Subject account `Administrator`
- Subject domain `CORP`
- Access Mask `0x100`
- Control Access
- Replication-related extended rights

### Evidence

![DCSync Event 4662 Control Access and replication rights](../screenshots/Day10/Day10-08-ADDC-DCSync-4662-Control-Access-Replication.png)

The combination of Control Access and replication-related properties provided the primary detection signal for the simulated attack.

---

# 10. Replication Rights

The Event 4662 Properties field contained replication-related extended-right GUIDs.

Important DCSync detection GUIDs include:

| Replication Right | GUID |
|---|---|
| DS-Replication-Get-Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-In-Filtered-Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

The observed DCSync telemetry contained replication-related GUIDs associated with the operation.

---

# 11. XML Correlation

The raw XML representation of the DCSync-generated Event 4662 was reviewed.

This allowed the observed Event Viewer information to be correlated with the underlying Windows event fields.

### Evidence

![DCSync Event 4662 XML correlation](../screenshots/Day10/Day10-09-ADDC-DCSync-4662-XML-Correlation.png)

The XML analysis provided additional validation of:

- Event ID
- Subject account
- Access Mask
- Replication-related properties

---

# 12. Detection Engineering

The primary detection logic focused on the combination of:

**Event ID `4662`**

+

**Access Mask `0x100`**

+

**Replication-related extended rights**

This combination provides a stronger detection signal than Event 4662 alone.

A custom Wazuh detection rule, **Rule ID `100005`**, was developed around these characteristics.

The rule was independently validated using `wazuh-logtest`.

### Detection Status

| Detection Component | Status |
|---|---|
| Windows Event 4662 | Confirmed |
| Access Mask `0x100` | Confirmed |
| Replication-related GUIDs | Confirmed |
| Wazuh ingestion / decoding | Confirmed |
| Custom Rule `100005` | Created |
| Rule syntax | Validated |
| `wazuh-logtest` validation | Confirmed |
| Live Rule `100005` alert | Not claimed |

The distinction between telemetry confirmation and live alert generation is intentionally maintained to keep the project evidence accurate.

---

# 13. Attack-to-Detection Chain

The Day 10 exercise demonstrated the following attack-to-detection workflow:

**Kali Linux**

↓

**Impacket `secretsdump`**

↓

**DCSync / DRSUAPI request**

↓

**Active Directory Domain Controller**

↓

**Windows Security Event 4662**

↓

**Access Mask `0x100`**

↓

**Replication-related extended rights**

↓

**XML-level telemetry validation**

↓

**Detection engineering**

↓

**MITRE ATT&CK T1003.006**

---

# 14. MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| OS Credential Dumping: DCSync | T1003.006 | Credential Access |

DCSync is categorized under the Credential Access tactic because successful abuse can expose sensitive Active Directory credential material.

---

# 15. False-Positive Considerations

DCSync detection must account for legitimate Active Directory replication.

Potential legitimate activity can originate from:

- Domain Controllers
- Domain Controller machine accounts
- Authorized replication services
- Approved administrative infrastructure
- Accounts legitimately assigned replication permissions

Therefore, the detection should not simply alert on Event 4662.

Detection should consider:

- Subject account
- Source system
- Replication rights
- Expected Domain Controller behavior
- Account privileges
- Authentication context
- Historical baseline

---

# 16. Analyst Investigation Workflow

When potential DCSync activity is detected:

1. Identify the account performing the directory operation.
2. Confirm Event ID `4662`.
3. Confirm Access Mask `0x100`.
4. Inspect the Properties field for replication-related GUIDs.
5. Identify the source system where possible.
6. Determine whether the account legitimately requires replication permissions.
7. Compare the activity against the established baseline.
8. Correlate surrounding authentication events.
9. Search for additional activity from the same account or source.
10. Determine whether the activity represents legitimate replication or unauthorized credential access.

---

# 17. Security Impact

Successful DCSync can potentially expose sensitive Active Directory credential material.

Potential consequences include:

- Privileged account compromise
- Credential reuse
- Kerberos-based attacks
- Lateral movement
- Persistence
- Broader domain compromise

The risk is particularly significant when highly privileged accounts are involved.

---

# 18. Key Technical Findings

### Finding 1 — Directory Service Access auditing is required

Event 4662 visibility depends on appropriate Active Directory auditing and SACL configuration.

### Finding 2 — Event 4662 alone is insufficient

Normal Active Directory activity can also generate Event 4662.

### Finding 3 — Control Access provides important context

The observed `0x100` Access Mask represents Control Access and increases the relevance of the event when combined with replication rights.

### Finding 4 — Replication GUIDs strengthen detection

Replication-related extended rights provide additional context for identifying potential DCSync activity.

### Finding 5 — Baseline analysis is essential

Legitimate replication activity must be understood before deploying a production detection.

### Finding 6 — Raw XML improves detection engineering

Reviewing the underlying Windows event XML helps validate the fields used by SIEM detection logic.

---

# 19. Evidence Summary

| Evidence | Purpose |
|---|---|
| `Day10-01-ADDC-Audit-Directory-Service-Access-Success.png` | Directory Service Access auditing |
| `Day10-02-ADDC-AuditPol-Directory-Service-Access-Success.png` | Effective audit policy verification |
| `Day10-03-ADDC-DCSync-Audit-Rights-Configured.png` | Replication auditing configuration |
| `Day10-04-ADDC-Event4662-Directory-Service-Access-Baseline.png` | Event 4662 baseline |
| `Day10-05-ADDC-4662-Replication-Control-Access-Baseline.png` | Replication Control Access baseline |
| `Day10-06-ADDC-4662-Legitimate-Replication-Baseline-XML.png` | Legitimate replication XML baseline |
| `Day10-07-Kali-DCSync-SecretsDump-Success.png` | Successful DCSync execution |
| `Day10-08-ADDC-DCSync-4662-Control-Access-Replication.png` | DCSync Event 4662 telemetry |
| `Day10-09-ADDC-DCSync-4662-XML-Correlation.png` | Raw XML correlation |

---

# 20. Day 10 Outcome

| Area | Result |
|---|---|
| DCSync theory | Completed |
| Directory Service Access auditing | Completed |
| Audit policy verification | Completed |
| Replication auditing | Completed |
| Event 4662 baseline | Completed |
| Legitimate replication baseline | Completed |
| DCSync execution | Successful |
| Event 4662 generation | Confirmed |
| Control Access `0x100` | Confirmed |
| Replication rights | Confirmed |
| XML correlation | Completed |
| Wazuh ingestion / decoding | Confirmed |
| Custom detection rule | Created |
| Detection rule validation | Completed |
| MITRE mapping | T1003.006 |
| Investigation documentation | Completed |

---

# 21. Day 10 SOC Takeaway

Day 10 demonstrated the complete lifecycle of an Active Directory credential-access investigation:

**Attack → Windows Telemetry → Evidence Correlation → Detection Logic → MITRE Mapping → Investigation**

The key lesson is that effective SOC detection depends on understanding normal behavior before identifying abnormal behavior.

For DCSync, Event ID `4662` becomes significantly more valuable when combined with Control Access, replication-related extended rights, account context, source context, and an established Active Directory baseline.

The exercise therefore moves beyond simply executing an attack and demonstrates practical **Blue Team detection engineering and SOC investigation methodology**.