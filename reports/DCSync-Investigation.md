# DCSync Investigation Report

## Incident Title

**Potential Active Directory DCSync Credential Access**

---

## Executive Summary

A controlled DCSync attack was performed against the `CORP.LOCAL` Active Directory environment to evaluate the ability to detect replication-based credential access.

The attack originated from the Kali Linux system at `192.168.159.129` and targeted the Domain Controller `AD-DC` at `192.168.159.10`.

The attack successfully executed using Impacket `secretsdump` through the DRSUAPI replication mechanism. The Domain Controller subsequently generated Windows Security Event ID `4662` containing Control Access (`0x100`) and Active Directory replication-related extended rights.

The observed telemetry was correlated at both the Event Viewer and raw XML levels.

The activity was classified as **confirmed DCSync activity within the controlled lab environment**.

The investigation demonstrates how a SOC analyst can correlate attacker behavior with Windows Active Directory telemetry rather than relying on a single event or alert.

---

## Incident Classification

| Field | Value |
|---|---|
| Incident Type | Credential Access |
| Attack | DCSync |
| MITRE ATT&CK | T1003.006 |
| Severity | High |
| Status | Confirmed — Controlled Lab |
| Attack Source | `192.168.159.129` |
| Target | `AD-DC` (`192.168.159.10`) |
| Domain | `CORP.LOCAL` |
| Primary Event | Windows Security Event ID `4662` |
| Primary Detection Signal | Control Access `0x100` + replication rights |

---

## Investigation Objective

The investigation was designed to determine whether a controlled DCSync operation could be identified through Windows Active Directory security telemetry.

The investigation objectives were to:

1. Establish a normal Event 4662 baseline.
2. Enable appropriate Directory Service Access auditing.
3. Configure auditing for replication-related rights.
4. Execute a controlled DCSync operation.
5. Identify the resulting Windows Security telemetry.
6. Correlate the attack with Event ID 4662.
7. Validate the Control Access (`0x100`) field.
8. Identify replication-related extended rights.
9. Correlate the Event Viewer representation with raw XML.
10. Evaluate whether the observed behavior represented legitimate replication or suspicious credential access.
11. Document detection and response considerations.

---

## Environment

| System | Role | IP Address |
|---|---|---|
| AD-DC | Windows Server 2022 Domain Controller | `192.168.159.10` |
| WIN10-CLIENT | Domain-joined Windows endpoint | `192.168.159.133` |
| Kali Linux | Attack simulation system | `192.168.159.129` |
| Ubuntu / Wazuh | SIEM / detection platform | `192.168.159.130` |

### Active Directory Domain

`CORP.LOCAL`

---

## Initial Baseline

Before executing the attack, normal Event ID 4662 activity was examined.

This step was necessary because Active Directory generates legitimate directory-service and replication activity.

The investigation therefore established a baseline before attempting to classify DCSync-related telemetry.

### Evidence — Event 4662 Baseline

![Event 4662 Directory Service Access baseline](../screenshots/Day10/Day10-04-ADDC-Event4662-Directory-Service-Access-Baseline.png)

The baseline demonstrated that Event 4662 should not automatically be classified as malicious.

---

## Replication Activity Baseline

Replication-related Control Access activity was examined to understand normal Active Directory behavior.

### Evidence

![Replication Control Access baseline](../screenshots/Day10/Day10-05-ADDC-4662-Replication-Control-Access-Baseline.png)

This baseline was important for distinguishing expected replication activity from suspicious replication access.

---

## Audit Configuration

Directory Service Access auditing was enabled on the Domain Controller.

### Evidence

![Directory Service Access auditing](../screenshots/Day10/Day10-01-ADDC-Audit-Directory-Service-Access-Success.png)

The effective audit policy was then verified using `auditpol`.

### Evidence

![Audit policy verification](../screenshots/Day10/Day10-02-ADDC-AuditPol-Directory-Service-Access-Success.png)

Targeted auditing for Active Directory replication-related rights was subsequently configured.

### Evidence

![DCSync replication audit configuration](../screenshots/Day10/Day10-03-ADDC-DCSync-Audit-Rights-Configured.png)

---

## Legitimate Replication Comparison

Before analyzing the attack-generated event, legitimate replication telemetry was reviewed at the XML level.

### Evidence

![Legitimate replication XML baseline](../screenshots/Day10/Day10-06-ADDC-4662-Legitimate-Replication-Baseline-XML.png)

This provided a reference point for determining whether the post-attack event represented expected Active Directory behavior or suspicious credential-access activity.

---

## Attack Execution

A controlled DCSync operation was executed from Kali Linux against the Domain Controller.

### Attack Source

`192.168.159.129`

### Target

`AD-DC — 192.168.159.10`

### Tool

Impacket `secretsdump`

### Target Account

`Administrator`

The attack used the DRSUAPI method to request directory credential information through Active Directory replication.

The command successfully performed the DCSync operation.

### Evidence — Successful DCSync

![Successful DCSync execution](../screenshots/Day10/Day10-07-Kali-DCSync-SecretsDump-Success.png)

The successful execution provides the initial attack-side evidence required to correlate the subsequent Windows security telemetry.

> **Security note:** The original screenshot may contain credential hashes or cryptographic key material. Sensitive values must be redacted before publishing the evidence publicly.

---

## Windows Security Telemetry

Following the DCSync execution, the Domain Controller generated Windows Security Event ID `4662`.

The event contained characteristics associated with Active Directory replication access.

### Observed Fields

| Field | Observed Value |
|---|---|
| Event ID | `4662` |
| Subject User | `Administrator` |
| Subject Domain | `CORP` |
| Access Mask | `0x100` |
| Access Type | Control Access |
| Replication Rights | Present |
| Target System | `AD-DC` |

### Evidence — DCSync Event 4662

![DCSync Event 4662](../screenshots/Day10/Day10-08-ADDC-DCSync-4662-Control-Access-Replication.png)

The presence of `0x100` Control Access together with replication-related properties significantly increased the relevance of this event for DCSync investigation.

---

## Replication Rights Analysis

The Event 4662 Properties field contained replication-related extended-right identifiers.

The relevant rights include:

| Extended Right | GUID |
|---|---|
| DS-Replication-Get-Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-In-Filtered-Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

The observed event contained replication-related GUIDs including:

`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`

and

`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`

These properties provided critical evidence connecting the directory operation to Active Directory replication functionality.

---

## XML Correlation

The raw Windows Event 4662 XML was reviewed to validate the underlying event structure.

### Evidence

![DCSync Event 4662 XML correlation](../screenshots/Day10/Day10-09-ADDC-DCSync-4662-XML-Correlation.png)

The XML analysis confirmed the relevant telemetry fields associated with the operation.

This provided an additional layer of validation beyond the graphical Event Viewer representation.

---

## Timeline

| Stage | Activity |
|---|---|
| 1 | Directory Service Access auditing enabled |
| 2 | Effective audit policy verified |
| 3 | Replication-related auditing configured |
| 4 | Event 4662 baseline collected |
| 5 | Legitimate replication behavior reviewed |
| 6 | Kali initiated controlled DCSync |
| 7 | Impacket `secretsdump` successfully used DRSUAPI |
| 8 | Domain Controller generated Event 4662 |
| 9 | Event contained `0x100` Control Access |
| 10 | Replication-related GUIDs were identified |
| 11 | Raw XML was reviewed for correlation |
| 12 | Detection logic was validated independently |

---

## Attack-to-Evidence Correlation

The investigation established the following chain:

**Kali Linux — `192.168.159.129`**

↓

**Impacket `secretsdump`**

↓

**DRSUAPI replication request**

↓

**AD-DC — `192.168.159.10`**

↓

**Windows Security Event 4662**

↓

**Access Mask `0x100`**

↓

**Replication-related extended rights**

↓

**XML-level telemetry confirmation**

↓

**DCSync classification**

This multi-stage correlation provides stronger evidence than relying on a single event.

---

## Analyst Reasoning

The investigation did not classify Event 4662 as malicious solely because the event existed.

The analyst considered:

### 1. Event Type

Event ID `4662` indicates an Active Directory object operation when appropriate auditing is configured.

### 2. Access Mask

The observed `0x100` value represents Control Access.

### 3. Replication Rights

Replication-related extended rights were present in the event properties.

### 4. Account Context

The operation was associated with the `Administrator` account.

### 5. Attack Confirmation

The Kali-side evidence independently demonstrated successful DCSync execution immediately associated with the investigation.

### 6. Baseline Comparison

Legitimate replication activity had already been examined before the attack.

### Analyst Conclusion

The combination of:

- Successful DCSync execution
- Event ID `4662`
- Control Access `0x100`
- Replication-related extended rights
- Corresponding XML telemetry
- Controlled attack context

supports classification as **confirmed DCSync activity in the laboratory environment**.

---

## Wazuh Detection Analysis

The Domain Controller's Windows Security telemetry was successfully ingested and decoded by Wazuh.

A custom DCSync detection rule, **Rule `100005`**, was developed around the observed Event 4662 characteristics.

The detection logic evaluates:

- Event ID `4662`
- Access Mask `0x100`
- Replication-related extended-right information

The custom rule was independently validated using `wazuh-logtest`.

The investigation therefore distinguishes between:

**Telemetry confirmation:** Confirmed

**Detection logic validation:** Confirmed

**Live Rule 100005 alert:** Not claimed

This distinction ensures that the investigation report accurately represents the evidence collected during the lab.

---

## MITRE ATT&CK Mapping

### T1003.006 — OS Credential Dumping: DCSync

**Tactic:** Credential Access

DCSync abuses Active Directory replication functionality to obtain credential information from a Domain Controller.

The controlled attack performed during this investigation directly corresponds to this MITRE ATT&CK sub-technique.

---

## Impact Assessment

### Potential Impact

If this activity occurred in a production environment without authorization, potential impact could include:

- Exposure of domain credential material.
- Compromise of privileged accounts.
- Credential reuse.
- Kerberos-based attacks.
- Lateral movement.
- Persistence through compromised credentials.
- Broader Active Directory compromise.

The risk is particularly significant when DCSync is performed using highly privileged credentials or from an unauthorized endpoint.

### Lab Impact

In this controlled environment, the attack was intentionally executed for detection and investigation purposes.

No production systems or real organizational credentials were involved.

---

## False Positive Assessment

Potential legitimate sources of Event 4662 replication activity include:

- Domain Controllers
- Machine accounts
- Normal Active Directory replication
- Authorized administrative services
- Identity-management infrastructure
- Accounts legitimately assigned replication permissions

For this reason, Event 4662 should be evaluated using account, source, privilege, and behavioral context.

The baseline evidence collected during this exercise provides the foundation for reducing false positives.

---

## Recommended Response

If similar activity were identified in a production environment:

### Immediate Actions

1. Identify the account responsible for the replication operation.
2. Identify the source system.
3. Determine whether the operation was authorized.
4. Contain the suspected source endpoint if compromise is suspected.
5. Restrict or disable the affected account where appropriate.

### Investigation

6. Review Domain Controller Security logs.
7. Review authentication activity for the affected account.
8. Examine replication permissions.
9. Search for additional Event 4662 activity.
10. Investigate potential lateral movement.
11. Determine whether privileged credentials may have been exposed.

### Recovery

12. Rotate affected privileged credentials as appropriate.
13. Remove unauthorized replication permissions.
14. Validate Domain Controller security.
15. Continue monitoring for related credential-access activity.

---

## Detection Improvement Recommendations

The detection can be improved by correlating Event 4662 with additional context.

### Account-Based Filtering

Prioritize unexpected accounts performing replication-related operations.

### Source-Based Filtering

Differentiate known Domain Controllers from ordinary workstations.

### Privilege Analysis

Monitor changes to accounts receiving replication-related privileges.

### Behavioral Correlation

Correlate Event 4662 with:

- Event 4624
- Event 4672
- Event 4768
- Event 4769
- Event 4776

### Baseline-Aware Detection

Maintain a list of expected replication sources and accounts to reduce false positives.

---

## Evidence Gallery

### Audit Configuration

![Directory Service Access auditing](../screenshots/Day10/Day10-01-ADDC-Audit-Directory-Service-Access-Success.png)

![Audit policy verification](../screenshots/Day10/Day10-02-ADDC-AuditPol-Directory-Service-Access-Success.png)

![Replication audit rights configured](../screenshots/Day10/Day10-03-ADDC-DCSync-Audit-Rights-Configured.png)

### Baseline

![Event 4662 baseline](../screenshots/Day10/Day10-04-ADDC-Event4662-Directory-Service-Access-Baseline.png)

![Replication Control Access baseline](../screenshots/Day10/Day10-05-ADDC-4662-Replication-Control-Access-Baseline.png)

![Legitimate replication XML baseline](../screenshots/Day10/Day10-06-ADDC-4662-Legitimate-Replication-Baseline-XML.png)

### Attack

![Successful DCSync execution](../screenshots/Day10/Day10-07-Kali-DCSync-SecretsDump-Success.png)

### Detection Telemetry

![DCSync Event 4662 Control Access and replication rights](../screenshots/Day10/Day10-08-ADDC-DCSync-4662-Control-Access-Replication.png)

![DCSync Event 4662 XML correlation](../screenshots/Day10/Day10-09-ADDC-DCSync-4662-XML-Correlation.png)

---

## Final Analyst Verdict

**Classification:** Confirmed DCSync activity

**Confidence:** High

**Reasoning:**

The attacker-side execution successfully demonstrated DCSync behavior, while the Domain Controller generated Event ID 4662 containing Control Access (`0x100`) and replication-related extended rights. The event was further validated through raw XML analysis and compared against legitimate replication baselines.

The combined evidence supports the conclusion that the observed operation represented a successful DCSync attack within the controlled laboratory environment.

---

## Key SOC Takeaways

This investigation demonstrates the importance of correlating multiple pieces of evidence during Active Directory incident response.

The strongest indicators were not simply the existence of Event 4662, but the combination of:

- Confirmed attacker activity
- Event ID `4662`
- Control Access (`0x100`)
- Replication-related extended rights
- Subject account context
- Baseline comparison
- Raw XML validation
- SIEM detection engineering

The investigation also demonstrates a critical SOC principle:

**A security event becomes meaningful when it is interpreted in context.**

Legitimate Active Directory replication can generate similar telemetry. Effective detection therefore requires understanding normal behavior, identifying deviations, and correlating multiple sources of evidence before declaring malicious activity.

---

## Investigation Outcome

| Investigation Component | Result |
|---|---|
| Attack execution | Confirmed |
| DCSync behavior | Confirmed |
| Event 4662 | Confirmed |
| Control Access `0x100` | Confirmed |
| Replication rights | Confirmed |
| XML correlation | Confirmed |
| Baseline comparison | Completed |
| Wazuh ingestion / decoding | Confirmed |
| Custom Rule 100005 validation | Confirmed through controlled testing |
| MITRE ATT&CK | T1003.006 |
| Final Classification | Confirmed DCSync — Controlled Lab |