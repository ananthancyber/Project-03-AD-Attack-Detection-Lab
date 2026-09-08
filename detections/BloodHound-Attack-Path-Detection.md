# BloodHound Attack-Path Detection

## Detection Overview

This detection documents a **Blue-Team approach for identifying and investigating Active Directory privilege exposure caused by nested group membership**.

The Day 11 lab demonstrated how a low-privileged identity could become indirectly connected to a Tier Zero privileged group through:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

BloodHound was used to identify and visualize the relationship path.

From a SOC perspective, the important detection objective is not to treat BloodHound itself as an attack alert.

Instead, the finding should be used to identify **dangerous Active Directory relationships that require investigation and remediation**.

---

# 1. Detection Name

**Active Directory Privilege Exposure Through Nested Group Membership**

---

# 2. Detection Type

**Identity and Access Management / Active Directory Security**

---

# 3. Severity

**High**

### Severity Rationale

A low-privileged identity becoming indirectly connected to `Domain Admins` represents significant privilege exposure.

The risk is particularly high when the relationship provides an effective administrative privilege path toward Tier Zero assets.

---

# 4. Detection Objective

The objective is to identify and investigate:

- Unexpected nested membership involving privileged groups.
- Low-privileged users connected to administrative groups.
- Helpdesk or operational groups nested into privileged groups.
- Unexpected membership changes involving `Domain Admins`.
- Indirect privilege paths toward Tier Zero assets.
- Excessive administrative group inheritance.

The detection process combines:

**Active Directory group analysis + BloodHound attack-path analysis + Windows security telemetry**

---

# 5. Security Principle

Active Directory privilege should not be evaluated solely by looking at direct group membership.

For example:

`BH_ENUM`

may not directly belong to:

`Domain Admins`

but the following relationship can create indirect privilege exposure:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

Therefore:

**Direct membership ≠ Effective privilege exposure**

---

# 6. Lab Environment

| Component | Value |
|---|---|
| Domain | `corp.local` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Analysis Host | Kali Linux |
| BloodHound | Community Edition |
| Enumeration Account | `bh_enum` |
| Intermediate Group | `Helpdesk-Tier1` |
| Administrative Group | `IT-Admins` |
| Tier Zero Group | `Domain Admins` |
| Privileged Account | `Administrator` |

---

# 7. Detection Logic

A potential privilege-exposure condition exists when the following pattern is identified:

`Low-Privileged User → Non-Privileged Group → Administrative Group → Tier Zero Group`

The detection workflow should identify:

1. The starting identity.
2. Direct group memberships.
3. Nested group relationships.
4. Administrative group memberships.
5. Effective recursive membership.
6. Whether the final destination is a Tier Zero group or asset.

### Example

`BH_ENUM`

↓

`Helpdesk-Tier1`

↓

`IT-Admins`

↓

`Domain Admins`

This relationship should be treated as a **high-priority identity security finding**.

---

# 8. Baseline Validation

Before introducing the controlled scenario, the Active Directory environment was reviewed.

The domain and Domain Controller were identified and documented.

### Evidence

![Active Directory Domain Baseline](../screenshots/Day11/Day11-01-ADDC-Domain-Baseline.png)

---

# 9. Privileged Group Baseline

Existing privileged groups were reviewed before performing the controlled configuration.

The baseline established the expected privileged structure.

### Evidence

![Privileged Group Baseline](../screenshots/Day11/Day11-02-AD-Privileged-Groups-Baseline.png)

---

# 10. Low-Privilege Identity Baseline

The `bh_enum` account was intentionally maintained as a low-privileged identity.

The account did not have direct privileged-group membership.

### Evidence

![bh_enum Low Privilege Baseline](../screenshots/Day11/Day11-03-bh_enum-LowPrivilege-Baseline.png)

---

# 11. BloodHound Collection

BloodHound Python was used to collect Active Directory relationship data.

The collection provided visibility into:

- Users
- Groups
- Computers
- Domains
- OUs
- GPOs
- Containers
- Trust relationships

### Evidence

![BloodHound AD Collection](../screenshots/Day11/Day11-04-BloodHound-AD-Collection-Success.png)

---

# 12. Dataset Validation

The generated BloodHound collection was extracted and validated before ingestion.

### Evidence

![BloodHound Dataset Extracted](../screenshots/Day11/Day11-05-BloodHound-Collection-Dataset-Extracted.png)

---

# 13. BloodHound CE Analysis

The BloodHound Community Edition interface was used to perform graph-based Active Directory analysis.

### Evidence

![BloodHound CE](../screenshots/Day11/Day11-06-BloodHound-CE-Login.png)

---

# 14. Dataset Ingestion

The Active Directory dataset was successfully ingested into BloodHound CE.

### Evidence

![BloodHound Dataset Ingestion](../screenshots/Day11/Day11-07-BloodHound-AD-Dataset-Ingest-Complete.png)

---

# 15. Tier Zero Identification

The built-in `Administrator` account was analyzed within BloodHound.

The account was identified as a highly privileged Tier Zero identity.

This establishes why relationships leading toward the privileged administrative hierarchy require additional scrutiny.

### Evidence

![Administrator Tier Zero Analysis](../screenshots/Day11/Day11-08-BloodHound-Administrator-TierZero-Analysis.png)

---

# 16. Clean Baseline Path Analysis

The initial pathfinding query was:

**Source**

`BH_ENUM@CORP.LOCAL`

**Target**

`ADMINISTRATOR@CORP.LOCAL`

The initial result was:

**Path Not Found**

This established the clean baseline.

### Evidence

![Clean Baseline Path](../screenshots/Day11/Day11-09-BloodHound-No-Path-BH_ENUM-to-Administrator.png)

---

# 17. Controlled Security Configuration

For the controlled lab scenario, a temporary group named:

`Helpdesk-Tier1`

was introduced.

The purpose was to demonstrate how an otherwise low-privileged identity could become connected to privileged resources through nested membership.

---

# 18. Detection Condition — User to Intermediate Group

The `bh_enum` account was added to:

`Helpdesk-Tier1`

The resulting relationship was:

`BH_ENUM → Helpdesk-Tier1`

### Evidence

![bh_enum Helpdesk-Tier1 Membership](../screenshots/Day11/Day11-10-BH_ENUM-Helpdesk-Tier1-Membership.png)

---

# 19. Detection Condition — Intermediate Group to Administrative Group

The `Helpdesk-Tier1` group was nested into:

`IT-Admins`

The relationship became:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins`

This should be considered suspicious when the intermediate group does not have a documented business requirement to inherit administrative privileges.

### Evidence

![Helpdesk-Tier1 Nested into IT-Admins](../screenshots/Day11/Day11-11-IT-Admins-Helpdesk-Tier1-Nested-Group.png)

---

# 20. Updated BloodHound Collection

A fresh BloodHound collection was performed after the controlled group modification.

### Evidence

![Post-Misconfiguration Collection](../screenshots/Day11/Day11-12-BloodHound-Post-Misconfiguration-Collection.png)

---

# 21. Updated Dataset Ingestion

The updated Active Directory dataset was successfully ingested into BloodHound CE.

### Evidence

![Post-Misconfiguration Ingestion](../screenshots/Day11/Day11-13-BloodHound-Post-Misconfiguration-Ingest-Complete.png)

---

# 22. Detection Condition — Privileged Group Relationship

The controlled scenario was extended by nesting:

`IT-Admins`

into:

`Domain Admins`

The complete relationship became:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

This is the critical privilege-exposure condition.

### Evidence

![Domain Admins Nested Group](../screenshots/Day11/Day11-14-Domain-Admins-IT-Admins-Nested-Group.png)

---

# 23. Final Pre-Remediation Collection

A further BloodHound collection was performed to capture the complete controlled relationship state.

### Evidence

![Final BloodHound Collection](../screenshots/Day11/Day11-15-BloodHound-Final-Collection-Success.png)

---

# 24. Final Pre-Remediation Ingestion

The collected dataset was successfully ingested into BloodHound CE.

### Evidence

![Final BloodHound Ingestion](../screenshots/Day11/Day11-16-BloodHound-Final-Ingest-Complete.png)

---

# 25. Attack Path Detection

BloodHound pathfinding was used to analyze:

**Source**

`BH_ENUM@CORP.LOCAL`

**Target**

`DOMAIN ADMINS@CORP.LOCAL`

BloodHound identified:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

This is the primary detection finding.

### Detection Result

**Potential high-risk Active Directory privilege path identified.**

### Evidence

![BloodHound Attack Path](../screenshots/Day11/Day11-17-BloodHound-BH_ENUM-to-Domain-Admins-Attack-Path.png)

---

# 26. Relationship Validation

The attack path was decomposed into individual relationships.

## Relationship A

`BH_ENUM → Helpdesk-Tier1`

### Evidence

![bh_enum to Helpdesk-Tier1](../screenshots/Day11/Day11-20-BloodHound-BH_ENUM-to-Helpdesk-Tier1-MemberOf.png)

---

## Relationship B

`Helpdesk-Tier1 → IT-Admins`

### Evidence

![Helpdesk-Tier1 to IT-Admins](../screenshots/Day11/Day11-19-BloodHound-Helpdesk-Tier1-to-IT-Admins-MemberOf.png)

---

## Relationship C

`IT-Admins → Domain Admins`

### Evidence

![IT-Admins to Domain Admins](../screenshots/Day11/Day11-18-BloodHound-IT-Admins-to-Domain-Admins-MemberOf.png)

---

# 27. Effective Privilege Validation

BloodHound's graph relationship was independently validated from Active Directory.

Recursive group membership analysis demonstrated that the controlled nested relationships resulted in `bh_enum` being effectively represented within the `Domain Admins` hierarchy.

This provides stronger evidence than relying solely on the BloodHound visualization.

### Evidence

![Effective Domain Admins Membership](../screenshots/Day11/Day11-21-BH_ENUM-Effective-Domain-Admins-Membership.png)

---

# 28. Detection Assessment

### Finding

**Indirect privilege escalation exposure through nested Active Directory group membership**

### Severity

**High**

### Confidence

**High**

### Source

BloodHound graph analysis + Active Directory validation

### Attack Path

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

### Security Impact

The relationship creates an indirect privilege path from a low-privileged identity to a highly privileged Active Directory group.

In a production environment, an equivalent configuration could significantly increase the impact of a compromised low-privileged account.

---

# 29. Recommended SOC Investigation

When a similar finding is identified in production, the analyst should investigate:

## Step 1 — Identify the Starting Account

Determine:

- Username
- Account status
- Department
- Business owner
- Normal role
- Last authentication activity

## Step 2 — Review Direct Membership

Determine which groups the user directly belongs to.

## Step 3 — Review Recursive Membership

Determine which privileged groups the user effectively inherits through nested relationships.

## Step 4 — Identify the Privileged Destination

Determine whether the final destination is:

- Domain Admins
- Enterprise Admins
- Administrators
- Other Tier Zero groups
- Critical servers
- Domain Controllers

## Step 5 — Review Group Modification Activity

Investigate when and by whom the suspicious membership was created.

## Step 6 — Correlate Authentication Telemetry

Review Windows security events for suspicious authentication involving the affected identity.

Relevant telemetry may include:

- Event ID 4624 — Successful logon
- Event ID 4625 — Failed logon
- Event ID 4672 — Special privileges assigned to new logon
- Event ID 4728 — Member added to security-enabled global group
- Event ID 4732 — Member added to security-enabled local group
- Event ID 4756 — Member added to security-enabled universal group

The exact event should be selected according to the group scope and membership-change operation.

## Step 7 — Determine Whether the Privilege Was Used

A dangerous relationship does not automatically prove malicious activity.

The analyst should determine whether the account actually used the inherited privilege.

---

# 30. False Positives

Potential legitimate explanations include:

- Approved administrative group nesting
- Temporary access assignments
- Delegated administration
- Helpdesk escalation procedures
- Service-account requirements
- Migration activities
- Authorized identity-management changes

However, privileged group nesting should always have a documented business justification.

---

# 31. False-Positive Reduction

A mature detection process should consider:

- Approved group relationships
- Known administrative groups
- Authorized change windows
- Identity ownership
- Privileged access management records
- Change-management tickets
- Baseline group structures

A relationship should receive higher priority when:

- The starting user is not expected to have administrative privileges.
- The nested group is newly created.
- The privileged relationship is newly introduced.
- The change occurred outside an approved window.
- The account is unusual for the destination privilege.
- The relationship leads directly to Tier Zero.

---

# 32. Remediation

After validating the controlled privilege path, the temporary relationship was removed.

The privileged nested relationship was eliminated.

### Evidence

![Domain Admins Remediation](../screenshots/Day11/Day11-22-Domain-Admins-Remediation-IT-Admins-Removed.png)

---

# 33. Post-Remediation Collection

A fresh BloodHound collection was performed after remediation.

This ensured that the BloodHound graph represented the current Active Directory state rather than the previous configuration.

### Evidence

![Post-Remediation BloodHound Collection](../screenshots/Day11/Day11-23-BloodHound-Post-Remediation-Collection.png)

---

# 34. Clean Dataset Ingestion

The post-remediation collection was successfully ingested into BloodHound CE.

### Evidence

![Clean Post-Remediation Ingest](../screenshots/Day11/Day11-24-BloodHound-Clean-Post-Remediation-Ingest.png)

---

# 35. Final Detection Validation

The original pathfinding analysis was repeated after remediation.

The previously identified path:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

was no longer present.

BloodHound returned:

**Path Not Found**

This confirms that the previously identified privilege path was removed from the current graph.

### Evidence

![BloodHound Remediation Path Removed](../screenshots/Day11/Day11-25-BloodHound-Remediation-Path-Removed.png)

---

# 36. Detection Workflow

The complete defensive workflow is:

```text
Active Directory Baseline
        ↓
BloodHound Collection
        ↓
Privileged Group Analysis
        ↓
Attack-Path Analysis
        ↓
Suspicious Relationship Identified
        ↓
Recursive Membership Validation
        ↓
SOC Investigation
        ↓
Privilege Relationship Remediation
        ↓
Fresh BloodHound Collection
        ↓
Post-Remediation Path Analysis
        ↓
Path Not Found
        ↓
Finding Closed
```

---

# 37. Recommended Response

If this condition is discovered in a production environment:

### Immediate Actions

1. Validate whether the relationship is authorized.
2. Identify the account owner.
3. Identify who created or modified the group relationship.
4. Review recent authentication activity.
5. Determine whether the inherited privilege was used.
6. Remove unauthorized privileged relationships.
7. Preserve relevant security telemetry.

### Follow-Up Actions

1. Review other nested administrative groups.
2. Perform a Tier Zero privilege review.
3. Audit privileged group membership.
4. Implement least-privilege controls.
5. Establish change-management requirements for privileged groups.
6. Periodically perform Active Directory attack-path analysis.

---

# 38. MITRE ATT&CK Relevance

The detection is relevant to Active Directory discovery and privilege-related activity.

Relevant techniques include:

- **T1069.002 — Permission Groups Discovery: Domain Groups**
- **T1087.002 — Account Discovery: Domain Account**
- **T1078 — Valid Accounts**

The specific Day 11 activity focused on identifying and remediating a privilege path rather than executing a real-world compromise.

---

# 39. Detection Limitations

BloodHound attack-path analysis should not be treated as proof of malicious activity by itself.

A discovered path means:

**A potentially dangerous relationship exists.**

It does not automatically mean:

**An attacker used the path.**

SOC analysts should therefore correlate BloodHound findings with:

- Windows Security logs
- Authentication activity
- Account changes
- Group membership changes
- Endpoint telemetry
- Network activity
- Change-management records

This distinction helps prevent false conclusions during incident investigation.

---

# 40. Blue-Team Takeaway

The most important defensive lesson from this exercise is:

> **Attack paths can exist before an attack occurs.**

A SOC does not always need to wait for malicious activity before identifying risk.

By analyzing identity relationships proactively, security teams can discover privilege escalation opportunities and remove them before they are abused.

The Day 11 workflow demonstrated:

**Discover → Validate → Remediate → Re-Collect → Confirm**

---

# 41. Final Detection Result

### Before Controlled Configuration

`BH_ENUM → DOMAIN ADMINS`

**Path Not Found**

### During Controlled Misconfiguration

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

**Attack Path Identified**

### After Remediation

`BH_ENUM → DOMAIN ADMINS`

**Path Not Found**

The security exposure was therefore successfully identified, validated, remediated, and re-validated.

---

# 42. Evidence Index

| # | Evidence |
|---:|---|
| 01 | `Day11-01-ADDC-Domain-Baseline.png` |
| 02 | `Day11-02-AD-Privileged-Groups-Baseline.png` |
| 03 | `Day11-03-bh_enum-LowPrivilege-Baseline.png` |
| 04 | `Day11-04-BloodHound-AD-Collection-Success.png` |
| 05 | `Day11-05-BloodHound-Collection-Dataset-Extracted.png` |
| 06 | `Day11-06-BloodHound-CE-Login.png` |
| 07 | `Day11-07-BloodHound-AD-Dataset-Ingest-Complete.png` |
| 08 | `Day11-08-BloodHound-Administrator-TierZero-Analysis.png` |
| 09 | `Day11-09-BloodHound-No-Path-BH_ENUM-to-Administrator.png` |
| 10 | `Day11-10-BH_ENUM-Helpdesk-Tier1-Membership.png` |
| 11 | `Day11-11-IT-Admins-Helpdesk-Tier1-Nested-Group.png` |
| 12 | `Day11-12-BloodHound-Post-Misconfiguration-Collection.png` |
| 13 | `Day11-13-BloodHound-Post-Misconfiguration-Ingest-Complete.png` |
| 14 | `Day11-14-Domain-Admins-IT-Admins-Nested-Group.png` |
| 15 | `Day11-15-BloodHound-Final-Collection-Success.png` |
| 16 | `Day11-16-BloodHound-Final-Ingest-Complete.png` |
| 17 | `Day11-17-BloodHound-BH_ENUM-to-Domain-Admins-Attack-Path.png` |
| 18 | `Day11-18-BloodHound-IT-Admins-to-Domain-Admins-MemberOf` |
| 19 | `Day11-19-BloodHound-Helpdesk-Tier1-to-IT-Admins-MemberOf.png` |
| 20 | `Day11-20-BloodHound-BH_ENUM-to-Helpdesk-Tier1-MemberOf.png` |
| 21 | `Day11-21-BH_ENUM-Effective-Domain-Admins-Membership.png` |
| 22 | `Day11-22-Domain-Admins-Remediation-IT-Admins-Removed.png` |
| 23 | `Day11-23-BloodHound-Post-Remediation-Collection.png` |
| 24 | `Day11-24-BloodHound-Clean-Post-Remediation-Ingest.png` |
| 25 | `Day11-25-BloodHound-Remediation-Path-Removed.png` |

---

# 43. Portfolio Significance

This detection demonstrates practical Blue-Team capabilities in:

- Active Directory security monitoring
- Identity and access management
- Privileged group analysis
- Nested group analysis
- Attack-path discovery
- Tier Zero identification
- Effective privilege analysis
- Security investigation
- False-positive analysis
- Privilege remediation
- Post-remediation validation
- Evidence-based SOC documentation

The key SOC capability demonstrated is the ability to move beyond individual security events and understand **how identity relationships create potential attack paths**.

The complete defensive methodology is:

**Baseline → Detect → Investigate → Validate → Remediate → Re-Analyze → Close**