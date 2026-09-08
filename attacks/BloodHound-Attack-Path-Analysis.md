# BloodHound Attack-Path Analysis

## Overview

This lab exercise demonstrates how a low-privileged Active Directory identity can become indirectly connected to a highly privileged group through **nested Active Directory group membership**.

The attack-path scenario was intentionally created in a controlled Active Directory lab and analyzed using **BloodHound Community Edition (CE)**.

The exercise focused on understanding the relationship between:

`User → Group → Nested Group → Privileged Group`

rather than directly compromising a privileged account.

---

## Objective

The objectives of this exercise were to:

- Establish a clean Active Directory privilege baseline.
- Use a dedicated low-privileged account for BloodHound enumeration.
- Collect Active Directory relationship data.
- Identify a Tier Zero privileged identity/group.
- Create a controlled nested-group misconfiguration.
- Re-collect Active Directory data.
- Identify the resulting attack path using BloodHound.
- Validate the relationship independently from Active Directory.
- Remove the temporary misconfiguration.
- Perform post-remediation validation.

---

# 1. Lab Environment

| Component | Value |
|---|---|
| Domain | `corp.local` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Analysis Host | Kali Linux |
| BloodHound Platform | BloodHound Community Edition |
| Collector | BloodHound Python |
| Enumeration Account | `bh_enum` |
| Privileged Group | `Domain Admins` |
| Administrative Group | `IT-Admins` |
| Temporary Lab Group | `Helpdesk-Tier1` |

---

# 2. Attack Concept

Active Directory permissions and group memberships form a relationship graph.

A low-privileged user may not directly belong to a privileged group, but nested group membership can create an indirect privilege path.

The controlled scenario used the following relationship:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

The important security concept is that the individual memberships may appear legitimate when viewed separately, while the combined relationships create a potentially dangerous privilege path.

BloodHound is useful for identifying these relationships because it represents Active Directory objects and their relationships as a graph.

---

# 3. Initial Security Baseline

Before creating the controlled attack-path scenario, the Active Directory environment was reviewed.

The domain was confirmed as:

`corp.local`

The Domain Controller was:

`AD-DC.corp.local`

with IP address:

`192.168.159.10`

### Evidence

![Active Directory Domain Baseline](../screenshots/Day11/Day11-01-ADDC-Domain-Baseline.png)

---

# 4. Privileged Group Baseline

The existing privileged groups were reviewed before making any modifications.

The baseline confirmed that:

- `Administrator` was a member of `Domain Admins`.
- `Administrator` was a member of `Enterprise Admins`.
- `IT-Admins` existed as an administrative group.
- `SOC-Analysts` contained the expected analyst accounts.

This provided the reference point for the later controlled attack-path scenario.

### Evidence

![Privileged Groups Baseline](../screenshots/Day11/Day11-02-AD-Privileged-Groups-Baseline.png)

---

# 5. Low-Privilege Enumeration Account

A dedicated account named:

`bh_enum`

was used as the starting identity for the attack-path analysis.

The account was intentionally configured as a low-privileged domain identity.

Its direct membership did not include privileged groups.

This established the starting point of the attack-path scenario.

### Evidence

![bh_enum Low Privilege Baseline](../screenshots/Day11/Day11-03-bh_enum-LowPrivilege-Baseline.png)

---

# 6. BloodHound Enumeration

BloodHound Python was used from Kali Linux to collect Active Directory relationship information.

The collection successfully enumerated the lab Active Directory environment, including users, groups, computers, OUs, GPOs, and other directory objects.

The collected information was subsequently imported into BloodHound CE for graph analysis.

### Evidence

![BloodHound AD Collection](../screenshots/Day11/Day11-04-BloodHound-AD-Collection-Success.png)

---

# 7. BloodHound Dataset

The BloodHound collector generated a dataset containing Active Directory relationship information.

The collected files were extracted and prepared for ingestion into BloodHound CE.

### Evidence

![BloodHound Collection Dataset](../screenshots/Day11/Day11-05-BloodHound-Collection-Dataset-Extracted.png)

---

# 8. BloodHound CE Analysis Platform

BloodHound Community Edition was used to visualize and analyze the collected Active Directory relationships.

### Evidence

![BloodHound CE](../screenshots/Day11/Day11-06-BloodHound-CE-Login.png)

---

# 9. Dataset Ingestion

The Active Directory dataset was successfully ingested into BloodHound CE.

The ingestion completed successfully and made the collected relationships available for graph analysis.

### Evidence

![BloodHound Dataset Ingestion](../screenshots/Day11/Day11-07-BloodHound-AD-Dataset-Ingest-Complete.png)

---

# 10. Privileged Target Identification

The built-in:

`Administrator`

account was analyzed within BloodHound.

BloodHound identified the account as a highly privileged Tier Zero identity.

This established the privileged target for the attack-path analysis.

### Evidence

![Administrator Tier Zero Analysis](../screenshots/Day11/Day11-08-BloodHound-Administrator-TierZero-Analysis.png)

---

# 11. Clean Attack-Path Baseline

Before introducing the controlled misconfiguration, BloodHound pathfinding was performed between:

**Starting Node**

`BH_ENUM@CORP.LOCAL`

**Target**

`ADMINISTRATOR@CORP.LOCAL`

The initial analysis returned:

**Path Not Found**

This confirmed that the low-privileged account did not have an identified BloodHound path to the Administrator account in the clean baseline.

### Evidence

![Clean BloodHound Attack Path Baseline](../screenshots/Day11/Day11-09-BloodHound-No-Path-BH_ENUM-to-Administrator.png)

---

# 12. Controlled Attack-Path Construction

To demonstrate the security impact of nested group membership, a temporary Active Directory security group was created:

`Helpdesk-Tier1`

The group was used only for the controlled lab scenario.

The attack path was constructed in multiple stages.

---

# 13. Stage 1 — Low-Privilege User to Helpdesk Group

The `bh_enum` account was added to:

`Helpdesk-Tier1`

This created the first relationship:

`BH_ENUM → MemberOf → Helpdesk-Tier1`

### Security Significance

An attacker controlling or compromising `bh_enum` would now inherit the memberships and permissions associated with the intermediate group.

### Evidence

![bh_enum Helpdesk-Tier1 Membership](../screenshots/Day11/Day11-10-BH_ENUM-Helpdesk-Tier1-Membership.png)

---

# 14. Stage 2 — Helpdesk Group to IT-Admins

The temporary:

`Helpdesk-Tier1`

group was nested inside:

`IT-Admins`

The resulting relationship became:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins`

### Security Significance

This demonstrated how a low-privileged account can gain an indirect relationship with an administrative group without being directly added to that administrative group.

### Evidence

![Helpdesk-Tier1 Nested into IT-Admins](../screenshots/Day11/Day11-11-IT-Admins-Helpdesk-Tier1-Nested-Group.png)

---

# 15. Stage 3 — IT-Admins to Domain Admins

The controlled scenario was then extended by nesting:

`IT-Admins`

inside:

`Domain Admins`

The resulting relationship chain became:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

Because `Domain Admins` contained the privileged `Administrator` account, the nested relationships created an indirect route toward a Tier Zero identity.

### Evidence

![IT-Admins Nested into Domain Admins](../screenshots/Day11/Day11-14-Domain-Admins-IT-Admins-Nested-Group.png)

---

# 16. Updated BloodHound Collection

After constructing the controlled group relationships, a new BloodHound collection was performed.

The purpose was to ensure that the updated Active Directory relationships were represented in the BloodHound dataset.

### Evidence

![Post-Misconfiguration BloodHound Collection](../screenshots/Day11/Day11-12-BloodHound-Post-Misconfiguration-Collection.png)

---

# 17. Updated Dataset Ingestion

The updated BloodHound dataset was successfully ingested into BloodHound CE.

This made the newly created nested-group relationships available for pathfinding.

### Evidence

![Post-Misconfiguration Ingest](../screenshots/Day11/Day11-13-BloodHound-Post-Misconfiguration-Ingest-Complete.png)

---

# 18. Attack Path Discovery

BloodHound pathfinding was then used to analyze the relationship between:

**Starting Node**

`BH_ENUM@CORP.LOCAL`

and:

**Target**

`DOMAIN ADMINS@CORP.LOCAL`

BloodHound identified the following path:

`BH_ENUM`

↓

`Helpdesk-Tier1`

↓

`IT-Admins`

↓

`Domain Admins`

This was the central finding of the exercise.

### Complete Attack Path

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

### Evidence

![BloodHound Attack Path](../screenshots/Day11/Day11-17-BloodHound-BH_ENUM-to-Domain-Admins-Attack-Path.png)

---

# 19. Attack-Path Relationship -1

The first relationship was:

`BH_ENUM → Helpdesk-Tier1`

Relationship type:

`MemberOf`

This confirmed the low-privileged starting identity's relationship with the intermediate helpdesk group.

### Evidence

![bh_enum to Helpdesk-Tier1](../screenshots/Day11/Day11-20-BloodHound-BH_ENUM-to-Helpdesk-Tier1-MemberOf.png)

---

# 20. Attack-Path Relationship -2

The second relationship was:

`Helpdesk-Tier1 → IT-Admins`

Relationship type:

`MemberOf`

This demonstrated the nested administrative relationship.

### Evidence

![Helpdesk-Tier1 to IT-Admins](../screenshots/Day11/Day11-19-BloodHound-Helpdesk-Tier1-to-IT-Admins-MemberOf.png)

---

# 21. Attack-Path Relationship -3

The final privileged relationship was:

`IT-Admins → Domain Admins`

Relationship type:

`MemberOf`

This completed the controlled privilege path.

### Evidence

![IT-Admins to Domain Admins](../screenshots/Day11/Day11-18-BloodHound-IT-Admins-to-Domain-Admins-MemberOf.png)

---

# 22. Effective Membership Validation

The BloodHound relationship was independently validated from Active Directory using recursive group membership enumeration.

The validation demonstrated that `bh_enum` appeared within the effective `Domain Admins` membership hierarchy during the controlled scenario.

This confirmed that the issue was not simply a visualization artifact.

### Security Significance

This demonstrates why security reviews should consider:

- Direct membership
- Nested membership
- Recursive membership
- Effective privilege

rather than relying only on a user's immediate group list.

### Evidence

![Effective Domain Admins Membership](../screenshots/Day11/Day11-21-BH_ENUM-Effective-Domain-Admins-Membership.png)

---

# 23. Attack-Path Security Finding

## Finding

**Indirect Privilege Exposure Through Nested Active Directory Groups**

### Severity

**High**

### Attack Path

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

### Description

A low-privileged Active Directory identity was intentionally connected to a privileged group through nested group membership.

The relationship demonstrated how privilege exposure can arise without directly adding the low-privileged identity to a highly privileged group.

### Potential Impact

In a real environment, a comparable configuration could increase the impact of a compromised low-privileged account by providing an indirect route toward privileged administrative access.

Potential consequences could include:

- Privilege escalation
- Unauthorized administrative access
- Increased lateral movement capability
- Access to sensitive systems
- Increased exposure of Tier Zero assets
- Potential domain compromise depending on additional controls and permissions

---

# 24. Why the Attack Path Is Important

The security risk is not represented by one individual group membership alone.

The risk comes from the combination:

`BH_ENUM → Helpdesk-Tier1`

plus:

`Helpdesk-Tier1 → IT-Admins`

plus:

`IT-Admins → Domain Admins`

Together, these relationships form an attack path.

This is precisely the type of relationship that graph-based security analysis is designed to uncover.

---

# 25. Remediation

After the attack path was successfully validated, the temporary group relationships were removed.

The nested relationship between:

`Helpdesk-Tier1`

and:

`IT-Admins`

was removed.

The temporary:

`Helpdesk-Tier1`

group was subsequently deleted.

This returned the Active Directory environment to its intended clean configuration.

### Evidence

![Active Directory Remediation](../screenshots/Day11/Day11-22-Domain-Admins-Remediation-IT-Admins-Removed.png)

---

# 26. Post-Remediation BloodHound Collection

A fresh BloodHound collection was performed after remediation.

This ensured that the updated Active Directory state was represented in the BloodHound graph.

### Evidence

![Post-Remediation BloodHound Collection](../screenshots/Day11/Day11-23-BloodHound-Post-Remediation-Collection.png)

---

# 27. Clean Dataset Ingestion

The post-remediation BloodHound dataset was successfully ingested into BloodHound CE.

### Evidence

![Clean Post-Remediation Ingest](../screenshots/Day11/Day11-24-BloodHound-Clean-Post-Remediation-Ingest.png)

---

# 28. Attack Path Removal Validation

The original attack-path analysis was repeated after remediation.

The previously identified relationship:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

was no longer present in the clean BloodHound graph.

This confirmed that the temporary privilege path had been removed.

### Evidence

![BloodHound Remediation Path Removed](../screenshots/Day11/Day11-25-BloodHound-Remediation-Path-Removed.png)

---

# 29. Before vs After

| Stage | BloodHound Result |
|---|---|
| Clean baseline | No path identified |
| Controlled misconfiguration | Path identified |
| Remediation | Temporary nested groups removed |
| Fresh collection | Updated graph generated |
| Post-remediation analysis | Previous path removed |

This provides evidence of both **security exposure** and **successful remediation**.

---

# 30. Attack-Path Lifecycle

The complete exercise followed this workflow:

```text
Low-Privilege Identity
        ↓
Clean BloodHound Baseline
        ↓
No Path Found
        ↓
Controlled Group Relationship
        ↓
Nested Administrative Group
        ↓
BloodHound Re-Collection
        ↓
Attack Path Identified
        ↓
Effective Membership Validation
        ↓
Remediation
        ↓
Fresh BloodHound Collection
        ↓
Post-Remediation Analysis
        ↓
Attack Path Removed
```

---

# 31. Security Lessons

## Nested Group Membership Can Hide Privilege

A user may appear to have limited privileges when only direct membership is reviewed.

Recursive relationships can tell a different story.

## Privileged Groups Should Be Minimized

Groups such as `Domain Admins` should contain only identities that genuinely require domain-level administrative privileges.

## Administrative Group Nesting Requires Governance

Nested administrative groups should have a documented business purpose and be reviewed regularly.

## Attack Paths Should Be Validated

Finding a risky relationship is only the first step.

Security teams should validate whether the relationship creates an effective privilege path.

## Remediation Requires Re-Analysis

The strongest validation is:

**Change → Re-collect → Re-analyze → Confirm closure**

---

# 32. Defensive Recommendations

For a production Active Directory environment:

1. Minimize membership in `Domain Admins`.
2. Avoid unnecessary nesting of privileged groups.
3. Review administrative groups regularly.
4. Use dedicated administrative accounts.
5. Separate standard user identities from privileged identities.
6. Monitor privileged group membership changes.
7. Review effective permissions rather than only direct membership.
8. Periodically perform attack-path analysis.
9. Treat Tier Zero identities and groups as highly sensitive.
10. Re-run security analysis after remediation to verify closure.

---

# 33. MITRE ATT&CK Relevance

The exercise primarily focused on Active Directory discovery and privilege relationship analysis.

Relevant ATT&CK techniques include:

- **T1069.002 — Permission Groups Discovery: Domain Groups**
- **T1087.002 — Account Discovery: Domain Account**
- **T1078 — Valid Accounts**

The central security finding was an **Active Directory privilege exposure through nested group membership**.

No credential theft or direct compromise of the privileged account was required to demonstrate the relationship risk.

---

# 34. Analyst Perspective

From an offensive-security perspective, the important question is:

> What relationships could allow a low-privileged identity to reach a privileged asset?

From a defensive-security perspective, the question becomes:

> Which identity relationships should be removed or monitored before they can be abused?

BloodHound provides visibility into the first question, while Active Directory security controls and SIEM monitoring help address the second.

---

# 35. Final Assessment

The controlled exercise successfully demonstrated:

- Active Directory reconnaissance
- Privileged group identification
- Low-privilege account analysis
- BloodHound data collection
- BloodHound CE graph analysis
- Tier Zero identification
- Nested group analysis
- Attack-path discovery
- Effective membership validation
- Privilege exposure assessment
- Security remediation
- Post-remediation validation

The key finding was:

`BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins`

The temporary relationship was subsequently removed, and fresh BloodHound analysis confirmed that the previously identified path no longer existed.

---

# 36. Evidence Summary

| Evidence | Purpose |
|---|---|
| `Day11-01-ADDC-Domain-Baseline.png` | Active Directory domain baseline |
| `Day11-02-AD-Privileged-Groups-Baseline.png` | Privileged group baseline |
| `Day11-03-bh_enum-LowPrivilege-Baseline.png` | Low-privilege account baseline |
| `Day11-04-BloodHound-AD-Collection-Success.png` | BloodHound AD collection |
| `Day11-05-BloodHound-Collection-Dataset-Extracted.png` | Collection dataset validation |
| `Day11-06-BloodHound-CE-Login.png` | BloodHound CE access |
| `Day11-07-BloodHound-AD-Dataset-Ingest-Complete.png` | Dataset ingestion |
| `Day11-08-BloodHound-Administrator-TierZero-Analysis.png` | Tier Zero target analysis |
| `Day11-09-BloodHound-No-Path-BH_ENUM-to-Administrator.png` | Clean pathfinding baseline |
| `Day11-10-BH_ENUM-Helpdesk-Tier1-Membership.png` | Low-privilege user added to temporary group |
| `Day11-11-IT-Admins-Helpdesk-Tier1-Nested-Group.png` | Helpdesk-Tier1 nested into IT-Admins |
| `Day11-12-BloodHound-Post-Misconfiguration-Collection.png` | Collection after misconfiguration |
| `Day11-13-BloodHound-Post-Misconfiguration-Ingest-Complete.png` | Post-misconfiguration ingestion |
| `Day11-14-Domain-Admins-IT-Admins-Nested-Group.png` | IT-Admins nested into Domain Admins |
| `Day11-15-BloodHound-Final-Collection-Success.png` | Final collection before attack-path analysis |
| `Day11-16-BloodHound-Final-Ingest-Complete.png` | Final dataset ingestion |
| `Day11-17-BloodHound-BH_ENUM-to-Domain-Admins-Attack-Path.png` | Complete identified attack path |
| `Day11-18-BloodHound-IT-Admins-to-Domain-Admins-MemberOf` | IT-Admins to Domain Admins relationship |
| `Day11-19-BloodHound-Helpdesk-Tier1-to-IT-Admins-MemberOf.png` | Helpdesk-Tier1 to IT-Admins relationship |
| `Day11-20-BloodHound-BH_ENUM-to-Helpdesk-Tier1-MemberOf.png` | bh_enum to Helpdesk-Tier1 relationship |
| `Day11-21-BH_ENUM-Effective-Domain-Admins-Membership.png` | Recursive effective membership validation |
| `Day11-22-Domain-Admins-Remediation-IT-Admins-Removed.png` | Remediation of temporary privileged relationship |
| `Day11-23-BloodHound-Post-Remediation-Collection.png` | Post-remediation collection |
| `Day11-24-BloodHound-Clean-Post-Remediation-Ingest.png` | Clean dataset ingestion |
| `Day11-25-BloodHound-Remediation-Path-Removed.png` | Final attack-path removal validation |

---

# 37. Portfolio Value

This exercise demonstrates more than the ability to run BloodHound.

It demonstrates an end-to-end security workflow:

**Baseline → Enumerate → Model → Identify Attack Path → Validate → Remediate → Re-Collect → Confirm Closure**

This is directly relevant to:

- SOC Analyst
- Blue Team Analyst
- Detection & Response
- Identity Security
- Active Directory Security
- Security Operations
- Threat Hunting
- Security Engineering

The primary professional takeaway is:

> **Effective privilege must be evaluated as a graph of relationships, not simply as a list of direct group memberships.**