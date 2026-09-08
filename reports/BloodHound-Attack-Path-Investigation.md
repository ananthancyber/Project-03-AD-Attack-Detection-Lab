# BloodHound Attack Path Investigation

## Investigation Summary

This investigation documents the identification, validation, exploitation, and remediation of a controlled Active Directory privilege-escalation path discovered using BloodHound Community Edition (CE).

The investigation began with a clean Active Directory baseline in which the low-privileged `bh_enum` account had no path to the privileged `Administrator` account or the `Domain Admins` group.

A controlled Active Directory misconfiguration was then introduced by creating a temporary `Helpdesk-Tier1` group and establishing the following nested membership chain:

**BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins**

BloodHound subsequently identified this relationship chain as a viable attack path to the `Domain Admins` privilege boundary.

The finding was validated through both BloodHound graph analysis and recursive Active Directory group-membership verification. The misconfiguration was then removed, BloodHound was re-collected and re-ingested, and the attack path was confirmed to be no longer present.

This investigation demonstrates an end-to-end identity security workflow:

**Baseline → Enumeration → Attack-Path Discovery → Validation → Risk Assessment → Remediation → Re-Validation**

---

## Case Information

| Field | Value |
|---|---|
| Investigation Type | Active Directory Attack-Path Analysis |
| Platform | Windows Server Active Directory |
| Domain | `CORP.LOCAL` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Analysis Platform | BloodHound Community Edition |
| Collector | BloodHound Python |
| Initial Enumeration Account | `bh_enum` |
| Privileged Target | `Administrator` / `Domain Admins` |
| Temporary Group | `Helpdesk-Tier1` |
| Severity | High |
| Attack-Path Status | Successfully demonstrated in controlled lab |
| Final Status | Remediated and validated |
| MITRE ATT&CK Relevance | T1078, T1069.002 |

---

# 1. Investigation Objective

The objective of this investigation was to determine whether a low-privileged Active Directory account could reach a privileged security boundary through unintended group nesting or privilege relationships.

The investigation specifically evaluated:

- Active Directory domain structure
- Privileged group membership
- Low-privileged account permissions
- BloodHound enumeration
- Tier Zero assets
- Attack-path relationships
- Nested group membership
- Effective privilege exposure
- Remediation effectiveness
- Post-remediation attack-path validation

The exercise was intentionally performed in a controlled lab environment.

---

# 2. Environment

The investigation used the following Active Directory environment:

| Component | Configuration |
|---|---|
| Domain | `CORP.LOCAL` |
| DNS Domain | `corp.local` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Analysis Host | Kali Linux |
| BloodHound Version | CE v9.6.0 |
| BloodHound Collector | BloodHound.py Legacy |
| Enumeration Account | `bh_enum` |
| Initial Privilege Level | Domain Users |
| Target Privilege Boundary | Domain Admins |

---

# 3. Initial Domain Baseline

The investigation first established the Active Directory domain and domain-controller baseline.

The domain was confirmed as:

- DNS root: `corp.local`
- Distinguished Name: `DC=corp,DC=local`
- Domain Controller: `AD-DC.corp.local`
- Domain Controller IP: `192.168.159.10`

### Evidence

![AD Domain Baseline](../screenshots/Day11/Day11-01-ADDC-Domain-Baseline.png)

**Evidence:** `Day11-01-ADDC-Domain-Baseline.png`

This establishes the authoritative Active Directory environment used throughout the investigation.

---

# 4. Privileged Group Baseline

The following groups were examined to establish the existing privileged security boundaries:

- Domain Admins
- Enterprise Admins
- Administrators
- IT-Admins
- SOC-Analysts

The baseline showed:

- `Administrator` was a member of `Domain Admins`.
- `Administrator` was a member of `Enterprise Admins`.
- `Administrator` was present in the privileged `Administrators` and `IT-Admins` groups.
- `Alice` and `Bob` were members of `SOC-Analysts`.

### Evidence

![AD Privileged Groups Baseline](../screenshots/Day11/Day11-02-AD-Privileged-Groups-Baseline.png)

**Evidence:** `Day11-02-AD-Privileged-Groups-Baseline.png`

This baseline was important because attack-path analysis is meaningful only when the starting privilege level and privileged targets are clearly understood.

---

# 5. Low-Privilege Enumeration Account

A dedicated enumeration account named `bh_enum` was created for BloodHound collection.

The account was intentionally kept at a low privilege level.

The account was verified as:

- Enabled
- Not locked
- Not expired
- Not a member of privileged groups
- Directly associated with the standard `Domain Users` group

### Evidence

![BH Enum Low Privilege Baseline](../screenshots/Day11/Day11-03-bh_enum-LowPrivilege-Baseline.png)

**Evidence:** `Day11-03-bh_enum-LowPrivilege-Baseline.png`

This is an important security control in the investigation because the starting point represents a normal low-privileged domain identity rather than an administrator account.

---

# 6. BloodHound Active Directory Collection

BloodHound Python was used from the Kali analysis system to enumerate the Active Directory environment.

The collector successfully identified:

- 1 domain
- 1 forest
- 2 computers
- 10 users
- 54 groups during the initial collection
- 2 GPOs
- 5 OUs
- 19 containers
- 0 trusts

The collected dataset was compressed into a BloodHound-compatible ZIP archive.

### Evidence

![BloodHound Collection Success](../screenshots/Day11/Day11-04-BloodHound-AD-Collection-Success.png)

**Evidence:** `Day11-04-BloodHound-AD-Collection-Success.png`

---

# 7. BloodHound Dataset Verification

The generated BloodHound archive was verified and extracted locally.

The dataset contained information covering:

- Users
- Groups
- Computers
- Domains
- GPOs
- OUs
- Containers

### Evidence

![BloodHound Dataset Extracted](../screenshots/Day11/Day11-05-BloodHound-Collection-Dataset-Extracted.png)

**Evidence:** `Day11-05-BloodHound-Collection-Dataset-Extracted.png`

This confirmed that the collector produced a complete dataset suitable for graph-based analysis.

---

# 8. BloodHound CE Analysis Environment

BloodHound Community Edition was deployed locally and accessed through its web interface.

The BloodHound CE environment provided:

- Search
- Graph exploration
- Pathfinding
- Cypher-based analysis
- Tier Zero analysis
- Relationship visualization

### Evidence

![BloodHound CE Login](../screenshots/Day11/Day11-06-BloodHound-CE-Login.png)

**Evidence:** `Day11-06-BloodHound-CE-Login.png`

---

# 9. Initial Dataset Ingestion

The collected Active Directory dataset was successfully uploaded into BloodHound CE.

The ingest operation completed successfully and contained the expected seven collected JSON files.

### Evidence

![BloodHound Dataset Ingest Complete](../screenshots/Day11/Day11-07-BloodHound-AD-Dataset-Ingest-Complete.png)

**Evidence:** `Day11-07-BloodHound-AD-Dataset-Ingest-Complete.png`

---

# 10. Tier Zero Administrator Analysis

The built-in `Administrator` account was analyzed as a privileged Active Directory identity.

BloodHound identified the account as:

- Node Type: User
- Tier Zero
- Admin Count: TRUE
- Enabled: TRUE
- Domain: `CORP.LOCAL`
- Built-in Administrator account

### Evidence

![BloodHound Administrator Tier Zero Analysis](../screenshots/Day11/Day11-08-BloodHound-Administrator-TierZero-Analysis.png)

**Evidence:** `Day11-08-BloodHound-Administrator-TierZero-Analysis.png`

The Administrator account therefore represented a high-value privileged target.

---

# 11. Initial Attack-Path Baseline

Before introducing any controlled misconfiguration, BloodHound pathfinding was performed from the low-privileged `BH_ENUM` account toward the privileged `Administrator` account.

The initial analysis returned:

**Path Not Found**

This established the clean baseline.

### Evidence

![No Path from BH ENUM to Administrator](../screenshots/Day11/Day11-09-BloodHound-No-Path-BH_ENUM-to-Administrator.png)

**Evidence:** `Day11-09-BloodHound-No-Path-BH_ENUM-to-Administrator.png`

This baseline is critical because it demonstrates that the later attack path was not already present in the environment.

---

# 12. Controlled Security Misconfiguration

To demonstrate how Active Directory group nesting can create privilege escalation opportunities, a temporary group named:

`Helpdesk-Tier1`

was introduced.

The group was intentionally created as part of the controlled lab scenario.

The low-privileged `bh_enum` account was added to this group.

### Evidence

![BH ENUM Helpdesk Tier 1 Membership](../screenshots/Day11/Day11-10-BH_ENUM-Helpdesk-Tier1-Membership.png)

**Evidence:** `Day11-10-BH_ENUM-Helpdesk-Tier1-Membership.png`

At this stage, the first relationship became:

**BH_ENUM → Helpdesk-Tier1**

---

# 13. Helpdesk-Tier1 to IT-Admins Relationship

The temporary `Helpdesk-Tier1` group was then nested into the existing `IT-Admins` group.

This introduced the second privilege relationship:

**Helpdesk-Tier1 → IT-Admins**

### Evidence

![IT Admins Helpdesk Tier 1 Nested Group](../screenshots/Day11/Day11-11-IT-Admins-Helpdesk-Tier1-Nested-Group.png)

**Evidence:** `Day11-11-IT-Admins-Helpdesk-Tier1-Nested-Group.png`

This relationship was significant because group nesting can cause users to inherit the privileges associated with parent groups.

---

# 14. Updated BloodHound Collection

After modifying the Active Directory group relationships, BloodHound data was collected again.

The updated environment reflected the newly introduced group structure.

### Evidence

![BloodHound Post Misconfiguration Collection](../screenshots/Day11/Day11-12-BloodHound-Post-Misconfiguration-Collection.png)

**Evidence:** `Day11-12-BloodHound-Post-Misconfiguration-Collection.png`

---

# 15. Updated BloodHound Dataset Ingestion

The updated dataset was uploaded into BloodHound CE for graph analysis.

The ingestion completed successfully.

### Evidence

![BloodHound Post Misconfiguration Ingest](../screenshots/Day11/Day11-13-BloodHound-Post-Misconfiguration-Ingest-Complete.png)

**Evidence:** `Day11-13-BloodHound-Post-Misconfiguration-Ingest-Complete.png`

---

# 16. IT-Admins to Domain Admins Relationship

The final privilege relationship required for the controlled attack path was established by nesting `IT-Admins` into `Domain Admins`.

This created:

**IT-Admins → Domain Admins**

### Evidence

![Domain Admins IT Admins Nested Group](../screenshots/Day11/Day11-14-Domain-Admins-IT-Admins-Nested-Group.png)

**Evidence:** `Day11-14-Domain-Admins-IT-Admins-Nested-Group.png`

The complete intended relationship chain was now:

**BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins**

---

# 17. Final BloodHound Collection Before Attack-Path Analysis

A fresh BloodHound collection was performed after the complete controlled group hierarchy had been established.

The collection completed successfully.

### Evidence

![BloodHound Final Collection Success](../screenshots/Day11/Day11-15-BloodHound-Final-Collection-Success.png)

**Evidence:** `Day11-15-BloodHound-Final-Collection-Success.png`

---

# 18. Final Dataset Ingestion

The final dataset representing the controlled misconfiguration was ingested into BloodHound CE.

### Evidence

![BloodHound Final Ingest Complete](../screenshots/Day11/Day11-16-BloodHound-Final-Ingest-Complete.png)

**Evidence:** `Day11-16-BloodHound-Final-Ingest-Complete.png`

---

# 19. Attack Path Identified

BloodHound pathfinding was executed from:

**Starting Node:** `BH_ENUM@CORP.LOCAL`

to:

**Ending Node:** `DOMAIN ADMINS@CORP.LOCAL`

BloodHound identified the following path:

**BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins**

This demonstrated that the low-privileged account had an indirect route to a Tier Zero privilege boundary.

### Evidence

![BH ENUM to Domain Admins Attack Path](../screenshots/Day11/Day11-17-BloodHound-BH_ENUM-to-Domain-Admins-Attack-Path.png)

**Evidence:** `Day11-17-BloodHound-BH_ENUM-to-Domain-Admins-Attack-Path.png`

---

# 20. Attack-Path Relationship Analysis

The identified path was broken down into individual graph relationships.

## Relationship 1

**IT-Admins → Domain Admins**

This relationship represents the critical privilege boundary crossing.

### Evidence

![IT Admins to Domain Admins MemberOf](../screenshots/Day11/Day11-18-BloodHound-IT-Admins-to-Domain-Admins-MemberOf.png)

**Evidence:** `Day11-18-BloodHound-IT-Admins-to-Domain-Admins-MemberOfg`

---

## Relationship 2

**Helpdesk-Tier1 → IT-Admins**

This relationship allowed membership in the temporary Helpdesk group to propagate into the IT administrator group.

### Evidence

![Helpdesk Tier 1 to IT Admins MemberOf](../screenshots/Day11/Day11-19-BloodHound-Helpdesk-Tier1-to-IT-Admins-MemberOf.png)

**Evidence:** `Day11-19-BloodHound-Helpdesk-Tier1-to-IT-Admins-MemberOf.png`

---

## Relationship 3

**BH_ENUM → Helpdesk-Tier1**

This relationship connected the low-privileged starting account to the privilege-escalation chain.

### Evidence

![BH ENUM to Helpdesk Tier 1 MemberOf](../screenshots/Day11/Day11-20-BloodHound-BH_ENUM-to-Helpdesk-Tier1-MemberOf.png)

**Evidence:** `Day11-20-BloodHound-BH_ENUM-to-Helpdesk-Tier1-MemberOf.png`

---

# 21. Effective Privilege Validation

The BloodHound graph finding was independently validated against Active Directory group membership.

Recursive group membership analysis demonstrated that `bh_enum` could effectively resolve into the `Domain Admins` privilege boundary through the nested group structure.

This provided an important second source of validation rather than relying solely on the visualization produced by BloodHound.

### Evidence

![BH ENUM Effective Domain Admins Membership](../screenshots/Day11/Day11-21-BH_ENUM-Effective-Domain-Admins-Membership.png)

**Evidence:** `Day11-21-BH_ENUM-Effective-Domain-Admins-Membership.png`

---

# 22. Analyst Assessment

The finding was assessed as a **High-severity Active Directory privilege exposure**.

The reason for the severity was not the existence of the `Helpdesk-Tier1` group itself.

The security impact resulted from the complete membership chain:

**Low-Privilege User**
↓
**Helpdesk-Tier1**
↓
**IT-Admins**
↓
**Domain Admins**

The final relationship crossed into a highly privileged administrative group.

If this configuration existed unintentionally in a production environment, compromise of the low-privileged account could potentially provide a route toward administrative control of the Active Directory environment.

---

# 23. Security Impact

The demonstrated configuration creates several security concerns.

### Privilege Escalation

A low-privileged account could inherit access through nested group relationships.

### Tier Zero Exposure

The path ultimately reached `Domain Admins`, a Tier Zero security boundary.

### Identity-Based Attack Surface

The attack path did not require exploitation of a software vulnerability.

Instead, the risk originated from identity and authorization relationships.

### Reduced Privilege Separation

The nested group hierarchy weakened the separation between helpdesk-level access and domain-administrator privileges.

### Attack-Path Visibility

Without graph-based analysis, the indirect relationship could be difficult to recognize from individual group-membership reviews.

---

# 24. Remediation

The controlled misconfiguration was removed.

The remediation consisted of:

1. Removing `bh_enum` from `Helpdesk-Tier1`.
2. Removing `Helpdesk-Tier1` from `IT-Admins`.
3. Removing the temporary `Helpdesk-Tier1` group.
4. Preserving `bh_enum` as a low-privileged enumeration account.
5. Re-collecting Active Directory data.
6. Re-ingesting the clean dataset.
7. Re-running BloodHound pathfinding.

The remediation specifically targeted the unnecessary privilege relationships rather than weakening the Active Directory environment.

### Evidence

![Domain Admins Remediation](../screenshots/Day11/Day11-22-Domain-Admins-Remediation-IT-Admins-Removed.png)

**Evidence:** `Day11-22-Domain-Admins-Remediation-IT-Admins-Removed.png`

---

# 25. Post-Remediation BloodHound Collection

After the privilege relationships were removed, a new BloodHound collection was performed.

### Evidence

![BloodHound Post Remediation Collection](../screenshots/Day11/Day11-23-BloodHound-Post-Remediation-Collection.png)

**Evidence:** `Day11-23-BloodHound-Post-Remediation-Collection.png`

The new collection represented the remediated Active Directory state.

---

# 26. Clean Post-Remediation Dataset Ingestion

The post-remediation dataset was ingested into a clean BloodHound CE analysis environment.

The ingestion completed successfully.

### Evidence

![BloodHound Clean Post Remediation Ingest](../screenshots/Day11/Day11-24-BloodHound-Clean-Post-Remediation-Ingest.png)

**Evidence:** `Day11-24-BloodHound-Clean-Post-Remediation-Ingest.png`

Using a clean analysis state ensured that the previous attack-path graph did not remain as historical graph data during final validation.

---

# 27. Final Attack-Path Validation

BloodHound pathfinding was executed again from:

**BH_ENUM@CORP.LOCAL**

to:

**DOMAIN ADMINS@CORP.LOCAL**

The previously identified attack path was no longer available.

BloodHound returned:

**Path Not Found**

### Evidence

![BloodHound Remediation Path Removed](../screenshots/Day11/Day11-25-BloodHound-Remediation-Path-Removed.png)

**Evidence:** `Day11-25-BloodHound-Remediation-Path-Removed.png`

This confirmed that the controlled privilege-escalation path had been successfully removed.

---

# 28. Investigation Timeline

| Stage | Activity | Result |
|---|---|---|
| 1 | AD domain baseline | Established |
| 2 | Privileged group baseline | Established |
| 3 | Low-privileged `bh_enum` baseline | Confirmed |
| 4 | BloodHound enumeration | Successful |
| 5 | Initial graph analysis | No path |
| 6 | `Helpdesk-Tier1` created | Controlled change |
| 7 | `bh_enum` added to Helpdesk-Tier1 | Relationship created |
| 8 | Helpdesk-Tier1 nested into IT-Admins | Privilege chain extended |
| 9 | IT-Admins nested into Domain Admins | Tier Zero path created |
| 10 | BloodHound re-collection | Successful |
| 11 | Attack-path analysis | Path identified |
| 12 | Recursive AD validation | Effective membership confirmed |
| 13 | Group relationships removed | Remediation completed |
| 14 | BloodHound re-collection | Successful |
| 15 | Clean dataset ingestion | Successful |
| 16 | Final pathfinding | Path Not Found |

---

# 29. Before-and-After Assessment

| Security State | BH_ENUM → Domain Admins |
|---|---|
| Initial Baseline | No path |
| Controlled Misconfiguration | Path identified |
| After Remediation | No path |

### Initial State

**BH_ENUM → No Path → Domain Admins**

### Controlled Misconfiguration

**BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins**

### Remediated State

**BH_ENUM → No Path → Domain Admins**

This demonstrates that the security control was validated across the entire lifecycle rather than only at the point of detection.

---

# 30. Detection and Investigation Logic

From a SOC perspective, this type of finding should be treated as an **identity and access-control investigation**.

An analyst should investigate:

1. Which user initiated the privilege relationship?
2. Which groups are involved?
3. Is the group nesting intentional?
4. Is the affected group privileged?
5. Does the relationship cross a Tier Zero boundary?
6. Which users inherit the privilege?
7. Was the configuration recently changed?
8. Are there corresponding Windows security events?
9. Did the affected account perform suspicious authentication or administrative activity?
10. Does the relationship remain after remediation?

BloodHound provides the relationship and attack-path perspective, while Windows security telemetry can provide the temporal evidence needed to investigate actual account activity.

---

# 31. False Positive Considerations

Nested group relationships are not inherently malicious.

Legitimate reasons may include:

- Delegated administration
- Helpdesk role separation
- Organizational group structures
- Application access groups
- Infrastructure management
- Controlled administrative delegation

Therefore, a SOC analyst should not automatically classify every nested group relationship as malicious.

The investigation should determine whether the relationship is:

- documented
- approved
- required
- appropriately scoped
- reviewed regularly
- consistent with least-privilege principles

The highest-risk relationships are those that unexpectedly connect low-privileged identities to Tier Zero administrative groups.

---

# 32. Recommended SOC Response

If a similar attack path were discovered in a production environment, recommended actions would include:

### Immediate

- Validate the affected group memberships.
- Identify all users inheriting the privilege.
- Confirm whether the relationship is authorized.
- Review recent directory changes.
- Review authentication and administrative activity involving affected accounts.

### Containment

- Remove unauthorized nested group relationships.
- Disable compromised accounts where appropriate.
- Revoke unnecessary administrative membership.
- Reset credentials if compromise is suspected.

### Investigation

- Review Windows Security events.
- Review account-management events.
- Review privileged logons.
- Correlate source hosts and timestamps.
- Search for additional privilege-escalation paths.

### Long-Term

- Apply least privilege.
- Minimize nested privileged groups.
- Implement privileged access management.
- Regularly review Tier Zero membership.
- Perform recurring BloodHound or equivalent attack-path assessments.
- Monitor changes to privileged groups.

---

# 33. MITRE ATT&CK Relevance

This investigation has relevance to multiple MITRE ATT&CK techniques.

## T1078 — Valid Accounts

Valid domain credentials may be used to access resources or perform actions that the account is authorized to perform.

## T1069.002 — Permission Groups Discovery: Domain Groups

The investigation involved enumeration and analysis of Active Directory groups and group relationships.

## T1098 — Account Manipulation

Changes to group membership can alter the effective privileges associated with an account.

The primary security concept demonstrated by this lab is **privilege escalation through identity and authorization relationships**, rather than exploitation of a software vulnerability.

---

# 34. Evidence Correlation

The investigation used multiple evidence sources rather than relying on a single screenshot or tool.

| Evidence Category | Purpose |
|---|---|
| AD domain baseline | Establish environment |
| Privileged group enumeration | Identify privilege boundaries |
| Low-privilege account baseline | Establish attacker starting point |
| BloodHound collection | Enumerate AD relationships |
| BloodHound graph | Identify attack paths |
| AD group membership | Independently validate relationships |
| BloodHound re-collection | Reflect configuration changes |
| Post-remediation collection | Validate clean state |
| Final pathfinding | Confirm attack-path removal |

This multi-stage evidence model improves investigation confidence.

---

# 35. Key Investigation Finding

The central finding was:

> A controlled nested-group configuration created an indirect privilege-escalation path from a low-privileged domain account to the `Domain Admins` group.

The path was:

**BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins**

The finding was:

- Identified through BloodHound
- Validated through Active Directory
- Classified as High severity
- Remediated by removing unnecessary relationships
- Re-tested through fresh BloodHound collection
- Confirmed as removed through final pathfinding

---

# 36. Lessons Learned

### 1. Group membership is an attack surface

Security reviews should evaluate not only direct privileged membership but also nested relationships.

### 2. Least privilege must include group architecture

A user can have apparently harmless direct memberships while still receiving significant effective privileges through nested groups.

### 3. Attack-path analysis provides context

Traditional group-membership lists show relationships individually.

BloodHound provides a graph view that helps analysts understand how those relationships combine into an attack path.

### 4. Baselines matter

The initial "Path Not Found" result established that the later attack path was introduced by the controlled configuration.

### 5. Remediation must be validated

Removing a group relationship is not sufficient evidence by itself.

The environment should be re-collected and the attack path should be tested again.

### 6. Identity security is a SOC concern

Privilege escalation can occur without malware or exploitation.

Unauthorized identity relationships can create equally significant security exposure.

---

# 37. Investigation Conclusion

The BloodHound investigation successfully demonstrated the complete lifecycle of an Active Directory attack-path finding.

A low-privileged account initially had no path to the privileged security boundary.

A controlled nested-group configuration then created the following path:

**BH_ENUM → Helpdesk-Tier1 → IT-Admins → Domain Admins**

BloodHound successfully visualized the path, while recursive Active Directory analysis validated the effective privilege relationship.

The configuration was subsequently remediated by removing the unnecessary group relationships.

A fresh BloodHound collection and clean dataset ingestion were then performed.

Final pathfinding returned:

**Path Not Found**

The finding was therefore successfully demonstrated, investigated, remediated, and independently validated.

---

# 38. Evidence Index

## Baseline

- [AD Domain Baseline](../screenshots/Day11/Day11-01-ADDC-Domain-Baseline.png)
- [AD Privileged Groups Baseline](../screenshots/Day11/Day11-02-AD-Privileged-Groups-Baseline.png)
- [bh_enum Low-Privilege Baseline](../screenshots/Day11/Day11-03-bh_enum-LowPrivilege-Baseline.png)

## BloodHound Collection and Initial Analysis

- [BloodHound AD Collection Success](../screenshots/Day11/Day11-04-BloodHound-AD-Collection-Success.png)
- [BloodHound Collection Dataset Extracted](../screenshots/Day11/Day11-05-BloodHound-Collection-Dataset-Extracted.png)
- [BloodHound CE Login](../screenshots/Day11/Day11-06-BloodHound-CE-Login.png)
- [BloodHound AD Dataset Ingest Complete](../screenshots/Day11/Day11-07-BloodHound-AD-Dataset-Ingest-Complete.png)
- [BloodHound Administrator Tier Zero Analysis](../screenshots/Day11/Day11-08-BloodHound-Administrator-TierZero-Analysis.png)
- [No Path from BH_ENUM to Administrator](../screenshots/Day11/Day11-09-BloodHound-No-Path-BH_ENUM-to-Administrator.png)

## Controlled Attack-Path Construction

- [BH_ENUM Helpdesk-Tier1 Membership](../screenshots/Day11/Day11-10-BH_ENUM-Helpdesk-Tier1-Membership.png)
- [IT-Admins Helpdesk-Tier1 Nested Group](../screenshots/Day11/Day11-11-IT-Admins-Helpdesk-Tier1-Nested-Group.png)
- [BloodHound Post-Misconfiguration Collection](../screenshots/Day11/Day11-12-BloodHound-Post-Misconfiguration-Collection.png)
- [BloodHound Post-Misconfiguration Ingest Complete](../screenshots/Day11/Day11-13-BloodHound-Post-Misconfiguration-Ingest-Complete.png)
- [Domain Admins IT-Admins Nested Group](../screenshots/Day11/Day11-14-Domain-Admins-IT-Admins-Nested-Group.png)
- [BloodHound Final Collection Success](../screenshots/Day11/Day11-15-BloodHound-Final-Collection-Success.png)
- [BloodHound Final Ingest Complete](../screenshots/Day11/Day11-16-BloodHound-Final-Ingest-Complete.png)

## Attack-Path Investigation

- [BH_ENUM to Domain Admins Attack Path](../screenshots/Day11/Day11-17-BloodHound-BH_ENUM-to-Domain-Admins-Attack-Path.png)
- [IT-Admins to Domain Admins MemberOf Relationship](../screenshots/Day11/Day11-18-BloodHound-IT-Admins-to-Domain-Admins-MemberOf.png)
- [Helpdesk-Tier1 to IT-Admins MemberOf Relationship](../screenshots/Day11/Day11-19-BloodHound-Helpdesk-Tier1-to-IT-Admins-MemberOf.png)
- [BH_ENUM to Helpdesk-Tier1 MemberOf Relationship](../screenshots/Day11/Day11-20-BloodHound-BH_ENUM-to-Helpdesk-Tier1-MemberOf.png)
- [BH_ENUM Effective Domain Admins Membership](../screenshots/Day11/Day11-21-BH_ENUM-Effective-Domain-Admins-Membership.png)

## Remediation and Validation

- [Domain Admins Remediation](../screenshots/Day11/Day11-22-Domain-Admins-Remediation-IT-Admins-Removed.png)
- [BloodHound Post-Remediation Collection](../screenshots/Day11/Day11-23-BloodHound-Post-Remediation-Collection.png)
- [BloodHound Clean Post-Remediation Ingest](../screenshots/Day11/Day11-24-BloodHound-Clean-Post-Remediation-Ingest.png)
- [BloodHound Remediation Path Removed](../screenshots/Day11/Day11-25-BloodHound-Remediation-Path-Removed.png)

---

# 39. Portfolio Significance

This investigation demonstrates practical experience with:

- Active Directory security
- Identity and access management
- Privilege escalation analysis
- BloodHound Community Edition
- BloodHound Python
- Active Directory enumeration
- Nested group analysis
- Tier Zero identification
- Attack-path analysis
- Security baseline creation
- Evidence collection
- SOC investigation methodology
- Risk assessment
- Remediation
- Post-remediation validation
- MITRE ATT&CK mapping

The strongest aspect of the investigation is that it demonstrates more than simply running BloodHound.

It shows the complete analyst workflow:

**Establish a baseline → identify a security relationship → validate the attack path → assess impact → remediate the configuration → re-collect telemetry → prove the path is gone.**

This is the type of workflow that translates well to **SOC Analyst, Blue Team, Identity Security, and Junior Cybersecurity Analyst** responsibilities.