# Pass-the-Hash Detection — Wazuh Rule 92652

## Detection Overview

This detection identifies successful remote **NTLM network authentication** that may indicate **Pass-the-Hash (PtH)** activity.

The detection uses Wazuh's existing Windows EventChannel rules to correlate:

**Successful Windows Logon → Remote Source → NTLM Authentication → Potential Pass-the-Hash**

In this lab, the detection was validated through a controlled Pass-the-Hash simulation using the dedicated `CORP\pt_test` account.

> **Important:** NTLM authentication alone does not prove Pass-the-Hash. The Wazuh alert identifies a suspicious authentication pattern that requires analyst correlation with source host, account behavior, authentication history, and attack context.

---

## Detection Metadata

| Field | Value |
|---|---|
| Detection Name | Pass-the-Hash / Suspicious Remote NTLM Authentication |
| SIEM | Wazuh 4.14.6 |
| Primary Rule | `92652` |
| Parent Rule | `92651` |
| Windows Event ID | `4624` |
| Authentication Protocol | NTLM |
| Logon Type | `3` — Network |
| Severity | Medium-High / Level 6 |
| MITRE ATT&CK | T1550.002 — Pass the Hash |
| Secondary Mapping | T1078 — Valid Accounts |
| Log Source | Windows Security Event Log |
| Endpoint | `WIN10-CLIENT` |
| Test Account | `CORP\pt_test` |

---

# 1. Detection Objective

The objective of this detection is to identify remote NTLM authentication that may represent credential reuse or Pass-the-Hash activity.

The detection is particularly useful when:

- NTLM is used for a remote network logon.
- The source system is unexpected.
- The account is privileged or sensitive.
- The source IP is unusual for the account.
- Multiple systems are accessed using the same account.
- The authentication occurs outside the user's normal behavior.

---

# 2. Required Telemetry

The detection relies primarily on Windows Security Event ID `4624`.

Important fields include:

| Field | Purpose |
|---|---|
| `eventID` | Identifies successful logon |
| `logonType` | Identifies network authentication |
| `authenticationPackageName` | Identifies NTLM authentication |
| `targetUserName` | Identifies authenticated account |
| `ipAddress` | Identifies authentication source |
| `logonProcessName` | Provides authentication-process context |
| `lmPackageName` | Identifies NTLM version/package |

The Domain Controller's Event ID `4776` provides additional authentication-validation context.

---

# 3. Wazuh Detection Chain

The detection is implemented through two related Wazuh rules.

## Rule 92651 — Successful Remote Logon

Rule `92651` acts as the parent condition.

It identifies successful Windows logons originating from a remote, non-loopback IPv4 address.

Conceptually:

**Windows Successful Logon**
→ Remote Source IP
→ Non-loopback Source
→ `Rule 92651`

The rule is associated with:

**MITRE T1078 — Valid Accounts**

---

## Rule 92652 — NTLM Remote Logon

Rule `92652` builds on Rule `92651`.

The rule checks whether the authentication package is:

`NTLM`

When the parent condition and NTLM condition are satisfied, Wazuh generates:

**Successful Remote Logon Detected**

with:

**Rule Level: 6**

The rule description identifies the authentication as potentially consistent with a Pass-the-Hash attack.

The rule is mapped to:

- **T1550.002 — Pass the Hash**
- **T1078 — Valid Accounts**

---

# 4. Detection Logic

The effective detection chain can be represented as:

**Event 4624**
→ Successful Logon

↓

**Rule 60106**
→ Windows Logon Success

↓

**Rule 92651**
→ Remote Logon from Non-Loopback Source

↓

**Rule 92652**
→ Authentication Package = NTLM

↓

**Level 6 Alert**
→ Potential Pass-the-Hash Activity

---

# 5. Detection Validation

A controlled PtH authentication was performed from the Kali attacker system against `WIN10-CLIENT`.

The dedicated test account `CORP\pt_test` was used.

The authentication successfully established an SMB session using NTLM credential material.

![Controlled Pass-the-Hash Authentication](../screenshots/Day09/Day09-05-Kali-PassTheHash-SMB-Authentication.png)

The test was repeated after confirming that the Wazuh agent on `WIN10-CLIENT` was online.

![Pass-the-Hash Authentication with Wazuh Online](../screenshots/Day09/Day09-09-Kali-PtH-SMB-Authentication-Wazuh-Online.png)

> Any credential hash shown in raw terminal output must remain redacted before public publication.

---

# 6. Windows Event 4624 Validation

The target endpoint generated Windows Security Event ID `4624`.

The event showed:

| Field | Observed Value |
|---|---|
| Account | `CORP\pt_test` |
| Event ID | `4624` |
| Logon Type | `3` — Network |
| Authentication Package | `NTLM` |
| NTLM Package | `NTLM V2` |
| Logon Process | `NtLmSsp` |
| Source IP | `192.168.159.129` |
| Target | `WIN10-CLIENT` |

![Windows 10 PtH 4624 NTLM Network Logon](../screenshots/Day09/Day09-06-Windows10-PtH-4624-NTLM-Network-Logon.png)

### Detection Significance

The combination of:

**Logon Type 3 + NTLM + Remote Source IP**

is more significant than a generic successful logon.

However, this combination should still be investigated rather than automatically classified as malicious.

---

# 7. Domain Controller Event 4776 Correlation

The Domain Controller generated Event ID `4776` for the same test account.

The correlated event occurred approximately one second before the target-side 4624 event.

![AD-DC PtH 4776 Correlation](../screenshots/Day09/Day09-07-ADDC-PtH-4776-Correlation.png)

The full telemetry showed:

| Field | Value |
|---|---|
| Event ID | `4776` |
| Logon Account | `pt_test` |
| Authentication Package | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` |
| Error Code | `0x0` |
| Authentication Result | Successful |

![AD-DC PtH 4776 Full Telemetry](../screenshots/Day09/Day09-08-ADDC-PtH-4776-Full-Telemetry.png)

### Correlation

The authentication sequence was:

**23:25:09**
→ AD-DC `4776`
→ `pt_test` credentials validated successfully

↓

**23:25:10**
→ WIN10 `4624`
→ Network Logon Type `3`
→ NTLM
→ Source `192.168.159.129`

This correlation strengthens the authentication investigation.

---

# 8. Wazuh Alert Validation

After the fresh PtH simulation was performed while the Wazuh agent was online, Wazuh generated a Rule `92652` alert.

The alert was observed on:

**WIN10-CLIENT**

with:

**Rule ID: 92652**

**Rule Level: 6**

**Description: Successful Remote Logon Detected**

The Wazuh event contained the expected account and authentication information.

![Wazuh PtH 4624 Document Details](../screenshots/Day09/Day09-10-Wazuh-PtH-4624-NTLM-Document-Details-01.png)

Additional fields confirmed:

- `targetUserName = pt_test`
- `authenticationPackageName = NTLM`
- `lmPackageName = NTLM V2`
- `logonProcessName = NtLmSsp`
- `logonType = 3`
- `ipAddress = 192.168.159.129`

![Wazuh PtH 4624 Authentication Details](../screenshots/Day09/Day09-11-Wazuh-PtH-4624-NTLM-Document-Details-02.png)

The key detection fields were also validated directly in the Wazuh event.

![Wazuh PtH 4624 Key Fields](../screenshots/Day09/Day09-12-Wazuh-PtH-4624-Key-Fields.png)

---

# 9. Alert Timestamp

The primary Wazuh alert used for validation occurred at:

**September 3, 2026 @ 15:22:03.826**

| Field | Value |
|---|---|
| Agent | `WIN10-CLIENT` |
| Agent ID | `002` |
| Rule | `92652` |
| Rule Level | `6` |
| Detection | Successful Remote Logon Detected |

The alert was generated from the Windows Security Event `4624` telemetry collected by the Wazuh agent.

---

# 10. Detection Assessment

The detection was successfully validated.

### Observed Attack Chain

**Kali**
`192.168.159.129`

↓

**NTLM hash-based authentication**

↓

**WIN10-CLIENT**

↓

**Windows Event 4624**

`pt_test + Logon Type 3 + NTLM`

↓

**Wazuh Rule 92651**

Remote successful logon

↓

**Wazuh Rule 92652**

NTLM authentication

↓

**Level 6 Alert**

Potential Pass-the-Hash

---

# 11. Analyst Investigation Fields

When investigating this alert, an analyst should prioritize the following fields.

### Identity

- Username
- Domain
- Account privilege level
- Account ownership
- Recent password changes

### Source

- Source IP
- Hostname
- Asset ownership
- Whether the source is an approved administrative workstation
- Previous activity from the source

### Authentication

- Event ID
- Logon Type
- Authentication Package
- Logon Process
- Logon ID
- Authentication timestamp

### Target

- Destination hostname
- Server role
- Criticality
- Previous authentication history

### Behavioral Context

- Frequency of authentication
- First-seen source
- Multiple destination systems
- Multiple accounts from the same source
- Other suspicious activity on the source host

---

# 12. False Positives

Legitimate NTLM remote authentication can trigger this detection.

Potential false-positive scenarios include:

- Legacy applications requiring NTLM.
- Administrative tools using NTLM.
- File-server authentication.
- Service accounts using NTLM.
- Older Windows systems.
- Applications that do not support Kerberos.
- Approved remote administration.

### Recommended Tuning

Do not immediately whitelist all NTLM activity.

Instead, baseline:

- Known administrative hosts
- Known service accounts
- Expected source IPs
- Expected destination systems
- Normal authentication frequency

An authentication becomes more suspicious when it deviates from the established baseline.

---

# 13. Severity Assessment

### Default Wazuh Severity

**Level 6 — Medium-High**

### Recommended SOC Assessment

The final severity should depend on context.

| Scenario | Suggested Severity |
|---|---|
| Known administrative source | Low / Medium |
| Unusual source for standard user | Medium |
| Unusual source + privileged account | High |
| Privileged account + unexpected source + lateral movement | Critical |

The Wazuh Level 6 alert should therefore be treated as an **investigation trigger**, not an automatic incident verdict.

---

# 14. MITRE ATT&CK Mapping

## T1550.002 — Pass the Hash

**Tactic:** Defense Evasion / Credential Access

Attackers can use NTLM credential hashes to authenticate without knowing the plaintext password.

This was the primary technique demonstrated during the controlled lab exercise.

## T1078 — Valid Accounts

**Tactic:** Defense Evasion / Persistence / Privilege Escalation / Initial Access

The authentication used a legitimate domain account:

`CORP\pt_test`

The detection demonstrates how legitimate credentials can be abused from an unexpected source.

---

# 15. Investigation Workflow

A SOC analyst receiving Rule `92652` should follow this workflow:

### 1. Validate the Authentication

Confirm:

- Account
- Source IP
- Destination host
- Logon Type
- Authentication Package
- Timestamp

### 2. Validate the Source

Determine whether the source system is:

- Authorized
- Expected for the user
- An administrative workstation
- A known server
- Potentially compromised

### 3. Investigate the Account

Determine:

- Privilege level
- Normal login locations
- Recent password changes
- Recent authentication anomalies
- Other systems accessed

### 4. Correlate Events

Review:

- Event `4624`
- Event `4776`
- Wazuh Rule `92651`
- Wazuh Rule `92652`
- Sysmon telemetry
- Other endpoint activity

### 5. Establish Scope

Search for:

- Additional remote logons
- Additional destination hosts
- Additional accounts
- Repeated NTLM authentication
- Lateral movement

### 6. Determine Impact

Assess whether the account was used to:

- Access sensitive resources
- Move laterally
- Access administrative shares
- Execute commands
- Access privileged systems

---

# 16. Sysmon Role

Sysmon was enabled and verified on `WIN10-CLIENT` as part of the endpoint telemetry architecture.

![Windows 10 Sysmon Process Baseline](../screenshots/Day09/Day09-03-Windows10-Sysmon-Process-Baseline.png)

During the specific authentication window, no relevant Sysmon Event ID `1` process-creation event was observed.

This is not unexpected because a successful SMB authentication does not necessarily result in a new process being created on the target.

Therefore, Sysmon is treated as **supporting endpoint telemetry**, while the primary PtH detection relies on:

- Windows Security Event `4624`
- Domain Controller Event `4776`
- Wazuh Rule `92652`

---

# 17. Detection Strengths

This detection provides several useful capabilities:

- Detects successful remote NTLM authentication.
- Identifies unusual remote authentication patterns.
- Provides source IP visibility.
- Integrates directly with Windows Security telemetry.
- Maps suspicious activity to MITRE ATT&CK.
- Provides a Level 6 Wazuh alert.
- Can be correlated with Domain Controller authentication events.
- Supports investigation of potential credential reuse and lateral movement.

---

# 18. Detection Limitations

The detection has important limitations.

### NTLM Does Not Equal Pass-the-Hash

A legitimate application can use NTLM.

Therefore:

**NTLM authentication ≠ confirmed PtH**

The analyst must correlate:

**Identity + Source + Destination + Authentication + Behavior**

### No Hash-Level Proof

The Windows Security event does not directly indicate whether the password or NTLM hash was used.

The PtH conclusion in this lab was established because the authentication was deliberately generated using the known test account's NTLM hash.

In a production investigation, additional endpoint and identity telemetry would be required to increase confidence.

---

# 19. Recommended Defensive Response

If this alert occurs in a production environment:

### Immediate Actions

1. Validate whether the source IP is authorized.
2. Investigate the affected account.
3. Review recent authentication activity.
4. Investigate the source endpoint for compromise.
5. Search for additional lateral movement.
6. Reset credentials if compromise is confirmed.
7. Isolate the source host when appropriate.

### Long-Term Hardening

- Reduce unnecessary NTLM usage.
- Prefer Kerberos where supported.
- Enforce least privilege.
- Protect privileged accounts.
- Restrict administrative logons.
- Monitor abnormal authentication sources.
- Maintain authentication baselines.
- Strengthen endpoint detection coverage.

---

# 20. Detection Validation Summary

| Validation | Result |
|---|---|
| PtH simulation | Successful |
| Windows 4624 | Confirmed |
| Logon Type 3 | Confirmed |
| NTLM authentication | Confirmed |
| Kali source IP | `192.168.159.129` |
| AD-DC 4776 | Confirmed |
| Credential validation | Successful |
| Wazuh ingestion | Confirmed |
| Wazuh Rule 92652 | Triggered |
| Rule Level | `6` |
| MITRE T1550.002 | Mapped |
| MITRE T1078 | Mapped |
| Sysmon Event 1 during authentication | Not observed |

---

# 21. Conclusion

The Pass-the-Hash detection was successfully validated using a controlled Active Directory lab scenario.

The attack generated a complete defensive telemetry chain:

**NTLM Hash-Based Authentication**

→ **AD-DC Event 4776**

→ **WIN10 Event 4624**

→ **Remote Logon Type 3**

→ **NTLM Authentication**

→ **Wazuh Rule 92651**

→ **Wazuh Rule 92652**

→ **Level 6 Detection**

→ **MITRE ATT&CK T1550.002 / T1078**

The exercise demonstrates that effective SOC detection is not based on a single event. Instead, analysts should correlate **authentication protocol, account identity, source system, destination system, timing, and behavioral context** before determining whether an alert represents malicious activity.

**Detection Status: Validated in Controlled Lab Environment**