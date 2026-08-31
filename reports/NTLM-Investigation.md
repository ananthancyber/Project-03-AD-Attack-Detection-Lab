# NTLM Authentication Investigation Report

## Incident / Investigation ID

**Investigation ID:** IR-NTLM-001  
**Project:** Project 03 — Active Directory Attack & Detection Lab  
**Investigation Type:** Authentication Anomaly Investigation  
**Severity:** Medium  
**Status:** Closed — Controlled Lab Validation  
**Detection Category:** Unexpected-Source NTLM Authentication  
**Primary Events:** Windows Security Event ID 4624 and Event ID 4776  
**Authentication Protocol:** NTLM / NTLMv2

---

# 1. Executive Summary

This investigation examined a successful NTLM authentication involving the domain account `CORP\pt_test` from an unexpected workstation.

A normal authentication baseline was first established for the test account. The expected authentication source was `WIN10-CLIENT` (`192.168.159.133`).

A controlled SMB authentication was subsequently performed from the Kali Linux system (`192.168.159.129`).

The authentication generated Windows Security Event ID `4624` and corresponding Domain Controller Event ID `4776` telemetry.

The Event ID `4624` record showed:

- Account: `pt_test`
- Domain: `CORP`
- Logon Type: `3`
- Workstation: `KALI`
- Source IP: `192.168.159.129`
- Authentication Package: `NTLM`
- Package Name: `NTLM V2`

The corresponding Event ID `4776` record showed:

- Logon Account: `pt_test`
- Source Workstation: `KALI`
- Error Code: `0x0`

The matching account, source workstation, and timestamp provided sufficient evidence to correlate the two events to the same authentication activity.

The authentication was intentionally generated as part of a controlled security lab. Therefore, the investigation does **not** conclude that the account was compromised or that credential theft occurred.

The investigation successfully validated a detection concept:

> **Successful NTLM authentication from an unexpected source should be investigated when the authentication context differs from the account's established baseline.**

---

# 2. Investigation Objective

The objective of this investigation was to determine whether an NTLM authentication event originating from an unexpected source could be detected, investigated, and correlated using native Windows Security telemetry.

The investigation specifically evaluated:

1. Whether successful NTLM authentication could be identified.
2. Whether the authentication source could be extracted.
3. Whether a normal authentication baseline could be established.
4. Whether an unexpected authentication source could be detected.
5. Whether Event ID `4624` could be correlated with Event ID `4776`.
6. Whether successful credential validation could be confirmed.
7. Whether repeatable detection queries could identify the behavior.
8. Whether the resulting telemetry was sufficient for SOC investigation.

---

# 3. Scope

## In Scope

The investigation covered:

- Active Directory authentication
- NTLM authentication
- SMB-based authentication
- Windows Security Event ID `4624`
- Windows Security Event ID `4776`
- Account `CORP\pt_test`
- Source workstation `WIN10-CLIENT`
- Source workstation `KALI`
- Source IP `192.168.159.133`
- Source IP `192.168.159.129`
- Authentication correlation
- Detection validation

## Out of Scope

The investigation did not attempt to prove:

- Credential theft
- Credential dumping
- Pass-the-Hash
- Password cracking
- Persistence
- Privilege escalation
- Actual malicious lateral movement
- Compromise of the `pt_test` account

The activity was intentionally generated within an isolated Active Directory lab.

---

# 4. Lab Environment

| Asset | Value |
|---|---|
| Domain | `corp.local` |
| NetBIOS Domain | `CORP` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Windows Client | `WIN10-CLIENT` |
| Windows Client IP | `192.168.159.133` |
| Security Test Host | `KALI` |
| Kali IP | `192.168.159.129` |
| Test Account | `CORP\pt_test` |
| Network Protocol | SMB |
| SMB Port | TCP/445 |
| Authentication | NTLM / NTLMv2 |
| Primary Event | `4624` |
| Correlation Event | `4776` |

---

# 5. Investigation Hypothesis

The investigation was based on the following hypothesis:

> If a domain account successfully performs a Type 3 NTLM authentication from a workstation or source IP that differs from its expected authentication baseline, the activity should be considered suspicious and investigated.

The hypothesis was further strengthened if:

- Event ID `4776` identified the same account.
- Event ID `4776` identified the same source workstation.
- Credential validation succeeded.
- The timestamps aligned with the Event ID `4624` activity.

The investigation therefore evaluated authentication behavior rather than treating NTLM itself as malicious.

---

# 6. Authentication Baseline

Before testing the suspicious source condition, normal authentication behavior was established for `CORP\pt_test`.

The expected authentication source was:

`WIN10-CLIENT`

Expected IP:

`192.168.159.133`

Expected authentication protocol:

`NTLM`

This baseline was important because an NTLM authentication from the normal workstation is not automatically suspicious.

The baseline created the following reference:

`CORP\pt_test → WIN10-CLIENT → NTLM`

The suspicious test would later produce:

`CORP\pt_test → KALI → NTLM`

The authentication protocol remained the same, while the source changed.

This source deviation became the primary anomaly investigated.

---

# 7. Test Account

A dedicated account was created specifically for controlled authentication testing:

`CORP\pt_test`

Using a dedicated test identity reduced ambiguity and avoided relying on an existing administrative account.

## Evidence

![PT Test Account Creation](../screenshots/Day07/Day07-08-PT-Test-Account-Creation.png)

**Evidence:** `Day07-08-PT-Test-Account-Creation.png`

The account was subsequently validated for use in the controlled authentication workflow.

![PT Test Local Access](../screenshots/Day07/Day07-09-PT-Test-Local-Access.png)

**Evidence:** `Day07-09-PT-Test-Local-Access.png`

---

# 8. SMB Connectivity Verification

Before generating authentication telemetry, SMB connectivity was verified.

SMB was selected because Windows network authentication over SMB can generate useful authentication telemetry for investigation.

## Evidence

![SMB Connectivity Verified](../screenshots/Day07/Day07-07-SMB-Connectivity-Verified.png)

**Evidence:** `Day07-07-SMB-Connectivity-Verified.png`

This confirmed that the lab environment was ready for the controlled SMB authentication test.

---

# 9. Normal Authentication Activity

The first authentication was performed from the expected Windows client.

Expected source:

`WIN10-CLIENT`

Source IP:

`192.168.159.133`

Account:

`CORP\pt_test`

## Evidence

![PT Test Normal Authentication](../screenshots/Day07/Day07-10-PT-Test-Normal-Authentication.png)

**Evidence:** `Day07-10-PT-Test-Normal-Authentication.png`

The corresponding Event ID `4776` telemetry was also identified.

![PT Test 4776 Success](../screenshots/Day07/Day07-11-PT-Test-4776-Success.png)

**Evidence:** `Day07-11-PT-Test-4776-Success.png`

The corresponding Event ID `4624` activity was then correlated.

![PT Test 4624 Correlation](../screenshots/Day07/Day07-12-PT-Test-4624-Correlation.png)

**Evidence:** `Day07-12-PT-Test-4624-Correlation.png`

Full normal NTLM telemetry was also examined.

![PT Test Full NTLM Telemetry](../screenshots/Day07/Day07-13-PT-Test-4624-Full-NTLM-Telemetry.png)

**Evidence:** `Day07-13-PT-Test-4624-Full-NTLM-Telemetry.png`

The baseline established:

| Attribute | Baseline |
|---|---|
| Account | `pt_test` |
| Source Host | `WIN10-CLIENT` |
| Source IP | `192.168.159.133` |
| Logon Type | `3` |
| Authentication | `NTLM` |
| Package | `NTLM V2` |

---

# 10. Controlled Suspicious Authentication

After establishing the baseline, the same test account was used from the Kali Linux host.

Source workstation:

`KALI`

Source IP:

`192.168.159.129`

Account:

`CORP\pt_test`

The authentication was performed through SMB.

## Evidence

![PT Test SMB Authentication](../screenshots/Day07/Day07-14-PT-Test-SMB-Authentication.png)

**Evidence:** `Day07-14-PT-Test-SMB-Authentication.png`

This activity was intentionally generated to test whether the change in authentication source could be detected.

---

# 11. Event ID 4624 Analysis

Event ID `4624` was identified on the Windows client following the controlled authentication.

## Evidence

![PT Test Kali 4624 Detection](../screenshots/Day07/Day07-15-PT-Test-Kali-4624-Detection.png)

**Evidence:** `Day07-15-PT-Test-Kali-4624-Detection.png`

The full event telemetry was then examined.

![PT Test Kali 4624 Full Telemetry](../screenshots/Day07/Day07-16-PT-Test-Kali-4624-Full-Telemetry.png)

**Evidence:** `Day07-16-PT-Test-Kali-4624-Full-Telemetry.png`

## Observed Fields

| Field | Observed Value |
|---|---|
| Event ID | `4624` |
| Account Name | `pt_test` |
| Account Domain | `CORP` |
| Logon Type | `3` |
| Workstation Name | `KALI` |
| Source Network Address | `192.168.159.129` |
| Logon Process | `NtLmSsp` |
| Authentication Package | `NTLM` |
| Package Name | `NTLM V2` |
| Key Length | `128` |

### Interpretation

The event confirms that the `pt_test` account successfully performed a Type 3 network authentication using NTLM.

The primary anomaly was the authentication source:

`KALI`

This differed from the established baseline:

`WIN10-CLIENT`

---

# 12. Event ID 4776 Analysis

The Domain Controller was then examined for Event ID `4776`.

The event showed credential validation activity for the same test account.

## Evidence

![PT Test Kali 4776 Correlation](../screenshots/Day07/Day07-17-PT-Test-Kali-4776-Correlation.png)

**Evidence:** `Day07-17-PT-Test-Kali-4776-Correlation.png`

## Observed Fields

| Field | Observed Value |
|---|---|
| Event ID | `4776` |
| Logon Account | `pt_test` |
| Source Workstation | `KALI` |
| Error Code | `0x0` |

### Interpretation

The `0x0` result indicates successful credential validation.

This provides Domain Controller-side evidence supporting the successful authentication observed in Event ID `4624`.

---

# 13. Event Correlation

The Event ID `4624` and Event ID `4776` records were correlated using:

- Account
- Source workstation
- Authentication context
- Timestamp

The observed relationship was:

| Attribute | Event 4624 | Event 4776 |
|---|---|---|
| Account | `pt_test` | `pt_test` |
| Source | `KALI` | `KALI` |
| Authentication | NTLM | Credential Validation |
| Result | Successful | `0x0` |
| Timestamp | `30-08-2026 23:39:33` | `30-08-2026 23:39:33` |

The matching values provide strong evidence that both events relate to the same controlled authentication activity.

---

# 14. Timeline

| Time | Activity |
|---|---|
| Before test | Normal authentication baseline established |
| Before suspicious test | SMB connectivity verified |
| Test execution | `pt_test` used from Kali |
| `23:39:33` | Event ID `4624` recorded successful NTLM network logon |
| `23:39:33` | Event ID `4776` recorded successful credential validation |
| After authentication | 4624 and 4776 events correlated |
| After correlation | Detection queries validated |

The exact timestamps were taken from the Windows Security event telemetry collected during the lab.

---

# 15. Detection Validation

Two detection queries were validated during the investigation.

## 15.1 Event ID 4624 Detection

The query searched for:

- Event ID `4624`
- Account `pt_test`
- Source `KALI`
- NTLM authentication

## Evidence

![NTLM Suspicious 4624 Detection Query](../screenshots/Day07/Day07-18-NTLM-Suspicious-4624-Detection-Query.png)

**Evidence:** `Day07-18-NTLM-Suspicious-4624-Detection-Query.png`

The query successfully returned the expected suspicious authentication.

---

## 15.2 Event ID 4776 Detection

The second query searched for:

- Event ID `4776`
- Account `pt_test`
- Source `KALI`
- Successful credential validation
- Error Code `0x0`

## Evidence

![NTLM Suspicious 4776 Detection Query](../screenshots/Day07/Day07-19-NTLM-Suspicious-4776-Detection-Query.png)

**Evidence:** `Day07-19-NTLM-Suspicious-4776-Detection-Query.png`

The query successfully returned the expected credential-validation event.

---

# 16. Detection Assessment

The investigation validated the following detection condition:

> **A domain account performs successful Type 3 NTLM authentication from a source that differs from its established authentication baseline.**

Confidence is increased when:

- Event ID `4624` confirms successful network authentication.
- Authentication Package is NTLM.
- Event ID `4776` confirms credential validation.
- Error Code is `0x0`.
- Account identity matches.
- Source workstation matches.
- Timestamps correlate.

This provides a stronger detection than simply alerting on NTLM usage.

---

# 17. Key Finding

## Finding F-001 — Unexpected-Source NTLM Authentication

**Severity:** Medium  
**Status:** Validated  
**Confidence:** High for observed lab activity

The `CORP\pt_test` account successfully authenticated using NTLM from `KALI` (`192.168.159.129`) instead of its established baseline source `WIN10-CLIENT` (`192.168.159.133`).

The authentication generated:

- Event ID `4624`
- Logon Type `3`
- NTLM authentication
- NTLM V2
- Source workstation `KALI`
- Source IP `192.168.159.129`

The Domain Controller generated Event ID `4776` for:

- Account `pt_test`
- Source workstation `KALI`
- Error Code `0x0`

The events were successfully correlated.

---

# 18. Security Interpretation

The authentication should be considered suspicious from a behavioral-detection perspective because the source changed from the established baseline.

The relevant behavioral pattern is:

**Valid Account + Successful Authentication + Unexpected Source**

This pattern can be important in real environments because attackers who obtain valid credentials may attempt to use them from systems that are not normally associated with the account.

However, the same pattern can also occur legitimately.

Therefore, the detection should initiate investigation rather than automatically declare compromise.

---

# 19. False Positive Analysis

Potential legitimate causes include:

### Administrative Activity

An administrator may authenticate from a different workstation during troubleshooting or emergency operations.

### Service Accounts

Applications and infrastructure services may use accounts from multiple hosts.

### Legacy Applications

Older applications may depend on NTLM.

### Backup Infrastructure

Backup systems may authenticate against multiple Windows systems.

### Monitoring Systems

Monitoring or management infrastructure may generate network authentication.

### New Workstations

A newly deployed workstation may legitimately become a new authentication source.

### Security Testing

Penetration testing or authorized security validation can intentionally produce this behavior.

The lab itself represents this final category.

---

# 20. Investigation Recommendations

If this alert occurred in a production environment, the analyst should perform the following checks.

## Account Investigation

Determine:

- Account owner
- Account type
- Privilege level
- Whether the account normally authenticates from the observed source
- Recent password changes
- Recent administrative activity

## Source Investigation

Determine:

- Host owner
- Host role
- IP address
- Whether the workstation is managed
- Whether the source is authorized
- Other authentication activity from the source

## Authentication Investigation

Search for:

- Additional Event ID `4624`
- Additional Event ID `4776`
- Failed authentication attempts
- Authentication from additional hosts
- Authentication to multiple systems
- Unusual authentication times

## Endpoint Investigation

If the source is suspicious, review:

- Process creation
- Network connections
- PowerShell activity
- Remote execution
- Privilege escalation
- Security-tool alerts
- Credential-access indicators

---

# 21. Recommended Response

If the activity is confirmed to be unauthorized:

1. Validate the affected account.
2. Determine whether the account is privileged.
3. Identify all recent authentication sources.
4. Investigate the originating workstation.
5. Search for additional lateral-movement activity.
6. Review endpoint telemetry on the source host.
7. Restrict or disable the account when appropriate.
8. Reset credentials according to incident-response procedures.
9. Preserve relevant logs and evidence.
10. Continue monitoring for additional authentication activity.

Response actions should be performed according to the organization's incident-response procedures.

---

# 22. MITRE ATT&CK Mapping

## T1078 — Valid Accounts

**Relevance:** High

The investigation demonstrated successful authentication using a valid domain account.

Observed behavior:

`Valid Account → Successful Authentication → Unexpected Source`

The lab does not establish how the credentials were obtained.

Therefore, the detection identifies behavior consistent with potential misuse of valid credentials but does not prove credential theft.

---

## T1021.002 — SMB/Windows Admin Shares

**Relevance:** Supporting

The controlled authentication used SMB as the network authentication path.

The experiment demonstrates SMB-related authentication telemetry.

It does not claim that malicious administrative-share abuse or successful malicious lateral movement occurred.

---

# 23. Detection Limitations

## NTLM Is Not Inherently Malicious

NTLM remains present in many Windows environments.

A detection that alerts on every NTLM authentication would generate excessive noise.

## Baselines Can Change

Users may legitimately authenticate from new workstations.

The expected-source baseline must therefore be maintained.

## Event 4624 Alone Is Not Sufficient

A successful authentication event provides important context but does not establish malicious intent.

## Event 4776 Alone Is Not Sufficient

Successful credential validation confirms authentication processing but does not prove compromise.

## Additional Telemetry Is Required

A production SOC should correlate authentication events with:

- Endpoint telemetry
- Process creation
- Network activity
- Account activity
- Privilege changes
- Other SIEM detections

---

# 24. Severity Rationale

**Assigned Severity: Medium**

The activity contains several characteristics that justify investigation:

- Successful authentication
- Domain account
- NTLM authentication
- Type 3 network logon
- Unexpected source
- Successful credential validation

However, the activity was intentionally generated within the lab.

There was no independent evidence demonstrating:

- Credential theft
- Credential dumping
- Pass-the-Hash
- Persistence
- Privilege escalation
- Malicious lateral movement

Therefore, Medium is appropriate for the demonstrated detection scenario.

In production, severity should be dynamically adjusted according to:

- Account privilege
- Source reputation
- Destination
- Number of systems accessed
- Authentication frequency
- Time of activity
- Other correlated indicators

---

# 25. Evidence Index

| Evidence ID | Artifact | Purpose |
|---|---|---|
| E01 | `Day07-01-NTLM-4776-Baseline.png` | Initial NTLM 4776 baseline |
| E02 | `Day07-02-NTLM-Authentication-Test.png` | NTLM authentication test |
| E03 | `Day07-03-NTLM-4624-Correlation.png` | Initial 4624 correlation |
| E04 | `Day07-04-NTLM-Detection-Query.png` | Initial detection query |
| E05 | `Day07-05-NTLM-4624-Full-Telemetry.png` | Full 4624 telemetry |
| E06 | `Day07-06-NTLM-4776-Correlation-Query.png` | 4776 correlation query |
| E07 | `Day07-07-SMB-Connectivity-Verified.png` | SMB connectivity validation |
| E08 | `Day07-08-PT-Test-Account-Creation.png` | Dedicated test account creation |
| E09 | `Day07-09-PT-Test-Local-Access.png` | Test account validation |
| E10 | `Day07-10-PT-Test-Normal-Authentication.png` | Normal authentication baseline |
| E11 | `Day07-11-PT-Test-4776-Success.png` | Baseline 4776 validation |
| E12 | `Day07-12-PT-Test-4624-Correlation.png` | Baseline 4624 correlation |
| E13 | `Day07-13-PT-Test-4624-Full-NTLM-Telemetry.png` | Full baseline NTLM telemetry |
| E14 | `Day07-14-PT-Test-SMB-Authentication.png` | Controlled SMB authentication |
| E15 | `Day07-15-PT-Test-Kali-4624-Detection.png` | Suspicious 4624 detection |
| E16 | `Day07-16-PT-Test-Kali-4624-Full-Telemetry.png` | Full suspicious 4624 telemetry |
| E17 | `Day07-17-PT-Test-Kali-4776-Correlation.png` | Suspicious 4776 correlation |
| E18 | `Day07-18-NTLM-Suspicious-4624-Detection-Query.png` | Validated 4624 query |
| E19 | `Day07-19-NTLM-Suspicious-4776-Detection-Query.png` | Validated 4776 query |

---

# 26. Evidence Chain

The complete investigation chain is:

**Baseline**

`CORP\pt_test`

↓

`WIN10-CLIENT`

↓

`192.168.159.133`

↓

**Normal NTLM Authentication**

↓

**Controlled Source Change**

`KALI`

↓

`192.168.159.129`

↓

**SMB Authentication**

↓

**Event 4624**

`pt_test + Type 3 + NTLM + KALI`

↓

**Event 4776**

`pt_test + KALI + Error 0x0`

↓

**Correlation**

`Same Account + Same Source + Matching Timestamp`

↓

**Detection**

`Unexpected-Source NTLM Authentication`

↓

**SOC Investigation**

---

# 27. Investigation Conclusion

The investigation successfully validated an unexpected-source NTLM authentication detection scenario.

The controlled test demonstrated that:

- A dedicated domain account could be used to establish an authentication baseline.
- Normal authentication could be associated with an expected workstation.
- SMB authentication from Kali generated Windows authentication telemetry.
- Event ID `4624` identified the successful Type 3 NTLM network logon.
- Event ID `4624` identified `KALI` as the source workstation.
- Event ID `4624` identified `192.168.159.129` as the source IP.
- Event ID `4776` identified the same `pt_test` account.
- Event ID `4776` identified `KALI` as the source workstation.
- Event ID `4776` returned Error Code `0x0`.
- The two events could be correlated.
- Repeatable detection queries successfully identified the activity.

The final security conclusion is:

> **The authentication was successful, but its source differed from the established baseline. This behavioral deviation is a valid SOC investigation signal.**

Because the authentication was intentionally generated in the controlled lab, the evidence should not be interpreted as proof of real-world compromise.

---

# 28. Analyst Assessment

**Finding:** Unexpected-source NTLM authentication  
**Severity:** Medium  
**Confidence:** High for controlled lab activity  
**Disposition:** Benign / Authorized Lab Activity  
**Detection:** Validated  
**Further Production Investigation:** Required if observed outside the lab

The most important lesson from this investigation is that **authentication context matters more than authentication success alone**.

A mature SOC should ask:

> Who authenticated?

> From where?

> Using which protocol?

> Was that source expected?

> Was the authentication successful?

> Can the activity be correlated with Domain Controller telemetry?

> What happened immediately before and after the authentication?

This investigation demonstrated that approach using native Windows Security telemetry.

---

# 29. Related Detection

The reusable detection developed from this investigation is documented separately in:

`detections/NTLM-Unexpected-Source-4624-4776.md`

The detection artifact contains the detection logic, investigation workflow, tuning considerations, false-positive analysis, and operational recommendations.

---

# 30. Investigation Status

**STATUS: CLOSED — CONTROLLED LAB VALIDATION**

The detection was successfully reproduced, investigated, correlated, and documented.

No additional remediation was required because the observed authentication was intentionally generated as part of the Active Directory security lab.

---

# 31. Final Security Takeaway

> **A successful authentication is not automatically a legitimate authentication.**

Authentication source, account identity, protocol, timing, and correlated Domain Controller telemetry provide the context required to determine whether an authentication event deserves investigation.

Day 7 demonstrated this principle by establishing a normal authentication baseline and then identifying the same account authenticating from an unexpected source.

**Baseline → Anomaly → Telemetry → Correlation → Detection → Investigation**

This is the core workflow demonstrated by the investigation.