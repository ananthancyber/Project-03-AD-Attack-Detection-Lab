# Detection — Kerberoasting via Windows Event 4769

## Detection ID

`DET-AD-001`

## Detection Name

**Suspicious Kerberos TGS Request — Potential Kerberoasting**

## Detection Status

**Validated in Lab**

## Detection Type

**Behavioral / Credential Access**

## Severity

**Medium by default**

**High when multiple indicators correlate**

## MITRE ATT&CK

**Tactic:** Credential Access

**Technique:** T1558 — Steal or Forge Kerberos Tickets

**Sub-technique:** T1558.003 — Kerberoasting

---

# 1. Detection Objective

Detect potentially malicious Kerberos service-ticket requests that may indicate **Kerberoasting** activity.

The detection focuses primarily on Windows Security Event ID `4769`, which records Kerberos service-ticket requests.

The strongest detection signals are:

- Successful Event ID `4769`
- RC4 encryption type `0x17`
- Requests targeting SPN-backed service accounts
- Unusual requester-to-service relationships
- Multiple TGS requests from the same account within a short period
- Deviation from the normal Kerberos encryption baseline

The detection should use multiple indicators rather than treating RC4 alone as definitive proof of malicious activity.

---

# 2. Why Event ID 4769 Matters

Windows Security Event ID `4769` is generated when a Kerberos service ticket is requested.

Kerberoasting abuses this normal Kerberos functionality to request TGS tickets for SPN-backed service accounts.

The resulting ticket material may potentially be subjected to offline password cracking.

MITRE ATT&CK identifies this behavior as:

**T1558.003 — Kerberoasting**

---

# 3. Required Telemetry

## Primary Data Source

**Windows Security Event Log**

## Primary Event

`4769`

## Required Fields

The following fields are useful for detection and investigation:

| Field | Purpose |
|---|---|
| Event ID | Identifies the Kerberos service-ticket request |
| Account Name | Identifies the requesting account |
| Service Name | Identifies the requested service |
| Client Address | Identifies the source system |
| Ticket Encryption Type | Identifies the encryption used |
| Failure Code | Determines whether the request succeeded |
| Ticket Options | Provides additional Kerberos request context |
| TimeCreated | Supports temporal correlation |

---

# 4. Primary Detection Logic

The primary high-value signal is:

    Event ID = 4769
        AND
    Failure Code = 0x0
        AND
    Ticket Encryption Type = 0x17

Where:

- `4769` = Kerberos service-ticket request
- `0x0` = successful request
- `0x17` = RC4-HMAC

RC4 is an important Kerberoasting indicator because Kerberoasting tools may request RC4-encrypted service tickets that can be subjected to offline password attacks.

However:

**RC4 alone is not sufficient to confirm Kerberoasting.**

---

# 5. PowerShell Detection Query — Lab Validation

The following query was validated against the Windows Security log during the lab exercise:

    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
    Where-Object {
        $_.Message -match 'Ticket Encryption Type:\s+0x17' -and
        $_.Message -match 'Failure Code:\s+0x0'
    } |
    Select-Object -First 20 TimeCreated, Id, Message

## Expected Result

The query should return successful Event 4769 records using RC4 encryption.

During the lab, the query identified the simulated Kerberoasting event.

---

# 6. Targeted Validation Query

During the controlled attack, the target service account was known to be:

`svc_sql`

A targeted query was used to validate the attack:

    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
    Where-Object {
        $_.Message -match 'svc_sql' -and
        $_.Message -match '0x17'
    } |
    Select-Object -First 10 TimeCreated, Id, Message

This query successfully identified the attack-related Event 4769.

The targeted query is useful for **lab validation**, but should not be the final production detection because it depends on knowing the target account in advance.

---

# 7. Generalized Detection

A more useful detection does not hardcode the service account.

The generalized logic is:

    Event ID 4769
        +
    Successful request
        +
    RC4 / 0x17
        ↓
    Suspicious Kerberos TGS Request
        ↓
    Investigate requester + service + source + baseline

Validated query:

    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
    Where-Object {
        $_.Message -match 'Ticket Encryption Type:\s+0x17' -and
        $_.Message -match 'Failure Code:\s+0x0'
    } |
    Select-Object -First 20 TimeCreated, Id, Message

---

# 8. Detection Correlation Logic

The strongest detection should correlate multiple indicators.

## Indicator 1 — Event ID

`4769`

## Indicator 2 — Encryption

`0x17 / RC4`

## Indicator 3 — Successful Request

`Failure Code = 0x0`

## Indicator 4 — SPN Context

The requested service is associated with an SPN-backed service account.

## Indicator 5 — Requester Context

The requesting account does not normally request tickets for the target service.

## Indicator 6 — Source Context

The request originates from an unusual workstation or source IP.

## Indicator 7 — Volume

The account requests multiple service tickets within a short period.

## Indicator 8 — Baseline Deviation

RC4 usage is unusual compared with the environment's normal Kerberos encryption profile.

---

# 9. High-Confidence Detection

A high-confidence detection can be represented as:

    4769
      +
    Successful Request
      +
    RC4 / 0x17
      +
    SPN-backed Service Account
      +
    Unusual Requester or Source
      +
    Baseline Deviation
      ↓
    HIGH-CONFIDENCE KERBEROASTING INDICATOR

This approach is preferred over:

    RC4 = Kerberoasting

because legitimate legacy systems may still generate RC4 traffic.

---

# 10. Volume-Based Detection

Kerberoasting may involve an account requesting service tickets for multiple SPNs within a short period.

A useful behavioral detection is therefore:

    Event ID = 4769
        AND
    Encryption Type = 0x17
        AND
    Multiple unique Service Names
        AND
    Same Account Name
        AND
    Short time window

Example conceptual threshold:

    ≥ 5 unique SPNs
    requested by the same account
    within 10 minutes

The threshold should be tuned against the organization's normal authentication behavior.

Do not treat this threshold as a universal value.

---

# 11. Service Account Baseline

A production detection should maintain a baseline of:

- Expected service accounts
- Expected SPNs
- Expected requesting accounts
- Expected source systems
- Expected encryption types
- Normal TGS request volume

An alert becomes more suspicious when:

    Requester
        +
    Target Service
        +
    Source Host
        +
    Encryption Type

deviates from its historical baseline.

---

# 12. Lab Baseline

The Day 06 lab established the following observed Kerberos encryption baseline:

| Encryption Type | Observed Count |
|---|---:|
| `0x12` / AES-256 | 49 |
| `0x17` / RC4 | 1 |

This demonstrated that AES-256 was dominant within the observed sample.

RC4 was therefore anomalous within this lab environment.

### Lab Detection Interpretation

    AES-256 / 0x12
        ↓
    Normal / dominant baseline

    RC4 / 0x17
        ↓
    Rare event
        ↓
    Investigate

The baseline should be treated as **environment-specific evidence**, not a universal rule.

---

# 13. Observed Attack

The controlled lab attack involved:

| Field | Observed Value |
|---|---|
| Requester | `alice@CORP.LOCAL` |
| Target Account | `svc_sql` |
| SPN | `MSSQLSvc/AD-DC.corp.local:1433` |
| Source IP | `192.168.159.129` |
| Event ID | `4769` |
| Encryption | `0x17` / RC4 |
| Failure Code | `0x0` |

The combination of these indicators produced a high-confidence detection within the lab.

---

# 14. Detection Evidence

## Evidence 01 — Pre-Attack Baseline

![Pre-Attack Kerberos 4769 Baseline](../screenshots/Day06/Day06-05-PreAttack-Kerberos-4769-Baseline.png)

## Evidence 02 — TGS Request

![Kerberoasting TGS Request](../screenshots/Day06/Day06-06-Kerberoasting-TGS-Request.png)

## Evidence 03 — Event 4769

![Kerberos Event 4769](../screenshots/Day06/Day06-07-Kerberos-4769-Attack-Evidence.png)

## Evidence 04 — Detection Query

![Kerberoasting Detection Query](../screenshots/Day06/Day06-08-Kerberoasting-Detection-Query.png)

## Evidence 05 — RC4 Detection

![RC4 Kerberos Detection](../screenshots/Day06/Day06-09-RC4-Kerberos-Detection.png)

## Evidence 06 — Correlation

![Kerberoasting Correlation](../screenshots/Day06/Day06-10-Kerberoasting-Correlation-Evidence.png)

## Evidence 07 — Encryption Baseline

![Kerberos Encryption Baseline](../screenshots/Day06/Day06-11-Kerberos-Encryption-Baseline.png)

---

# 15. Severity

## Medium

Assign Medium severity when:

- A single RC4 TGS request is observed.
- No unusual requester behavior is identified.
- The service account is known to legitimately use RC4.
- No additional suspicious telemetry exists.

## High

Escalate to High when multiple indicators correlate:

- Successful Event 4769
- RC4 / `0x17`
- SPN-backed service account
- Unusual requester
- Unusual source system
- Multiple SPN requests
- Baseline deviation
- Additional credential-access telemetry

## Critical Consideration

Escalation beyond High should depend on evidence of:

- Compromised privileged service account
- Successful credential compromise
- Lateral movement
- Privilege escalation
- Broader domain compromise

---

# 16. False Positive Analysis

Potential legitimate RC4 activity may originate from:

- Legacy applications
- Legacy service accounts
- Older operating systems
- Legacy authentication dependencies
- Applications that have not yet migrated to AES

Therefore:

**An RC4 Event 4769 should trigger investigation, not automatic incident confirmation.**

The analyst should investigate:

1. Requester identity.
2. Target service.
3. Source host.
4. Historical behavior.
5. Service-account requirements.
6. Encryption baseline.
7. Request volume.
8. Related endpoint telemetry.

---

# 17. Investigation Workflow

When an alert fires:

    Alert
      |
      v
    Confirm Event ID 4769
      |
      v
    Check encryption type
      |
      v
    Identify requester
      |
      v
    Identify target service
      |
      v
    Verify SPN
      |
      v
    Identify source IP / host
      |
      v
    Review request volume
      |
      v
    Compare against baseline
      |
      v
    Correlate endpoint telemetry
      |
      v
    Determine malicious / benign
      |
      v
    Escalate or close

---

# 18. Analyst Questions

The analyst should answer:

### Who?

Who requested the service ticket?

Expected field:

`Account Name`

### What?

Which service was requested?

Expected field:

`Service Name`

### Where?

Which host or IP generated the request?

Expected field:

`Client Address`

### How?

Which encryption type was used?

Expected field:

`Ticket Encryption Type`

### Was it successful?

Check:

`Failure Code`

### Is the target an SPN-backed account?

Validate the SPN using Active Directory data.

### Is the behavior normal?

Compare against:

- Request history
- Service-account baseline
- Encryption baseline
- Source-host baseline

---

# 19. MITRE ATT&CK Mapping

## Tactic

**Credential Access**

## Technique

**T1558 — Steal or Forge Kerberos Tickets**

## Sub-technique

**T1558.003 — Kerberoasting**

MITRE's current detection strategy for Kerberoasting includes anomalous Event 4769 TGS requests, RC4 `0x17`, unusual service-ticket volume, and deviations from normal service-account usage. citeturn0search0turn0search1

---

# 20. Detection Data Sources

The primary data source is:

**Domain Controller → Windows Security Log**

Primary event:

`4769`

Additional telemetry that can improve confidence includes:

- Event `4624` — successful logon
- Event `4648` — explicit credential use
- Event `4672` — special privileges assigned
- Sysmon Event `1` — process creation
- Sysmon Event `10` — process access

Correlating endpoint activity with Kerberos telemetry can improve detection confidence.

---

# 21. Detection Tuning

The detection should be tuned using:

### Allowlist

Known legitimate systems or accounts that regularly use RC4.

### Service Baseline

Known requester-to-service relationships.

### Encryption Baseline

Expected AES/RC4 usage.

### Volume Threshold

Expected TGS request volume per account.

### Source Baseline

Known workstation/server sources.

The goal is:

    High Detection Confidence
            +
    Low False Positive Rate

---

# 22. Recommended Response

If Kerberoasting is confirmed:

## Immediate

1. Investigate the source host.
2. Validate the requesting account.
3. Review surrounding authentication activity.
4. Identify all targeted SPNs.

## Service Account

5. Review the targeted service account.
6. Determine its privileges.
7. Reset credentials if compromise is suspected.
8. Review unnecessary SPNs.

## Hardening

9. Prefer AES-based Kerberos encryption where supported.
10. Strengthen service-account passwords.
11. Consider managed service accounts where appropriate.
12. Restrict service-account privileges.

## Follow-Up

13. Search for additional Kerberoasting indicators.
14. Review lateral-movement activity.
15. Monitor the source account and workstation.

---

# 23. Validation Result

## Attack

**Successful**

A controlled TGS request was generated against:

`MSSQLSvc/AD-DC.corp.local:1433`

## Telemetry

**Generated**

Windows Event:

`4769`

## Detection

**Validated**

The Event 4769 + RC4 detection successfully identified the simulated attack.

## Correlation

**Validated**

The following indicators were correlated:

- `alice`
- `svc_sql`
- SPN
- `192.168.159.129`
- `0x17`
- Event `4769`

## Baseline

**Validated**

The observed sample contained:

`49 × 0x12`

and:

`1 × 0x17`

## MITRE Mapping

**Validated**

`T1558.003 — Kerberoasting`

---

# 24. Detection Limitations

This detection should not be considered sufficient as a standalone enterprise Kerberoasting detection.

Limitations include:

- Legitimate RC4 usage can create alerts.
- Some Kerberoasting activity may use AES encryption.
- A single TGS request may not be enough to establish malicious intent.
- Service-account baselines may be incomplete.
- Event collection must be properly configured.
- Detection quality depends on accurate parsing of Event 4769 fields.
- Thresholds must be tuned for the specific environment.

For stronger coverage, this detection should be combined with:

- TGS request volume analysis
- SPN enumeration telemetry
- Authentication events
- Endpoint process telemetry
- Service-account baselines
- Other credential-access detections

---

# 25. Related Project Artifacts

## Attack Simulation

`attacks/Kerberoasting.md`

Contains:

- Attack objective
- Service-account preparation
- SPN configuration
- TGS request
- Attack evidence
- Attack flow
- MITRE mapping

## SOC Investigation

`reports/Kerberoasting-Investigation.md`

Contains:

- Alert triage
- Timeline
- Event analysis
- Correlation
- Severity
- Analyst assessment
- Response recommendations

## Daily Documentation

`docs/Day06.md`

Contains the complete Day 06 engineering journal.

---

# 26. Detection Summary

The final detection strategy is:

    EVENT 4769
        |
        +---- Successful request
        |
        +---- RC4 / 0x17
        |
        +---- SPN-backed service
        |
        +---- Unusual requester/source
        |
        +---- Request volume anomaly
        |
        +---- Baseline deviation
        |
        v
    SUSPICIOUS KERBEROS ACTIVITY
        |
        v
    INVESTIGATE FOR KERBEROASTING
        |
        v
    MITRE T1558.003

---

# 27. Final Assessment

The detection was successfully validated against a controlled Kerberoasting simulation.

The lab demonstrated that Windows Event ID 4769 can provide valuable telemetry for identifying suspicious Kerberos service-ticket activity.

The strongest signal observed in this environment was the combination of:

**Event 4769 + successful request + RC4 `0x17` + SPN-backed service account + unusual requester/source + baseline deviation**

The detection should therefore be treated as a **behavioral investigation rule**, rather than a simple signature.

This approach provides a more realistic SOC detection model and demonstrates practical detection-engineering skills:

**Telemetry → Detection Logic → Baseline → Correlation → Investigation → MITRE Mapping → Response**

---

# 28. Detection Engineering Outcome

**Detection Status:** Validated

**Detection ID:** `DET-AD-001`

**Technique:** `T1558.003`

**Primary Event:** `4769`

**Primary Indicator:** `RC4 / 0x17`

**Lab Result:** Successfully detected controlled Kerberoasting activity

**False Positive Strategy:** Baseline + requester/service/source correlation

**Recommended Production Enhancement:** Add TGS-volume analytics, service-account baselines, and endpoint telemetry correlation.