# Kerberoasting — SOC Investigation Report

## Incident Information

| Field | Details |
|---|---|
| Incident Type | Suspected Kerberoasting |
| Severity | High |
| Status | Confirmed — Controlled Lab Simulation |
| Environment | Active Directory |
| Domain | `corp.local` |
| Domain Controller | `AD-DC.corp.local` |
| Source Host | Kali Linux |
| Source IP | `192.168.159.129` |
| Requesting Account | `alice@CORP.LOCAL` |
| Target Account | `svc_sql` |
| Target SPN | `MSSQLSvc/AD-DC.corp.local:1433` |
| Primary Event | Windows Security Event ID `4769` |
| Encryption Type | `0x17` / RC4 |
| MITRE ATT&CK | T1558.003 — Kerberoasting |
| Investigation Type | Controlled Security Lab Exercise |

---

# 1. Executive Summary

A suspicious Kerberos service-ticket request was identified within the Active Directory lab environment.

The activity involved the low-privileged domain account:

`alice@CORP.LOCAL`

requesting a Kerberos service ticket for the SPN-backed service account:

`svc_sql`

The target SPN was:

`MSSQLSvc/AD-DC.corp.local:1433`

The Domain Controller generated Windows Security Event ID `4769`, which showed:

- Requesting account: `alice@CORP.LOCAL`
- Target service: `svc_sql`
- Source IP: `192.168.159.129`
- Ticket Encryption Type: `0x17` / RC4
- Failure Code: `0x0`

The activity was correlated with the controlled Kerberoasting simulation performed from the Kali Linux attack host.

A Kerberos encryption baseline was also established. The observed sample contained:

- `49` AES-256 (`0x12`) events
- `1` RC4 (`0x17`) event

The RC4 request was therefore anomalous within the observed lab environment.

The investigation concluded that the activity represents a **successful controlled Kerberoasting simulation** and demonstrates a high-confidence detection scenario for the SOC.

---

# 2. Investigation Objective

The objective of this investigation was to determine whether the suspicious Kerberos service-ticket request represented Kerberoasting activity.

The investigation followed the workflow:

    Alert
      |
      v
    Initial Triage
      |
      v
    Event 4769 Analysis
      |
      v
    Requester Identification
      |
      v
    Target Service Identification
      |
      v
    SPN Verification
      |
      v
    Source IP Analysis
      |
      v
    Encryption Analysis
      |
      v
    Baseline Comparison
      |
      v
    Attack Correlation
      |
      v
    MITRE ATT&CK Mapping
      |
      v
    Analyst Verdict
      |
      v
    Recommended Response

---

# 3. Detection Trigger

The investigation was initiated after identifying suspicious Kerberos service-ticket activity.

The primary detection signal was:

**Windows Security Event ID 4769**

with:

**Ticket Encryption Type:** `0x17` / RC4

The detection was strengthened by additional contextual indicators:

- Successful service-ticket request
- SPN-backed service account
- Unusual requester
- Source IP associated with the attack host
- RC4 being rare in the observed baseline
- Correlation with a controlled Kerberoasting simulation

---

# 4. Initial Triage

The first stage of investigation was to identify the basic characteristics of the event.

The following questions were investigated:

1. Who requested the Kerberos service ticket?
2. Which service account was targeted?
3. What SPN was associated with the service?
4. Where did the request originate?
5. What encryption type was used?
6. Was the request successful?
7. Was the activity normal for the environment?

The investigation produced the following values:

| Investigation Field | Observed Value |
|---|---|
| Requester | `alice@CORP.LOCAL` |
| Target Service | `svc_sql` |
| Source IP | `192.168.159.129` |
| Encryption Type | `0x17` / RC4 |
| Failure Code | `0x0` |
| Event ID | `4769` |

These values justified deeper investigation.

---

# 5. Event 4769 Analysis

Windows Security Event ID `4769` indicates that a Kerberos service ticket was requested.

The relevant event contained:

**Account Name**

`alice@CORP.LOCAL`

**Service Name**

`svc_sql`

**Client Address**

`192.168.159.129`

**Ticket Encryption Type**

`0x17`

**Failure Code**

`0x0`

The request was therefore successful.

The combination of a successful service-ticket request, an SPN-backed service account, and RC4 encryption warranted further investigation.

---

# 6. Requesting Account Analysis

The requesting account was:

`alice@CORP.LOCAL`

The account represents a normal domain user rather than a privileged Domain Administrator account.

This is important because Kerberoasting does not inherently require administrative privileges.

The attack scenario therefore demonstrates how a lower-privileged domain account can interact with Kerberos service accounts.

The requesting account was subsequently correlated with the controlled attack simulation.

---

# 7. Target Service Account Analysis

The targeted service account was:

`svc_sql`

The account was intentionally created for this controlled lab scenario.

The account had an associated SPN:

`MSSQLSvc/AD-DC.corp.local:1433`

The SPN was verified using:

    setspn -L CORP\svc_sql

The presence of the SPN made the account a suitable target for the Kerberoasting simulation.

---

# 8. SPN Analysis

The Service Principal Name associated with the target account was:

`MSSQLSvc/AD-DC.corp.local:1433`

The relationship was:

    Service Account
          |
          v
       svc_sql
          |
          v
    MSSQLSvc/AD-DC.corp.local:1433
          |
          v
    Kerberos Service Ticket

Because the service account had a registered SPN, the Kerberos service-ticket request was relevant to a Kerberoasting investigation.

---

# 9. Source IP Analysis

The Event 4769 identified the client address as:

`192.168.159.129`

This address corresponded to the Kali Linux attack host used during the controlled simulation.

The source therefore correlated directly with the known attack infrastructure within the lab.

This significantly increased the confidence that the event represented malicious-looking behavior rather than normal domain activity.

---

# 10. Encryption Analysis

The Event 4769 contained:

`Ticket Encryption Type: 0x17`

This represents RC4-HMAC.

RC4 is important during Kerberoasting investigations because service-ticket material encrypted using RC4 may be more susceptible to offline password-cracking techniques than modern AES-based Kerberos encryption.

However:

**RC4 alone is not proof of Kerberoasting.**

The encryption type must be correlated with other indicators.

---

# 11. Kerberos Encryption Baseline

A baseline of recent Event 4769 encryption types was created.

Observed results:

| Encryption Type | Count |
|---|---:|
| `0x12` / AES-256 | 49 |
| `0x17` / RC4 | 1 |

The observed environment therefore showed significantly more AES-256 activity than RC4 activity.

The suspicious event was the observed RC4 request.

This made RC4 an anomalous and high-value investigation indicator within this specific lab environment.

---

# 12. Baseline Assessment

The baseline demonstrated why environmental context is important for detection engineering.

A generic rule such as:

    Event 4769 + RC4 = Kerberoasting

could generate false positives in environments where RC4 is legitimately used.

A stronger approach is:

    Event 4769
        +
    RC4 / 0x17
        +
    SPN-backed service account
        +
    Unusual requester/source
        +
    Baseline deviation
        =
    High-confidence investigation

This approach improves detection quality and provides stronger evidence for a SOC analyst.

---

# 13. Attack Correlation

The suspicious event was correlated with the controlled attack activity.

The complete chain was:

    Kali Linux
        |
        | 192.168.159.129
        v
    alice@CORP.LOCAL
        |
        | SPN Enumeration
        v
    svc_sql
        |
        | MSSQLSvc/AD-DC.corp.local:1433
        v
    Kerberos TGS Request
        |
        v
    AD-DC
        |
        | Event 4769
        v
    RC4 / 0x17
        |
        v
    Detection

The timing and attributes of the Windows event matched the controlled Kerberoasting activity.

---

# 14. Attack Evidence

The corresponding attack simulation produced Kerberos ticket material for the target SPN.

The attack-side evidence is documented in:

`attacks/Kerberoasting.md`

Relevant evidence:

![Kerberoasting TGS Request](../screenshots/Day06/Day06-06-Kerberoasting-TGS-Request.png)

The Windows-side evidence was:

![Kerberos Event 4769](../screenshots/Day06/Day06-07-Kerberos-4769-Attack-Evidence.png)

These artifacts establish the relationship between the offensive action and the defensive telemetry.

---

# 15. Detection Validation

The investigation validated multiple detection queries.

## Targeted Detection

The first query searched for:

- Event ID `4769`
- Target service `svc_sql`
- Encryption indicator `0x17`

The query successfully identified the attack event.

Evidence:

![Kerberoasting Detection Query](../screenshots/Day06/Day06-08-Kerberoasting-Detection-Query.png)

---

## Generalized Detection

The detection was then generalized to identify RC4-based service-ticket requests without hardcoding `svc_sql`.

Evidence:

![RC4 Kerberos Detection](../screenshots/Day06/Day06-09-RC4-Kerberos-Detection.png)

This demonstrated that the detection logic can identify suspicious Kerberos activity even when the target account is unknown.

---

# 16. Correlation Evidence

The final correlation connected:

- Requesting account
- Target service account
- SPN
- Source IP
- Event ID
- Encryption type
- Request success

Evidence:

![Kerberoasting Correlation](../screenshots/Day06/Day06-10-Kerberoasting-Correlation-Evidence.png)

This correlation provides stronger confidence than relying on a single event field.

---

# 17. MITRE ATT&CK Mapping

## Tactic

**Credential Access**

## Technique

**T1558 — Steal or Forge Kerberos Tickets**

## Sub-technique

**T1558.003 — Kerberoasting**

### Investigation Mapping

    Domain User
        |
        v
    SPN Discovery
        |
        v
    Service Ticket Request
        |
        v
    Kerberos Ticket Material
        |
        v
    Potential Credential Access

The observed activity is therefore mapped to:

**T1558.003 — Kerberoasting**

---

# 18. Analyst Assessment

### Finding

**Confirmed — Controlled Kerberoasting Simulation**

### Confidence

**High**

### Reasoning

The investigation identified multiple correlated indicators:

1. Successful Windows Event 4769.
2. Low-privileged domain requester `alice`.
3. Targeted SPN-backed service account `svc_sql`.
4. Registered SPN `MSSQLSvc/AD-DC.corp.local:1433`.
5. Source IP `192.168.159.129` associated with the Kali attack host.
6. RC4 encryption type `0x17`.
7. Successful request with failure code `0x0`.
8. RC4 was rare in the observed Kerberos baseline.
9. The activity directly correlated with the controlled attack simulation.

The combination of these indicators provides high-confidence evidence of the simulated Kerberoasting activity.

---

# 19. Severity Assessment

## Assigned Severity

**High**

## Reason

The activity contains multiple correlated indicators of credential-access behavior.

The severity is not based solely on the presence of RC4.

The high severity assessment is based on:

- Successful TGS request
- SPN-backed service account
- Unusual requester
- Unusual source system
- RC4 encryption
- Baseline deviation
- Direct attack correlation

In a production SOC, the final severity would also depend on the privileges and business importance of the targeted service account.

---

# 20. False Positive Considerations

Potential legitimate explanations for RC4 Kerberos activity include:

- Legacy applications
- Legacy service accounts
- Older authentication systems
- Systems that still depend on RC4

Therefore, an isolated Event 4769 with RC4 should not automatically be classified as malicious.

The following contextual information should be reviewed before escalation:

- Requester identity
- Target service
- Source host
- Historical requester/service relationship
- Request frequency
- Encryption baseline
- Endpoint telemetry
- Other authentication activity

---

# 21. Recommended Response

If the activity were confirmed in a production environment, the SOC should consider the following actions.

## Immediate Investigation

1. Investigate the source workstation.
2. Validate the requesting user's activity.
3. Review recent authentication activity for `alice`.
4. Review other service-ticket requests from the source IP.
5. Determine whether other SPN-backed accounts were targeted.

## Account Investigation

6. Review the `svc_sql` account.
7. Determine the privileges assigned to the account.
8. Determine whether the SPN is required.
9. Review whether the account has excessive permissions.

## Credential Protection

10. Reset the service-account password if compromise is suspected.
11. Review service-account credential management.
12. Prefer stronger Kerberos encryption where supported.

## Environment Hardening

13. Remove unnecessary SPNs.
14. Review legacy Kerberos dependencies.
15. Monitor for repeated Kerberoasting indicators.
16. Continue endpoint and authentication monitoring.

---

# 22. Detection Recommendation

The preferred detection strategy should not depend on a single indicator.

Recommended logic:

    Event ID 4769
        +
    RC4 / 0x17
        +
    SPN-backed service account
        +
    Unusual requester or source
        +
    Baseline deviation

Additional confidence can be gained from:

- Multiple TGS requests
- Short request intervals
- Multiple service accounts targeted
- Suspicious endpoint activity
- Other credential-access indicators

The reusable detection specification is maintained in:

`detections/Kerberoasting-4769.md`

---

# 23. Evidence Summary

| Evidence | Investigation Purpose |
|---|---|
| `Day06-01-SPN-Enumeration-Baseline.png` | Establishes initial SPN environment |
| `Day06-02-Service-Account-Creation.png` | Shows controlled service-account preparation |
| `Day06-03-Service-Account-SPN-Configuration.png` | Shows SPN configuration |
| `Day06-04-SPN-Uniqueness-Verification.png` | Confirms intended SPN ownership |
| `Day06-05-PreAttack-Kerberos-4769-Baseline.png` | Establishes pre-attack Kerberos telemetry |
| `Day06-06-Kerberoasting-TGS-Request.png` | Shows controlled attack execution |
| `Day06-07-Kerberos-4769-Attack-Evidence.png` | Shows Windows attack telemetry |
| `Day06-08-Kerberoasting-Detection-Query.png` | Validates targeted detection |
| `Day06-09-RC4-Kerberos-Detection.png` | Validates generalized detection |
| `Day06-10-Kerberoasting-Correlation-Evidence.png` | Demonstrates event correlation |
| `Day06-11-Kerberos-Encryption-Baseline.png` | Establishes encryption baseline |

---

# 24. Investigation Timeline

| Phase | Activity | Evidence |
|---|---|---|
| 1 | SPN enumeration | Day06-01 |
| 2 | Service account creation | Day06-02 |
| 3 | SPN configuration | Day06-03 |
| 4 | SPN verification | Day06-04 |
| 5 | Pre-attack Kerberos baseline | Day06-05 |
| 6 | TGS request / Kerberoasting simulation | Day06-06 |
| 7 | Event 4769 investigation | Day06-07 |
| 8 | Targeted detection | Day06-08 |
| 9 | RC4 detection | Day06-09 |
| 10 | Event correlation | Day06-10 |
| 11 | Encryption baseline comparison | Day06-11 |

---

# 25. Lessons Learned

### 1. SPNs are valuable detection context

SPN-backed accounts should receive additional scrutiny when unusual Kerberos service-ticket activity is observed.

### 2. Event 4769 is valuable Kerberos telemetry

Event 4769 provides useful information about service-ticket requests and can support Kerberoasting detection.

### 3. RC4 is useful but not definitive

RC4 should be treated as an investigation indicator rather than automatic proof of malicious activity.

### 4. Baselines improve detection quality

Understanding normal encryption usage allows analysts to identify deviations more effectively.

### 5. Correlation is more powerful than isolated indicators

Combining requester, target service, SPN, source IP, encryption type, and event timing produces stronger detection confidence.

### 6. Attack simulation improves detection engineering

Generating the attack inside the lab made it possible to observe the exact Windows telemetry produced by the technique.

---

# 26. Final Investigation Conclusion

The investigation confirmed that the suspicious Kerberos activity represented the controlled Kerberoasting simulation performed in the Active Directory lab.

The investigation successfully connected:

    Attacker
        |
        v
    alice@CORP.LOCAL
        |
        v
    SPN Enumeration
        |
        v
    svc_sql
        |
        v
    MSSQLSvc/AD-DC.corp.local:1433
        |
        v
    Kerberos TGS Request
        |
        v
    Event 4769
        |
        v
    RC4 / 0x17
        |
        v
    Baseline Deviation
        |
        v
    Detection
        |
        v
    SOC Investigation
        |
        v
    MITRE T1558.003

The investigation demonstrates an end-to-end Blue Team workflow:

**Detect → Triage → Correlate → Investigate → Assess → Map → Respond**

This investigation report, together with the attack documentation and detection specification, forms a complete attack-to-detection case study for the Active Directory Attack & Detection Lab.