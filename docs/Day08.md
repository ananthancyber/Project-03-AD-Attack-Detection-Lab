# Day 08 — AS-REP Roasting Attack, Detection & SOC Investigation

## Overview

Day 08 focused on simulating, detecting, and investigating **AS-REP Roasting** within the Active Directory laboratory environment.

The exercise demonstrated how an Active Directory account configured without Kerberos pre-authentication can be targeted to obtain an AS-REP response and how the resulting Kerberos authentication activity can be detected through Windows Security Event ID `4768`.

Unlike a simple attack demonstration, this exercise followed a complete SOC workflow:

    Attack Preparation
          ↓
    Controlled Attack Simulation
          ↓
    Windows Telemetry
          ↓
    Detection Engineering
          ↓
    Source & Account Correlation
          ↓
    Baseline Analysis
          ↓
    Analyst Alert
          ↓
    SOC Investigation
          ↓
    Final Assessment


---

## Objectives

The objectives of Day 08 were to:

- Understand the security implications of Kerberos pre-authentication.
- Understand the AS-REP Roasting attack technique.
- Create a dedicated Active Directory account for controlled testing.
- Configure the test account without requiring Kerberos pre-authentication.
- Verify Kali-to-Domain Controller connectivity.
- Perform a controlled AS-REP request.
- Identify the resulting Windows Security Event ID `4768`.
- Analyze Kerberos authentication metadata.
- Identify Pre-Authentication Type `0`.
- Correlate the activity with the Kali source IP.
- Compare the observed activity against a basic Kerberos authentication baseline.
- Build a behavioral detection query.
- Validate the detection against the simulated attack.
- Produce an analyst-oriented alert.
- Document the attack, detection, and investigation.


---

# 1. Lab Environment

| Component | Details |
|---|---|
| Active Directory Domain | `CORP.LOCAL` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Attack Host | Kali Linux |
| Kali IP | `192.168.159.129` |
| Target Account | `CORP\asrep_test` |
| Authentication Protocol | Kerberos |
| Primary Event ID | `4768` |
| Log Source | Windows Security Event Log |

The environment was used as an isolated Active Directory security testing laboratory.


---

# 2. AS-REP Roasting Theory

Kerberos normally uses pre-authentication as part of the authentication process.

AS-REP Roasting targets Active Directory accounts where Kerberos pre-authentication is not required.

When an attacker requests authentication material for such an account, the Domain Controller can return an AS-REP containing authentication material that may potentially be subjected to offline password cracking.

The attack therefore depends on an account configuration that permits authentication without the normal pre-authentication requirement.

### Attack Concept

    Active Directory Account
             ↓
    Pre-authentication disabled
             ↓
    Attacker requests AS-REP
             ↓
    Domain Controller responds
             ↓
    Kerberos authentication telemetry
             ↓
    Event ID 4768
             ↓
    Detection & Investigation


---

# 3. Dedicated Test Account

A dedicated account named `asrep_test` was created specifically for the exercise.

Before introducing the vulnerable configuration, the account was verified.

Initial state:

    Name                  : ASREP Test
    SamAccountName        : asrep_test
    Enabled               : True
    DoesNotRequirePreAuth : False

The account was then intentionally configured so that Kerberos pre-authentication was not required.

Final state:

    Name                  : ASREP Test
    SamAccountName        : asrep_test
    Enabled               : True
    DoesNotRequirePreAuth : True

This created the controlled AS-REP Roasting condition.

### Evidence

![AS-REP test account configuration](../screenshots/Day08/Day08-01-ASREP-Test-Account-PreAuth-Disabled.png)

**Evidence:** `Day08-01-ASREP-Test-Account-PreAuth-Disabled.png`

### Security Significance

The account configuration provided the prerequisite required for the controlled AS-REP Roasting simulation.

Only the dedicated laboratory account was used for this purpose.


---

# 4. Kali to Domain Controller Connectivity

Before executing the attack, connectivity between Kali and the Domain Controller was verified.

DNS resolution successfully identified:

    AD-DC.corp.local -> 192.168.159.10

Connectivity testing returned:

    2 packets transmitted
    2 packets received
    0% packet loss

This confirmed that Kali could communicate with the Domain Controller before generating the Kerberos request.

### Evidence

![Kali to AD-DC connectivity](../screenshots/Day08/Day08-02-Kali-ADDC-Connectivity.png)

**Evidence:** `Day08-02-Kali-ADDC-Connectivity.png`


---

# 5. AS-REP Roasting Simulation

The controlled AS-REP request was performed from Kali against:

    asrep_test@CORP.LOCAL

The attack tooling successfully obtained AS-REP/TGT material for the test account.

The terminal displayed:

    [*] Getting TGT for asrep_test

This demonstrated that the account could be targeted without requiring the normal Kerberos pre-authentication process.

### Evidence

![AS-REP Roasting request](../screenshots/Day08/Day08-03-ASREP-Roasting-Request.png)

**Evidence:** `Day08-03-ASREP-Roasting-Request.png`

### Evidence Handling

The original attack output contains returned AS-REP material.

For public portfolio use, unnecessary hash/material values should be redacted where appropriate.

The purpose of this project is to demonstrate attack simulation, detection engineering, telemetry analysis, and investigation rather than password cracking.


---

# 6. Windows Event ID 4768

After the attack was executed, the Domain Controller was investigated for Kerberos authentication telemetry.

Event ID `4768` was identified.

The relevant event fields were:

| Field | Observed Value |
|---|---|
| Event ID | `4768` |
| Account Name | `asrep_test` |
| Realm | `CORP.LOCAL` |
| Service Name | `krbtgt` |
| Client Address | `::ffff:192.168.159.129` |
| Result Code | `0x0` |
| Ticket Encryption Type | `0x17` |
| Pre-Authentication Type | `0` |

### Evidence

![Full Event 4768 telemetry](../screenshots/Day08/Day08-04-ASREP-4768-Full-Telemetry.png)

**Evidence:** `Day08-04-ASREP-4768-Full-Telemetry.png`

### Key Observation

The most important telemetry was:

    Pre-Authentication Type: 0

This correlated directly with the account configuration:

    DoesNotRequirePreAuth: True

The request also returned:

    Result Code: 0x0

indicating a successful request.


---

# 7. Pre-Authentication Analysis

The attack and telemetry were correlated as follows:

    DoesNotRequirePreAuth = True
                +
    Kerberos Event ID = 4768
                +
    Pre-Authentication Type = 0
                +
    Result Code = 0x0
                ↓
    Potential AS-REP Roasting Activity


The event also showed:

    Service Name: krbtgt

indicating that the activity involved a Kerberos Ticket Granting Ticket request.


---

# 8. 4768 Baseline Observation

A broader query was performed against Event ID `4768` records to identify successful requests with Pre-Authentication Type `0`.

Two matching events were observed.

Both occurred at:

    8/31/2026 11:08:51 PM

### Evidence

![AS-REP 4768 baseline](../screenshots/Day08/Day08-05-ASREP-4768-Baseline.png)

**Evidence:** `Day08-05-ASREP-4768-Baseline.png`

This confirmed that the controlled AS-REP activity generated the expected Type `0` Kerberos telemetry.


---

# 9. Behavioral Detection Engineering

A behavioral detection query was developed to identify the authentication characteristics associated with the attack.

The detection logic was:

    Event ID = 4768
    AND
    Pre-Authentication Type = 0
    AND
    Result Code = 0x0

The detection intentionally did not use:

    Account = asrep_test

This ensured that the detection was based on behavior rather than the known test account.

The detection extracted:

    TimeCreated
    Account
    ClientIP
    Encryption
    PreAuth
    Result

### Evidence

![AS-REP detection query](../screenshots/Day08/Day08-06-ASREP-Detection-Query.png)

**Evidence:** `Day08-06-ASREP-Detection-Query.png`

### Detection Result

The detection successfully identified the controlled AS-REP Roasting activity.


---

# 10. Account and Source Correlation

The detected events were grouped by account and client address.

Observed result:

    Account:
    asrep_test

    Source:
    ::ffff:192.168.159.129

    Count:
    2

The source address corresponds to the Kali host:

    192.168.159.129

### Evidence

![AS-REP frequency correlation](../screenshots/Day08/Day08-07-ASREP-Frequency-Correlation.png)

**Evidence:** `Day08-07-ASREP-Frequency-Correlation.png`

### Finding

Both matching Type `0` authentication events were associated with the same test account and Kali source.


---

# 11. Kerberos Authentication Baseline

A comparison of successful Event ID `4768` records was performed over the one-hour observation window.

Observed results:

    Pre-Authentication Type 2 -> 7 events
    Pre-Authentication Type 0 -> 2 events

### Evidence

![AS-REP pre-authentication baseline comparison](../screenshots/Day08/Day08-08-ASREP-PreAuth-Baseline-Comparison.png)

**Evidence:** `Day08-08-ASREP-PreAuth-Baseline-Comparison.png`

### Detection Engineering Significance

This demonstrated why Event ID `4768` alone is not sufficient for AS-REP Roasting detection.

The detection requires additional authentication context.

The observed baseline showed:

    Type 2
        ↓
    Dominant successful authentication pattern

    Type 0
        ↓
    Less common pattern requiring investigation


---

# 12. Analyst-Oriented Alert

The final detection converted the Windows authentication telemetry into an analyst-oriented alert.

Validated output:

    Detection : Potential AS-REP Roasting
    Severity  : High
    TimeCreated: 8/31/2026 11:08:51 PM
    Account   : asrep_test
    SourceIP  : ::ffff:192.168.159.129
    Encryption: 0x17
    PreAuth   : 0
    Result    : 0x0

Two matching events were returned.

### Evidence

![AS-REP analyst alert](../screenshots/Day08/Day08-09-ASREP-Analyst-Alert.png)

**Evidence:** `Day08-09-ASREP-Analyst-Alert.png`

This represents the final transition from raw Windows telemetry to an investigation-ready detection alert.


---

# 13. Detection Logic Summary

The validated detection logic is:

    Event ID = 4768
    AND
    Pre-Authentication Type = 0
    AND
    Result Code = 0x0

### Alert Enrichment

The alert should contain:

- Account Name
- Source IP
- Timestamp
- Pre-Authentication Type
- Result Code
- Ticket Encryption Type
- Service Name
- Event ID


---

# 14. SOC Investigation Workflow

When the detection triggers, the analyst should investigate:

    Alert
      ↓
    Identify account
      ↓
    Identify source IP / workstation
      ↓
    Confirm Event ID 4768
      ↓
    Check Pre-Authentication Type
      ↓
    Confirm Result Code
      ↓
    Review encryption type
      ↓
    Determine whether pre-authentication
    is intentionally disabled
      ↓
    Review account privilege
      ↓
    Search for repeated requests
      ↓
    Correlate with additional telemetry
      ↓
    Determine final verdict


---

# 15. False Positive Considerations

A Type `0` Event ID `4768` should not automatically be treated as confirmed malicious activity.

Potential legitimate situations may include:

- Legacy applications.
- Compatibility requirements.
- Service accounts with documented exceptions.
- Legacy authentication configurations.

A SOC analyst should therefore determine:

- Whether the account legitimately requires pre-authentication to be disabled.
- Whether the configuration has an approved business justification.
- Whether the source workstation is expected.
- Whether the account is privileged.
- Whether the activity is repeated.
- Whether the encryption type is expected.
- Whether additional suspicious activity is present.


---

# 16. MITRE ATT&CK Mapping

### Tactic

**Credential Access**

### Technique

**T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting**

### Relevance

The simulated attack targeted an Active Directory account configured without Kerberos pre-authentication.

The resulting Kerberos authentication telemetry was used to develop and validate the detection.

### Defensive Telemetry

Relevant telemetry included:

- Windows Security Event ID `4768`
- Account Name
- Client Address
- Pre-Authentication Type
- Result Code
- Ticket Encryption Type
- Service Name


---

# 17. Investigation Result

The investigation established:

1. A dedicated `asrep_test` account was created for controlled testing.
2. The account was configured with `DoesNotRequirePreAuth = True`.
3. Kali successfully communicated with the Domain Controller.
4. An AS-REP request was successfully performed.
5. The Domain Controller generated Event ID `4768`.
6. The event identified the `asrep_test` account.
7. The source correlated with Kali at `192.168.159.129`.
8. Pre-Authentication Type was `0`.
9. Result Code was `0x0`.
10. Ticket Encryption Type was `0x17`.
11. Two matching events were observed.
12. Successful Type `2` authentication was more common than Type `0` in the selected baseline.
13. The behavioral detection successfully identified the activity.
14. The final analyst alert contained sufficient contextual information for investigation.


---

# 18. Final Assessment

### Attack Simulation

**PASS**

The controlled AS-REP Roasting simulation successfully obtained AS-REP material for the dedicated test account.


### Telemetry

**PASS**

Windows Event ID `4768` was successfully generated and analyzed.


### Detection

**PASS**

The behavioral detection successfully identified successful Type `0` Kerberos authentication requests.


### Correlation

**PASS**

The activity was correlated to:

    Account: asrep_test
    Source: 192.168.159.129


### Investigation

**PASS**

The activity was investigated using account configuration, authentication metadata, source correlation, frequency, and baseline comparison.


### Overall Day 08 Status

**COMPLETE**

Day 08 successfully demonstrated a complete Active Directory attack-to-detection workflow:

    AS-REP Roasting
          ↓
    Windows Event 4768
          ↓
    PreAuth Type 0
          ↓
    Source Correlation
          ↓
    Baseline Analysis
          ↓
    Behavioral Detection
          ↓
    Analyst Alert
          ↓
    SOC Investigation


---

# 19. Evidence Index

All Day 08 evidence is stored under:

    screenshots/Day08/

| Evidence | Description |
|---|---|
| `Day08-01-ASREP-Test-Account-PreAuth-Disabled.png` | Dedicated test-account configuration and pre-authentication state. |
| `Day08-02-Kali-ADDC-Connectivity.png` | Kali DNS resolution and connectivity to the Domain Controller. |
| `Day08-03-ASREP-Roasting-Request.png` | Controlled AS-REP request and returned AS-REP material. |
| `Day08-04-ASREP-4768-Full-Telemetry.png` | Full Windows Event ID 4768 telemetry. |
| `Day08-05-ASREP-4768-Baseline.png` | Successful Type `0` Event ID 4768 observations. |
| `Day08-06-ASREP-Detection-Query.png` | Behavioral detection query successfully identifying the activity. |
| `Day08-07-ASREP-Frequency-Correlation.png` | Account, source, and frequency correlation. |
| `Day08-08-ASREP-PreAuth-Baseline-Comparison.png` | Comparison of successful Type `2` and Type `0` authentication events. |
| `Day08-09-ASREP-Analyst-Alert.png` | Final analyst-oriented detection output. |


---

# 20. Day 08 Deliverables

The following project artifacts were produced during Day 08:

    attacks/ASREP-Roasting.md

    detections/ASREP-Roasting-4768.md

    reports/ASREP-Roasting-Investigation.md

    docs/Day08.md

    screenshots/Day08/


---

# 21. Key Lessons Learned

Day 08 demonstrated the following practical cybersecurity concepts:

- Kerberos pre-authentication provides an important authentication security control.
- Accounts without pre-authentication can create an AS-REP Roasting exposure.
- Event ID `4768` provides valuable Kerberos authentication telemetry.
- Event ID `4768` alone is not sufficient for AS-REP Roasting detection.
- Pre-Authentication Type `0` is an important behavioral indicator.
- Result Code `0x0` confirms successful processing of the request.
- Source IP correlation helps identify the originating system.
- Frequency analysis provides additional investigative context.
- Baseline comparison helps distinguish common authentication behavior from unusual activity.
- Detection logic should identify behavior rather than depend on a known test account.
- A detection alert should provide enough context for SOC triage.
- Attack simulation, detection engineering, and investigation should be documented as one connected workflow.
- Laboratory confirmation should be clearly distinguished from production compromise.


---

# 22. Day 08 SOC Capability Demonstrated

This exercise demonstrates practical capability across multiple SOC functions:

### Detection Engineering

Developed a behavioral detection based on Windows Kerberos authentication telemetry.

### Threat Detection

Identified a potential AS-REP Roasting condition using Event ID `4768`.

### Log Analysis

Analyzed account, source, authentication, encryption, and result fields.

### Threat Investigation

Correlated account configuration, source IP, event metadata, frequency, and baseline behavior.

### MITRE ATT&CK

Mapped the activity to `T1558.004 — AS-REP Roasting`.

### Evidence Collection

Captured and organized nine pieces of attack, telemetry, detection, and investigation evidence.

### Documentation

Produced separate attack, detection, investigation, and daily project documentation.


---

# 23. Conclusion

Day 08 expanded the Active Directory attack-and-detection laboratory with a complete AS-REP Roasting scenario.

The exercise progressed from configuring a controlled vulnerable account through attack execution, Windows telemetry collection, detection engineering, source correlation, baseline analysis, and SOC investigation.

The strongest observed indicators were:

    Event ID: 4768
    Account: asrep_test
    Source: 192.168.159.129
    Pre-Authentication Type: 0
    Result Code: 0x0
    Encryption Type: 0x17

The detection successfully identified the controlled activity and produced an analyst-oriented alert.

The resulting workflow demonstrates:

    Attack Simulation
          ↓
    Telemetry Collection
          ↓
    Detection Engineering
          ↓
    Correlation
          ↓
    Baseline Analysis
          ↓
    SOC Investigation
          ↓
    Evidence-Based Assessment

**Day 08 — AS-REP Roasting Attack, Detection & Investigation: COMPLETE**