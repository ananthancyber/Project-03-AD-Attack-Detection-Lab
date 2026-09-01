# AS-REP Roasting Detection — Windows Event ID 4768

## Detection Overview

This detection identifies potential AS-REP Roasting activity in an Active Directory environment by monitoring successful Kerberos Ticket Granting Ticket (TGT) requests where Kerberos pre-authentication was not performed.

The detection is based on Windows Security Event ID `4768` and specifically evaluates:

    Event ID = 4768
    AND
    Pre-Authentication Type = 0
    AND
    Result Code = 0x0

The detection was developed and validated against a controlled AS-REP Roasting simulation performed in the Active Directory lab.

The test activity involved:

    Account: CORP\asrep_test
    Source: Kali Linux
    Source IP: 192.168.159.129
    Domain Controller: AD-DC.corp.local
    Domain Controller IP: 192.168.159.10


---

## Detection Objective

The objective is to identify Kerberos authentication requests that may indicate AS-REP Roasting activity while providing enough contextual information for a SOC analyst to investigate the event.

The detection should identify suspicious authentication behavior without relying on a hard-coded username such as `asrep_test`.

This makes the detection behavior-based rather than test-account-specific.


---

## Threat Description

AS-REP Roasting is a Kerberos-based credential-access technique targeting Active Directory accounts that do not require Kerberos pre-authentication.

When pre-authentication is disabled for an account, an attacker can request authentication material from the Domain Controller without first proving knowledge of the account password through normal Kerberos pre-authentication.

The returned authentication material can potentially be subjected to offline password-cracking attempts.

The attack therefore creates an opportunity to detect suspicious Kerberos behavior at the Domain Controller.


---

## MITRE ATT&CK Mapping

### Tactic

**Credential Access**

### Technique

**T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting**

The technique targets Active Directory accounts configured without Kerberos pre-authentication and attempts to obtain authentication material that can be subjected to offline password cracking.

### Detection Relevance

The attack generates Kerberos authentication-service requests that can be observed through Windows Security Event ID `4768`.

The most important indicator observed during this lab was:

    Pre-Authentication Type: 0


---

## Data Source

| Data Source | Value |
|---|---|
| Operating System | Windows Server / Active Directory Domain Controller |
| Log Source | Windows Security Event Log |
| Event ID | `4768` |
| Authentication Protocol | Kerberos |
| Primary Field | Pre-Authentication Type |
| Supporting Fields | Account, Client Address, Result Code, Encryption Type |

The Domain Controller was used as the primary telemetry source because Kerberos authentication-service requests are recorded there.


---

## Detection Logic

The core detection logic is:

    Event ID = 4768
    AND
    Pre-Authentication Type = 0
    AND
    Result Code = 0x0

The detection does not search for:

    Account = asrep_test

This is intentional.

The purpose is to detect the authentication behavior regardless of which account generates it.


---

## Detection Conditions

### Condition 1 — Event ID 4768

    Event ID = 4768

Event ID `4768` represents a Kerberos Authentication Service request for a Ticket Granting Ticket.

This provides the initial telemetry required for identifying Kerberos authentication activity.


### Condition 2 — Pre-Authentication Type 0

    Pre-Authentication Type = 0

This indicates that Kerberos pre-authentication was not performed for the request.

This is the primary behavioral indicator used by this detection.


### Condition 3 — Successful Result

    Result Code = 0x0

A result code of `0x0` indicates that the request was successful.

Combining success with the absence of pre-authentication produces a more meaningful detection signal than monitoring Event ID `4768` alone.


---

## Detection Severity

**Recommended Initial Severity: Medium**

**Lab Simulation Severity: High**

### Why Medium in a Production Environment?

A Type `0` Kerberos authentication event does not automatically prove malicious activity.

Some environments may contain legitimate accounts that intentionally do not require Kerberos pre-authentication.

Therefore, the event should initially be treated as suspicious and investigated.

Severity should increase when additional context supports malicious activity, such as:

- Unexpected source workstation.
- Unknown or suspicious source IP.
- Privileged account involvement.
- Repeated requests.
- Unusual encryption type.
- Other credential-access activity.
- Suspicious lateral movement following the event.

### Why High in This Lab?

The event was intentionally generated as part of a controlled AS-REP Roasting simulation.

The lab alert was therefore represented as:

    Detection: Potential AS-REP Roasting
    Severity: High


---

## Lab Configuration

The controlled test account was:

    CORP\asrep_test

Before the attack condition was enabled, the account showed:

    DoesNotRequirePreAuth : False

The account was then intentionally configured with:

    DoesNotRequirePreAuth : True

This created the controlled vulnerable condition used for the simulation.

### Evidence

![AS-REP test account configuration](../screenshots/Day08/Day08-01-ASREP-Test-Account-PreAuth-Disabled.png)

**Evidence:** `Day08-01-ASREP-Test-Account-PreAuth-Disabled.png`

This evidence establishes the account configuration used as the foundation for the detection test.


---

## Source Connectivity Validation

Before generating the authentication activity, connectivity between the Kali attack host and the Domain Controller was verified.

Observed environment:

    Kali
    IP: 192.168.159.129

    AD-DC
    IP: 192.168.159.10

DNS resolution successfully identified:

    AD-DC.corp.local -> 192.168.159.10

Connectivity testing returned:

    2 packets transmitted
    2 packets received
    0% packet loss

### Evidence

![Kali to AD-DC connectivity](../screenshots/Day08/Day08-02-Kali-ADDC-Connectivity.png)

**Evidence:** `Day08-02-Kali-ADDC-Connectivity.png`

This confirms the network path used to generate the controlled authentication activity.


---

## Attack Telemetry Generation

The AS-REP request was generated from Kali against:

    asrep_test@CORP.LOCAL

The request successfully obtained AS-REP/TGT material.

The attack terminal showed:

    [*] Getting TGT for asrep_test

### Evidence

![AS-REP request](../screenshots/Day08/Day08-03-ASREP-Roasting-Request.png)

**Evidence:** `Day08-03-ASREP-Roasting-Request.png`

This evidence establishes the Red Team action that generated the telemetry subsequently analyzed by the detection.


---

## Event ID 4768 Telemetry

The Domain Controller recorded Event ID `4768` following the AS-REP request.

The full event contained:

| Field | Observed Value |
|---|---|
| Event ID | `4768` |
| Account Name | `asrep_test` |
| Account Domain | `CORP.LOCAL` |
| Service Name | `krbtgt` |
| Client Address | `::ffff:192.168.159.129` |
| Result Code | `0x0` |
| Ticket Encryption Type | `0x17` |
| Pre-Authentication Type | `0` |

### Evidence

![Full Event 4768 telemetry](../screenshots/Day08/Day08-04-ASREP-4768-Full-Telemetry.png)

**Evidence:** `Day08-04-ASREP-4768-Full-Telemetry.png`

This is the primary Windows telemetry supporting the detection.


---

## Pre-Authentication Analysis

The critical field observed in the Event ID 4768 telemetry was:

    Pre-Authentication Type: 0

This was consistent with the account configuration:

    DoesNotRequirePreAuth: True

The request was also successful:

    Result Code: 0x0

The relationship between configuration and telemetry was therefore:

    DoesNotRequirePreAuth = True
                +
    Event ID = 4768
                +
    Pre-Authentication Type = 0
                +
    Result Code = 0x0
                ↓
    Potential AS-REP Roasting Indicator


---

## 4768 Baseline Observation

A broader query was performed against Event ID `4768` records to identify successful requests with Pre-Authentication Type `0`.

Two matching events were observed during the analysis window.

Both occurred at:

    8/31/2026 11:08:51 PM

### Evidence

![AS-REP 4768 baseline](../screenshots/Day08/Day08-05-ASREP-4768-Baseline.png)

**Evidence:** `Day08-05-ASREP-4768-Baseline.png`

This confirmed that the controlled AS-REP activity generated the expected Type `0` Kerberos telemetry.


---

## Behavioral Detection Validation

The detection query was intentionally designed around authentication behavior.

The validated logic was:

    Event ID = 4768
    AND
    Pre-Authentication Type = 0
    AND
    Result Code = 0x0

The query extracted:

    TimeCreated
    Account
    ClientIP
    Encryption
    PreAuth
    Result

The query successfully identified the controlled `asrep_test` activity.

### Evidence

![AS-REP detection query](../screenshots/Day08/Day08-06-ASREP-Detection-Query.png)

**Evidence:** `Day08-06-ASREP-Detection-Query.png`

This evidence demonstrates successful behavioral detection rather than simple username-based searching.


---

## Account and Source Correlation

The detected events were grouped by account and client address.

Observed result:

    Account:
    asrep_test

    Source:
    ::ffff:192.168.159.129

    Count:
    2

The IPv4-mapped IPv6 address corresponds to the Kali host:

    192.168.159.129

This correlation linked the suspicious Kerberos activity to the controlled attack host.

### Evidence

![AS-REP frequency correlation](../screenshots/Day08/Day08-07-ASREP-Frequency-Correlation.png)

**Evidence:** `Day08-07-ASREP-Frequency-Correlation.png`

The two observed requests originated from the same account/source combination.


---

## Authentication Baseline Comparison

Successful Event ID `4768` events were analyzed over the one-hour observation window.

Observed distribution:

    Pre-Authentication Type 2 -> 7 events
    Pre-Authentication Type 0 -> 2 events

This provided a simple behavioral baseline for the lab.

The dominant successful authentication pattern observed was Type `2`, while the two Type `0` events corresponded to the controlled AS-REP Roasting activity.

### Evidence

![AS-REP pre-authentication comparison](../screenshots/Day08/Day08-08-ASREP-PreAuth-Baseline-Comparison.png)

**Evidence:** `Day08-08-ASREP-PreAuth-Baseline-Comparison.png`

### Detection Engineering Significance

This comparison demonstrates why a detection should not alert on every Event ID `4768`.

Instead, the detection focuses on the combination of:

    4768
    +
    Pre-Authentication Type 0
    +
    Successful Result


---

## Analyst-Oriented Alert

The final detection transformed the Windows authentication telemetry into an analyst-oriented alert.

Validated output:

    Detection : Potential AS-REP Roasting
    Severity  : High
    TimeCreated: 8/31/2026 11:08:51 PM
    Account   : asrep_test
    SourceIP  : ::ffff:192.168.159.129
    Encryption: 0x17
    PreAuth   : 0
    Result    : 0x0

Two matching events were returned by the detection.

### Evidence

![AS-REP analyst alert](../screenshots/Day08/Day08-09-ASREP-Analyst-Alert.png)

**Evidence:** `Day08-09-ASREP-Analyst-Alert.png`

This represents the final detection output consumed by the analyst.


---

## Detection Correlation Chain

The detection can be represented as:

    Event ID 4768
          |
          v
    Successful Result 0x0
          |
          v
    Pre-Authentication Type 0
          |
          v
    Extract Account
          |
          v
    Extract Source IP
          |
          v
    Extract Encryption Type
          |
          v
    Correlate frequency
          |
          v
    Investigate account configuration
          |
          v
    Potential AS-REP Roasting


---

## Detection Fields

The following fields should be retained when generating an alert:

| Field | Purpose |
|---|---|
| Timestamp | Establishes when the activity occurred. |
| Account Name | Identifies the account requesting the TGT. |
| Client Address | Identifies the originating host or IP. |
| Pre-Authentication Type | Primary indicator for the detection. |
| Result Code | Determines whether the request succeeded. |
| Ticket Encryption Type | Provides additional authentication context. |
| Service Name | Confirms the Kerberos service involved. |
| Event ID | Identifies the Windows authentication event. |


---

## False Positive Considerations

The presence of Pre-Authentication Type `0` should not automatically be classified as confirmed malicious activity.

Potential legitimate scenarios may include:

- Legacy applications.
- Compatibility requirements.
- Service accounts with documented exceptions.
- Legacy authentication configurations.
- Specialized Kerberos implementations.

A SOC analyst should therefore verify whether the affected account legitimately requires pre-authentication to be disabled.

### Recommended Triage Questions

    Is the account intentionally configured without pre-authentication?
            |
            v
    Is there an approved business justification?
            |
            v
    Is the source workstation expected?
            |
            v
    Is the account privileged?
            |
            v
    Is the activity repeated?
            |
            v
    Is the encryption type unusual?
            |
            v
    Are there related suspicious events?
            |
            v
    Determine final disposition.


---

## Investigation Workflow

When this detection triggers:

### Step 1 — Identify the Account

Determine the account associated with Event ID `4768`.

Check:

- Account type.
- Privilege level.
- Group memberships.
- Recent authentication activity.
- Whether the account is expected to use Kerberos without pre-authentication.

### Step 2 — Validate Account Configuration

Check whether the account has:

    DoesNotRequirePreAuth = True

If true, determine whether the configuration is intentional.

### Step 3 — Identify the Source

Investigate the Client Address.

Determine:

- Hostname.
- Asset owner.
- Logged-on user.
- Whether the system is an expected authentication source.

### Step 4 — Review Authentication Activity

Search for:

- Additional Event ID `4768` events.
- Event ID `4769`.
- Event ID `4624`.
- Event ID `4625`.
- Unusual source systems.
- Repeated requests.

### Step 5 — Investigate Endpoint Activity

If the source is suspicious, review endpoint telemetry for:

- Credential-access activity.
- Suspicious processes.
- Network connections.
- Remote administration tools.
- Lateral movement.

### Step 6 — Determine Verdict

Classify the alert as:

    Benign
    Suspicious
    Malicious

based on the combined evidence.


---

## Recommended Response

If AS-REP Roasting activity is confirmed:

1. Disable unnecessary accounts configured without Kerberos pre-authentication.
2. Reset the affected account password if credential exposure is suspected.
3. Review account privileges and group memberships.
4. Investigate the source host.
5. Search for related authentication activity.
6. Check for lateral movement or privilege escalation.
7. Review other Active Directory accounts for the same insecure configuration.
8. Document the incident and containment actions.


---

## Detection Limitations

This detection has several limitations.

### 1. Legitimate Type 0 Accounts

Some environments may intentionally use accounts without pre-authentication.

This can create false positives.

### 2. Event Visibility

Detection depends on appropriate Windows Security auditing and Event ID `4768` telemetry being available.

### 3. Context Dependency

A Type `0` event alone does not prove that an attacker performed AS-REP Roasting.

Additional context is required.

### 4. Source Attribution

The Client Address may not always directly identify the actual originating user or process.

### 5. Offline Cracking Is Not Directly Observed

The Windows Domain Controller telemetry demonstrates the authentication request and AS-REP condition.

It does not directly prove that offline password cracking occurred.


---

## Detection Validation Results

The detection was validated against a controlled attack.

### Expected Behavior

    AS-REP request
          ↓
    Event ID 4768
          ↓
    PreAuth Type 0
          ↓
    Result 0x0
          ↓
    Detection triggered


### Observed Behavior

    Account: asrep_test
    Source: 192.168.159.129
    Event ID: 4768
    PreAuth: 0
    Result: 0x0
    Encryption: 0x17
    Detection: Triggered
    Matching Events: 2

### Validation Status

**PASS**

The detection successfully identified the controlled AS-REP Roasting activity.


---

## Evidence Summary

All Day 8 evidence is stored in:

    screenshots/Day08/

| Evidence | Detection Purpose |
|---|---|
| `Day08-01-ASREP-Test-Account-PreAuth-Disabled.png` | Establishes the account configuration used for the test. |
| `Day08-02-Kali-ADDC-Connectivity.png` | Establishes connectivity between the attack host and Domain Controller. |
| `Day08-03-ASREP-Roasting-Request.png` | Demonstrates the controlled AS-REP request. |
| `Day08-04-ASREP-4768-Full-Telemetry.png` | Provides full Windows Event ID 4768 telemetry. |
| `Day08-05-ASREP-4768-Baseline.png` | Demonstrates Type 0 Event ID 4768 activity. |
| `Day08-06-ASREP-Detection-Query.png` | Demonstrates successful behavioral detection. |
| `Day08-07-ASREP-Frequency-Correlation.png` | Correlates account, source, and repeated activity. |
| `Day08-08-ASREP-PreAuth-Baseline-Comparison.png` | Provides normal-vs-suspicious authentication context. |
| `Day08-09-ASREP-Analyst-Alert.png` | Demonstrates the final analyst-oriented alert. |


---

## Detection Maturity

This detection demonstrates the following stages of defensive engineering:

    Stage 1 — Attack Simulation
        Controlled AS-REP Roasting activity generated.

    Stage 2 — Telemetry Collection
        Windows Event ID 4768 captured.

    Stage 3 — Indicator Identification
        Pre-Authentication Type 0 identified.

    Stage 4 — Behavioral Detection
        Detection created without hard-coding the test account.

    Stage 5 — Context Enrichment
        Account, source IP, encryption, and result extracted.

    Stage 6 — Correlation
        Repeated activity correlated by account and source.

    Stage 7 — Baseline Comparison
        Type 0 activity compared with successful Type 2 activity.

    Stage 8 — Analyst Alert
        Raw telemetry converted into an investigation-ready alert.

    Stage 9 — Investigation
        False-positive considerations and response workflow defined.


---

## Lessons Learned

This detection exercise demonstrated several practical SOC concepts:

- Event ID `4768` is an important source of Kerberos authentication telemetry.
- Event ID `4768` alone is not sufficient to identify AS-REP Roasting.
- Pre-Authentication Type `0` is a critical indicator for accounts without Kerberos pre-authentication.
- Successful result code `0x0` provides additional confidence that the request was accepted.
- Source IP correlation provides important investigation context.
- Frequency analysis can strengthen correlation but should not independently determine maliciousness.
- Baseline comparison helps distinguish common authentication behavior from unusual activity.
- Detection logic should identify behavior instead of relying on a known test username.
- Alerts should provide enough context for a SOC analyst to begin triage.
- A detection should identify a potential threat and support investigation rather than automatically declaring compromise.


---

## Final Detection Assessment

The AS-REP Roasting detection was successfully developed and validated against a controlled Active Directory attack.

The validated detection condition is:

    Event ID = 4768
    AND
    Pre-Authentication Type = 0
    AND
    Result Code = 0x0

The controlled activity generated two matching events involving:

    Account: asrep_test
    Source: 192.168.159.129
    Encryption Type: 0x17
    Pre-Authentication Type: 0
    Result Code: 0x0

The detection successfully converted the underlying Windows authentication telemetry into an analyst-oriented alert.

The resulting workflow demonstrates a complete defensive detection lifecycle:

    Attack Simulation
          ↓
    Windows Telemetry
          ↓
    Indicator Identification
          ↓
    Detection Engineering
          ↓
    Correlation
          ↓
    Baseline Analysis
          ↓
    Alert Generation
          ↓
    SOC Investigation

This detection is mapped to **MITRE ATT&CK T1558.004 — AS-REP Roasting** and forms the defensive detection component of the Day 8 Active Directory attack-and-detection exercise.