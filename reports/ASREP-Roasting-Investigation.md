# SOC Investigation Report — Potential AS-REP Roasting Activity

## Case Overview

| Field | Details |
|---|---|
| Case Type | Credential Access Investigation |
| Detection | Potential AS-REP Roasting |
| MITRE ATT&CK | T1558.004 — AS-REP Roasting |
| Severity | High — Controlled Lab Simulation |
| Environment | Active Directory Lab |
| Domain | `CORP.LOCAL` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Source Host | Kali Linux |
| Source IP | `192.168.159.129` |
| Target Account | `CORP\asrep_test` |
| Primary Event | Windows Security Event ID `4768` |
| Pre-Authentication Type | `0` |
| Result Code | `0x0` |
| Ticket Encryption Type | `0x17` |
| Observed Matching Events | `2` |
| Investigation Verdict | Confirmed AS-REP Roasting Simulation |

---

## 1. Executive Summary

A controlled AS-REP Roasting simulation was conducted against the `CORP.LOCAL` Active Directory environment using the dedicated test account `CORP\asrep_test`.

The account was intentionally configured so that Kerberos pre-authentication was not required. The activity was initiated from the Kali Linux attack host at `192.168.159.129`.

Following the controlled attack, the Domain Controller generated Windows Security Event ID `4768`. The event contained the following indicators:

    Account Name: asrep_test
    Client Address: ::ffff:192.168.159.129
    Service Name: krbtgt
    Pre-Authentication Type: 0
    Result Code: 0x0
    Ticket Encryption Type: 0x17

Two matching successful Event ID `4768` events were observed during the investigation window.

The activity was subsequently identified by a behavioral detection based on:

    Event ID = 4768
    AND
    Pre-Authentication Type = 0
    AND
    Result Code = 0x0

The detection successfully correlated the activity to the `asrep_test` account and the Kali attack host.

### Final Assessment

**Confirmed AS-REP Roasting activity within the controlled laboratory environment.**

This verdict confirms that the attack simulation was successfully executed and detected.

It does **not** represent evidence of compromise of a real production environment.


---

## 2. Investigation Objective

The purpose of this investigation was to determine whether a generated detection alert represented AS-REP Roasting activity and to establish a complete evidence chain from the initial attack through Windows telemetry and detection.

The investigation focused on answering:

1. Which account was targeted?
2. Which host initiated the activity?
3. Was Kerberos pre-authentication absent?
4. Was the Kerberos request successful?
5. Was the activity repeated?
6. Did the authentication telemetry match the simulated attack?
7. Could the behavior be detected without relying on the known test account?
8. What additional investigation would be required in a real SOC?


---

## 3. Investigation Scope

The investigation covered:

- Active Directory account configuration.
- Kali-to-Domain Controller connectivity.
- AS-REP request generation.
- Windows Security Event ID `4768`.
- Kerberos pre-authentication metadata.
- Source IP correlation.
- Account/source frequency.
- Successful Kerberos authentication baseline.
- Behavioral detection output.
- Analyst-oriented alert generation.

The investigation was performed entirely within the controlled Active Directory lab.


---

## 4. Environment

The relevant architecture for the investigation was:

    Kali Linux
    192.168.159.129
          |
          | Kerberos request
          v
    AD-DC.corp.local
    192.168.159.10
          |
          v
    CORP.LOCAL
          |
          v
    CORP\asrep_test


### Systems Involved

| System | Role | Address |
|---|---|---|
| Kali Linux | Attack/Test Host | `192.168.159.129` |
| AD-DC.corp.local | Domain Controller | `192.168.159.10` |
| `asrep_test` | Dedicated Test Account | Active Directory |

---

## 5. Initial Account Assessment

Before the attack condition was introduced, the dedicated test account was inspected.

The initial configuration showed:

    Name                  : ASREP Test
    SamAccountName        : asrep_test
    Enabled               : True
    DoesNotRequirePreAuth : False

The account was subsequently configured for the controlled AS-REP Roasting simulation.

The final configuration showed:

    Name                  : ASREP Test
    SamAccountName        : asrep_test
    Enabled               : True
    DoesNotRequirePreAuth : True

This established the intended vulnerable condition.

### Evidence

![AS-REP test account configuration](../screenshots/Day08/Day08-01-ASREP-Test-Account-PreAuth-Disabled.png)

**Evidence:** `Day08-01-ASREP-Test-Account-PreAuth-Disabled.png`

### Investigation Finding

The targeted account was intentionally configured without Kerberos pre-authentication.

**Finding:** Account configuration was consistent with an AS-REP Roasting test condition.


---

## 6. Source Host Validation

Before analyzing the authentication activity, the connectivity between Kali and the Domain Controller was verified.

DNS resolution identified:

    AD-DC.corp.local -> 192.168.159.10

Connectivity testing produced:

    2 packets transmitted
    2 packets received
    0% packet loss

The Kali source address was:

    192.168.159.129

### Evidence

![Kali to AD-DC connectivity](../screenshots/Day08/Day08-02-Kali-ADDC-Connectivity.png)

**Evidence:** `Day08-02-Kali-ADDC-Connectivity.png`

### Investigation Finding

The Kali host had confirmed network connectivity to the Domain Controller before the attack was executed.

**Finding:** Network connectivity required for the simulated attack was confirmed.


---

## 7. Attack Activity

A controlled AS-REP request was generated from Kali against:

    asrep_test@CORP.LOCAL

The attack tool reported:

    [*] Getting TGT for asrep_test

The command returned AS-REP/TGT material associated with the test account.

### Evidence

![AS-REP Roasting request](../screenshots/Day08/Day08-03-ASREP-Roasting-Request.png)

**Evidence:** `Day08-03-ASREP-Roasting-Request.png`

### Investigation Finding

The attack simulation successfully generated an AS-REP response for the account configured without Kerberos pre-authentication.

**Finding:** The Red Team simulation was successful.


---

## 8. Primary Detection Telemetry

Following the attack, Windows Security Event ID `4768` was investigated on the Domain Controller.

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

### Investigation Finding

The Event ID `4768` data directly connected the Kerberos authentication request to:

    Account: asrep_test
    Source: 192.168.159.129
    PreAuth: 0
    Result: 0x0

**Finding:** The Domain Controller recorded successful Kerberos authentication-service requests matching the AS-REP Roasting test condition.


---

## 9. Authentication Analysis

The most important field in the investigation was:

    Pre-Authentication Type: 0

The event also showed:

    Result Code: 0x0

This indicates that the authentication-service request succeeded without Kerberos pre-authentication.

The relevant evidence relationship was:

    DoesNotRequirePreAuth = True
              +
    Event ID = 4768
              +
    Pre-Authentication Type = 0
              +
    Result Code = 0x0
              ↓
    AS-REP Roasting Indicator


---

## 10. Baseline Investigation

A broader query was performed against Event ID `4768` to identify successful requests with Pre-Authentication Type `0`.

Two matching events were observed.

Both events occurred at:

    8/31/2026 11:08:51 PM

### Evidence

![AS-REP 4768 baseline](../screenshots/Day08/Day08-05-ASREP-4768-Baseline.png)

**Evidence:** `Day08-05-ASREP-4768-Baseline.png`

### Investigation Finding

The controlled attack generated two successful Type `0` Kerberos authentication-service requests.

**Finding:** The expected authentication telemetry was present in the Domain Controller security log.


---

## 11. Detection Query Validation

The detection was intentionally designed to identify behavior rather than the known test username.

The detection conditions were:

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

### Evidence

![AS-REP detection query](../screenshots/Day08/Day08-06-ASREP-Detection-Query.png)

**Evidence:** `Day08-06-ASREP-Detection-Query.png`

### Investigation Finding

The detection successfully identified the `asrep_test` activity without requiring the account name to be hard-coded into the detection logic.

**Finding:** Behavioral detection successfully identified the simulated attack.


---

## 12. Account and Source Correlation

The matching events were grouped by account and source address.

Observed correlation:

    Account:
    asrep_test

    Source:
    ::ffff:192.168.159.129

    Count:
    2

The IPv4-mapped IPv6 representation corresponds to:

    192.168.159.129

which was the Kali attack host used during the simulation.

### Evidence

![AS-REP frequency correlation](../screenshots/Day08/Day08-07-ASREP-Frequency-Correlation.png)

**Evidence:** `Day08-07-ASREP-Frequency-Correlation.png`

### Investigation Finding

Both matching events were associated with the same account and source host.

**Finding:** Repeated Type `0` Kerberos activity was correlated to the controlled Kali source.


---

## 13. Normal Authentication Baseline

To determine whether Type `0` represented the dominant successful Kerberos pattern in the lab, successful Event ID `4768` records were grouped by Pre-Authentication Type.

The observed results were:

    Pre-Authentication Type 2 -> 7 events
    Pre-Authentication Type 0 -> 2 events

### Evidence

![AS-REP pre-authentication baseline comparison](../screenshots/Day08/Day08-08-ASREP-PreAuth-Baseline-Comparison.png)

**Evidence:** `Day08-08-ASREP-PreAuth-Baseline-Comparison.png`

### Investigation Finding

Type `2` was the dominant successful authentication pattern during the selected observation period, while the two Type `0` events were associated with the controlled AS-REP Roasting activity.

This provided additional context for the detection.

**Finding:** Type `0` activity was less common than Type `2` activity in the observed lab baseline.


---

## 14. Analyst Alert Review

The final detection transformed the raw Windows authentication telemetry into an analyst-oriented alert.

The validated output was:

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

### Investigation Finding

The detection generated a sufficiently enriched alert containing the account, source, authentication type, encryption type, result, and timestamp.

**Finding:** The detection successfully converted raw authentication telemetry into an investigation-ready alert.


---

## 15. Investigation Timeline

The observed sequence of events was:

| Sequence | Activity | Evidence |
|---|---|---|
| 1 | Dedicated `asrep_test` account prepared | `Day08-01` |
| 2 | Kali connectivity to AD-DC verified | `Day08-02` |
| 3 | AS-REP request performed | `Day08-03` |
| 4 | Event ID 4768 generated | `Day08-04` |
| 5 | Type `0` successful events identified | `Day08-05` |
| 6 | Behavioral detection executed | `Day08-06` |
| 7 | Account/source correlation performed | `Day08-07` |
| 8 | Authentication baseline compared | `Day08-08` |
| 9 | Analyst alert generated | `Day08-09` |

### Key Timestamp

The observed Event ID `4768` activity occurred at:

    8/31/2026 11:08:51 PM


---

## 16. Evidence Correlation

The investigation produced the following evidence chain:

    ACCOUNT CONFIGURATION
    DoesNotRequirePreAuth = True
              |
              v
    ATTACK SOURCE
    Kali — 192.168.159.129
              |
              v
    ATTACK ACTIVITY
    AS-REP request for asrep_test
              |
              v
    DOMAIN CONTROLLER
    Event ID 4768
              |
              v
    AUTHENTICATION DETAILS
    PreAuth = 0
    Result = 0x0
    Encryption = 0x17
              |
              v
    CORRELATION
    asrep_test + 192.168.159.129
              |
              v
    DETECTION
    Potential AS-REP Roasting
              |
              v
    ANALYST ALERT
    Detection successfully triggered


---

## 17. Indicator Analysis

### Account

    CORP\asrep_test

The account was intentionally created and configured for the simulation.

**Assessment:** Known controlled test account.


### Source IP

    192.168.159.129

The source corresponds to the Kali attack host.

**Assessment:** Confirmed attack/test source within the lab.


### Event ID

    4768

Represents a Kerberos Authentication Service ticket request.

**Assessment:** Relevant Kerberos telemetry.


### Pre-Authentication Type

    0

Indicates the request did not include normal Kerberos pre-authentication.

**Assessment:** Strong AS-REP Roasting indicator when correlated with account configuration and other context.


### Result Code

    0x0

Indicates a successful request.

**Assessment:** Confirms successful processing of the request.


### Ticket Encryption Type

    0x17

The observed event used RC4-HMAC.

**Assessment:** Additional contextual indicator that can increase investigative interest, particularly when correlated with other AS-REP Roasting indicators.


---

## 18. False Positive Assessment

The detection should not automatically classify every Type `0` Event ID `4768` as malicious.

A production environment may contain accounts intentionally configured without Kerberos pre-authentication because of legacy or compatibility requirements.

A real SOC analyst should therefore determine:

- Whether the account is legitimately configured without pre-authentication.
- Whether there is an approved business justification.
- Whether the source workstation is expected.
- Whether the account is privileged.
- Whether similar requests occur regularly.
- Whether the encryption type is expected.
- Whether additional suspicious activity is present.

### Lab Context

In this investigation, the account configuration and attack activity were intentionally created as part of a controlled simulation.

Therefore, the activity is considered confirmed within the lab.


---

## 19. MITRE ATT&CK Mapping

### Tactic

**Credential Access**

### Technique

**T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting**

### Technique Description

AS-REP Roasting targets Active Directory accounts that do not require Kerberos pre-authentication and attempts to obtain authentication material that may be subjected to offline password cracking.

### Observed Defensive Telemetry

The investigation demonstrated visibility through:

- Windows Security Event ID `4768`
- Account Name
- Client Address
- Service Name
- Pre-Authentication Type
- Result Code
- Ticket Encryption Type


---

## 20. Analyst Triage Decision

The investigation can be summarized using the following decision process:

    Was Event ID 4768 observed?
                |
               YES
                |
                v
    Was Pre-Authentication Type 0?
                |
               YES
                |
                v
    Was the request successful?
    Result Code = 0x0
                |
               YES
                |
                v
    What account generated the request?
                |
                v
        asrep_test
                |
                v
    Is the account configured without
    Kerberos pre-authentication?
                |
               YES
                |
                v
    What was the source?
                |
                v
    Kali — 192.168.159.129
                |
                v
    Was activity repeated?
                |
               YES
                |
                v
    Two matching events observed
                |
                v
    Does the activity match the
    controlled attack?
                |
               YES
                |
                v
    CONFIRMED AS-REP ROASTING
    SIMULATION


---

## 21. Final Verdict

### Verdict

**CONFIRMED — AS-REP Roasting Simulation**

### Confidence

**High**

### Reasoning

The investigation established all of the following:

1. A dedicated Active Directory test account was configured without Kerberos pre-authentication.
2. The Kali host successfully communicated with the Domain Controller.
3. An AS-REP request was successfully performed against the test account.
4. Event ID `4768` was generated on the Domain Controller.
5. The event identified `asrep_test`.
6. The source address correlated with Kali at `192.168.159.129`.
7. Pre-Authentication Type was `0`.
8. Result Code was `0x0`.
9. Ticket Encryption Type was `0x17`.
10. Two matching events were observed.
11. The activity was successfully detected using behavioral detection logic.
12. The final detection produced an analyst-oriented alert.

The combination of these observations provides sufficient evidence to confirm that the controlled AS-REP Roasting attack simulation occurred successfully.


---

## 22. Production SOC Interpretation

Although the lab verdict is confirmed, the same evidence in a production environment would require additional validation before declaring a compromised account.

A production analyst should investigate:

    Account legitimacy
          |
          v
    Account privilege
          |
          v
    Source workstation
          |
          v
    User activity
          |
          v
    Related Kerberos events
          |
          v
    Endpoint telemetry
          |
          v
    Lateral movement
          |
          v
    Credential-access activity
          |
          v
    Final incident determination


---

## 23. Recommended Response Actions

If the activity were confirmed as malicious in a production environment:

### Immediate Actions

1. Identify and validate the affected account.
2. Investigate the source workstation.
3. Determine whether the account password may have been exposed.
4. Reset the affected account credentials where appropriate.
5. Review the account's privileges.
6. Search for related authentication activity.

### Active Directory Hardening

1. Identify other accounts where Kerberos pre-authentication is disabled.
2. Remove unnecessary `DoesNotRequirePreAuth` configurations.
3. Review privileged and service accounts.
4. Enforce strong and unique passwords.
5. Review legacy authentication dependencies.

### Threat Hunting

Search for:

- Additional Event ID `4768` Type `0` events.
- Repeated TGT requests.
- Other suspicious Kerberos activity.
- Event ID `4769`.
- Event ID `4624`.
- Event ID `4625`.
- Suspicious SMB activity.
- Remote authentication.
- Lateral movement indicators.
- Credential-access activity.


---

## 24. Detection Effectiveness Assessment

| Detection Capability | Result |
|---|---|
| Event ID 4768 monitoring | PASS |
| PreAuth Type 0 identification | PASS |
| Successful request filtering | PASS |
| Account extraction | PASS |
| Source IP extraction | PASS |
| Encryption extraction | PASS |
| Account/source correlation | PASS |
| Baseline comparison | PASS |
| Behavioral detection | PASS |
| Analyst alert generation | PASS |

### Overall Detection Result

**PASS**

The detection successfully identified the controlled AS-REP Roasting activity and provided sufficient context for investigation.


---

## 25. Evidence Inventory

All investigation evidence is stored under:

    screenshots/Day08/

| Evidence | Investigation Purpose |
|---|---|
| `Day08-01-ASREP-Test-Account-PreAuth-Disabled.png` | Account configuration evidence. |
| `Day08-02-Kali-ADDC-Connectivity.png` | Attack-source connectivity validation. |
| `Day08-03-ASREP-Roasting-Request.png` | Attack execution evidence. |
| `Day08-04-ASREP-4768-Full-Telemetry.png` | Full Kerberos Event ID 4768 evidence. |
| `Day08-05-ASREP-4768-Baseline.png` | Successful Type 0 event evidence. |
| `Day08-06-ASREP-Detection-Query.png` | Behavioral detection validation. |
| `Day08-07-ASREP-Frequency-Correlation.png` | Account/source frequency correlation. |
| `Day08-08-ASREP-PreAuth-Baseline-Comparison.png` | Successful authentication baseline comparison. |
| `Day08-09-ASREP-Analyst-Alert.png` | Final analyst-oriented alert evidence. |


---

## 26. Investigation Lessons Learned

This investigation demonstrated several practical SOC capabilities:

- Translating an attack technique into observable Windows telemetry.
- Investigating Kerberos Event ID `4768`.
- Identifying Pre-Authentication Type `0` as an important AS-REP Roasting indicator.
- Correlating authentication activity with source IP information.
- Using account configuration as contextual evidence.
- Separating behavioral detection from hard-coded test-account searches.
- Using baseline activity to provide additional context.
- Building an evidence-backed detection rather than relying on assumptions.
- Transforming raw security events into an analyst-oriented alert.
- Distinguishing confirmed laboratory activity from confirmed production compromise.
- Developing a repeatable SOC triage workflow.


---

## 27. Investigation Conclusion

The controlled investigation successfully demonstrated the complete defensive lifecycle for an AS-REP Roasting scenario.

The attack began with a dedicated Active Directory account configured without Kerberos pre-authentication.

The Kali attack host then generated an AS-REP request against the account.

The Domain Controller recorded the activity as Event ID `4768`.

The resulting telemetry contained:

    Account: asrep_test
    Source: 192.168.159.129
    Pre-Authentication Type: 0
    Result Code: 0x0
    Ticket Encryption Type: 0x17

Two matching events were observed and correlated to the same account and source.

A behavioral detection successfully identified the activity without relying on the known test account.

The final analyst-oriented alert provided the information required to begin SOC triage.

The investigation therefore demonstrates:

    Attack
       ↓
    Telemetry
       ↓
    Detection
       ↓
    Correlation
       ↓
    Investigation
       ↓
    Verdict
       ↓
    Response Recommendations

### Final Case Status

**CLOSED — Controlled AS-REP Roasting Simulation Successfully Executed, Detected, Correlated, and Investigated.**

### MITRE ATT&CK

**T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting**

This case demonstrates the integration of Active Directory attack simulation, Windows security telemetry, behavioral detection engineering, evidence correlation, and SOC investigation within a controlled Blue Team laboratory environment.