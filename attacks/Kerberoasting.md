# Kerberoasting Attack Simulation

## Project

**Project:** Active Directory Attack & Detection Lab  
**Attack:** Kerberoasting  
**MITRE ATT&CK:** T1558.003 — Kerberoasting  
**Tactic:** Credential Access  
**Attack Platform:** Kali Linux  
**Target Environment:** Active Directory / Windows Server 2022  
**Domain:** `corp.local`  
**Domain Controller:** `AD-DC.corp.local`  
**Target Service Account:** `svc_sql`

---

# 1. Attack Overview

Kerberoasting is an Active Directory credential-access technique in which an authenticated domain user requests Kerberos service tickets for accounts associated with Service Principal Names (SPNs).

The resulting service-ticket material can potentially be subjected to offline password cracking.

For this lab, a controlled Kerberoasting simulation was performed against a dedicated service account named `svc_sql`.

The objective was not to compromise a production system or crack credentials. The purpose was to generate realistic Kerberos authentication telemetry that could subsequently be investigated and detected from a Blue Team perspective.

The attack lifecycle was:

    Domain User
        |
        v
    SPN Enumeration
        |
        v
    SPN-backed Service Account
        |
        v
    Kerberos TGS Request
        |
        v
    Service Ticket Material
        |
        v
    Windows Event ID 4769
        |
        v
    Blue Team Detection & Investigation

---

# 2. Attack Objectives

The objectives of the simulation were:

1. Identify Service Principal Names in the Active Directory environment.
2. Create a controlled SPN-backed service account.
3. Verify the SPN configuration.
4. Use a low-privileged domain account to enumerate the SPN.
5. Request a Kerberos service ticket for the target SPN.
6. Capture the resulting attack evidence.
7. Generate realistic Windows Kerberos telemetry.
8. Provide telemetry for subsequent detection engineering and SOC investigation.

---

# 3. Lab Environment

| Component | Configuration |
|---|---|
| Domain | `corp.local` |
| NetBIOS Domain | `CORP` |
| Domain Controller | `AD-DC.corp.local` |
| Domain Controller IP | `192.168.159.10` |
| Windows Client | `WIN10-CLIENT` |
| Attack Host | Kali Linux |
| Attacking User | `alice` |
| Target Service Account | `svc_sql` |
| Target SPN | `MSSQLSvc/AD-DC.corp.local:1433` |
| Primary Telemetry | Windows Security Event ID 4769 |

---

# 4. Attack Prerequisites

The following conditions were established before the simulation:

- Active Directory domain was operational.
- Kali Linux could communicate with the Domain Controller.
- The `alice` domain account was available.
- A dedicated `svc_sql` service account was created.
- The service account was not intentionally granted administrative privileges.
- The `svc_sql` account had a registered SPN.
- Kerberos service-ticket logging was available on the Domain Controller.

---

# 5. SPN Enumeration

The first stage was to establish the existing SPN baseline.

SPNs identify services associated with Kerberos-enabled accounts and are important when investigating Kerberoasting opportunities.

The Active Directory environment was queried for registered SPNs.

The initial enumeration established the existing Kerberos service-principal landscape before introducing the controlled service account.

### Evidence

![SPN Enumeration Baseline](../screenshots/Day06/Day06-01-SPN-Enumeration-Baseline.png)

**Evidence:** `Day06-01-SPN-Enumeration-Baseline.png`

---

# 6. Controlled Service Account Creation

A dedicated service account was created for the simulation:

`CORP\svc_sql`

The account was intentionally kept as a normal domain account and was not granted administrative privileges.

Using a dedicated account ensured that the attack remained controlled and that the resulting telemetry could be clearly attributed to the lab exercise.

### Evidence

![Service Account Creation](../screenshots/Day06/Day06-02-Service-Account-Creation.png)

**Evidence:** `Day06-02-Service-Account-Creation.png`

---

# 7. SPN Configuration

The service account was configured with the following MSSQL Service Principal Name:

`MSSQLSvc/AD-DC.corp.local:1433`

The SPN was registered using:

    setspn -S MSSQLSvc/AD-DC.corp.local:1433 CORP\svc_sql

The resulting relationship was:

    svc_sql
        |
        +---- MSSQLSvc/AD-DC.corp.local:1433

This created the controlled Kerberos service target required for the simulation.

### Evidence

![Service Account SPN Configuration](../screenshots/Day06/Day06-03-Service-Account-SPN-Configuration.png)

**Evidence:** `Day06-03-Service-Account-SPN-Configuration.png`

---

# 8. SPN Uniqueness Verification

Before starting the attack, the SPN was verified to ensure that it was associated with the intended service account.

The service account SPNs were queried using:

    setspn -L CORP\svc_sql

The target SPN was confirmed as:

    MSSQLSvc/AD-DC.corp.local:1433

The SPN was associated with:

    CORP\svc_sql

This ensured that the attack target was correctly configured and avoided ambiguity caused by duplicate SPNs.

### Evidence

![SPN Uniqueness Verification](../screenshots/Day06/Day06-04-SPN-Uniqueness-Verification.png)

**Evidence:** `Day06-04-SPN-Uniqueness-Verification.png`

---

# 9. Pre-Attack Kerberos Baseline

Before executing the attack, Kerberos service-ticket activity was reviewed on the Domain Controller.

The purpose was to establish a baseline for comparison after the attack.

The primary Windows event of interest was:

**Event ID 4769 — A Kerberos service ticket was requested.**

This baseline allowed the later investigation to distinguish existing authentication activity from attack-generated activity.

### Evidence

![Pre-Attack Kerberos Baseline](../screenshots/Day06/Day06-05-PreAttack-Kerberos-4769-Baseline.png)

**Evidence:** `Day06-05-PreAttack-Kerberos-4769-Baseline.png`

---

# 10. Kerberoasting Simulation

The attack was performed from Kali Linux using the Impacket `GetUserSPNs` utility.

The low-privileged domain account used for the simulation was:

`corp.local/alice`

The target service account was:

`svc_sql`

The target SPN was:

`MSSQLSvc/AD-DC.corp.local:1433`

The attack command was:

    impacket-GetUserSPNs corp.local/alice -dc-host AD-DC.corp.local -request

The command performed SPN enumeration and requested a Kerberos service ticket for the identified SPN.

---

# 11. Attack Result

The tool successfully identified the target SPN:

    MSSQLSvc/AD-DC.corp.local:1433

The SPN was associated with:

    svc_sql

A Kerberos service ticket was then requested.

The resulting ticket material was returned by the tool.

This confirmed that the controlled Kerberoasting simulation was successful.

The ticket material was **not cracked**.

The project intentionally focused on:

- Attack simulation
- Windows telemetry
- Detection engineering
- Event correlation
- SOC investigation

rather than password-cracking activity.

### Evidence

![Kerberoasting TGS Request](../screenshots/Day06/Day06-06-Kerberoasting-TGS-Request.png)

**Evidence:** `Day06-06-Kerberoasting-TGS-Request.png`

---

# 12. Attack-to-Telemetry Relationship

The simulated attack generated Kerberos service-ticket activity on the Domain Controller.

The attack relationship was:

    Kali Linux
        |
        | alice
        v
    SPN Enumeration
        |
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
        v
    Windows Security Event 4769

The resulting Event 4769 became the primary telemetry artifact used by the Blue Team investigation.

---

# 13. Observed Attack Indicators

The simulated attack produced the following important indicators:

| Indicator | Observed Value |
|---|---|
| Requesting Account | `alice@CORP.LOCAL` |
| Target Service Account | `svc_sql` |
| SPN | `MSSQLSvc/AD-DC.corp.local:1433` |
| Source IP | `192.168.159.129` |
| Windows Event | `4769` |
| Encryption Type | `0x17` / RC4 |
| Failure Code | `0x0` |

These indicators were subsequently used for detection and correlation.

---

# 14. Windows Event Evidence

The Domain Controller generated Event ID 4769 following the TGS request.

The event contained:

    Account Name:
    alice@CORP.LOCAL

    Service Name:
    svc_sql

    Client Address:
    192.168.159.129

    Ticket Encryption Type:
    0x17

    Failure Code:
    0x0

The successful request and its relationship to the SPN-backed service account provided the primary Windows evidence of the simulated attack.

### Evidence

![Kerberos Event 4769](../screenshots/Day06/Day06-07-Kerberos-4769-Attack-Evidence.png)

**Evidence:** `Day06-07-Kerberos-4769-Attack-Evidence.png`

---

# 15. Attack Validation

The attack was considered successfully simulated because:

1. The target SPN existed.
2. The SPN was associated with `svc_sql`.
3. `alice` was able to enumerate the SPN.
4. A TGS request was successfully generated.
5. Kerberos ticket material was returned.
6. Event ID 4769 was generated on the Domain Controller.
7. The event contained the expected requester and target information.

The attack therefore produced both:

**Offensive Evidence**

and

**Defensive Telemetry**

---

# 16. Attack Evidence Index

All attack evidence is stored under:

`screenshots/Day06/`

| Evidence | Description |
|---|---|
| `Day06-01-SPN-Enumeration-Baseline.png` | Initial SPN enumeration |
| `Day06-02-Service-Account-Creation.png` | Controlled service account creation |
| `Day06-03-Service-Account-SPN-Configuration.png` | SPN registration |
| `Day06-04-SPN-Uniqueness-Verification.png` | SPN verification |
| `Day06-05-PreAttack-Kerberos-4769-Baseline.png` | Pre-attack Kerberos baseline |
| `Day06-06-Kerberoasting-TGS-Request.png` | Successful TGS request |
| `Day06-07-Kerberos-4769-Attack-Evidence.png` | Windows Event 4769 evidence |

Detection-specific evidence is documented separately in:

`detections/Kerberoasting-4769.md`

Additional detection evidence includes:

- `Day06-08-Kerberoasting-Detection-Query.png`
- `Day06-09-RC4-Kerberos-Detection.png`
- `Day06-10-Kerberoasting-Correlation-Evidence.png`
- `Day06-11-Kerberos-Encryption-Baseline.png`

---

# 17. MITRE ATT&CK Mapping

## Tactic

**Credential Access**

## Technique

**T1558 — Steal or Forge Kerberos Tickets**

## Sub-technique

**T1558.003 — Kerberoasting**

### Technique Relationship

    Authenticated Domain User
            |
            v
    SPN Enumeration
            |
            v
    SPN-backed Service Account
            |
            v
    Kerberos TGS Request
            |
            v
    Service Ticket Material
            |
            v
    Potential Offline Credential Attack

The simulated activity therefore maps to:

**T1558.003 — Kerberoasting**

---

# 18. Attack Impact

If the password of a targeted service account is weak, the Kerberos service-ticket material obtained during Kerberoasting may be subjected to offline password cracking.

A successful compromise of the service account could potentially provide:

- Access to resources assigned to the service account
- Additional authentication opportunities
- A pathway toward privilege escalation
- Additional lateral-movement opportunities

The impact depends heavily on the privileges and resource access associated with the targeted service account.

In this lab, `svc_sql` was intentionally configured as a controlled, non-administrative account.

---

# 19. Defensive Significance

From a Blue Team perspective, the most important aspect of the attack is the telemetry it generates.

The attack produced:

    Kerberos TGS Request
            |
            v
    Event ID 4769
            |
            v
    Requester Identification
            +
    Service Account Identification
            +
    SPN Identification
            +
    Source IP
            +
    Encryption Type
            |
            v
    Detection Opportunity

This telemetry was subsequently used to develop the Kerberoasting detection documented in:

`detections/Kerberoasting-4769.md`

---

# 20. Attack Simulation Limitations

The simulation intentionally had several limitations:

- Only a controlled lab service account was targeted.
- The service account was not granted administrative privileges.
- The resulting ticket was not cracked.
- The simulation was performed entirely inside the isolated lab environment.
- No production systems or credentials were targeted.

These limitations ensured that the exercise remained safe while still generating realistic Active Directory and Kerberos telemetry.

---

# 21. Final Attack Summary

The controlled Kerberoasting simulation successfully demonstrated:

**SPN Enumeration**

→ Identification of an SPN-backed service account.

**Service Account Preparation**

→ Creation of the controlled `svc_sql` account.

**SPN Configuration**

→ Registration of `MSSQLSvc/AD-DC.corp.local:1433`.

**TGS Request**

→ `alice` requested a Kerberos service ticket.

**Attack Telemetry**

→ Windows generated Event ID 4769.

**Attack Indicators**

→ Requester, target service, source IP, encryption type, and request status were identified.

**MITRE Mapping**

→ T1558.003 — Kerberoasting.

---

# 22. Conclusion

The Day 06 Kerberoasting simulation successfully demonstrated a controlled Active Directory credential-access attack.

The simulation began with SPN enumeration and service-account preparation and progressed to a Kerberos TGS request from a low-privileged domain account.

The resulting Windows Event 4769 provided the defensive telemetry required for detection engineering and SOC investigation.

The attack therefore established the foundation for the next stages of the project:

    Attack Simulation
          |
          v
    Windows Telemetry
          |
          v
    Detection Engineering
          |
          v
    Event Correlation
          |
          v
    SOC Investigation
          |
          v
    MITRE ATT&CK Mapping
          |
          v
    Defensive Response

This attack documentation represents the **offensive side** of the Day 06 exercise.

The corresponding detection logic is maintained separately under:

`detections/Kerberoasting-4769.md`

The complete analyst investigation will be maintained under:

`reports/Kerberoasting-Investigation.md`