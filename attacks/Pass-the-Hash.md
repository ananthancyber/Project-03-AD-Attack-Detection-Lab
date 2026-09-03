# Pass-the-Hash Attack

## Overview

This lab demonstrates a controlled **Pass-the-Hash (PtH)** authentication scenario in an Active Directory environment.

The objective was to demonstrate how an attacker can authenticate to a Windows endpoint using an NTLM hash rather than the user's plaintext password, and how the resulting authentication activity can be investigated through Windows Security telemetry and Wazuh SIEM.

The exercise follows a realistic Blue Team workflow:

**Attack Simulation → Windows Telemetry → Domain Authentication Validation → Wazuh Detection → Event Correlation → Analyst Assessment**

> **Security Note:** All activity documented here was performed against an isolated Active Directory lab using a dedicated low-privilege test account. Credential material used during the exercise is intentionally excluded from this documentation.

---

## Attack Objective

The objective of this exercise was to:

- Demonstrate Pass-the-Hash authentication against a Windows endpoint.
- Understand how NTLM authentication appears in Windows Security logs.
- Correlate endpoint Event ID 4624 with Domain Controller Event ID 4776.
- Validate that the authentication originated from the Kali attacker system.
- Verify centralized visibility through Wazuh.
- Analyze Wazuh's existing Pass-the-Hash detection logic.
- Map the activity to MITRE ATT&CK.
- Produce an investigation-ready evidence chain.

---

## Attack Concept

### What is Pass-the-Hash?

**Pass-the-Hash (PtH)** is an authentication technique where an attacker uses an NTLM password hash to authenticate as a user without requiring knowledge of the user's plaintext password.

The attacker does not need to recover the original password. Instead, the NTLM hash can be supplied directly to an authentication-capable tool.

In this lab, a dedicated Active Directory account named `pt_test` was used for the demonstration.

The account was intentionally configured as a low-privilege test account and was a member of:

- `Domain Users`

No Domain Administrator privileges were required for this demonstration.

---

## Lab Environment

| Component | Role | IP Address |
|---|---|---|
| AD-DC | Windows Server 2022 / Active Directory Domain Controller | `192.168.159.10` |
| WIN10-CLIENT | Windows endpoint / authentication target | `192.168.159.133` |
| Kali Linux | Attack simulation system | `192.168.159.129` |
| Ubuntu / Wazuh | SIEM and centralized monitoring | `192.168.159.130` |

### Domain

`CORP.LOCAL`

### Test Account

`CORP\pt_test`

The test account was deliberately kept as a standard domain user to avoid introducing unnecessary administrative privileges into the exercise.

---

# 1. Pre-Attack Baseline

Before performing the authentication test, the Active Directory account and endpoint telemetry were validated.

The test account was confirmed to be enabled and suitable for the controlled exercise.

![Windows 10 User Session Baseline](../screenshots/Day09/Day09-01-Windows10-User-Session-Baseline.png)

The Domain Controller was also checked for existing NTLM authentication validation telemetry using Event ID 4776.

![AD-DC NTLM 4776 Baseline](../screenshots/Day09/Day09-02-ADDC-NTLM-4776-Baseline.png)

Sysmon process creation telemetry was verified on the Windows endpoint.

![Windows 10 Sysmon Process Baseline](../screenshots/Day09/Day09-03-Windows10-Sysmon-Process-Baseline.png)

Windows Security Event ID 4624 was also validated as part of the endpoint authentication baseline.

![Windows 10 4624 Logon Baseline](../screenshots/Day09/Day09-04-Windows10-4624-Logon-Baseline.png)

---

# 2. Controlled Pass-the-Hash Authentication

The controlled authentication was performed from Kali Linux against the SMB service of `WIN10-CLIENT`.

The dedicated `pt_test` account's NTLM credential material was used for the authentication test.

The authentication successfully established an SMB session to the Windows endpoint.

![Kali Pass-the-Hash SMB Authentication](../screenshots/Day09/Day09-05-Kali-PassTheHash-SMB-Authentication.png)

> The NTLM hash visible in the original terminal output must remain redacted from public documentation and portfolio material.

### Attack Flow

The simulated authentication path was:

**Kali Linux**
→ `CORP\pt_test`
→ NTLM hash-based authentication
→ SMB
→ `WIN10-CLIENT`

---

# 3. Windows Endpoint Telemetry

After the authentication, the Windows endpoint generated **Security Event ID 4624**, indicating a successful logon.

The event contained the following important fields:

| Field | Observed Value |
|---|---|
| Account | `CORP\pt_test` |
| Event ID | `4624` |
| Logon Type | `3` — Network |
| Authentication Package | `NTLM` |
| NTLM Package | `NTLM V2` |
| Logon Process | `NtLmSsp` |
| Source Network Address | `192.168.159.129` |
| Target Host | `WIN10-CLIENT` |

![Windows 10 PtH 4624 NTLM Network Logon](../screenshots/Day09/Day09-06-Windows10-PtH-4624-NTLM-Network-Logon.png)

### Analyst Interpretation

Event ID 4624 by itself does **not prove Pass-the-Hash**.

However, this event provides strong authentication context:

- The account was `pt_test`.
- The logon was a network logon.
- NTLM was used.
- The source address was the Kali attacker system.
- The authentication occurred during the controlled PtH test.

This information becomes significantly more valuable when correlated with the Domain Controller telemetry and the known attack activity.

---

# 4. Domain Controller Correlation

The Domain Controller generated **Security Event ID 4776** during the same authentication sequence.

The initial correlation showed the event occurring immediately before the endpoint-side 4624 event.

![AD-DC PtH 4776 Correlation](../screenshots/Day09/Day09-07-ADDC-PtH-4776-Correlation.png)

The full Event ID 4776 telemetry showed:

| Field | Observed Value |
|---|---|
| Event ID | `4776` |
| Logon Account | `pt_test` |
| Authentication Package | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` |
| Error Code | `0x0` |
| Result | Credential validation successful |

![AD-DC PtH 4776 Full Telemetry](../screenshots/Day09/Day09-08-ADDC-PtH-4776-Full-Telemetry.png)

### Authentication Timeline

The observed sequence was:

**23:25:09**
→ AD-DC Event `4776`
→ `pt_test` credential validation successful

**23:25:10**
→ WIN10-CLIENT Event `4624`
→ Network Logon Type `3`
→ NTLM authentication
→ Source `192.168.159.129`

This one-second correlation provides strong evidence that the Domain Controller authentication validation and endpoint network logon were part of the same authentication sequence.

---

# 5. Wazuh Detection Validation

After confirming the Windows-side telemetry, the attack was repeated while the Wazuh agent on `WIN10-CLIENT` was online.

The controlled authentication again successfully reached the SMB service.

![Kali PtH SMB Authentication with Wazuh Online](../screenshots/Day09/Day09-09-Kali-PtH-SMB-Authentication-Wazuh-Online.png)

This allowed the Windows authentication telemetry to be forwarded to the centralized Wazuh environment.

---

# 6. Wazuh Alert

Wazuh generated an alert for the successful remote NTLM authentication.

### Wazuh Detection

| Field | Value |
|---|---|
| Agent | `WIN10-CLIENT` |
| Agent ID | `002` |
| Event ID | `4624` |
| Account | `pt_test` |
| Authentication | `NTLM` |
| Source IP | `192.168.159.129` |
| Wazuh Rule | `92652` |
| Rule Level | `6` |
| Detection | Successful Remote Logon Detected |

The Wazuh Document Details confirmed that the event contained the expected authentication information.

![Wazuh PtH 4624 Document Details 01](../screenshots/Day09/Day09-10-Wazuh-PtH-4624-NTLM-Document-Details-01.png)

Additional event fields confirmed the NTLM authentication and Kali source address.

![Wazuh PtH 4624 Document Details 02](../screenshots/Day09/Day09-11-Wazuh-PtH-4624-NTLM-Document-Details-02.png)

The key fields used for the investigation were:

- `targetUserName = pt_test`
- `authenticationPackageName = NTLM`
- `lmPackageName = NTLM V2`
- `logonProcessName = NtLmSsp`
- `logonType = 3`
- `ipAddress = 192.168.159.129`
- `eventID = 4624`

![Wazuh PtH 4624 Key Fields](../screenshots/Day09/Day09-12-Wazuh-PtH-4624-Key-Fields.png)

---

# 7. Wazuh Detection Logic

The Wazuh environment already contained a detection chain specifically designed to identify suspicious remote NTLM authentication.

## Rule 92651

Rule `92651` acts as the parent detection condition.

It identifies successful remote logons originating from a non-loopback IPv4 address.

Conceptually:

**Successful Windows Logon**
→ Remote Source Address
→ Non-loopback Source
→ Rule `92651`

## Rule 92652

Rule `92652` builds on Rule `92651` and identifies NTLM authentication.

The resulting alert is:

**Successful Remote Logon Detected**

The rule is configured at **Level 6** and associates the activity with:

- `T1550.002` — Pass the Hash
- `T1078` — Valid Accounts

### Detection Chain

**Windows Event 4624**
→ Successful logon

**Rule 60106**
→ Windows Logon Success

**Rule 92651**
→ Successful remote logon from external/non-loopback source

**Rule 92652**
→ Authentication Package = NTLM

**Wazuh Level 6 Alert**
→ Possible Pass-the-Hash activity

---

# 8. Analyst Assessment

The activity was assessed as **consistent with Pass-the-Hash authentication** based on the combination of controlled attack execution and independent telemetry.

### Evidence Supporting the Assessment

1. A dedicated `pt_test` account was used.
2. The account was a standard domain user.
3. Kali successfully authenticated to `WIN10-CLIENT` using the account's NTLM hash.
4. Windows generated Event ID `4624`.
5. The 4624 event identified:
   - Network Logon Type `3`
   - NTLM authentication
   - NTLM V2
   - Source IP `192.168.159.129`
6. AD-DC generated Event ID `4776` for `pt_test`.
7. Event 4776 showed successful credential validation with error code `0x0`.
8. Wazuh received the authentication telemetry after the endpoint agent was online.
9. Wazuh Rule `92652` generated a Level 6 alert for the successful remote NTLM authentication.

### Confidence

**High confidence in the controlled lab context.**

The reason for the high confidence is that the authentication was deliberately generated using the known NTLM hash during the test, and the resulting Windows and Wazuh telemetry independently corroborated the activity.

> NTLM authentication alone is not sufficient to prove Pass-the-Hash in a production environment. A SOC analyst should correlate authentication telemetry with endpoint, identity, source-host, and behavioral evidence.

---

# 9. Sysmon Correlation

Sysmon was active on `WIN10-CLIENT` and Event ID `1` process-creation telemetry was verified before the attack.

![Windows 10 Sysmon Process Baseline](../screenshots/Day09/Day09-03-Windows10-Sysmon-Process-Baseline.png)

During the specific PtH authentication window, no relevant Sysmon Event ID `1` process-creation event was observed.

This is expected because SMB authentication does not necessarily require a new process to be created on the target endpoint.

Therefore:

**Sysmon was treated as supporting endpoint telemetry, not as the primary PtH detection source.**

The primary detection evidence was derived from:

- Windows Security Event `4624`
- Domain Controller Event `4776`
- Wazuh Rule `92652`

This distinction prevents overclaiming the capabilities of individual telemetry sources.

---

# 10. MITRE ATT&CK Mapping

## T1550.002 — Pass the Hash

**Tactic:** Credential Access / Defense Evasion

Pass-the-Hash allows an attacker to use an NTLM credential hash to authenticate without requiring the plaintext password.

This was the primary technique demonstrated in this exercise.

## T1078 — Valid Accounts

**Tactic:** Defense Evasion / Persistence / Privilege Escalation / Initial Access

The authentication used a legitimate domain account:

`CORP\pt_test`

The activity demonstrates why legitimate credentials can still represent malicious behavior when they are used from an unexpected source or in an abnormal authentication pattern.

---

# 11. Investigation Workflow

A SOC analyst investigating a similar alert should follow a structured process.

### Step 1 — Validate the Alert

Confirm:

- Alert timestamp
- Source IP
- Destination host
- Username
- Authentication package
- Logon type

### Step 2 — Investigate the Account

Determine:

- Is the account privileged?
- Is the account normally used from this source?
- Is the account active?
- Has the password recently changed?
- Are there recent authentication anomalies?

### Step 3 — Investigate the Source Host

Determine:

- Is the source system authorized?
- Is it an administrator workstation?
- Is it an attacker-controlled system?
- Are there other suspicious activities from the same source?

### Step 4 — Correlate Authentication Events

Review:

- Event `4624`
- Event `4776`
- Other authentication events
- Wazuh alerts
- Endpoint telemetry

### Step 5 — Establish Scope

Search for:

- Additional logons from the same source IP
- Additional accounts authenticated from the source
- Additional destination hosts
- Repeated NTLM authentication
- Lateral movement activity

### Step 6 — Determine Impact

Assess whether the account:

- Accessed sensitive systems
- Obtained administrative privileges
- Accessed file shares
- Performed lateral movement
- Executed additional malicious activity

---

# 12. Recommended Defensive Response

If this activity were identified in a production environment, recommended actions would include:

### Immediate Response

- Validate whether the authentication was authorized.
- Isolate the suspected source host if compromise is suspected.
- Disable or restrict the affected account when appropriate.
- Reset the affected credentials.
- Review other systems authenticated by the account.
- Investigate additional activity originating from the source IP.

### Detection Improvements

- Monitor unusual NTLM authentication.
- Alert on remote NTLM authentication from unexpected systems.
- Baseline normal authentication sources for privileged accounts.
- Correlate Event `4624` with Event `4776`.
- Monitor repeated remote authentication attempts.
- Integrate endpoint telemetry with identity and SIEM data.

### Hardening

- Reduce unnecessary NTLM usage.
- Prefer Kerberos where practical.
- Apply least privilege.
- Protect privileged accounts.
- Restrict administrative logons.
- Use dedicated administrative workstations where appropriate.
- Monitor lateral movement patterns.

---

# 13. Key Lessons Learned

This exercise demonstrated several important Blue Team concepts:

### 1. A single event rarely proves an attack

Event `4624` showed a successful NTLM network logon, but additional context was required to assess whether the activity was malicious.

### 2. Authentication correlation is powerful

Correlating:

**AD-DC 4776**
+
**WIN10 4624**
+
**Source IP**
+
**Account**
+
**Authentication Package**

provided significantly stronger evidence than inspecting one event independently.

### 3. SIEM detection requires context

Wazuh Rule `92652` identified the NTLM remote-logon pattern as potentially consistent with Pass-the-Hash.

The analyst still needs to validate the alert against the actual activity.

### 4. Sysmon is not the answer to every detection

Sysmon provided valuable process telemetry in the lab, but no relevant process creation occurred during this authentication.

The correct approach is to use the telemetry source that best represents the behavior being investigated.

### 5. Low-privilege test accounts are valuable

Using a dedicated `pt_test` account allowed the authentication technique to be demonstrated without unnecessarily exposing or using privileged credentials.

---

# 14. Evidence Summary

| Evidence | Purpose |
|---|---|
| `Day09-01-Windows10-User-Session-Baseline.png` | Endpoint/session baseline |
| `Day09-02-ADDC-NTLM-4776-Baseline.png` | NTLM authentication baseline |
| `Day09-03-Windows10-Sysmon-Process-Baseline.png` | Sysmon process telemetry baseline |
| `Day09-04-Windows10-4624-Logon-Baseline.png` | Windows successful-logon baseline |
| `Day09-05-Kali-PassTheHash-SMB-Authentication.png` | Controlled PtH authentication |
| `Day09-06-Windows10-PtH-4624-NTLM-Network-Logon.png` | Target-side authentication telemetry |
| `Day09-07-ADDC-PtH-4776-Correlation.png` | DC/endpoint authentication correlation |
| `Day09-08-ADDC-PtH-4776-Full-Telemetry.png` | Full DC-side credential validation |
| `Day09-09-Kali-PtH-SMB-Authentication-Wazuh-Online.png` | Fresh PtH execution with Wazuh online |
| `Day09-10-Wazuh-PtH-4624-NTLM-Document-Details-01.png` | Wazuh event investigation |
| `Day09-11-Wazuh-PtH-4624-NTLM-Document-Details-02.png` | Wazuh authentication details |
| `Day09-12-Wazuh-PtH-4624-Key-Fields.png` | Key Wazuh detection fields |

---

# 15. Conclusion

This exercise demonstrated a complete controlled Pass-the-Hash investigation from both the offensive and defensive perspectives.

The attack was successfully simulated using a dedicated Active Directory test account and NTLM credential material.

The authentication generated:

**AD-DC Event 4776**
→ successful credential validation

**WIN10-CLIENT Event 4624**
→ Network Logon Type 3
→ NTLM authentication
→ source `192.168.159.129`

**Wazuh Rule 92652**
→ Level 6
→ Successful Remote Logon Detected
→ MITRE T1550.002 / T1078

The investigation demonstrates how a SOC analyst can move beyond a single SIEM alert and correlate identity, endpoint, network-source, and authentication telemetry to assess potential credential abuse.

**Final Detection Chain:**

**PtH Simulation**
→ **NTLM Authentication**
→ **Windows 4624**
→ **AD-DC 4776**
→ **Wazuh Rule 92652**
→ **MITRE ATT&CK**
→ **SOC Investigation**
→ **Defensive Response**