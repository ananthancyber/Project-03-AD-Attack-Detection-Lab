# Pass-the-Hash Investigation Report

## 1. Executive Summary

A controlled Pass-the-Hash (PtH) authentication scenario was investigated within the `CORP.LOCAL` Active Directory lab environment.

The activity originated from the Kali Linux attacker system (`192.168.159.129`) and targeted `WIN10-CLIENT` (`192.168.159.133`) using the dedicated low-privilege domain account `CORP\pt_test`.

The authentication successfully established an SMB connection using NTLM credential material.

The activity generated multiple layers of defensive telemetry:

- Domain Controller Event ID `4776`
- Windows endpoint Event ID `4624`
- Network Logon Type `3`
- NTLM authentication
- Source IP `192.168.159.129`
- Wazuh Rule `92652`
- Wazuh Level `6` alert
- MITRE ATT&CK mappings for `T1550.002` and `T1078`

The evidence was correlated across the attacker system, Domain Controller, endpoint, and Wazuh SIEM.

**Investigation Result:** Confirmed controlled Pass-the-Hash activity in the isolated lab environment.

---

# 2. Incident Classification

| Field | Value |
|---|---|
| Incident Type | Credential Abuse / Lateral Authentication |
| Attack Technique | Pass-the-Hash |
| MITRE ATT&CK | T1550.002 |
| Secondary Technique | T1078 — Valid Accounts |
| Severity | Medium-High |
| Wazuh Rule | 92652 |
| Wazuh Level | 6 |
| Status | Confirmed — Controlled Lab Activity |
| Source Host | Kali Linux |
| Source IP | `192.168.159.129` |
| Target Host | `WIN10-CLIENT` |
| Target IP | `192.168.159.133` |
| Account | `CORP\pt_test` |
| Authentication | NTLM |
| Protocol/Service | SMB |

---

# 3. Environment

| System | Role | IP Address |
|---|---|---|
| AD-DC | Active Directory Domain Controller | `192.168.159.10` |
| WIN10-CLIENT | Windows endpoint / target | `192.168.159.133` |
| Kali Linux | Attack simulation host | `192.168.159.129` |
| Ubuntu / Wazuh | SIEM infrastructure | `192.168.159.130` |

### Domain

`CORP.LOCAL`

### Test Account

`CORP\pt_test`

The account was intentionally configured as a standard domain user and was used exclusively for the controlled lab exercise.

---

# 4. Investigation Objective

The investigation was designed to determine whether a successful remote NTLM authentication could be identified and correlated as Pass-the-Hash activity.

The investigation sought to answer:

1. Which account was used?
2. Where did the authentication originate?
3. Which endpoint received the authentication?
4. Which authentication protocol was used?
5. Did the Domain Controller validate the credentials?
6. Did the endpoint record the resulting logon?
7. Did Wazuh detect the authentication?
8. Does the observed activity correspond to a known MITRE ATT&CK technique?

---

# 5. Initial Baseline

Before the attack simulation, the Windows endpoint and authentication telemetry were validated.

The endpoint session baseline confirmed the existing Windows user/session state.

![Windows 10 User Session Baseline](../screenshots/Day09/Day09-01-Windows10-User-Session-Baseline.png)

Existing NTLM credential-validation telemetry was confirmed on the Domain Controller through Event ID `4776`.

![AD-DC NTLM 4776 Baseline](../screenshots/Day09/Day09-02-ADDC-NTLM-4776-Baseline.png)

Sysmon Event ID `1` process-creation telemetry was also verified on the Windows endpoint.

![Windows 10 Sysmon Process Baseline](../screenshots/Day09/Day09-03-Windows10-Sysmon-Process-Baseline.png)

Windows Security Event ID `4624` was confirmed as part of the endpoint authentication baseline.

![Windows 10 4624 Logon Baseline](../screenshots/Day09/Day09-04-Windows10-4624-Logon-Baseline.png)

These baseline checks established that the required Windows and endpoint telemetry was available before the controlled attack.

---

# 6. Account Assessment

The `pt_test` account was selected as the controlled test identity.

The account was confirmed to be:

- Enabled
- A standard domain account
- A member of `Domain Users`
- Not intentionally elevated for this exercise

This reduced unnecessary risk while allowing the authentication technique to be demonstrated.

---

# 7. Attack Simulation

The PtH authentication was initiated from:

**Kali Linux — `192.168.159.129`**

against:

**WIN10-CLIENT — `192.168.159.133`**

using the NTLM credential material associated with:

`CORP\pt_test`

The authentication successfully established an SMB session.

![Kali Pass-the-Hash SMB Authentication](../screenshots/Day09/Day09-05-Kali-PassTheHash-SMB-Authentication.png)

The authentication was subsequently repeated while the Wazuh agent on `WIN10-CLIENT` was confirmed to be online.

![Kali PtH SMB Authentication with Wazuh Online](../screenshots/Day09/Day09-09-Kali-PtH-SMB-Authentication-Wazuh-Online.png)

> Credential hashes and temporary passwords are intentionally excluded from this report.

---

# 8. Endpoint Investigation — Event 4624

Following the successful authentication, `WIN10-CLIENT` generated Windows Security Event ID `4624`.

The event contained the following relevant fields:

| Field | Observed Value |
|---|---|
| Account | `CORP\pt_test` |
| Event ID | `4624` |
| Logon Type | `3` — Network |
| Authentication Package | `NTLM` |
| NTLM Package | `NTLM V2` |
| Logon Process | `NtLmSsp` |
| Source IP | `192.168.159.129` |
| Destination | `WIN10-CLIENT` |

![Windows 10 PtH 4624 NTLM Network Logon](../screenshots/Day09/Day09-06-Windows10-PtH-4624-NTLM-Network-Logon.png)

### Analyst Assessment

The event demonstrates that:

- `pt_test` successfully authenticated.
- The authentication was a network logon.
- NTLM was used.
- The source was the Kali attacker host.

Event `4624` alone does not prove Pass-the-Hash. However, because the authentication was deliberately generated using the known NTLM hash during this controlled exercise, the event can be correlated directly with the simulated PtH activity.

---

# 9. Domain Controller Investigation — Event 4776

The Domain Controller generated Event ID `4776` for the same account.

The correlated event occurred at approximately:

**23:25:09**

![AD-DC PtH 4776 Correlation](../screenshots/Day09/Day09-07-ADDC-PtH-4776-Correlation.png)

The full event showed:

| Field | Observed Value |
|---|---|
| Event ID | `4776` |
| Account | `pt_test` |
| Authentication Package | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` |
| Error Code | `0x0` |
| Result | Successful credential validation |

![AD-DC PtH 4776 Full Telemetry](../screenshots/Day09/Day09-08-ADDC-PtH-4776-Full-Telemetry.png)

### Timeline Correlation

The authentication sequence was:

**23:25:09**

AD-DC:

`4776 → pt_test → credential validation successful`

↓

**23:25:10**

WIN10-CLIENT:

`4624 → pt_test → Logon Type 3 → NTLM → 192.168.159.129`

The one-second difference provides strong temporal correlation between the Domain Controller validation and the endpoint logon.

---

# 10. Wazuh Investigation

The fresh PtH authentication was performed while the Wazuh agent on `WIN10-CLIENT` was online.

The authentication successfully reached the SMB service.

![Kali PtH SMB Authentication with Wazuh Online](../screenshots/Day09/Day09-09-Kali-PtH-SMB-Authentication-Wazuh-Online.png)

Wazuh subsequently received the Windows authentication telemetry.

---

# 11. Wazuh Detection

Wazuh generated a Level 6 alert using:

**Rule 92652 — Successful Remote Logon Detected**

The alert was associated with the suspicious remote NTLM authentication pattern.

The primary alert timestamp was:

**September 3, 2026 @ 15:22:03.826**

The event was associated with:

| Field | Value |
|---|---|
| Agent | `WIN10-CLIENT` |
| Agent ID | `002` |
| Event ID | `4624` |
| Account | `pt_test` |
| Authentication | `NTLM` |
| Logon Type | `3` |
| Source IP | `192.168.159.129` |
| Rule | `92652` |
| Level | `6` |

Wazuh Document Details confirmed the authentication context.

![Wazuh PtH 4624 Document Details 01](../screenshots/Day09/Day09-10-Wazuh-PtH-4624-NTLM-Document-Details-01.png)

Additional authentication fields were identified within the event.

![Wazuh PtH 4624 Document Details 02](../screenshots/Day09/Day09-11-Wazuh-PtH-4624-NTLM-Document-Details-02.png)

The key fields used during the investigation were also confirmed.

![Wazuh PtH 4624 Key Fields](../screenshots/Day09/Day09-12-Wazuh-PtH-4624-Key-Fields.png)

---

# 12. Wazuh Detection Logic

Rule `92652` is part of a detection chain rather than an isolated rule.

### Rule 60106

Identifies successful Windows logon activity.

↓

### Rule 92651

Identifies successful remote logon activity originating from a non-loopback source.

↓

### Rule 92652

Identifies NTLM authentication associated with the remote logon.

↓

### Result

**Successful Remote Logon Detected**

**Level 6**

The rule is mapped to:

- `T1550.002` — Pass the Hash
- `T1078` — Valid Accounts

This detection logic allows Wazuh to identify authentication patterns that warrant further investigation.

---

# 13. Evidence Correlation

The investigation combined multiple independent sources.

| Source | Evidence | Finding |
|---|---|---|
| Kali | Successful SMB authentication | Hash-based authentication succeeded |
| WIN10-CLIENT | Event `4624` | Network logon |
| WIN10-CLIENT | Authentication Package | NTLM |
| WIN10-CLIENT | Source IP | `192.168.159.129` |
| AD-DC | Event `4776` | Credential validation succeeded |
| Wazuh | Rule `92652` | Remote NTLM logon detected |
| Wazuh | Level `6` | Medium-High alert |
| MITRE | `T1550.002` | Pass the Hash |
| MITRE | `T1078` | Valid Accounts |

---

# 14. Investigation Timeline

## Phase 1 — Baseline

Windows authentication and Sysmon telemetry were validated.

## Phase 2 — PtH Simulation

Kali initiated SMB authentication against `WIN10-CLIENT` using the `pt_test` NTLM credential material.

## Phase 3 — Domain Authentication

AD-DC generated:

`Event 4776`

indicating successful credential validation.

## Phase 4 — Endpoint Authentication

WIN10-CLIENT generated:

`Event 4624`

with:

- Logon Type `3`
- NTLM
- Source `192.168.159.129`

## Phase 5 — SIEM Detection

Wazuh generated:

`Rule 92652 — Successful Remote Logon Detected`

at Level `6`.

## Phase 6 — Correlation

The authentication activity was correlated across:

**Kali → AD-DC → WIN10-CLIENT → Wazuh**

---

# 15. Sysmon Investigation

Sysmon was verified as operational before the attack.

![Windows 10 Sysmon Process Baseline](../screenshots/Day09/Day09-03-Windows10-Sysmon-Process-Baseline.png)

No relevant Sysmon Event ID `1` process creation was observed during the specific authentication window.

This does not invalidate the detection.

SMB authentication can occur without creating a new process on the target endpoint.

Therefore, Sysmon was treated as **supporting telemetry**, while Windows Security Events and Wazuh provided the primary authentication evidence.

---

# 16. Analyst Assessment

### Finding

**Confirmed Pass-the-Hash activity within the controlled lab environment.**

### Confidence

**High**

### Reasoning

The conclusion is supported by multiple independent observations:

1. The PtH technique was deliberately executed using the known test account's NTLM hash.
2. The SMB authentication succeeded.
3. WIN10-CLIENT generated Event `4624`.
4. The event showed Network Logon Type `3`.
5. The authentication package was NTLM.
6. The source IP corresponded to the Kali attacker system.
7. AD-DC generated Event `4776`.
8. The credential validation result was successful.
9. Wazuh generated Rule `92652`.
10. The Wazuh detection was mapped to MITRE T1550.002.

---

# 17. Impact Assessment

The test account was deliberately configured as a standard domain user.

Therefore, the demonstrated impact was limited to:

- Successful remote authentication
- SMB access/authentication
- Demonstration of credential reuse
- Demonstration of potential lateral movement capability

No Domain Administrator credential was used for this exercise.

### Potential Production Impact

If the same technique were performed using a privileged account, an attacker could potentially:

- Authenticate to additional systems.
- Access administrative resources.
- Move laterally.
- Access sensitive shares.
- Execute further actions depending on available privileges.
- Expand control across the Active Directory environment.

The actual impact would depend on the privileges associated with the compromised account.

---

# 18. False-Positive Analysis

The presence of NTLM does not automatically indicate malicious activity.

Potential legitimate scenarios include:

- Legacy applications.
- Approved administrative activity.
- File-server authentication.
- Service accounts.
- Older systems.
- Applications that cannot use Kerberos.

### Analyst Validation

An analyst should therefore compare:

- Source IP
- User
- Destination
- Normal authentication behavior
- Account privilege
- Authentication frequency
- Asset ownership

An unexpected NTLM network logon from an unusual workstation is more suspicious than a known, documented administrative authentication.

---

# 19. Recommended Response

If this alert occurred in a production environment, the following actions would be appropriate.

### Immediate Actions

1. Validate whether the authentication was authorized.
2. Identify the source host.
3. Investigate the source system for compromise.
4. Review the affected account's recent activity.
5. Search for additional remote logons.
6. Search for additional destination systems.
7. Reset credentials if compromise is suspected.
8. Isolate the source endpoint when appropriate.

### Follow-Up Investigation

Search for:

- Additional Event `4624` activity.
- Additional Event `4776` activity.
- Other accounts authenticated from the same source.
- Other hosts accessed by the account.
- Repeated NTLM authentication.
- Administrative activity.
- Lateral movement indicators.

---

# 20. Defensive Recommendations

### Authentication Hardening

- Reduce unnecessary NTLM usage.
- Prefer Kerberos where practical.
- Monitor abnormal NTLM authentication.
- Restrict legacy authentication dependencies.

### Identity Security

- Apply least privilege.
- Protect privileged accounts.
- Separate administrative and standard accounts.
- Restrict where privileged accounts can authenticate.

### Monitoring

- Monitor Event `4624`.
- Monitor Event `4776`.
- Monitor unusual source IPs.
- Baseline normal authentication paths.
- Correlate authentication events with endpoint telemetry.
- Maintain SIEM detection coverage for suspicious NTLM activity.

---

# 21. MITRE ATT&CK Mapping

## T1550.002 — Pass the Hash

**Tactic:** Defense Evasion / Credential Access

The attacker uses an NTLM hash as authentication material instead of requiring the plaintext password.

This was the primary technique demonstrated in the controlled exercise.

## T1078 — Valid Accounts

**Tactic:** Defense Evasion / Persistence / Privilege Escalation / Initial Access

The attack used the legitimate Active Directory account:

`CORP\pt_test`

The detection demonstrates why legitimate accounts can still be abused for malicious authentication.

---

# 22. Evidence Gallery

### Attack Simulation

![Kali PtH SMB Authentication](../screenshots/Day09/Day09-05-Kali-PassTheHash-SMB-Authentication.png)

### Windows Authentication

![Windows 10 PtH 4624](../screenshots/Day09/Day09-06-Windows10-PtH-4624-NTLM-Network-Logon.png)

### Domain Controller Correlation

![AD-DC 4776 Correlation](../screenshots/Day09/Day09-07-ADDC-PtH-4776-Correlation.png)

### Domain Controller Full Telemetry

![AD-DC 4776 Full Telemetry](../screenshots/Day09/Day09-08-ADDC-PtH-4776-Full-Telemetry.png)

### Wazuh Detection

![Wazuh PtH Detection](../screenshots/Day09/Day09-10-Wazuh-PtH-4624-NTLM-Document-Details-01.png)

### Wazuh Authentication Fields

![Wazuh PtH Authentication Details](../screenshots/Day09/Day09-11-Wazuh-PtH-4624-NTLM-Document-Details-02.png)

### Wazuh Key Detection Fields

![Wazuh PtH Key Fields](../screenshots/Day09/Day09-12-Wazuh-PtH-4624-Key-Fields.png)

---

# 23. Investigation Summary

The controlled investigation successfully demonstrated how Pass-the-Hash activity can be investigated through correlated Windows and SIEM telemetry.

The final evidence chain was:

**Kali**

`192.168.159.129`

↓

**NTLM Hash-Based Authentication**

↓

**AD-DC**

`Event 4776`

↓

**WIN10-CLIENT**

`Event 4624`

`Logon Type 3`

`NTLM`

`Source 192.168.159.129`

↓

**Wazuh**

`Rule 92651`

↓

`Rule 92652`

↓

**Level 6 — Successful Remote Logon Detected**

↓

**MITRE T1550.002 / T1078**

The investigation demonstrates a complete SOC workflow from **attack simulation to telemetry collection, SIEM detection, evidence correlation, analyst assessment, and defensive response**.

---

## Final Assessment

**Detection Status:** Validated

**Attack Status:** Confirmed in Controlled Lab

**Primary Technique:** T1550.002 — Pass the Hash

**Detection Platform:** Wazuh

**Primary Windows Telemetry:** 4624 / 4776

**Analyst Confidence:** High

**Recommended Production Response:** Investigate source host, validate account usage, correlate authentication activity, and contain the source if unauthorized activity is confirmed.