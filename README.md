# Active Directory Attack & Detection Lab

> A documented, isolated Active Directory lab that builds identity infrastructure and endpoint telemetry, then runs three controlled credential-access simulations — Kerberoasting, AS-REP Roasting, and unexpected-source NTLM authentication — through detection, correlation, and SOC investigation.

## Overview

This repository documents an end-to-end Active Directory security lab built in VMware Workstation. It begins with a Windows Server 2022 domain controller and a domain-joined Windows 10 endpoint, adds Windows Security auditing, Sysmon, and Wazuh endpoint monitoring, then uses the resulting telemetry and native Windows Security logging to investigate three controlled attack scenarios.

The work is evidence-led: 9 days of build/attack documentation, 150 screenshots, three attack narratives, three detection specifications, and three SOC investigation reports. Each scenario follows the same lifecycle — attack condition, controlled execution, Windows telemetry, behavioral detection query, baseline comparison, and a written analyst verdict.

## Objectives

- Build and validate an isolated Active Directory environment with a Windows endpoint.
- Establish authentication, process, identity, privilege, policy, and Kerberos baselines before evaluating attack activity.
- Centralize and review `WIN10-CLIENT` Sysmon telemetry in Wazuh.
- Generate controlled AD credential-access scenarios and capture their Windows telemetry.
- Develop and validate detection logic that uses context and baseline deviation rather than a single indicator.
- Document the investigative process, result, MITRE mapping, and defensive response considerations for each scenario.

## What was implemented

- Provisioned `AD-DC`, a Windows Server 2022 domain controller for `corp.local` (`CORP`), with AD DS and AD-integrated DNS.
- Built an OU structure for users, groups, workstations, and servers; created lab users and security groups; and joined `WIN10-CLIENT` to the domain.
- Enabled and investigated Windows authentication and process telemetry: Security Events `4624`, `4625`, and `4688`, plus Sysmon Event `1`.
- Deployed Sysmon and enrolled `WIN10-CLIENT` in Wazuh as agent `002`; validated endpoint-to-dashboard process telemetry.
- Established an identity, privilege, policy, Kerberos-ticket, trust, and secure-channel baseline on the Windows client.
- **Kerberoasting (Day 06):** performed a controlled simulation from Kali Linux against the dedicated `svc_sql` service account and validated `DET-AD-001`, a PowerShell detection for successful Kerberos TGS requests using RC4 (`0x17`).
- **Unexpected-source NTLM (Day 07):** established a normal authentication baseline for a dedicated `pt_test` account from `WIN10-CLIENT`, then generated and detected the same account authenticating from Kali via SMB, correlating Event `4624` (endpoint) with Event `4776` (domain controller).
- **AS-REP Roasting (Day 08):** configured a dedicated `asrep_test` account without Kerberos pre-authentication, requested its AS-REP from Kali, and validated a behavioral detection on Event `4768` using Pre-Authentication Type `0` rather than a hard-coded account name.
- Produced three SOC investigation reports, each correlating requester, account, source IP, encryption/result codes, and baseline deviation to a documented analyst verdict.

## Lab architecture

```text
Windows 11 host / VMware Workstation 17 (NAT)
│
├── AD-DC — Windows Server 2022
│   ├── `corp.local` / `CORP`
│   ├── Active Directory Domain Services + AD-integrated DNS
│   └── Windows Security telemetry: Events 4768, 4769, 4776
│
├── WIN10-CLIENT — Windows 10 (`192.168.159.133`)
│   ├── Domain joined to `corp.local`
│   ├── Windows Security auditing + Sysmon
│   ├── Wazuh agent `002`
│   └── Windows Security telemetry: Event 4624
│          │
│          └── Wazuh Manager / Dashboard — Ubuntu (`192.168.159.130`)
│
└── Kali Linux (`192.168.159.129`)
    └── Kerberoasting, AS-REP Roasting, and NTLM authentication simulations
```

`AD-DC` uses `192.168.159.10`. The Wazuh evidence in this repository demonstrates Sysmon/process-telemetry monitoring of `WIN10-CLIENT` (Days 03–04). **All three attack detections (Kerberoasting, NTLM, AS-REP) query the Windows Security event log directly via PowerShell, not through Wazuh** — there is no custom Wazuh correlation rule file, and Wazuh is not part of the detection path for any of the three scenarios. That gap is intentional to disclose rather than paper over; see Limitations.

## Technologies and evidence

| Area | Technologies / implementation evidence |
| --- | --- |
| Identity infrastructure | Windows Server 2022, AD DS, AD-integrated DNS, `corp.local` / `CORP` |
| Endpoint | Windows 10, Windows Security auditing, Sysmon |
| SIEM monitoring | Wazuh 4.14.6 Manager and Wazuh Agent `002` on `WIN10-CLIENT` (Sysmon/process telemetry only) |
| Attack simulation | Kali Linux, Impacket (`GetUserSPNs`, `GetNPUsers`), SMB/NTLM authentication testing |
| Detection and investigation | PowerShell `Get-WinEvent`, Events `4624`/`4768`/`4769`/`4776`, encryption-type and pre-auth-type analysis, source/account correlation |
| Virtualization | Windows 11 host, VMware Workstation 17, NAT networking |
| Documentation | Markdown, Git/GitHub, 150 captured screenshots |

## Build and monitoring workflow

```text
AD foundation → domain-joined endpoint → Windows Security auditing
    → Sysmon process telemetry → Wazuh endpoint ingestion
    → identity / privilege / Kerberos baselines
    → controlled Kerberoasting simulation (Day 06)
    → controlled unexpected-source NTLM simulation (Day 07)
    → controlled AS-REP Roasting simulation (Day 08)
    → detection, correlation, and SOC investigation for each
```

## Active Directory and endpoint foundations

The domain controller was promoted as the first writable DC for `corp.local`, with DNS and Global Catalog enabled. The repository verifies the custom OUs `Lab-Users`, `Lab-Groups`, `Lab-Workstations`, and `Lab-Servers`, along with users `alice` and `bob`, the `SOC-Analysts` and `IT-Admins` groups, and the `WIN10-CLIENT` computer object.

Day 05 expands the baseline from the endpoint perspective: domain and privileged-group membership, local administrators, the `LabAdmin` local account, account policy, applied GPOs, active sessions, Kerberos tickets, domain trusts, and secure-channel health. In the captured policy baseline, the minimum password length is 7 characters and the lockout threshold is `Never` — lab observations, not recommended production settings.

![Active Directory OU structure](screenshots/Day01/Day01-09-AD-Organizational-Structure.png)

## Telemetry and Wazuh validation

| Source | What the repository demonstrates |
| --- | --- |
| Windows Security `4624` | Successful-logon analysis, Logon ID correlation, and (Day 07) unexpected-source detection |
| Windows Security `4625` | Failed-logon investigation |
| Windows Security `4688` | Process-creation investigation for Notepad and PowerShell |
| Windows Security `4768` | (Day 08) Kerberos AS-REQ / AS-REP detection via Pre-Authentication Type |
| Windows Security `4769` | (Day 06) Kerberos TGS request detection via encryption type |
| Windows Security `4776` | (Day 07) Domain-controller credential-validation correlation |
| Sysmon Event `1` | Process creation and parent-child process analysis |
| Wazuh | Ingestion of `WIN10-CLIENT` Sysmon telemetry and dashboard review (Days 03–04 only) |

![Wazuh dashboard process-creation evidence](screenshots/Day04/Day04-12-Wazuh-Dashboard-Cmd-ProcessCreation.png)

---

## Attack scenarios

### Scenario 1 — Kerberoasting (Day 06)

A dedicated normal domain account, `CORP\svc_sql`, was created with the SPN `MSSQLSvc/AD-DC.corp.local:1433`. From Kali, the low-privileged account `alice` used Impacket `GetUserSPNs` to enumerate SPNs and request a service ticket. The returned ticket material was not cracked.

| Field | Observed lab value |
| --- | --- |
| MITRE ATT&CK | Credential Access — `T1558.003` Kerberoasting |
| Requester | `alice@CORP.LOCAL` |
| Target service account | `svc_sql` |
| SPN | `MSSQLSvc/AD-DC.corp.local:1433` |
| Source | Kali Linux, `192.168.159.129` |
| Primary telemetry | Windows Security Event `4769` on `AD-DC` |
| Request outcome | Successful (`Failure Code: 0x0`) |
| Encryption indicator | RC4 / `0x17` |

**Detection (`DET-AD-001`):** successful Event `4769` with RC4 (`0x17`) encryption, cross-checked against a baseline of 50 sampled `4769` records where 49 used AES-256 and only 1 used RC4 — making RC4 anomalous in this environment, though not inherently malicious (legacy services can legitimately use it).

**Verdict:** Confirmed — Controlled Lab Simulation, high confidence.

![Kerberos Event 4769 correlation evidence](screenshots/Day06/Day06-10-Kerberoasting-Correlation-Evidence.png)

Full documentation: [`attacks/Kerberoasting.md`](attacks/Kerberoasting.md) · [`detections/Kerberoasting-4769.md`](detections/Kerberoasting-4769.md) · [`reports/Kerberoasting-Investigation.md`](reports/Kerberoasting-Investigation.md)

---

### Scenario 2 — Unexpected-source NTLM authentication (Day 07)

A dedicated account, `CORP\pt_test`, was used first from `WIN10-CLIENT` to establish a normal authentication baseline (Event `4624`/`4776`, source `192.168.159.133`). The same account was then used from Kali via SMB, generating an identical account/protocol but a different source (`KALI`, `192.168.159.129`).

| Field | Observed lab value |
| --- | --- |
| MITRE ATT&CK | `T1078` Valid Accounts (primary); `T1021.002` SMB/Windows Admin Shares (supporting) |
| Test account | `CORP\pt_test` |
| Baseline source | `WIN10-CLIENT`, `192.168.159.133` |
| Suspicious source | `KALI`, `192.168.159.129` |
| Primary telemetry | Event `4624` (endpoint, Logon Type `3`, NTLM V2) |
| Correlated telemetry | Event `4776` (domain controller, `Error Code: 0x0`) |

**Detection (`DET-NTLM-001`):** successful Type 3 NTLM logon where the source workstation/IP deviates from the account's expected baseline, with Event `4776` used to confirm the domain controller successfully validated the same credentials from the same source at a matching timestamp. Explicitly scoped as a Medium-severity investigation trigger, not proof of compromise — NTLM from an unfamiliar host has plenty of legitimate explanations (admin activity, service accounts, new workstations).

**Verdict:** Closed — Controlled Lab Validation. Detection and correlation both validated; no compromise claimed.

Full documentation: [`attacks/NTLM-Authentication-Test.md`](attacks/NTLM-Authentication-Test.md) · [`detections/NTLM-Unexpected-Source-4624-4776.md`](detections/NTLM-Unexpected-Source-4624-4776.md) · [`reports/NTLM-Investigation.md`](reports/NTLM-Investigation.md)

---

### Scenario 3 — AS-REP Roasting (Day 08)

A dedicated account, `CORP\asrep_test`, was reconfigured with `DoesNotRequirePreAuth = True`. From Kali, an AS-REP request was sent for the account, and the Domain Controller returned AS-REP material without requiring pre-authentication.

| Field | Observed lab value |
| --- | --- |
| MITRE ATT&CK | Credential Access — `T1558.004` AS-REP Roasting |
| Target account | `asrep_test` |
| Source | Kali Linux, `192.168.159.129` |
| Primary telemetry | Windows Security Event `4768` on `AD-DC` |
| Result Code | `0x0` (successful) |
| Pre-Authentication Type | `0` |
| Ticket Encryption Type | `0x17` |
| Matching events observed | 2 |

**Detection:** behavioral, not account-name-based — flags successful Event `4768` where Pre-Authentication Type is `0`, deliberately avoiding a hard-coded match on `asrep_test`. Baselined against a one-hour window of 9 successful `4768` events, of which 7 used normal Type `2` pre-auth and 2 matched the Type `0` condition — both belonging to the simulated account.

**Verdict:** Confirmed AS-REP Roasting activity within the controlled lab environment.

> **Note:** the recovered AS-REP hash material for this scenario is visible unredacted in one of the Day 08 screenshots. It's a lab-only artifact and not exploitable outside the isolated network, but redact it before treating this repo as final — a portfolio reviewer will notice it.

Full documentation: [`attacks/ASREP-Roasting.md`](attacks/ASREP-Roasting.md) · [`detections/ASREP-Roasting-4768.md`](detections/ASREP-Roasting-4768.md) · [`reports/ASREP-Roasting-Investigation.md`](reports/ASREP-Roasting-Investigation.md)

---

## MITRE ATT&CK mapping

| Tactic | Technique | ID | Scenario |
| --- | --- | --- | --- |
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | `T1558.003` | Day 06 |
| Credential Access | Steal or Forge Kerberos Tickets: AS-REP Roasting | `T1558.004` | Day 08 |
| Defense Evasion / Initial Access | Valid Accounts | `T1078` | Day 07 |
| Lateral Movement | SMB/Windows Admin Shares (supporting) | `T1021.002` | Day 07 |

## Evidence highlights

| Stage | Evidence |
| --- | --- |
| AD structure | [`Day01-09-AD-Organizational-Structure.png`](screenshots/Day01/Day01-09-AD-Organizational-Structure.png) |
| Sysmon process-tree baseline | [`Day03-11-Windows10-Sysmon-Cmd-ProcessTree.png`](screenshots/Day03/Day03-11-Windows10-Sysmon-Cmd-ProcessTree.png) |
| Wazuh process telemetry | [`Day04-12-Wazuh-Dashboard-Cmd-ProcessCreation.png`](screenshots/Day04/Day04-12-Wazuh-Dashboard-Cmd-ProcessCreation.png) |
| Kerberoasting detection correlation | [`Day06-10-Kerberoasting-Correlation-Evidence.png`](screenshots/Day06/Day06-10-Kerberoasting-Correlation-Evidence.png) |
| NTLM unexpected-source detection | [`Day07-15-PT-Test-Kali-4624-Detection.png`](screenshots/Day07/Day07-15-PT-Test-Kali-4624-Detection.png) |
| AS-REP analyst alert | [`Day08-09-ASREP-Analyst-Alert.png`](screenshots/Day08/Day08-09-ASREP-Analyst-Alert.png) |

## Repository guide

```text
.
├── README.md
├── docs/
│   └── Day00.md … Day08.md
├── attacks/
│   ├── Kerberoasting.md
│   ├── NTLM-Authentication-Test.md
│   └── ASREP-Roasting.md
├── detections/
│   ├── Kerberoasting-4769.md
│   ├── NTLM-Unexpected-Source-4624-4776.md
│   └── ASREP-Roasting-4768.md
├── reports/
│   ├── Kerberoasting-Investigation.md
│   ├── NTLM-Investigation.md
│   └── ASREP-Roasting-Investigation.md
└── screenshots/
    └── Day00/ … Day08/
```

## Skills demonstrated

- Active Directory administration: AD DS, DNS, OUs, users, groups, workstation domain join, and PowerShell validation.
- Endpoint and SIEM operations: Windows audit events, Sysmon, Wazuh agent enrollment, telemetry validation, and dashboard inspection.
- Security analysis: Logon ID correlation, process-tree analysis, baseline creation, Kerberos ticket review, and false-positive reasoning.
- Detection engineering: behavioral (not hard-coded) detection logic across Events `4624`, `4768`, `4769`, and `4776`; encryption-type, pre-auth-type, and source-baseline analysis.
- SOC investigation: triage, source/requester/service/account correlation, MITRE ATT&CK mapping, severity rationale, and response recommendations across three closed cases.
- Safe adversary emulation: three controlled attack simulations (Kerberoasting, AS-REP Roasting, unexpected-source NTLM) using dedicated low-privilege accounts, without credential cracking.

## Documentation

- [Day 00 — Project initialization and server preparation](docs/Day00.md)
- [Day 01 — Active Directory foundation and identity lab](docs/Day01.md)
- [Day 02 — Windows client and Security auditing](docs/Day02.md)
- [Day 03 — Sysmon deployment and process telemetry](docs/Day03.md)
- [Day 04 — Wazuh SIEM integration and cross-source correlation](docs/Day04.md)
- [Day 05 — Active Directory identity, privilege, and security baseline](docs/Day05.md)
- [Day 06 — Kerberoasting simulation and detection engineering](docs/Day06.md)
- [Day 07 — NTLM authentication investigation, correlation & detection engineering](docs/Day07.md)
- [Day 08 — AS-REP Roasting attack, detection & SOC investigation](docs/Day08.md)

## Reviewing or reproducing the documented workflow

This repository is documentation and evidence, not a deployable application: it contains no installation script, infrastructure-as-code, Wazuh rule file, container configuration, or package manifest.

1. Verify the AD, client, Sysmon, and Wazuh monitoring prerequisites in [Day 00–Day 05 documentation](docs/Day05.md).
2. Review the controlled account and Kali-host prerequisites in the relevant attack narrative ([Kerberoasting](attacks/Kerberoasting.md), [NTLM](attacks/NTLM-Authentication-Test.md), [AS-REP Roasting](attacks/ASREP-Roasting.md)).
3. In an authorized isolated lab only, perform the documented simulation and inspect the Domain Controller's Security Event log.
4. Validate the PowerShell detection queries in the corresponding [`detections/`](detections/) file, then investigate account, source, encryption/pre-auth type, request result, and baseline context.

The repository does not provide a production deployment procedure.



## Responsible-use disclaimer

This project was developed for educational and authorized security testing in an isolated lab environment. All three attack simulations used dedicated accounts created for the exercise; the AS-REP and Kerberoasting ticket material recovered was not cracked. Do not use these techniques against systems or accounts without explicit authorization.

## License

No license file is present in this repository.

## Author

**Ananthan D**
[GitHub](https://github.com/ananthancyber)