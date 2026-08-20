# Active Directory Attack & Detection Lab

> A documented, isolated Active Directory lab that builds identity infrastructure and endpoint telemetry, then validates a controlled Kerberoasting detection and SOC investigation workflow.

## Overview

This repository documents an end-to-end Active Directory security lab built in VMware Workstation. It begins with a Windows Server 2022 domain controller and a domain-joined Windows 10 endpoint, adds Windows Security auditing, Sysmon, and Wazuh endpoint monitoring, and then uses the resulting telemetry to investigate a controlled Kerberoasting simulation.

The work is evidence-led: the repository contains daily build documentation, 122 screenshots, a dedicated attack narrative, a detection specification, and a SOC investigation report. The completed case study focuses on the path from an SPN-backed service account and a Kerberos TGS request to Windows Security Event ID `4769`, contextual detection, baseline comparison, and an analyst verdict.

## Objectives

- Build and validate an isolated Active Directory environment with a Windows endpoint.
- Establish authentication, process, identity, privilege, policy, and Kerberos baselines before evaluating attack activity.
- Centralize and review `WIN10-CLIENT` Sysmon telemetry in Wazuh.
- Generate a controlled AD credential-access scenario and capture its Windows telemetry.
- Develop and validate detection logic that uses context and baseline deviation rather than a single indicator.
- Document the investigative process, result, MITRE mapping, and defensive response considerations.

## What was implemented

- Provisioned `AD-DC`, a Windows Server 2022 domain controller for `corp.local` (`CORP`), with AD DS and AD-integrated DNS.
- Built an OU structure for users, groups, workstations, and servers; created lab users and security groups; and joined `WIN10-CLIENT` to the domain.
- Enabled and investigated Windows authentication and process telemetry: Security Events `4624`, `4625`, and `4688`, plus Sysmon Event `1`.
- Deployed Sysmon and enrolled `WIN10-CLIENT` in Wazuh as agent `002`; validated endpoint-to-dashboard process telemetry.
- Established an identity, privilege, policy, Kerberos-ticket, trust, and secure-channel baseline on the Windows client.
- Performed a controlled Kerberoasting simulation from Kali Linux against the dedicated, non-administrative `svc_sql` account.
- Validated `DET-AD-001`, a documented PowerShell-based detection specification for suspicious successful Kerberos TGS requests using RC4 (`0x17`) and supporting context.
- Produced a SOC investigation report that correlates requester, target service, SPN, source IP, encryption type, request success, and the observed encryption baseline.

## Lab architecture

```text
Windows 11 host / VMware Workstation 17 (NAT)
│
├── AD-DC — Windows Server 2022
│   ├── `corp.local` / `CORP`
│   ├── Active Directory Domain Services + AD-integrated DNS
│   └── Windows Security telemetry, including Event 4769
│
├── WIN10-CLIENT — Windows 10 (`192.168.159.133`)
│   ├── Domain joined to `corp.local`
│   ├── Windows Security auditing + Sysmon
│   └── Wazuh agent `002`
│          │
│          └── Wazuh Manager / Dashboard — Ubuntu (`192.168.159.130`)
│
└── Kali Linux (`192.168.159.129`)
    └── Controlled Kerberoasting simulation
```

`AD-DC` uses `192.168.159.10`. The Wazuh evidence in this repository demonstrates monitoring of `WIN10-CLIENT`; the Kerberoasting detection queries were validated against the Domain Controller's Windows Security log. No custom Wazuh detection-rule file is included.

## Technologies and evidence

| Area | Technologies / implementation evidence |
| --- | --- |
| Identity infrastructure | Windows Server 2022, AD DS, AD-integrated DNS, `corp.local` / `CORP` |
| Endpoint | Windows 10, Windows Security auditing, Sysmon |
| SIEM monitoring | Wazuh 4.14.6 Manager and Wazuh Agent `002` on `WIN10-CLIENT` |
| Attack simulation | Kali Linux, Impacket `GetUserSPNs`, controlled SPN-backed service account |
| Detection and investigation | PowerShell `Get-WinEvent`, Event `4769`, RC4 (`0x17`) analysis, SPN/service/source correlation |
| Virtualization | Windows 11 host, VMware Workstation 17, NAT networking |
| Documentation | Markdown, Git/GitHub, 122 captured screenshots |

## Build and monitoring workflow

```text
AD foundation → domain-joined endpoint → Windows Security auditing
    → Sysmon process telemetry → Wazuh endpoint ingestion
    → identity / privilege / Kerberos baselines
    → controlled Kerberoasting simulation
    → Event 4769 detection and contextual correlation
    → SOC investigation and response recommendations
```

Before the attack exercise, the project established known-good telemetry and identity context. For example, it correlates Security Event `4624` with later process activity by Logon ID, examines Security Event `4688` and Sysmon Event `1`, and reconstructs the benign process chain `powershell.exe → cmd.exe → whoami.exe`.

## Active Directory and endpoint foundations

The domain controller was promoted as the first writable DC for `corp.local`, with DNS and Global Catalog enabled. The repository verifies the custom OUs `Lab-Users`, `Lab-Groups`, `Lab-Workstations`, and `Lab-Servers`, along with users `alice` and `bob`, the `SOC-Analysts` and `IT-Admins` groups, and the `WIN10-CLIENT` computer object.

Day 05 expands the baseline from the endpoint perspective: it documents domain and privileged-group membership, local administrators, the `LabAdmin` local account, account policy, applied GPOs, active sessions, Kerberos tickets, domain trusts, and secure-channel health. In the captured policy baseline, the minimum password length is 7 characters and the lockout threshold is `Never`; these are lab observations, not recommended production settings.

![Active Directory OU structure](screenshots/Day01/Day01-09-AD-Organizational-Structure.png)

## Telemetry and Wazuh validation

| Source | What the repository demonstrates |
| --- | --- |
| Windows Security `4624` | Successful-logon analysis and Logon ID correlation |
| Windows Security `4625` | Failed-logon investigation |
| Windows Security `4688` | Process-creation investigation for Notepad and PowerShell |
| Sysmon Event `1` | Process creation and parent-child process analysis |
| Wazuh | Ingestion of `WIN10-CLIENT` Sysmon telemetry and dashboard review |

![Wazuh dashboard process-creation evidence](screenshots/Day04/Day04-12-Wazuh-Dashboard-Cmd-ProcessCreation.png)

## Controlled Kerberoasting case study

The completed attack simulation is intentionally scoped to an isolated lab. A dedicated normal domain account, `CORP\svc_sql`, was created and configured with the SPN `MSSQLSvc/AD-DC.corp.local:1433`. From Kali Linux, the low-privileged account `alice` used Impacket `GetUserSPNs` to enumerate SPNs and request a service ticket. The returned ticket material was not cracked.

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

![Kerberos Event 4769 correlation evidence](screenshots/Day06/Day06-10-Kerberoasting-Correlation-Evidence.png)

## Detection engineering: `DET-AD-001`

[`detections/Kerberoasting-4769.md`](detections/Kerberoasting-4769.md) defines **Suspicious Kerberos TGS Request — Potential Kerberoasting**. It is a validated lab detection specification, not an automated Wazuh correlation rule.

The validated PowerShell logic looks for successful Security Event `4769` records with RC4 (`0x17`) encryption. It is an investigation signal, not a standalone verdict. High confidence in the lab came from correlating:

```text
successful Event 4769
  + RC4 / 0x17
  + SPN-backed service account
  + unusual requester and source
  + encryption-baseline deviation
  = high-confidence Kerberoasting indicator
```

The detection documentation distinguishes a known-target validation query for `svc_sql` from a generalized query that does not hard-code the service account. It proposes future production tuning such as requester/service/source baselines and ticket-volume analysis.

### Baseline result

For the observed sample of 50 Event `4769` records, the repository recorded:

| Ticket encryption type | Count |
| --- | ---: |
| AES-256 / `0x12` | 49 |
| RC4 / `0x17` | 1 |

This makes RC4 anomalous in this lab sample. It does **not** mean every RC4 ticket is malicious; the supporting documentation explicitly discusses legitimate legacy use and false-positive review.

## Investigation outcome

[`reports/Kerberoasting-Investigation.md`](reports/Kerberoasting-Investigation.md) documents the SOC-style assessment: alert triage, Event `4769` analysis, requester and service-account identification, SPN validation, source-IP review, encryption analysis, baseline comparison, attack correlation, MITRE mapping, severity assessment, and defensive recommendations.

The report concludes **Confirmed — Controlled Lab Simulation** with high confidence because the ticket request, SPN-backed target, source, requester, RC4 indicator, successful request, rare baseline occurrence, and known simulation align.

## Evidence highlights

| Stage | Evidence |
| --- | --- |
| AD structure | [`Day01-09-AD-Organizational-Structure.png`](screenshots/Day01/Day01-09-AD-Organizational-Structure.png) |
| Endpoint domain authentication | [`Day02-07-Windows10-Domain-Login.png`](screenshots/Day02/Day02-07-Windows10-Domain-Login.png) |
| Sysmon process-tree baseline | [`Day03-11-Windows10-Sysmon-Cmd-ProcessTree.png`](screenshots/Day03/Day03-11-Windows10-Sysmon-Cmd-ProcessTree.png) |
| Wazuh process telemetry | [`Day04-12-Wazuh-Dashboard-Cmd-ProcessCreation.png`](screenshots/Day04/Day04-12-Wazuh-Dashboard-Cmd-ProcessCreation.png) |
| AD security baseline | [`Day05-32-Kerberos-Ticket-Baseline.png`](screenshots/Day05/Day05-32-Kerberos-Ticket-Baseline.png) |
| Kerberoasting request | [`Day06-06-Kerberoasting-TGS-Request.png`](screenshots/Day06/Day06-06-Kerberoasting-TGS-Request.png) |
| Windows evidence | [`Day06-07-Kerberos-4769-Attack-Evidence.png`](screenshots/Day06/Day06-07-Kerberos-4769-Attack-Evidence.png) |
| Detection correlation | [`Day06-10-Kerberoasting-Correlation-Evidence.png`](screenshots/Day06/Day06-10-Kerberoasting-Correlation-Evidence.png) |

## Repository guide

```text
.
├── README.md
├── docs/
│   ├── Day00.md … Day06.md
├── attacks/
│   └── Kerberoasting.md
├── detections/
│   └── Kerberoasting-4769.md
├── reports/
│   └── Kerberoasting-Investigation.md
└── screenshots/
    └── Day00/ … Day06/
```

## Skills demonstrated

- Active Directory administration: AD DS, DNS, OUs, users, groups, workstation domain join, and PowerShell validation.
- Endpoint and SIEM operations: Windows audit events, Sysmon, Wazuh agent enrollment, telemetry validation, and dashboard inspection.
- Security analysis: Logon ID correlation, process-tree analysis, baseline creation, Kerberos ticket review, and false-positive reasoning.
- Detection engineering: Event `4769` field analysis, contextual correlation, and environment-specific tuning.
- SOC investigation: triage, source/requester/service/SPN correlation, MITRE ATT&CK mapping, severity rationale, and response recommendations.
- Safe adversary emulation: a controlled Kerberoasting exercise using a low-privileged account and dedicated service account, without credential cracking.

## Documentation

- [Day 00 — Project initialization and server preparation](docs/Day00.md)
- [Day 01 — Active Directory foundation and identity lab](docs/Day01.md)
- [Day 02 — Windows client and Security auditing](docs/Day02.md)
- [Day 03 — Sysmon deployment and process telemetry](docs/Day03.md)
- [Day 04 — Wazuh SIEM integration and cross-source correlation](docs/Day04.md)
- [Day 05 — Active Directory identity, privilege, and security baseline](docs/Day05.md)
- [Day 06 — Kerberoasting simulation and detection engineering](docs/Day06.md)
- [Attack simulation](attacks/Kerberoasting.md) · [Detection specification](detections/Kerberoasting-4769.md) · [Investigation report](reports/Kerberoasting-Investigation.md)

## Reviewing or reproducing the documented workflow

This repository is documentation and evidence, not a deployable application: it contains no installation script, infrastructure-as-code, Wazuh rule file, container configuration, or package manifest.

1. Verify the AD, client, Sysmon, and Wazuh monitoring prerequisites in [Day 00–Day 05 documentation](docs/Day05.md).
2. Review the controlled service-account, SPN, and Kali-host prerequisites in [the attack narrative](attacks/Kerberoasting.md).
3. In an authorized isolated lab only, perform the documented simulation and inspect the Domain Controller's Security Event `4769` records.
4. Validate the PowerShell Event `4769` queries in [the detection specification](detections/Kerberoasting-4769.md), then investigate requester, service, source, encryption type, request result, and baseline context.

Verify the required configuration from the project documentation before attempting to reproduce the environment. The repository does not provide a production deployment procedure.

## Future improvements

The following are documented as future work and are not claimed as complete:

- Additional controlled AD attack scenarios, such as password spraying, AS-REP roasting, lateral movement, and privilege escalation.
- Additional detection content and automated SIEM correlation rules.
- Broader MITRE ATT&CK coverage based on future simulations.
- Expanded endpoint-to-domain-controller telemetry correlation and detection tuning.

## Responsible-use disclaimer

This project was developed for educational and authorized security testing in an isolated lab environment. The Kerberoasting activity was a controlled simulation using a dedicated service account; the resulting ticket material was not cracked. Do not use these techniques against systems or accounts without explicit authorization.

## License

No license file is present in this repository.

## Author

**Ananthan D**  
[GitHub](https://github.com/ananthancyber)