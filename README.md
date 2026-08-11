# Active Directory Attack & Detection Lab

A self-built enterprise lab simulating a small corporate Active Directory environment, built from the ground up to eventually support controlled attack simulation, Windows telemetry collection, and detection engineering mapped to MITRE ATT&CK.

> **Status: 🔨 In Progress — Foundation Phase (Day 00–01 of a multi-phase build)**
> Domain infrastructure and identity foundation are complete and verified. Attack simulation, Sysmon telemetry, SIEM integration, and detection engineering have **not started yet** and will be added in upcoming phases. This README will be updated as each phase lands.

---

## Project Goal

Most "AD lab" projects on GitHub stop at "I installed a domain controller." The goal here is to go further: stand up a realistic small-enterprise AD environment, generate real Windows security telemetry, run controlled attacks against it (Kerberoasting, password spraying, lateral movement, privilege escalation), forward that telemetry to a SIEM, and write custom detection rules for each attack — with every step documented and screenshot-verified.

This repo documents that build as it happens, day by day, rather than presenting a finished product retroactively.

---

## Lab Architecture

```
Windows 11 Host
       |
VMware Workstation
       |
   +---+--------------------------+
   |                              |
   v                              v
Windows Server 2022             Ubuntu (Wazuh SIEM)
AD-DC (Domain Controller)       existing infra, to be integrated
   |
   v
Active Directory
corp.local (CORP)
   |
   +-- Lab-Users        (alice, bob)
   +-- Lab-Groups       (SOC-Analysts, IT-Admins)
   +-- Lab-Workstations (WIN10-CLIENT)
   +-- Lab-Servers

Kali Linux (Attacker) --> planned controlled attack simulation
```

| Component | Configuration |
|---|---|
| Host OS | Windows 11 |
| Virtualization | VMware Workstation 17 |
| Domain Controller | Windows Server 2022 Standard Evaluation |
| DC Hostname | `AD-DC` |
| DC IP Address | `192.168.159.10` |
| AD Domain / NetBIOS | `corp.local` / `CORP` |
| Domain & Forest Functional Level | Windows Server 2016 |
| Client Workstation | `WIN10-CLIENT` |
| SIEM (existing, reused) | Ubuntu VM running Wazuh |
| Attacker Machine | Kali Linux |
| Network Mode | VMware NAT |

---

## What's Actually Built So Far

### Day 00 — Infrastructure Foundation
- Windows Server 2022 VM provisioned (2 vCPU, 4 GB RAM, 80 GB disk)
- Windows Server 2022 Standard Evaluation installed and validated
- Server renamed to `AD-DC`
- Static IPv4 addressing configured (gateway + DNS)
- Gateway and external connectivity verified via `ping`
- Project repository, folder structure, and documentation workflow established

### Day 01 — Active Directory Foundation & Identity Setup
- Active Directory Domain Services role installed
- Server promoted to first Domain Controller of a new forest: `corp.local` (NetBIOS: `CORP`)
- AD-integrated DNS deployed and verified (`corp.local`, `_msdcs.corp.local` zones confirmed)
- Custom OU structure created: `Lab-Users`, `Lab-Groups`, `Lab-Workstations`, `Lab-Servers`
- Two domain user accounts created and PowerShell-verified: `alice`, `bob`
- Two security groups created: `SOC-Analysts` (alice, bob), `IT-Admins` (Administrator)
- `WIN10-CLIENT` workstation joined to the domain and placed in `Lab-Workstations`
- Full environment baseline independently re-verified via `Get-ADUser`, `Get-ADGroupMember`, `Get-ADComputer`, `Get-ADOrganizationalUnit`

Every step above is backed by a command run in PowerShell (or the relevant GUI tool) plus a corresponding screenshot — see `docs/` for the full walkthrough with commands and output.

### Not built yet (planned)
- Sysmon deployment and telemetry tuning on `AD-DC` and `WIN10-CLIENT`
- Wazuh agent integration and log forwarding from the domain environment
- Controlled attack simulation (password spraying, Kerberoasting, AS-REP roasting, lateral movement, privilege escalation)
- Custom detection/correlation rules mapped to MITRE ATT&CK
- SOC-style investigation write-ups and incident reports

---

## Repository Structure

```
Project-03-AD-Attack-Detection-Lab/
├── README.md
├── docs/
│   ├── Day00.md          # Infra setup — full walkthrough, commands, verification
│   └── Day01.md          # AD domain, OUs, users, groups, workstation join
├── screenshots/
│   ├── Day00/            # 10 screenshots
│   └── Day01/            # 23 screenshots
├── architecture/         # planned
├── diagrams/             # planned
├── attacks/              # planned — attack simulation logs & steps
├── detections/           # planned — detection rules, MITRE mapping
├── reports/              # planned — investigation write-ups
└── scripts/               # planned
```

---

## Documentation

Each phase is documented in full in `docs/`, including every command executed, its output, and a corresponding screenshot as evidence:

- [`docs/Day00.md`](docs/Day00.md) — Windows Server provisioning and network setup
- [`docs/Day01.md`](docs/Day01.md) — Active Directory domain, OU, identity, and workstation build-out

33 screenshots are currently captured across both phases, following a consistent `DayXX-Number-Description.png` naming convention.

---

## Roadmap

| Phase | Focus | Status |
|---|---|---|
| Day 00 | Windows Server provisioning & network config | ✅ Complete |
| Day 01 | AD domain, OUs, users, groups, workstation join | ✅ Complete |
| Day 02 | Sysmon deployment & Windows event log tuning | ⏳ Planned |
| Day 03 | Wazuh integration & telemetry forwarding | ⏳ Planned |
| Day 04+ | Controlled attack simulation (Kerberoasting, spraying, lateral movement) | ⏳ Planned |
| Day N | Detection rule engineering & MITRE ATT&CK mapping | ⏳ Planned |
| Day N+1 | SOC investigation write-ups & incident reports | ⏳ Planned |

---

## Author

**Ananthan D**
B.Tech Information Technology, University College of Engineering, Kariavattom
[GitHub](https://github.com/ananthancyber)