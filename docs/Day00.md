# Day 00 — Project Initialization

## Project
Active Directory Attack & Detection Lab

## Objective

Prepare the project workspace, documentation structure, and evidence management system before beginning the Active Directory lab implementation.

## Environment

- Host OS: Windows 11
- Virtualization Platform: VMware Workstation
- Existing Linux SIEM: Ubuntu VM with Wazuh
- Attacker VM: Kali Linux
- Documentation: Visual Studio Code
- Version Control: Git and GitHub

## Project Scope

This project will build an isolated Active Directory environment and demonstrate:

- Active Directory administration
- Windows security monitoring
- Sysmon telemetry
- Windows Event Log analysis
- Attack simulation
- Detection engineering
- MITRE ATT&CK mapping
- SOC investigation and reporting

## Project Architecture

The existing Ubuntu Wazuh environment will be reused as the SIEM infrastructure.

Kali Linux will be used as the attacker system.

A new Windows Server virtual machine will be introduced as the Active Directory Domain Controller.

The lab will eventually allow Windows security telemetry to flow into the existing Wazuh SIEM for detection and investigation.

## Repository Structure

```text
Project-03-AD-Attack-Detection-Lab/
├── README.md
├── docs/
├── architecture/
├── diagrams/
├── screenshots/
├── reports/
├── attacks/
├── detections/
├── scripts/
└── resources/

## Windows Server Virtual Machine

A dedicated Windows Server 2022 virtual machine was created to serve as the future Active Directory Domain Controller.

### VM Configuration

| Component | Configuration |
|---|---|
| Operating System | Windows Server 2022 Standard |
| RAM | 4 GB |
| CPU | 2 cores |
| Storage | 80 GB |
| VM Storage Location | E:\Virtual Machines |
| Network | NAT (temporary) |
| Virtualization | VMware Workstation 17 |

The VM will later be configured as the Active Directory Domain Controller for the lab.

## Progress

### Day 00 — Environment Preparation

- [x] Windows Server 2022 Evaluation ISO obtained
- [x] Windows Server VM created
- [x] VM hardware configured
- [x] VM stored on `E:\Virtual Machines`
- [x] Windows Server 2022 installed
- [x] Administrator account configured
- [x] Server Manager verified
- [x] Server renamed to `AD-DC`
- [x] Static IPv4 address configured
- [x] Gateway connectivity verified
- [x] Internet connectivity verified

**Day 00 Status: ✅ Complete**

See [`docs/Day00.md`](docs/Day00.md) for the complete implementation log and evidence.