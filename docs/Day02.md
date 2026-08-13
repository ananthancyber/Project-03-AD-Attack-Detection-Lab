# Day 02 — Windows 10 Domain Client & Security Auditing

## 1. Objective

The objective of Day 02 was to configure and validate the Windows 10 client in the Active Directory lab and establish the Windows security auditing required for future attack detection and investigation.

The main goals were:

- Validate the Windows 10 client configuration
- Verify network connectivity
- Configure and verify Active Directory DNS
- Confirm domain membership
- Authenticate using the domain user `CORP\alice`
- Enable Windows security auditing
- Generate authentication and process activity
- Investigate Windows Security Event IDs 4624, 4625, and 4688
- Understand Windows Logon IDs and session correlation
- Correlate authentication activity with process creation

---

## 2. Lab Environment

| Component | Configuration |
|---|---|
| Domain | `corp.local` |
| Domain Controller | `AD-DC` |
| Windows Client | `WIN10-CLIENT` |
| Domain User | `CORP\alice` |
| Client IPv4 | `192.168.159.133` |
| Network | `192.168.159.0/24` |
| DNS | Active Directory DNS |

---

## 3. Windows 10 Client Configuration

The Windows 10 virtual machine was configured as the endpoint workstation for the Active Directory environment.

The client hostname was verified using:

    hostname

Output:

    WIN10-CLIENT

The network configuration was verified using:

    ipconfig

The client was assigned:

    IPv4 Address : 192.168.159.133
    Subnet Mask  : 255.255.255.0
    Gateway      : 192.168.159.2

The Windows 10 client was configured to use the Active Directory DNS infrastructure.

### Evidence

![Windows 10 VM Configuration](../screenshots/Day02-01-WIN10-CLIENT-VM-Configuration.png)

![Windows 10 Region](../screenshots/Day02-02-Windows10-Region.png)

![Windows 10 Client Desktop](../screenshots/Day02-03-Windows10-Client-Desktop.png)

![Windows 10 Hostname](../screenshots/Day02-04-Windows10-Hostname-Configured.png)

---

## 4. Active Directory DNS Configuration

Active Directory depends heavily on DNS.

The Windows 10 client was configured to use the Domain Controller as its DNS server.

DNS resolution was verified using:

    nslookup corp.local

Successful resolution confirmed that the Windows 10 client could locate the Active Directory DNS infrastructure.

### Why DNS Matters

DNS in an Active Directory environment is used to locate important domain services such as:

- Domain Controllers
- Kerberos services
- LDAP services
- Global Catalog services
- Other Active Directory service records

If the client cannot correctly resolve the Active Directory domain, domain joining and authentication can fail.

### Evidence

![AD DNS Configuration](../screenshots/Day02-05-Windows10-AD-DNS-Configured.png)

![AD DNS Verification](../screenshots/Day02-06-Windows10-AD-DNS-Verification.png)

---

## 5. Domain Membership

The Windows 10 client was successfully joined to:

    corp.local

The workstation hostname was:

    WIN10-CLIENT

The domain relationship was verified from the Windows 10 client.

### Why Domain Membership Matters

Domain membership allows the workstation to use centralized Active Directory authentication and security policies.

Instead of relying only on local accounts, the workstation can authenticate users against the Active Directory domain.

This provides the foundation for centralized:

- Authentication
- Authorization
- Group Policy
- Security auditing
- User management

### Evidence

![Windows 10 Domain Login](../screenshots/Day02-07-Windows10-Domain-Login.png)

![Windows 10 Domain Network Verification](../screenshots/Day02-08-Windows10-Domain-Network-Verification.png)

---

## 6. Domain User Authentication

The primary domain user used during this lab was:

    CORP\alice

After logging into the Windows 10 client, the authenticated identity was verified using:

    whoami

Output:

    corp\alice

This confirmed that Alice was authenticated as a domain user.

### Why This Matters

For SOC investigations, identifying the authenticated user is critical.

A security analyst needs to determine:

    Who authenticated?
    Which account was used?
    Which session was created?
    What activity occurred after authentication?

This allows endpoint activity to be attributed to a specific user and session.

### Evidence

![Normal Domain User Login](../screenshots/Day02-09-Windows10-Normal-User-Login.png)

---

## 7. Windows Security Audit Policy

Windows Security auditing was enabled to generate the security telemetry required for investigation.

The configured audit policy included security-relevant categories such as:

- Logon
- Logoff
- Account Lockout
- Process Creation
- Account Management
- Security Group Management
- User Account Management
- Policy Change

### Why Audit Policies Matter

Windows generates security events based on its configured auditing policies.

For a SOC analyst, these events provide the telemetry required to investigate activity on an endpoint.

For example:

    User Authentication
            ↓
       Security Event
            ↓
       Process Execution
            ↓
       Security Event
            ↓
       Investigation

Without appropriate auditing, important activity may not be recorded in the Security log.

### Evidence

![Windows 10 Audit Policy](../screenshots/Day02-10-Windows10-Audit-Policy-Enabled.png)

---

## 8. Event ID 4688 — Process Creation

Windows Security Event ID `4688` represents a new process being created.

The event can provide important information such as:

- User
- Domain
- Logon ID
- Process name
- Process ID
- Command line
- Parent process

### Why Event ID 4688 Matters

Process creation telemetry allows a SOC analyst to investigate what was executed on a Windows endpoint.

For example:

    Who executed it?
            ↓
    What was executed?
            ↓
    What command was used?
            ↓
    Which session executed it?
            ↓
    What was the parent process?

This makes Event ID 4688 valuable for endpoint detection and threat hunting.

### Evidence

![Event 4688 Process Creation](../screenshots/Day02-11-Windows10-Event4688-Process-Creation.png)

---

## 9. Event ID 4625 — Failed Logon

Windows Security Event ID `4625` represents a failed logon.

The event was generated and investigated on the Windows 10 client.

The event displayed:

    An account failed to log on.

### Why Event ID 4625 Matters

Repeated failed authentication events can indicate:

- Password guessing
- Brute-force activity
- Credential misuse
- Account compromise attempts
- Automated authentication attempts
- User mistakes

A SOC analyst would investigate:

    Who failed to authenticate?
    When did it happen?
    How frequently did it happen?
    What account was targeted?
    Was a successful login observed afterward?

### Evidence

![Event 4625 Failed Logon](../screenshots/Day02-12-Windows10-Event4625-Failed-Logon.png)

---

## 10. Event ID 4688 — Notepad Process Creation

Notepad was launched from the Windows 10 client to generate controlled process activity.

Windows Security Event ID `4688` recorded the process creation.

The event contained information including:

    SubjectUserName   : alice
    SubjectDomainName : CORP
    NewProcessName    : C:\Windows\System32\notepad.exe

The event also contained the Logon ID associated with the user session.

This allowed the process to be associated with the authenticated user session.

### Evidence

![Notepad Process Creation XML](../screenshots/Day02-13-Windows10-Event4688-Notepad-Process-Creation-XML.png)

---

## 11. Event ID 4688 — PowerShell Process Creation

PowerShell was executed on the Windows 10 client to generate additional process telemetry.

Windows Security Event ID `4688` recorded the PowerShell process creation.

The event contained information such as:

    NewProcessName : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    CommandLine    : powershell.exe -NoProfile -Command "Get-Date"

### Why PowerShell Monitoring Matters

PowerShell is a legitimate Windows administration tool, but it is also frequently used during post-exploitation.

Therefore, SOC analysts pay attention to:

- PowerShell execution
- Command-line arguments
- Parent processes
- User context
- Logon session
- Suspicious commands

The objective here was not to perform a malicious action, but to understand how Windows records PowerShell execution.

### Evidence

![PowerShell Process Creation XML](../screenshots/Day02-14-Windows10-Event4688-PowerShell-Process-Creation-XML.png)

---

## 12. Event ID 4624 — Successful Logon

Windows Security Event ID `4624` represents a successful logon.

A successful authentication event for the domain user was investigated through Event Viewer.

The event contained information such as:

    SubjectUserName     : alice
    SubjectDomainName   : CORP
    TargetUserName      : Administrator
    TargetDomainName    : CORP
    LogonType           : 2

The event also contained a Windows Logon ID.

Example:

    TargetLogonId : 0x5999f

### What Is a Logon ID?

A Windows Logon ID identifies a particular logon session.

It can be used to correlate multiple security events that belong to the same session.

For example:

    4624
    Successful Logon
          |
          | Logon ID = 0x5999f
          ↓
    4688
    Process Creation
          |
          | Logon ID = 0x5999f
          ↓
    Same Windows Logon Session

### Evidence

![Alice Logon ID](../screenshots/Day02-15-Windows10-Event4624-Alice-LogonID-5999f.png)

---

## 13. Understanding Windows Sessions

One of the important concepts learned during Day 02 was:

    Same Username ≠ Same Session

A single user can create multiple Windows logon sessions.

For example:

    CORP\alice
        |
        +---- Session A
        |       Logon ID: 0x5999f
        |       |
        |       +---- notepad.exe
        |
        +---- Session B
                Logon ID: 0x5C3AE
                |
                +---- powershell.exe

If an analyst only searches for the username `alice`, activity from multiple sessions could become mixed together.

The Logon ID provides a more reliable way to correlate activity belonging to the same session.

---

## 14. Authentication-to-Process Correlation

The most important investigation performed during Day 02 was correlating authentication activity with process creation.

The successful logon event contained:

    Event ID   : 4624
    User       : CORP\alice
    Logon ID   : 0x5999f

The process creation event contained:

    Event ID        : 4688
    User            : CORP\alice
    Process         : notepad.exe
    Logon ID        : 0x5999f

The matching Logon ID provides a correlation between the authentication event and the process creation event.

The investigation chain can therefore be represented as:

    CORP\alice
         |
         ↓
    Event ID 4624
    Successful Logon
         |
         ↓
    Logon ID: 0x5999f
         |
         ↓
    Event ID 4688
    Process Creation
         |
         ↓
    notepad.exe
         |
         ↓
    Logon ID: 0x5999f

This demonstrates how a SOC analyst can connect a user authentication event to activity performed during that authenticated session.

---

## 15. Why Logon ID Is Important for SOC Investigation

Consider a situation where the same user logs in multiple times.

    CORP\alice
        |
        +---- Logon Session 1
        |       Logon ID: 0x5999f
        |       |
        |       +---- notepad.exe
        |
        +---- Logon Session 2
                Logon ID: 0x5C3AE
                |
                +---- powershell.exe

Both sessions belong to the same username.

However, they are different Windows sessions.

Therefore:

    Username alone
          ↓
    Not always sufficient

Whereas:

    Username + Logon ID
          ↓
    Stronger session correlation

This is an important concept when investigating Windows authentication and endpoint activity.

---

## 16. Event Correlation Model

The investigation performed during Day 02 can be represented as:

                 WINDOWS 10 CLIENT
                        |
                        ↓
                User Authentication
                        |
                        ↓
                 Event ID 4624
                 Successful Logon
                        |
                        ↓
                    Logon ID
                    0x5999f
                        |
                        ↓
                 Process Execution
                        |
                        ↓
                 Event ID 4688
                        |
                        ↓
                   notepad.exe
                        |
                        ↓
                 Same Logon ID
                    0x5999f
                        |
                        ↓
              User-to-Process Attribution

This is the foundation of endpoint detection and investigation.

---

## 17. Day 02 Investigation Timeline

The complete workflow was:

    Windows 10 Client
            ↓
    Network Configuration
            ↓
    AD DNS Configuration
            ↓
    DNS Verification
            ↓
    Domain Membership
            ↓
    CORP\alice Authentication
            ↓
    Windows Audit Policy
            ↓
    Event ID 4625
    Failed Authentication
            ↓
    Event ID 4624
    Successful Authentication
            ↓
    Logon ID Identified
            ↓
    Event ID 4688
    Process Creation
            ↓
    notepad.exe / PowerShell
            ↓
    Logon ID Correlation
            ↓
    User-to-Process Attribution

---

## 18. Key Findings

The following findings were established during Day 02:

1. The Windows 10 client was successfully configured for the Active Directory environment.
2. The client successfully resolved the Active Directory domain through DNS.
3. The Windows 10 client was successfully joined to `corp.local`.
4. The domain account `CORP\alice` successfully authenticated on the client.
5. Windows Security auditing was enabled.
6. Event ID `4625` recorded failed authentication activity.
7. Event ID `4624` recorded successful authentication activity.
8. Event ID `4688` recorded process creation.
9. Notepad execution was recorded through Event ID `4688`.
10. PowerShell execution was recorded through Event ID `4688`.
11. Windows Logon IDs were observed in security events.
12. Authentication and process activity could be correlated using the Logon ID.
13. The investigation demonstrated why username-only correlation is insufficient for reliable Windows session tracking.

---

## 19. Concepts Learned

### Event ID 4624

    4624 = Successful Logon

Used to investigate successful authentication.

### Event ID 4625

    4625 = Failed Logon

Used to investigate failed authentication attempts.

### Event ID 4688

    4688 = Process Creation

Used to investigate process execution on Windows endpoints.

### Logon ID

    Logon ID = Identifier for a Windows Logon Session

Used to correlate security events belonging to the same session.

### Logon Type 2

    Logon Type 2 = Interactive Logon

Typically represents a user logging on interactively at the Windows machine.

---

## 20. SOC Investigation Perspective

A SOC analyst should not investigate Windows events in isolation.

Instead, the analyst should build a chain of activity:

    Who authenticated?
            ↓
    Which account was used?
            ↓
    Which Logon ID was created?
            ↓
    What processes were created?
            ↓
    Which process belonged to that session?
            ↓
    What command or activity was performed?

This transforms individual Windows events into an investigation timeline.

For example:

    CORP\alice
         ↓
    4624 — Successful Logon
         ↓
    Logon ID: 0x5999f
         ↓
    4688 — Process Creation
         ↓
    notepad.exe

This is much more useful to a SOC analyst than simply seeing:

    alice logged in

---

## 21. Skills Demonstrated

### Active Directory

- Domain membership
- Domain authentication
- Active Directory DNS
- Domain user validation
- Windows domain client configuration

### Windows Security

- Windows Event Viewer
- Windows Security Event Logs
- Audit Policy
- Event ID 4624
- Event ID 4625
- Event ID 4688
- Logon Type analysis
- Logon ID analysis

### SOC Investigation

- Authentication investigation
- Failed login investigation
- Successful login investigation
- Process creation analysis
- User-to-process attribution
- Event correlation
- Windows endpoint telemetry analysis

---

## 22. Day 02 Conclusion

Day 02 established the Windows 10 workstation as a functioning domain-joined endpoint and enabled the security telemetry required for future Active Directory attack detection.

The most important lesson was learning how to move from individual Windows events to event correlation.

A SOC analyst should ask:

    Who authenticated?
           ↓
    Which session was created?
           ↓
    What activity occurred in that session?
           ↓
    Which process performed the activity?

The Windows Logon ID provides an important correlation mechanism for connecting authentication events with subsequent endpoint activity.

The Day 02 lab therefore established the foundation for the next stage of the project, where controlled Active Directory attack activity will be generated and investigated through Windows security telemetry.

---

## 23. Day 02 Status

**STATUS: COMPLETED**

### Evidence Collected

- Windows 10 VM configuration
- Windows 10 network configuration
- Active Directory DNS configuration
- DNS verification
- Domain membership
- Domain user authentication
- Windows audit policy configuration
- Event ID 4688 process creation
- Event ID 4625 failed logon
- Event ID 4688 Notepad process creation
- Event ID 4688 PowerShell process creation
- Event ID 4624 successful logon
- Windows Logon ID investigation
- Authentication-to-process correlation

### Next Stage

**Day 03 — Active Directory Attack Simulation & Detection**