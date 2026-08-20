# Kerberoasting Detection — Windows Event 4769

## Detection Name
Suspicious Kerberos RC4 TGS Request

## Objective
Detect potentially suspicious Kerberos service-ticket requests that may indicate
Kerberoasting activity.

## Log Source
Windows Security Event Log

## Event ID
4769 — A Kerberos service ticket was requested.

## Detection Logic

Trigger when:

- Event ID = 4769
- Ticket Encryption Type = 0x17 (RC4)
- Failure Code = 0x0 (successful request)

Increase confidence when:

- The target account has a registered Service Principal Name (SPN)
- The requester is not expected to access the service
- The request originates from an unusual workstation or source IP
- Multiple SPN-backed service tickets are requested in a short period

## Observed Attack

Requester:
alice@CORP.LOCAL

Target Service Account:
svc_sql

SPN:
MSSQLSvc/AD-DC.corp.local:1433

Source IP:
192.168.159.129

Encryption Type:
0x17 (RC4)

Failure Code:
0x0

## MITRE ATT&CK

Tactic: Credential Access

Technique: T1558.003 — Kerberoasting

## Severity

Medium by default for an isolated RC4 (0x17) TGS request.

High when RC4 is combined with:
- An SPN-backed service account
- An unusual requester
- An unusual source host/IP
- Multiple suspicious TGS requests
- Other credential-access indicators

In this lab environment, RC4 was rare compared with AES-256,
making the observed RC4 request a high-value investigation signal.
## False Positives

RC4-based Kerberos authentication may occur legitimately in legacy
environments or with older applications.

The presence of Event 4769 with RC4 alone should therefore not be treated
as definitive proof of malicious activity.

## Investigation Steps

1. Identify the requesting account.
2. Identify the requested service and SPN.
3. Identify the source IP/host.
4. Review nearby Event 4769 activity.
5. Check whether the requester normally accesses the service.
6. Correlate with endpoint telemetry.
7. Determine whether the activity is legitimate or suspicious.

## Recommended Response

If Kerberoasting is confirmed:

- Investigate the requesting workstation.
- Review the targeted service account.
- Reset the affected service-account credentials.
- Prefer AES-based Kerberos encryption where supported.
- Review unnecessary SPNs.
- Continue monitoring for additional credential-access activity.