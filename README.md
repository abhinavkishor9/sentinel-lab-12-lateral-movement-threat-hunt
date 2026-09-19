# Sentinel Lab 12 — Threat Hunt: Lateral Movement

## Overview

This lab focuses on identifying and investigating possible lateral movement inside a Windows environment using Microsoft Sentinel and KQL.

The original investigation approach was based on querying Windows `SecurityEvent` data for Event ID `4624`. The workspace did not return the required events, so the lab was modified to use a simulated dataset created with KQL `datatable()`.

The investigation follows the evidence across multiple Windows-style events instead of treating a single remote login as proof of malicious activity.

## Lab Objectives

- Identify successful remote logons.
- Identify failed authentication attempts preceding successful access.
- Correlate failed and successful authentication activity.
- Investigate privileged activity after remote authentication.
- Identify process execution associated with remote access.
- Detect service creation following privileged access.
- Investigate administrative share access.
- Build a chronological lateral movement timeline.
- Compare suspicious-looking activity with potentially legitimate administrative activity.

## Environment

- Microsoft Sentinel
- KQL
- Simulated Windows security telemetry
- KQL `datatable()` for lab data generation

## Simulated Event IDs

| Event ID | Activity |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Explicit credential use |
| 4672 | Special privileges assigned |
| 4688 | Process creation |
| 7045 | New service installed |
| 5140 | Network share accessed |

## Investigation Flow

```text
Simulated Telemetry
        ↓
Successful Remote Logons
        ↓
Failed Logons
        ↓
Authentication Correlation
        ↓
Privileged Activity
        ↓
Process Execution
        ↓
Service Creation
        ↓
Administrative Share Access
        ↓
Timeline Analysis
        ↓
Evidence Assessment
```

## Key Findings

### SERVER-LAB02

The most significant sequence involved `DESKTOP-LAB01` accessing `SERVER-LAB02` using the `administrator` account.

```text
08:10:21  4625  Failed network logon
08:10:29  4625  Failed network logon
08:10:42  4624  Successful network logon
08:10:55  4672  Special privileges assigned
08:11:02  7045  New service installed
08:11:15  4688  cmd.exe /c whoami
```

The sequence shows repeated authentication failures followed by successful authentication, privileged activity, service creation, and command execution.

This represents a strong investigation lead, but the simulated data alone does not establish that the activity was malicious.

### SERVER-LAB03

A separate sequence involved explicit credential use followed by successful network authentication and administrative share access.

```text
08:20:05  4648  Explicit credential use
08:20:20  4624  Successful network logon
08:21:10  5140  ADMIN$ accessed
```

This provides additional evidence of remote administrative activity that should be correlated with surrounding events.

### SERVER-LAB01

Two different activity patterns were observed involving `SERVER-LAB01`.

The first involved:

```text
DESKTOP-LAB01 → SERVER-LAB01
Account: admin

4624 → 4672 → 4688
```

The second involved:

```text
ADMIN-LAB01 → SERVER-LAB01
Account: backupsvc

4624 → 4688
```

The `backupsvc` activity includes `backup.exe -full`, providing a useful comparison against the more unusual authentication sequence involving `SERVER-LAB02`.

## Source and Destination Relationships

| Source | Source IP | Destination | Account | Events |
|---|---|---|---|---|
| DESKTOP-LAB01 | 10.10.10.10 | SERVER-LAB02 | administrator | 4625, 4624, 4672, 7045, 4688 |
| DESKTOP-LAB01 | 10.10.10.10 | SERVER-LAB01 | admin | 4624, 4672, 4688 |
| DESKTOP-LAB01 | 10.10.10.10 | SERVER-LAB03 | admin | 4648, 4624, 5140 |
| ADMIN-LAB01 | 10.10.10.20 | SERVER-LAB01 | backupsvc | 4624, 4688 |

## MITRE ATT&CK

### T1021 — Remote Services

The investigation focuses on remote access between hosts and the resulting activity on destination systems.

### Related Evidence

- `4624` — successful remote/network logon
- `4625` — failed authentication attempts
- `4648` — explicit credential use
- `4672` — privileged logon activity
- `4688` — process execution
- `7045` — service creation
- `5140` — network share access

## Analyst Takeaway

The main lesson from this hunt is to correlate events rather than relying on one indicator.

A successful remote logon can be normal administrative activity. A sequence such as:

```text
Failed Authentication
        ↓
Successful Remote Logon
        ↓
Privileged Activity
        ↓
Service Creation
        ↓
Command Execution
```

provides stronger investigative context and should trigger deeper validation.

## Limitations

This lab uses simulated telemetry generated with `datatable()`.

The original `SecurityEvent` query returned no results for the available data, so the investigation does not represent telemetry collected from a live Windows host.

The simulated events are intended to demonstrate the hunting and correlation process rather than prove a real intrusion.

## Conclusion

This lab demonstrates a practical Sentinel threat-hunting workflow for possible lateral movement.

The investigation moved from individual authentication events to correlated host-to-host activity and then to supporting evidence such as privileges, process execution, service creation, and administrative share access.

The key principle is to follow the evidence and build the sequence before drawing a conclusion.
