# sentinel-lab-12-lateral-movement-threat-hunt
## Overview
Lateral movement means an attacker moves from one compromised computer to another computer inside a network.

For a SOC analyst, the goal is not to treat every remote login as malicious. Instead, look for a sequence of related events.

For example:

Failed Logon
    ↓
Successful Remote Logon
    ↓
Special Privileges
    ↓
Service Creation
    ↓
Command Execution

That sequence provides more investigative context than a single event.

In this lab, we will simulate Windows security telemetry with datatable() and investigate:

Remote logons — 4624
Failed logons — 4625
Explicit credential use — 4648
Special privileges — 4672
Process creation — 4688
Service creation — 7045
Network share access — 5140

Primary MITRE ATT&CK technique: T1021 – Remote Services

This lab focuses on identifying and investigating possible lateral movement inside a Windows environment using Microsoft Sentinel and KQL.

The original investigation approach was based on querying Windows `SecurityEvent` data for Event ID `4624`. The workspace did not return the required events, so the lab was modified to use a simulated dataset created with KQL `datatable()`.

The investigation follows the evidence across multiple Windows-style events instead of treating a single remote login as proof of malicious activity.

## Lab Objectives

The objective of this lab is to investigate a simulated lateral movement scenario in Microsoft Sentinel by following related authentication, privilege, execution, and remote-access activity across multiple systems.

- Identify host-to-host remote authentication activity and determine the source, destination, account, and logon type involved.
- Investigate failed authentication attempts and determine whether they are followed by successful access.
- Correlate authentication events with privileged activity to understand what happened after remote access was established.
- Examine process creation events to identify commands or executables executed following remote authentication.
- Identify service creation activity that occurs after privileged remote access.
- Detect administrative share access and relate it to the associated authentication activity.
- Build a chronological sequence of events for the investigated source and destination systems.
- Compare different remote-access patterns to distinguish activity that requires further investigation from activity that may have a legitimate administrative context.
- Practice evidence-based threat hunting by correlating multiple events instead of treating a single event as proof of lateral movement.
- Document telemetry limitations and clearly distinguish simulated evidence from data collected from a live environment.


## Lab Scenario

A security analyst is investigating unusual activity between several Windows systems in an internal environment. The initial hunt was intended to use Windows `SecurityEvent` telemetry and focus on successful remote logons, but the required events were not available in the Microsoft Sentinel workspace.

To continue the investigation without fabricating live telemetry, a simulated dataset was created with KQL `datatable()`. The dataset represents activity between `DESKTOP-LAB01`, `ADMIN-LAB01`, and several server systems.

During the investigation, the analyst observes multiple forms of remote activity:

- `DESKTOP-LAB01` connects to `SERVER-LAB01` using the `admin` account.
- `DESKTOP-LAB01` attempts to authenticate to `SERVER-LAB02` twice unsuccessfully before receiving a successful logon.
- The successful access to `SERVER-LAB02` is followed by privileged activity, service creation, and command execution.
- `DESKTOP-LAB01` uses explicit credentials to access `SERVER-LAB03` and later accesses the `ADMIN$` administrative share.
- `ADMIN-LAB01` performs separate activity against `SERVER-LAB01` using the `backupsvc` account and executes a backup process.

The analyst must determine how these events relate to one another and whether the observed sequences provide evidence consistent with lateral movement.

The investigation should focus on the relationship between source and destination hosts, authentication attempts, privilege assignment, process execution, service creation, and administrative share access. The goal is to follow the event sequence and build sufficient context before drawing any conclusion.

This scenario is intentionally based on simulated telemetry. The events demonstrate the investigation workflow and correlation techniques rather than representing a confirmed real-world compromise.

  
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

## MITRE ATT&CK Used

The investigation maps the simulated activity to the following MITRE ATT&CK techniques:

| Technique ID | Technique | How It Appears in the Lab |
|---|---|---|
| T1021 | Remote Services | Remote access from one host to another through network logons |
| T1021.002 | SMB/Windows Admin Shares | `ADMIN$` administrative share accessed on `SERVER-LAB03` |
| T1078 | Valid Accounts | Existing accounts such as `admin`, `administrator`, and `backupsvc` are used for remote access |

### T1021 — Remote Services

The lab focuses primarily on remote access between Windows systems. Event ID `4624` with Logon Type `3` is used in the simulated dataset to represent successful network authentication between hosts.

### T1021.002 — SMB/Windows Admin Shares

The `SERVER-LAB03` sequence includes access to the `ADMIN$` administrative share:

```text
4648 → 4624 → 5140
### Related Evidence

- `4624` — successful remote/network logon
- `4625` — failed authentication attempts
- `4648` — explicit credential use
- `4672` — privileged logon activity
- `4688` — process execution
- `7045` — service creation
- `5140` — network share access


