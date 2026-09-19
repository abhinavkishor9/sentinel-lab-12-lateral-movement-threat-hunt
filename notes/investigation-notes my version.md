# Investigation Notes 

## Initial Query

The original query attempted to identify Event ID `4624` from `SecurityEvent`:

```kusto
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, Computer, LogonType, IpAddress, AuthenticationPackageName
| order by TimeGenerated desc
```

Result:

```text
No results found from the last 24 hours.
```

Because the required telemetry was unavailable, a simulated dataset was created with `datatable()`.

## Investigation Dataset

The simulated dataset contained:

- Source host
- Source IP
- Destination host
- Account
- Logon type
- Event ID
- Activity
- Process name
- Process command line
- Service name
- Share name

## Remote Logon Findings

Event ID `4624` was used to identify successful network logons.

Observed relationships:

| Source | Destination | Account | Logon Type |
|---|---|---|---:|
| DESKTOP-LAB01 | SERVER-LAB01 | admin | 3 |
| DESKTOP-LAB01 | SERVER-LAB02 | administrator | 3 |
| DESKTOP-LAB01 | SERVER-LAB03 | admin | 3 |
| ADMIN-LAB01 | SERVER-LAB01 | backupsvc | 3 |

The dataset therefore contained multiple remote access paths rather than a single isolated connection.

## Failed Authentication Findings

Event ID `4625` identified two failed network logons:

| Time UTC | Source | Destination | Account |
|---|---|---|---|
| 08:10:21 | DESKTOP-LAB01 | SERVER-LAB02 | administrator |
| 08:10:29 | DESKTOP-LAB01 | SERVER-LAB02 | administrator |

Both failures involved the same source, destination, and account.

## Authentication Correlation

The failed authentication events were followed by a successful network logon:

```text
08:10:21  4625
08:10:29  4625
08:10:42  4624
```

The correlation query identified:

| Source | Destination | Account | Failed | Successful |
|---|---|---|---:|---:|
| DESKTOP-LAB01 | SERVER-LAB02 | administrator | 2 | 1 |

This creates an investigation lead because the successful authentication occurred shortly after repeated failures.

## Privileged Activity

Event ID `4672` was used to identify special privilege assignment.

Observed events:

| Time UTC | Source | Destination | Account |
|---|---|---|---|
| 08:01:15 | DESKTOP-LAB01 | SERVER-LAB01 | admin |
| 08:10:55 | DESKTOP-LAB01 | SERVER-LAB02 | administrator |

The `SERVER-LAB02` privileged activity occurred shortly after the successful network logon.

## Process Execution

Event ID `4688` identified three process creation events.

| Time UTC | Source | Destination | Account | Process | Command |
|---|---|---|---|---|---|
| 08:02:03 | DESKTOP-LAB01 | SERVER-LAB01 | admin | powershell.exe | powershell.exe -NoProfile -Command Get-Process |
| 08:11:15 | DESKTOP-LAB01 | SERVER-LAB02 | administrator | cmd.exe | cmd.exe /c whoami |
| 09:05:30 | ADMIN-LAB01 | SERVER-LAB01 | backupsvc | backup.exe | backup.exe -full |

The `SERVER-LAB02` process event occurred shortly after the privileged logon and service creation events.

## Service Creation

Event ID `7045` identified the following service installation:

| Time UTC | Source | Destination | Account | Service |
|---|---|---|---|---|
| 08:11:02 | DESKTOP-LAB01 | SERVER-LAB02 | administrator | RemoteUpdate |

The event occurred after:

```text
4625 → 4625 → 4624 → 4672
```

and immediately before:

```text
4688 → cmd.exe /c whoami
```

This makes the service creation an important part of the investigation sequence.

## Administrative Share Access

Event ID `5140` identified access to an administrative share:

| Time UTC | Source | Destination | Account | Share |
|---|---|---|---|---|
| 08:21:10 | DESKTOP-LAB01 | SERVER-LAB03 | admin | ADMIN$ |

The sequence was:

```text
4648 → 4624 → 5140
```

This represents explicit credential use followed by successful network authentication and administrative share access.

## Primary Investigation Sequence

The strongest simulated sequence was observed on `SERVER-LAB02`:

```text
DESKTOP-LAB01
      |
      v
SERVER-LAB02
```

```text
08:10:21  4625  Failed network logon
08:10:29  4625  Failed network logon
08:10:42  4624  Successful network logon
08:10:55  4672  Special privileges assigned
08:11:02  7045  New service installed
08:11:15  4688  cmd.exe /c whoami
```

The sequence should be treated as a correlated investigation lead rather than as standalone proof of compromise.

## Comparison Activity

The `ADMIN-LAB01` activity provides a useful comparison:

```text
09:05:00  4624  Successful network logon
09:05:30  4688  backup.exe -full
```

The account was `backupsvc`, and the process command line was consistent with a backup operation in the simulated dataset.

This demonstrates why context matters when evaluating remote administrative activity.

## Analyst Assessment

### SERVER-LAB02

Evidence of interest:

- Two failed authentication attempts
- Successful network authentication
- Special privileges assigned
- New service installation
- Command execution

Assessment:

```text
High-interest sequence requiring further validation.
```

The simulated telemetry does not independently establish malicious intent.

### SERVER-LAB03

Evidence of interest:

- Explicit credential use
- Successful network authentication
- ADMIN$ access

Assessment:

```text
Remote administrative activity requiring contextual validation.
```

### SERVER-LAB01

Evidence observed from `DESKTOP-LAB01`:

```text
4624 → 4672 → 4688
```

Evidence observed from `ADMIN-LAB01`:

```text
4624 → 4688
```

These sequences demonstrate different types of remote administrative activity and should be evaluated in context.

## MITRE ATT&CK Mapping

| Technique | Relevance |
|---|---|
| T1021 — Remote Services | Host-to-host remote access |
| T1021.002 — SMB/Windows Admin Shares | ADMIN$ share access |
| T1078 — Valid Accounts | Potentially relevant to the use of existing administrative credentials |

The mappings describe techniques represented by the simulated activity; they do not establish that the activity was performed by an attacker.

