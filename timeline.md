# Timeline — Sentinel Lab 12: Threat Hunt: Lateral Movement

## Investigation Timeline

All timestamps below are based on the simulated dataset and are shown in UTC.

| Time UTC | Event ID | Source | Destination | Account | Activity | Investigation Note |
|---|---:|---|---|---|---|---|
| 08:00:10 | 4624 | DESKTOP-LAB01 | SERVER-LAB01 | admin | Successful network logon | Remote access established |
| 08:01:15 | 4672 | DESKTOP-LAB01 | SERVER-LAB01 | admin | Special privileges assigned | Privileged activity followed remote access |
| 08:02:03 | 4688 | DESKTOP-LAB01 | SERVER-LAB01 | admin | Process created | `powershell.exe` executed |
| 08:10:21 | 4625 | DESKTOP-LAB01 | SERVER-LAB02 | administrator | Failed network logon | First failed authentication |
| 08:10:29 | 4625 | DESKTOP-LAB01 | SERVER-LAB02 | administrator | Failed network logon | Second failed authentication |
| 08:10:42 | 4624 | DESKTOP-LAB01 | SERVER-LAB02 | administrator | Successful network logon | Successful access after failures |
| 08:10:55 | 4672 | DESKTOP-LAB01 | SERVER-LAB02 | administrator | Special privileges assigned | Privileged activity follows successful logon |
| 08:11:02 | 7045 | DESKTOP-LAB01 | SERVER-LAB02 | administrator | New service installed | Service `RemoteUpdate` created |
| 08:11:15 | 4688 | DESKTOP-LAB01 | SERVER-LAB02 | administrator | Process created | `cmd.exe /c whoami` executed |
| 08:20:05 | 4648 | DESKTOP-LAB01 | SERVER-LAB03 | admin | Explicit credential use | Explicit credentials used |
| 08:20:20 | 4624 | DESKTOP-LAB01 | SERVER-LAB03 | admin | Successful network logon | Remote access established |
| 08:21:10 | 5140 | DESKTOP-LAB01 | SERVER-LAB03 | admin | Network share accessed | `ADMIN$` accessed |
| 09:05:00 | 4624 | ADMIN-LAB01 | SERVER-LAB01 | backupsvc | Successful network logon | Separate administrative activity |
| 09:05:30 | 4688 | ADMIN-LAB01 | SERVER-LAB01 | backupsvc | Process created | `backup.exe -full` executed |

## Primary Sequence

The main investigation sequence occurred on `SERVER-LAB02`.

```text
08:10:21  4625  Failed network logon
08:10:29  4625  Failed network logon
08:10:42  4624  Successful network logon
08:10:55  4672  Special privileges assigned
08:11:02  7045  New service installed
08:11:15  4688  cmd.exe /c whoami
```

## Secondary Sequence

The `SERVER-LAB03` sequence was:

```text
08:20:05  4648  Explicit credential use
08:20:20  4624  Successful network logon
08:21:10  5140  ADMIN$ accessed
```

## Comparison Activity

The `ADMIN-LAB01 → SERVER-LAB01` sequence was:

```text
09:05:00  4624  Successful network logon
09:05:30  4688  backup.exe -full
```

This was included to demonstrate that remote access and process execution require context before an analyst can determine whether activity is suspicious.

## Investigation Summary

The timeline shows three distinct host-to-host activity patterns:

### DESKTOP-LAB01 → SERVER-LAB01

```text
4624 → 4672 → 4688
```

### DESKTOP-LAB01 → SERVER-LAB02

```text
4625 → 4625 → 4624 → 4672 → 7045 → 4688
```

### DESKTOP-LAB01 → SERVER-LAB03

```text
4648 → 4624 → 5140
```

The `SERVER-LAB02` sequence contains the greatest concentration of correlated events and therefore represents the primary investigation lead in this simulated hunt.

## Timeline Limitation

This timeline represents simulated KQL telemetry generated with `datatable()`.

It is not a timeline extracted from live Windows event logs or a confirmed security incident.
