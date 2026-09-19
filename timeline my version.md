# Timeline 

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

