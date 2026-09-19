# Troubleshooting Notes — Sentinel Lab 12

## Issue 1 — No Results from SecurityEvent

### Problem

The original KQL query was:

```kusto
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, Computer, LogonType, IpAddress, AuthenticationPackageName
| order by TimeGenerated desc
```

The query returned:

```text
No results found from the last 24 hours.
```

### Impact

The investigation could not depend on live Windows `SecurityEvent` telemetry because the required records were not available in the workspace.

### Resolution

The lab was modified to use a simulated dataset created directly in KQL with `datatable()`.

This allowed the investigation to continue without fabricating live Sentinel results.

---

## Issue 2 — KQL Parsing Error at LateralMovementData

### Error

The query produced:

```text
A syntax error has been identified in the query.
Query could not be parsed at 'LateralMovementData'
```

The reported location was the line where `LateralMovementData` was referenced after the `datatable()` declaration.

### Initial Structure

The query used a `let` statement followed by a separate reference:

```kusto
let LateralMovementData = datatable(...)
[
    ...
]

LateralMovementData
| order by TimeGenerated asc
```

### Resolution

The dataset definition was corrected so the `let` statement was properly terminated before the dataset was referenced:

```kusto
let LateralMovementData = datatable(...)
[
    ...
];
LateralMovementData
| order by TimeGenerated asc
```

The working result was then validated in Sentinel.

### Validation

The full dataset returned successfully and displayed the expected chronological events.

---

## Issue 3 — Share Name Formatting

### Problem

The simulated data originally used a UNC-style path such as:

```text
\\SERVER-LAB03\ADMIN$
```

Backslash escaping made the query harder to troubleshoot.

### Resolution

The `ShareName` field was simplified to:

```text
ADMIN$
```

This preserved the investigative meaning while reducing unnecessary escaping inside the simulated dataset.

---

## Issue 4 — Long Queries Repeated in Every Investigation Step

### Problem

Each investigation step was designed to run independently. Using the same simulated dataset in every query resulted in large repeated KQL blocks.

### Resolution

Each query was kept self-contained so that an individual investigation step could be copied directly into Sentinel without depending on a previous query execution.

This makes the lab easier to reproduce and troubleshoot.

---

## Issue 5 — Avoiding Fabricated Sentinel Telemetry

### Problem

The workspace did not provide the Windows events needed for the original `SecurityEvent` hunt.

### Resolution

No claim was made that the events came from an actual Windows endpoint.

Instead, the lab explicitly used:

```text
KQL datatable()
```

to create controlled simulated telemetry.

### Documentation Principle

The investigation distinguishes between:

```text
Observed in simulated data
```

and:

```text
Observed from live Sentinel telemetry
```

This prevents simulated evidence from being presented as a real security incident.

---

## Issue 6 — Interpreting Individual Events

### Problem

A single successful remote logon can occur during legitimate administrative activity.

Treating `4624` alone as proof of lateral movement would create unnecessary false positives.

### Resolution

The investigation was changed from:

```text
Find 4624
```

to:

```text
Find remote logon
        ↓
Check authentication failures
        ↓
Check privileged activity
        ↓
Check process execution
        ↓
Check service creation
        ↓
Check share access
        ↓
Build timeline
```

This provides more useful context for SOC investigation.

---

## Troubleshooting Outcome

The lab ultimately used a functioning simulated dataset and successfully produced results for:

- Successful remote logons
- Failed logons
- Authentication correlation
- Privileged activity
- Process execution
- Service creation
- Administrative share access
- Chronological investigation timeline
- Source-to-destination relationship summary

## Key Lesson

When required telemetry is unavailable, do not invent results.

Use controlled simulated data for the lab, clearly document the limitation, and separate the demonstration of the hunting method from evidence collected from a real environment.
