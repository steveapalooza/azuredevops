# ADO Permissions Auditor

A read-only PowerShell auditing tool that interrogates every project in an Azure DevOps organization and verifies that security group roles exist, hold the correct permissions, and contain only the expected Azure Active Directory members.

> **Non-destructive by design.** The script makes no changes to any Azure DevOps or Azure Active Directory resource under any circumstances.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Personal Access Token](#personal-access-token)
  - [Baseline Permissions File](#baseline-permissions-file)
- [Usage](#usage)
  - [Parameters](#parameters)
  - [Examples](#examples)
- [Architecture](#architecture)
  - [Parallel Execution Model](#parallel-execution-model)
  - [Intra-Project Concurrency](#intra-project-concurrency)
  - [Rate-Limit Handling](#rate-limit-handling)
  - [Thread-Safe Telemetry](#thread-safe-telemetry)
- [Output](#output)
  - [Console](#console)
  - [JSON Report](#json-report)
- [CI/CD Integration](#cicd-integration)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Managing a consistent permissions model across a large Azure DevOps tenant is a manual, error-prone process. This tool automates that audit by connecting to the ADO REST API and the ADO Graph API to answer three questions for every project in scope:

1. **Does the specified role exist?**
2. **Do the role's permissions match the defined baseline?**
3. **Is the role's membership exactly the expected list of AD groups or users?**

Results are written to the console in real time and persisted as a structured JSON report that can be ingested by dashboards, ticketing systems, or CI gates.

---

## Features

- ✅ **Parallel project auditing** — projects audited concurrently via `ForEach-Object -Parallel` (PowerShell 7+), with configurable worker pool size
- ✅ **Intra-project concurrency** — permission ACE retrieval and membership resolution run as simultaneous background jobs within each project worker, eliminating sequential wait on independent I/O calls
- ✅ **Thread-safe telemetry** — `ConcurrentDictionary` + `Interlocked.Add` counters aggregate API stats across all runspaces without race conditions
- ✅ **Full tenant sweep** — audits all projects or a filtered subset using wildcard matching
- ✅ **Permissions baseline** — compares both raw ACE bitmasks and human-readable named permissions against a JSON baseline file
- ✅ **Exact membership verification** — detects extra members, missing members, and raises drift for either
- ✅ **Adaptive rate-limit handling** — proactive inter-call delay per runspace, reactive 429 back-off with `Retry-After` header support, and exponential back-off with a configurable ceiling
- ✅ **Buffered console output** — per-project output is collected within each runspace and flushed atomically to the console, preventing interleaved output from concurrent workers
- ✅ **Pipeline-ready exit codes** — exits `0` (compliant) or `1` (drift detected)
- ✅ **No external dependencies** — PowerShell 7+ only; uses `Invoke-WebRequest` exclusively

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| PowerShell | 7.0 or later | `$PSVersionTable.PSVersion` to check. `ForEach-Object -Parallel` requires PS7+ |
| Azure DevOps PAT | — | See [Personal Access Token](#personal-access-token) |
| ADO PAT scopes | `vso.project`, `vso.security`, `vso.graph` | All read-only |
| Network access | `dev.azure.com`, `vssps.dev.azure.com` | Outbound HTTPS (port 443) |

---

## Repository Structure

```
ado-permissions-auditor/
├── Verify-ADOProjectPermissions.ps1     # Main audit script
├── baseline-permissions-template.json   # Annotated permissions baseline template
├── examples/
│   ├── baseline-project-admins.json     # Example: Project Administrators baseline
│   └── baseline-contributors.json       # Example: Contributors baseline
├── .github/
│   └── workflows/
│       └── nightly-audit.yml            # Example GitHub Actions workflow
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## Installation

Clone the repository and verify your PowerShell version. No packages or modules need to be installed.

```powershell
git clone https://github.com/your-org/ado-permissions-auditor.git
cd ado-permissions-auditor

# Verify PowerShell version (must be 7.0 or later)
$PSVersionTable.PSVersion
```

If you are running Windows PowerShell 5.x, install PowerShell 7 from the [official Microsoft releases page](https://github.com/PowerShell/PowerShell/releases).

---

## Configuration

### Personal Access Token

The script accepts the PAT exclusively as a `SecureString` so it is never stored in plain text in memory or echoed to the console. Internally it is converted to a Base64 Authorization header once in the main thread; only that header string is passed into runspaces — the `SecureString` itself never crosses a runspace boundary.

Generate a PAT in Azure DevOps under **User Settings → Personal Access Tokens** with the following scopes:

| Scope | Access Level |
|---|---|
| Project and Team | Read |
| Security | Read |
| Graph | Read |

Store the token securely. At runtime, supply it interactively or load it from a secrets manager:

```powershell
# Interactive — recommended for local use
$pat = Read-Host -AsSecureString "Enter Azure DevOps PAT"

# From an environment variable — recommended for CI/CD
$pat = ConvertTo-SecureString $env:ADO_PAT -AsPlainText -Force
```

> **Never hard-code a PAT in a script, commit it to source control, or pass it as a plain-text string at the command line.**

### Baseline Permissions File

The baseline file defines what the role's permissions **should** look like. Two assertion modes are supported and can be combined in the same file.

**Mode 1 — Raw bitmask** asserts the exact integer ACE values from the ADO security namespace:

```json
{
  "allow": 31,
  "deny": 0
}
```

**Mode 2 — Named permissions** asserts individual permission flags by name:

```json
{
  "permissions": {
    "GenericRead":            true,
    "GenericWrite":           true,
    "Delete":                 false,
    "ViewBuilds":             true,
    "ManageBuildDefinitions": false
  }
}
```

**Combined** — both modes are evaluated when present in the same file:

```json
{
  "allow": 31,
  "deny": 0,
  "permissions": {
    "GenericRead":  true,
    "GenericWrite": true,
    "Delete":       false
  }
}
```

See [`baseline-permissions-template.json`](baseline-permissions-template.json) for the full list of supported named permission keys and inline documentation.

---

## Usage

### Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-Organization` | `string` | ✅ | — | ADO organization name (from `https://dev.azure.com/<org>`) |
| `-RoleName` | `string` | ✅ | — | Security group / role to verify (e.g. `"Project Administrators"`) |
| `-BaselineFile` | `string` | ✅ | — | Path to the JSON permissions baseline file |
| `-ExpectedMembers` | `string` | ✅ | — | Comma-separated expected member display names or UPNs |
| `-Pat` | `SecureString` | ✅ | — | Azure DevOps PAT |
| `-ProjectName` | `string[]` | ❌ | _(all projects)_ | One or more project names; supports wildcards (`Team-*`) |
| `-OutputPath` | `string` | ❌ | `.\ADO-Audit-<ts>.json` | Destination path for the JSON audit report |
| `-ParallelThrottle` | `int` | ❌ | `10` | Max concurrent project audits (worker pool size) |
| `-ThrottleDelay` | `int` | ❌ | `100` | Milliseconds to pause between API calls per runspace |
| `-RetryJitter` | `int` | ❌ | `2` | Extra seconds added to `Retry-After` on HTTP 429 |
| `-MaxRetries` | `int` | ❌ | `5` | Max retry attempts per API call before a hard failure |
| `-MaxBackoffSeconds` | `int` | ❌ | `120` | Ceiling in seconds for exponential back-off |

### Examples

**Audit all projects with default concurrency (10 workers):**

```powershell
$pat = Read-Host -AsSecureString "Enter PAT"

.\Verify-ADOProjectPermissions.ps1 `
    -Organization    "contoso" `
    -RoleName        "Project Administrators" `
    -BaselineFile    ".\baseline-permissions-template.json" `
    -ExpectedMembers "Corp\ADO-Admins, Corp\DevOps-Leads" `
    -Pat             $pat
```

**Large tenant — 20 parallel workers with a conservative per-worker throttle:**

```powershell
.\Verify-ADOProjectPermissions.ps1 `
    -Organization    "contoso" `
    -RoleName        "Project Administrators" `
    -BaselineFile    ".\baseline-permissions-template.json" `
    -ExpectedMembers "Corp\ADO-Admins, Corp\DevOps-Leads" `
    -Pat             $pat `
    -ParallelThrottle 20 `
    -ThrottleDelay    250 `
    -MaxRetries       8
```

**Single project — serial execution (no parallel overhead):**

```powershell
.\Verify-ADOProjectPermissions.ps1 `
    -Organization    "contoso" `
    -ProjectName     "MyProject" `
    -RoleName        "Contributors" `
    -BaselineFile    ".\examples\baseline-contributors.json" `
    -ExpectedMembers "Corp\Dev-Team" `
    -Pat             $pat `
    -ParallelThrottle 1
```

**Wildcard-filtered subset of projects:**

```powershell
.\Verify-ADOProjectPermissions.ps1 `
    -Organization    "contoso" `
    -ProjectName     "Platform-*", "Infra-*" `
    -RoleName        "Project Administrators" `
    -BaselineFile    ".\baseline-permissions-template.json" `
    -ExpectedMembers "Corp\ADO-Admins" `
    -Pat             $pat `
    -OutputPath      "C:\Reports\audit.json" `
    -Verbose
```

---

## Architecture

### Parallel Execution Model

The script runs in two phases:

```
Phase 1 — Sequential  (main thread)
──────────────────────────────────────────────────────────────────────
  GET /_apis/projects  →  paginate until all projects collected
  Filter by -ProjectName wildcards if supplied

Phase 2 — Parallel  (ForEach-Object -Parallel, up to -ParallelThrottle workers)
──────────────────────────────────────────────────────────────────────
  Worker 1: Project A  ──┐
  Worker 2: Project B  ──┤  Each worker independently:
  Worker 3: Project C  ──┤    A. GET scope descriptor
  ...                    ┤    B. GET security groups
  Worker N: Project N  ──┘    C. Locate role
                              D. GET ACE + GET membership  (concurrent background jobs)
                              E. Compare permissions
                              F. Diff membership
                              →  return { Result, Log }

Main thread receives results as workers complete:
  • Flush buffered log to console atomically per project
  • Accumulate into $auditResults
  • Merge thread-safe telemetry counters
```

Project enumeration is kept sequential to avoid a concurrent burst on a single paginated endpoint. All per-project API calls (which are stateless GET requests) are fully parallelised.

The following ADO REST API endpoints are stateless and support concurrent clients under the same PAT, making them safe to parallelise:

| Endpoint | Usage |
|---|---|
| `GET /graph/descriptors/{id}` | Scope descriptor lookup |
| `GET /graph/groups` | Group listing per project |
| `GET /graph/memberships/{descriptor}` | Membership resolution |
| `GET /graph/subjects/{descriptor}` | Subject display name resolution |
| `GET /graph/storagekeys/{descriptor}` | ACL SID resolution |
| `GET /accesscontrollists/{nsId}` | Permission ACE retrieval |

### Intra-Project Concurrency

Within each project runspace, permission ACE retrieval and membership resolution are independent — neither call depends on the other's result. The script launches these as simultaneous background jobs (`Start-Job`) within the runspace, waits for both to complete with `Wait-Job`, then proceeds to comparison. This eliminates the sequential stall that would otherwise occur waiting for two unrelated I/O calls in series.

```
Per-project runspace timeline:

  GET scope descriptor  →  GET groups  →  find role
                                                │
                            ┌───────────────────┴──────────────────────┐
                            │                                          │
                     Background job 1                          Background job 2
                  GET storagekey + GET ACL                  GET memberships
                   (permission lookup)                    + resolve all names
                            │                                          │
                            └───────────────────┬──────────────────────┘
                                          Wait-Job (both)
                                                │
                                  Compare permissions + diff members
```

### Rate-Limit Handling

Each runspace independently manages throttling using three layers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Layer 1 — Proactive inter-call delay  (-ThrottleDelay, default 100 ms)     │
│                                                                             │
│  Every API call within a runspace is preceded by a configurable sleep.     │
│  With N parallel workers the effective org-wide call rate is approximately  │
│  N × (1000 / ThrottleDelay) calls/sec. Increase ThrottleDelay if you see  │
│  sustained 429s, or reduce ParallelThrottle to lower the total rate.       │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 2 — Reactive 429 back-off                                            │
│                                                                             │
│  On HTTP 429 the Retry-After header is read and honoured. The runspace      │
│  sleeps for (Retry-After + RetryJitter) seconds then retries automatically. │
│  When no header is present, exponential back-off is applied:               │
│  sleep = min(2^attempt, MaxBackoffSeconds). HTTP 503/504 use the same       │
│  exponential scheme. Because ADO's rate limit is shared across all workers, │
│  a 429 in one runspace typically means others should also slow down — the   │
│  server's Retry-After value accounts for this.                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 3 — Hard failure after MaxRetries                                    │
│                                                                             │
│  When all retry attempts are exhausted the call returns null. The failure   │
│  is recorded in the project's audit result; the runspace continues with the │
│  remaining audit steps rather than aborting.                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Thread-Safe Telemetry

Ordinary PowerShell variables are not shared between runspaces. API statistics are accumulated using a `System.Collections.Concurrent.ConcurrentDictionary<string, long>` initialised on the main thread and passed into each runspace via `$using:`. Increment operations use `System.Threading.Interlocked.Add` to guarantee atomicity without locks:

```powershell
[System.Threading.Interlocked]::Add([ref]($Bag.GetOrAdd($Key, 0L)), $Value)
```

This means `TotalApiCalls`, `RateLimitHits`, `TotalRetries`, and `TotalThrottleMs` reflect an accurate aggregate across all workers at the time the parallel phase completes.

---

## Output

### Console

Each project's output is buffered within its runspace and printed atomically when the worker completes, ensuring clean, non-interleaved output even with 20+ concurrent workers.

```
────────────────────────────────────────────────────────────────────────────────
  PlatformCore
────────────────────────────────────────────────────────────────────────────────
  ✔  Role found  →  [contoso]\Project Administrators
  ✔  Permissions match the baseline
  ✖  Membership drift:
      Unexpected members (in role, NOT in expected list):
        ✖ Corp\SRE-Team
      Missing members (in expected list, NOT in role):
        ✖ Corp\DevOps-Leads

────────────────────────────────────────────────────────────────────────────────
  Audit Summary
────────────────────────────────────────────────────────────────────────────────
  Projects audited  : 40
  Compliant         : 37
  Non-compliant     : 3
  Elapsed           : 18.2s  (parallel, 10 workers)

  API telemetry:
    Total calls      : 487
    Rate-limit hits  : 1
    Total retries    : 1
    Reactive sleep   : 4.0s  (across all workers)
```

Note that project output order in the console reflects completion order, not the order projects were enumerated, because faster workers finish before slower ones.

### JSON Report

A machine-readable report is written on every run. Its path defaults to `.\ADO-Audit-<timestamp>.json` and can be overridden with `-OutputPath`.

```json
{
  "AuditStart": "2025-04-12T09:00:00.000Z",
  "AuditEnd":   "2025-04-12T09:00:18.000Z",
  "ElapsedSeconds": 18.2,
  "Organization": "contoso",
  "RoleName": "Project Administrators",
  "OverallCompliant": false,
  "ParallelConfig": {
    "ParallelThrottle": 10,
    "ThrottleDelayMs":  100,
    "RetryJitterSec":   2,
    "MaxRetries":       5,
    "MaxBackoffSec":    120
  },
  "ApiTelemetry": {
    "TotalApiCalls":   487,
    "RateLimitHits":   1,
    "TotalRetries":    1,
    "TotalThrottleMs": 4000
  },
  "Results": [
    {
      "ProjectName":      "PlatformCore",
      "Compliant":        false,
      "RoleFound":        true,
      "PermissionsMatch": true,
      "MembersMatch":     false,
      "ExtraMembers":     ["Corp\\SRE-Team"],
      "MissingMembers":   ["Corp\\DevOps-Leads"],
      "ActualMembers":    ["Corp\\ADO-Admins", "Corp\\SRE-Team"],
      "PermissionDrift":  [],
      "Errors":           []
    }
  ]
}
```

---

## CI/CD Integration

The script exits with code `0` when all audited projects are compliant and `1` when any drift is detected, making it a natural fit for automated pipeline gates.

**GitHub Actions — nightly audit:**

```yaml
name: ADO Permissions Audit

on:
  schedule:
    - cron: "0 6 * * *"   # 06:00 UTC daily
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run permissions audit
        shell: pwsh
        env:
          ADO_PAT: ${{ secrets.ADO_PAT }}
        run: |
          $pat = ConvertTo-SecureString $env:ADO_PAT -AsPlainText -Force
          .\Verify-ADOProjectPermissions.ps1 `
              -Organization    "contoso" `
              -RoleName        "Project Administrators" `
              -BaselineFile    ".\baseline-permissions-template.json" `
              -ExpectedMembers "Corp\ADO-Admins, Corp\DevOps-Leads" `
              -Pat             $pat `
              -OutputPath      "audit-report.json" `
              -ParallelThrottle 10

      - name: Upload audit report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ado-audit-report
          path: audit-report.json
```

**Azure DevOps Pipelines:**

```yaml
- task: PowerShell@2
  displayName: "ADO Permissions Audit"
  inputs:
    filePath: "$(Build.SourcesDirectory)/Verify-ADOProjectPermissions.ps1"
    pwsh: true
    arguments: >
      -Organization    "contoso"
      -RoleName        "Project Administrators"
      -BaselineFile    "$(Build.SourcesDirectory)/baseline-permissions-template.json"
      -ExpectedMembers "Corp\ADO-Admins"
      -Pat             (ConvertTo-SecureString "$(ADO_PAT)" -AsPlainText -Force)
      -OutputPath      "$(Build.ArtifactStagingDirectory)/audit-report.json"
      -ParallelThrottle 10
  env:
    ADO_PAT: $(ADO_PAT)
```

> Store your PAT as an encrypted pipeline secret variable. Never embed it directly in the pipeline YAML.

---

## Performance Tuning

The two primary levers controlling throughput are `ParallelThrottle` (how many projects run simultaneously) and `ThrottleDelay` (how fast each worker fires calls). Their combined effect determines the org-wide API call rate:

```
Effective call rate ≈ ParallelThrottle × (1000 / ThrottleDelay) calls/sec
```

| Scenario | Suggested settings |
|---|---|
| Default — balanced | `-ParallelThrottle 10 -ThrottleDelay 100` |
| Small tenant (<20 projects) | `-ParallelThrottle 5 -ThrottleDelay 50` |
| Large tenant (100+ projects) | `-ParallelThrottle 20 -ThrottleDelay 200` |
| Sustained 429s | Reduce `-ParallelThrottle` first, then increase `-ThrottleDelay` |
| CI runner with limited CPU | Reduce `-ParallelThrottle` to match available cores |
| Single project | `-ParallelThrottle 1` to eliminate parallel overhead |

Use `ApiTelemetry.RateLimitHits` in the JSON report to determine whether throttling is needed. Zero hits means there is headroom to increase throughput.

---

## Troubleshooting

**No projects are returned**

Verify that your PAT has the `vso.project` (Project and Team — Read) scope and that the organization name matches exactly what appears in your ADO URL. The name is case-sensitive.

**Role is not found in any project**

The `-RoleName` value must match the group's `displayName` exactly as it appears in ADO. For built-in groups this is typically `"Project Administrators"`, `"Contributors"`, or `"Readers"`. Confirm the exact name in the ADO portal under **Project Settings → Permissions**.

**Permission drift on every project despite correct settings**

The script targets the **Project** security namespace by default (`52d39943-cb85-4d7f-8fa8-c6baac873819`). If you are auditing a different namespace — for example, Git repositories or Build pipelines — the namespace ID and ACL token format must be updated in the script. Refer to the [ADO Security Namespaces reference](https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference?view=azure-devops) for the correct values.

**Frequent HTTP 429 errors**

Reduce `-ParallelThrottle` first (e.g. from `10` to `5`) to lower the aggregate call rate, then increase `-ThrottleDelay` as a secondary adjustment. Review `ApiTelemetry.RateLimitHits` across runs to track whether changes are effective.

**Member names do not match the expected list**

The script resolves member identities using `principalName` (e.g. `DOMAIN\groupname` or `user@tenant.onmicrosoft.com`) in preference to `displayName`. Ensure the values supplied to `-ExpectedMembers` use the same format. Run the script with `-Verbose` to see resolved names printed during execution.

**Console output appears out of order**

This is expected behaviour. Because workers run concurrently, project output is printed in completion order rather than enumeration order. All results are correctly ordered by project name in the JSON report regardless of print order.

**Script fails on Windows PowerShell 5.x**

`ForEach-Object -Parallel` and `ConcurrentDictionary` require PowerShell 7+. Install it from the [official releases page](https://github.com/PowerShell/PowerShell/releases). On Windows, PowerShell 7 installs side-by-side with Windows PowerShell 5.x and does not replace it.

---

## Security Considerations

- **PAT storage** — never commit a PAT to source control. Use a secrets manager, CI/CD secret variable, or interactive prompt at the terminal.
- **PAT scope** — restrict the token to the three read-only scopes listed in [Prerequisites](#prerequisites). Do not grant `vso.security_manage` or any write-capable scope.
- **PAT lifetime** — use short-lived tokens (30–90 days) and rotate on a schedule. Revoke tokens that are no longer needed immediately.
- **Runspace PAT handling** — the script converts the `SecureString` PAT to a Base64 Authorization header value exactly once in the main thread. Only this header string (not the `SecureString`) crosses runspace boundaries, minimising the window in which the credential exists in memory across multiple contexts.
- **Report contents** — the JSON report contains group membership information. Treat it as sensitive and apply appropriate access controls and encryption at rest to the output directory.
- **Network** — all communication is over HTTPS to `dev.azure.com` and `vssps.dev.azure.com`. Ensure outbound port 443 is permitted and that TLS inspection does not break certificate trust.

---

## Contributing

Contributions are welcome. Please follow these steps:

1. **Fork** the repository and create a feature branch from `main`.
2. **Test** your changes against a non-production ADO organization before opening a pull request.
3. **Update** `baseline-permissions-template.json` and this README if your change introduces new named permission keys or script parameters.
4. **Submit a pull request** with a clear description of the change and the problem it solves.

Please open an issue before beginning significant changes so the approach can be aligned with the project direction before implementation.

---

## License

This project is licensed under the [MIT License](LICENSE).
