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
- [Rate-Limit Handling](#rate-limit-handling)
- [Output](#output)
  - [Console](#console)
  - [JSON Report](#json-report)
- [CI/CD Integration](#cicd-integration)
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

- ✅ **Full tenant sweep** — audits all projects or a filtered subset using wildcard matching
- ✅ **Permissions baseline** — compares both raw ACE bitmasks and human-readable named permissions against a JSON baseline file
- ✅ **Exact membership verification** — detects extra members, missing members, and raises drift for either
- ✅ **Adaptive rate-limit handling** — proactive inter-call delay, reactive 429 back-off with `Retry-After` header support, and exponential back-off with a configurable ceiling
- ✅ **Structured JSON report** — full audit trail including drift details, API telemetry, and throttle statistics
- ✅ **Pipeline-ready exit codes** — exits `0` (compliant) or `1` (drift detected) for clean CI gate integration
- ✅ **No external dependencies** — PowerShell 7+ only; uses `Invoke-WebRequest` exclusively

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| PowerShell | 7.0 or later | Run `$PSVersionTable.PSVersion` to check |
| Azure DevOps PAT | — | See [Personal Access Token](#personal-access-token) |
| ADO PAT scopes | `vso.project`, `vso.security`, `vso.graph` | All read-only |
| Network access | `dev.azure.com`, `vssps.dev.azure.com` | Outbound HTTPS (port 443) |

---

## Repository Structure

```
ado-permissions-auditor/
├── Verify-ADOProjectPermissions.ps1     # Main audit script
├── baseline-permissions-template.json   # Annotated permissions baseline template
├── examples/
│   ├── baseline-project-admins.json     # Example: Project Administrators baseline
│   └── baseline-contributors.json       # Example: Contributors baseline
├── .github/
│   └── workflows/
│       └── nightly-audit.yml            # Example GitHub Actions workflow
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

The script accepts the PAT exclusively as a `SecureString` so it is never stored in plain text in memory or echoed to the console.

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
    "GenericRead":            true,
    "GenericWrite":           true,
    "Delete":                 false,
    "ViewBuilds":             true,
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
    "GenericRead":  true,
    "GenericWrite": true,
    "Delete":       false
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
| `-ThrottleDelay` | `int` | ❌ | `200` | Milliseconds to pause between every API call |
| `-RetryJitter` | `int` | ❌ | `2` | Extra seconds added to `Retry-After` on HTTP 429 |
| `-MaxRetries` | `int` | ❌ | `5` | Max retry attempts per API call before a hard failure is recorded |
| `-MaxBackoffSeconds` | `int` | ❌ | `120` | Ceiling in seconds for exponential back-off |

### Examples

**Audit all projects in the organization:**

```powershell
$pat = Read-Host -AsSecureString "Enter PAT"

.\Verify-ADOProjectPermissions.ps1 `
    -Organization    "contoso" `
    -RoleName        "Project Administrators" `
    -BaselineFile    ".\baseline-permissions-template.json" `
    -ExpectedMembers "Corp\ADO-Admins, Corp\DevOps-Leads" `
    -Pat             $pat
```

**Audit a single named project:**

```powershell
.\Verify-ADOProjectPermissions.ps1 `
    -Organization    "contoso" `
    -ProjectName     "MyProject" `
    -RoleName        "Contributors" `
    -BaselineFile    ".\examples\baseline-contributors.json" `
    -ExpectedMembers "Corp\Dev-Team" `
    -Pat             $pat `
    -OutputPath      "C:\Reports\audit.json"
```

**Audit a wildcard-matched subset of projects with conservative throttle settings:**

```powershell
.\Verify-ADOProjectPermissions.ps1 `
    -Organization    "contoso" `
    -ProjectName     "Platform-*", "Infra-*" `
    -RoleName        "Project Administrators" `
    -BaselineFile    ".\baseline-permissions-template.json" `
    -ExpectedMembers "Corp\ADO-Admins" `
    -Pat             $pat `
    -ThrottleDelay   600 `
    -MaxRetries      8 `
    -Verbose
```

---

## Rate-Limit Handling

Azure DevOps enforces per-resource throttling. The script implements three layers of protection to keep audit runs stable across tenants of any size.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Layer 1 — Proactive inter-call delay  (-ThrottleDelay, default 200 ms)     │
│                                                                             │
│  Every API call is preceded by a configurable sleep. This prevents tight    │
│  loops from hitting ADO at full CPU speed. Increase this value first when   │
│  you encounter frequent 429 responses.                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 2 — Reactive 429 back-off                                            │
│                                                                             │
│  On HTTP 429 the Retry-After header is read and honoured. The script sleeps │
│  for (Retry-After + RetryJitter) seconds and then retries automatically.    │
│  When no header is present, exponential back-off is applied instead:        │
│  sleep = min(2^attempt, MaxBackoffSeconds). HTTP 503 and 504 transient      │
│  errors use the same exponential scheme.                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 3 — Hard failure after MaxRetries                                    │
│                                                                             │
│  When all retry attempts are exhausted the call returns null. The failure   │
│  is recorded in the project's audit result and the script continues with    │
│  the remaining projects rather than aborting the entire run.                │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Tuning guide:**

| Symptom | Recommended adjustment |
|---|---|
| Occasional 429s on a large tenant | Increase `-ThrottleDelay` to `500`–`1000` |
| 429s with a long `Retry-After` value | Increase `-RetryJitter` to `5`–`10` |
| Calls still failing after retries | Increase `-MaxRetries` to `8`–`10` |
| Runs are slower than needed on a small tenant | Decrease `-ThrottleDelay` to `50`–`100` |

All throttle events are counted and written to the JSON report under `ApiTelemetry` so you can track trends across runs and tune these values over time.

---

## Output

### Console

The script emits colour-coded, real-time output for every project audited.

```
────────────────────────────────────────────────────────────────────────────────
  [3 / 12]  PlatformCore
────────────────────────────────────────────────────────────────────────────────
  ✔  Role found  →  [contoso]\Project Administrators
  ✔  Permissions match the baseline
  ✖  Membership drift:
      Unexpected members (in role, NOT in expected list):
        ✖ Corp\SRE-Team
      Missing members (in expected list, NOT in role):
        ✖ Corp\DevOps-Leads

────────────────────────────────────────────────────────────────────────────────
  Audit Summary
────────────────────────────────────────────────────────────────────────────────
  Projects audited : 12
  Compliant        : 10
  Non-compliant    : 2
  Elapsed          : 47.3s

  API telemetry:
    Total calls      : 312
    Rate-limit hits  : 2
    Total retries    : 3
    Reactive sleep   : 12.4s
```

### JSON Report

A machine-readable report is written on every run. Its path defaults to `.\ADO-Audit-<timestamp>.json` and can be overridden with `-OutputPath`.

```json
{
  "AuditStart": "2025-04-12T09:00:00.000Z",
  "AuditEnd":   "2025-04-12T09:00:47.000Z",
  "ElapsedSeconds": 47.3,
  "Organization": "contoso",
  "RoleName": "Project Administrators",
  "OverallCompliant": false,
  "ThrottleConfig": {
    "ThrottleDelayMs": 200,
    "RetryJitterSec":  2,
    "MaxRetries":      5,
    "MaxBackoffSec":   120
  },
  "ApiTelemetry": {
    "TotalApiCalls":   312,
    "RateLimitHits":   2,
    "TotalRetries":    3,
    "TotalThrottleMs": 12400
  },
  "Results": [
    {
      "ProjectName":      "PlatformCore",
      "Compliant":        false,
      "RoleFound":        true,
      "PermissionsMatch": true,
      "MembersMatch":     false,
      "ExtraMembers":     ["Corp\\SRE-Team"],
      "MissingMembers":   ["Corp\\DevOps-Leads"],
      "ActualMembers":    ["Corp\\ADO-Admins", "Corp\\SRE-Team"],
      "PermissionDrift":  [],
      "Errors":           []
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
    - cron: "0 6 * * *"   # 06:00 UTC daily
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
              -Organization    "contoso" `
              -RoleName        "Project Administrators" `
              -BaselineFile    ".\baseline-permissions-template.json" `
              -ExpectedMembers "Corp\ADO-Admins, Corp\DevOps-Leads" `
              -Pat             $pat `
              -OutputPath      "audit-report.json" `
              -ThrottleDelay   400

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
      -Organization    "contoso"
      -RoleName        "Project Administrators"
      -BaselineFile    "$(Build.SourcesDirectory)/baseline-permissions-template.json"
      -ExpectedMembers "Corp\ADO-Admins"
      -Pat             (ConvertTo-SecureString "$(ADO_PAT)" -AsPlainText -Force)
      -OutputPath      "$(Build.ArtifactStagingDirectory)/audit-report.json"
  env:
    ADO_PAT: $(ADO_PAT)
```

> Store your PAT as an encrypted pipeline secret variable. Never embed it directly in the pipeline YAML.

---

## Troubleshooting

**No projects are returned**

Verify that your PAT has the `vso.project` (Project and Team — Read) scope and that the organization name matches exactly what appears in your ADO URL. The name is case-sensitive.

**Role is not found in any project**

The `-RoleName` value must match the group's `displayName` exactly as it appears in ADO. For built-in groups this is typically `"Project Administrators"`, `"Contributors"`, or `"Readers"`. Confirm the exact name in the ADO portal under **Project Settings → Permissions**.

**Permission drift reported on every project despite correct settings**

The script targets the **Project** security namespace by default (`52d39943-cb85-4d7f-8fa8-c6baac873819`). If you are auditing a different namespace — for example, Git repositories or Build pipelines — the namespace ID and ACL token format must be updated in the script. Refer to the [ADO Security Namespaces reference](https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference?view=azure-devops) for the correct values.

**Frequent HTTP 429 errors**

Increase `-ThrottleDelay` (e.g. `-ThrottleDelay 600`) and `-MaxRetries` (e.g. `-MaxRetries 8`). Review `ApiTelemetry.RateLimitHits` and `ApiTelemetry.TotalThrottleMs` in the JSON report to understand the scope of throttling across a run.

**Member names do not match the expected list**

The script resolves member identities using `principalName` (e.g. `DOMAIN\groupname` or `user@tenant.onmicrosoft.com`) in preference to `displayName`. Ensure the values supplied to `-ExpectedMembers` use the same format. Run the script with `-Verbose` to see all resolved names printed during execution.

---

## Security Considerations

- **PAT storage** — never commit a PAT to source control. Use a secrets manager, CI/CD secret variable, or interactive prompt at the terminal.
- **PAT scope** — restrict the token to the three read-only scopes listed in [Prerequisites](#prerequisites). Do not grant `vso.security_manage` or any write-capable scope.
- **PAT lifetime** — use short-lived tokens (30–90 days) and rotate on a schedule. Revoke tokens that are no longer needed immediately.
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

