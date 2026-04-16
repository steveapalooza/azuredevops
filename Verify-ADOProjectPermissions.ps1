<#
.SYNOPSIS
    Audits Azure DevOps project roles, permissions, and group memberships against a defined baseline.

.DESCRIPTION
    Read-only script that connects to the Azure DevOps REST API and the ADO Graph API to
    interrogate every project in an Azure DevOps organization and verify that:

      1. A specified security group / role is present in each target project.
      2. The role's permissions match a provided JSON baseline file.
      3. The role's membership contains ONLY the expected AD groups or user principals
         (no more, no fewer).

    The script is strictly READ-ONLY. It will never create, update, or delete any
    resource in Azure DevOps or Azure Active Directory.

    ── RATE-LIMIT HANDLING ──────────────────────────────────────────────────────
    Azure DevOps enforces per-resource throttling and may return HTTP 429
    ("Too Many Requests") with a "Retry-After" response header.
    Every API call is routed through Invoke-AdoApi which implements three layers:

      Layer 1 — Proactive inter-call delay  (-ThrottleDelay, default 200 ms)
        Applied between EVERY API call during loops so the tenant is never hit
        at full CPU speed.  Increase this first if you see frequent 429s.

      Layer 2 — Reactive 429 back-off
        On HTTP 429 the "Retry-After" header is read (seconds).  The script
        sleeps for (Retry-After + RetryJitter) seconds and then retries.
        If no header is present, exponential back-off is used instead:
        sleep = min(2^attempt, MaxBackoffSeconds).

      Layer 3 — Hard failure after MaxRetries
        If all retry attempts are exhausted the call returns $null.  The
        failure is logged in the audit result; the script continues with the
        remaining projects rather than aborting entirely.

    All throttle events and retry counts are recorded in RateLimitStats and
    written to the JSON report so you can tune the parameters over time.

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from https://dev.azure.com/myorg).

.PARAMETER ProjectName
    One or more project names to audit.  Accepts wildcards (e.g. "Team-*").
    Omit to audit ALL projects in the organization.

.PARAMETER RoleName
    The Azure DevOps security group / role to verify
    (e.g. "Project Administrators", "Contributors").

.PARAMETER BaselineFile
    Path to a JSON file describing the expected permission bits for the role.
    See baseline-permissions-template.json for the supported schema.

.PARAMETER ExpectedMembers
    Comma-separated list of expected member display names or UPNs.
    The role membership must EXACTLY match this list — no additions, no omissions.

.PARAMETER Pat
    Azure DevOps Personal Access Token supplied as a SecureString.
    Minimum required scopes: vso.project (read), vso.security (read), vso.graph (read).

.PARAMETER OutputPath
    Optional path for the JSON audit report.
    Defaults to .\ADO-Audit-<timestamp>.json in the current directory.

.PARAMETER ThrottleDelay
    Milliseconds to sleep between EVERY API call (proactive throttle).
    Default: 200.  Increase to 500–1000 on large tenants or noisy pipelines.

.PARAMETER RetryJitter
    Extra seconds added on top of the server-supplied Retry-After value before
    retrying a 429 response.  Default: 2.

.PARAMETER MaxRetries
    Maximum retry attempts per API call before treating it as a hard failure.
    Default: 5.

.PARAMETER MaxBackoffSeconds
    Upper ceiling (seconds) for exponential back-off when no Retry-After header
    is present.  Default: 120.

.EXAMPLE
    $pat = Read-Host -AsSecureString "Enter PAT"

    .\Verify-ADOProjectPermissions.ps1 `
        -Organization    "contoso" `
        -RoleName        "Project Administrators" `
        -BaselineFile    ".\baseline-permissions.json" `
        -ExpectedMembers "Corp\ADO-Admins, Corp\DevOps-Leads" `
        -Pat             $pat

.EXAMPLE
    # Single project with aggressive throttle for a large or busy tenant
    $pat = Read-Host -AsSecureString "Enter PAT"

    .\Verify-ADOProjectPermissions.ps1 `
        -Organization    "contoso" `
        -ProjectName     "MyProject" `
        -RoleName        "Contributors" `
        -BaselineFile    ".\baseline-contributors.json" `
        -ExpectedMembers "Corp\Dev-Team" `
        -Pat             $pat `
        -OutputPath      "C:\Reports\audit.json" `
        -ThrottleDelay   600 `
        -MaxRetries      8

.NOTES
    Author   : Lead DevOps Engineer
    Version  : 2.0.0
    Requires : PowerShell 7+  |  No external modules (uses Invoke-WebRequest only)
    This script is strictly READ-ONLY and will never mutate any ADO or AAD resource.
#>

[CmdletBinding()]
param (
    # ── Required / core ──────────────────────────────────────────────────────
    [Parameter(Mandatory, HelpMessage = "ADO organization name")]
    [ValidateNotNullOrEmpty()]
    [string] $Organization,

    [Parameter(HelpMessage = "Project name(s) to audit. Omit for all. Supports wildcards.")]
    [string[]] $ProjectName,

    [Parameter(Mandatory, HelpMessage = "Security group / role name to verify")]
    [ValidateNotNullOrEmpty()]
    [string] $RoleName,

    [Parameter(Mandatory, HelpMessage = "Path to the JSON permissions baseline file")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string] $BaselineFile,

    [Parameter(Mandatory, HelpMessage = "Comma-separated expected member display names or UPNs")]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedMembers,

    [Parameter(Mandatory, HelpMessage = "Azure DevOps PAT as a SecureString")]
    [System.Security.SecureString] $Pat,

    [Parameter(HelpMessage = "Path for the JSON audit report (default: .\ADO-Audit-<ts>.json)")]
    [string] $OutputPath,

    # ── Rate-limit / throttle ─────────────────────────────────────────────────
    [Parameter(HelpMessage = "ms to sleep between every API call (proactive throttle). Default 200.")]
    [ValidateRange(0, 60000)]
    [int] $ThrottleDelay = 200,

    [Parameter(HelpMessage = "Extra seconds added to Retry-After on HTTP 429. Default 2.")]
    [ValidateRange(0, 300)]
    [int] $RetryJitter = 2,

    [Parameter(HelpMessage = "Max retries per API call before giving up. Default 5.")]
    [ValidateRange(1, 20)]
    [int] $MaxRetries = 5,

    [Parameter(HelpMessage = "Ceiling (s) for exponential back-off when no Retry-After header. Default 120.")]
    [ValidateRange(5, 600)]
    [int] $MaxBackoffSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
#  Script-level rate-limit telemetry  (written to the JSON report)
# ─────────────────────────────────────────────────────────────────────────────
$script:Stats = [pscustomobject]@{
    TotalApiCalls    = 0
    RateLimitHits    = 0   # HTTP 429 responses received
    TotalRetries     = 0   # all retry attempts across all call types
    TotalThrottleMs  = 0   # cumulative ms spent in reactive sleep (429 + back-off)
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 1 ─ Console output helpers
#endregion

function Write-Section ([string]$Title) {
    Write-Host "`n$('─' * 72)" -ForegroundColor DarkGray
    Write-Host "  $Title"      -ForegroundColor Cyan
    Write-Host "$('─' * 72)"   -ForegroundColor DarkGray
}
function Write-Pass  ([string]$Msg) { Write-Host "  ✔  $Msg" -ForegroundColor Green   }
function Write-Fail  ([string]$Msg) { Write-Host "  ✖  $Msg" -ForegroundColor Red     }
function Write-Info  ([string]$Msg) { Write-Host "  ℹ  $Msg" -ForegroundColor Yellow  }
function Write-Warn  ([string]$Msg) { Write-Host "  ⚠  $Msg" -ForegroundColor Magenta }
function Write-Retry ([string]$Msg) { Write-Host "  ↺  $Msg" -ForegroundColor DarkYellow }


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 2 ─ PAT / authentication helpers
#endregion

function ConvertTo-PlainText {
    param([System.Security.SecureString]$Secure)
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
}

function New-AuthHeader {
    param([System.Security.SecureString]$SecurePat)
    $plain = ConvertTo-PlainText $SecurePat
    $b64   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$plain"))
    $plain = $null   # encourage early GC
    return @{ Authorization = "Basic $b64" }
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 3 ─ Core API engine with full rate-limit handling
#
#  Invoke-AdoApi routes EVERY API call through three protection layers:
#
#  ┌─ Layer 1: Proactive delay ──────────────────────────────────────────────┐
#  │  Start-Sleep -Milliseconds $ThrottleDelay before every call.           │
#  │  Prevents burst-fire loops from ever reaching ADO at full speed.       │
#  └─────────────────────────────────────────────────────────────────────────┘
#  ┌─ Layer 2: Reactive 429 back-off ────────────────────────────────────────┐
#  │  HTTP 429 → read Retry-After header → sleep (header + RetryJitter) s.  │
#  │  No header → exponential back-off: min(2^attempt, MaxBackoffSeconds).  │
#  │  HTTP 503/504 → same exponential back-off (transient server errors).   │
#  │  All sleep time is recorded in $script:Stats.TotalThrottleMs.          │
#  └─────────────────────────────────────────────────────────────────────────┘
#  ┌─ Layer 3: Hard failure ─────────────────────────────────────────────────┐
#  │  After MaxRetries attempts the function returns $null.                 │
#  │  Callers log the failure in the audit result; execution continues.     │
#  └─────────────────────────────────────────────────────────────────────────┘
#endregion

function Invoke-AdoApi {
    param(
        [Parameter(Mandatory)][string]    $Uri,
        [Parameter(Mandatory)][hashtable] $Headers,
        [string] $Description = ""
    )

    $script:Stats.TotalApiCalls++

    # Layer 1 — proactive inter-call delay
    if ($ThrottleDelay -gt 0) {
        Start-Sleep -Milliseconds $ThrottleDelay
    }

    $attempt = 0

    while ($attempt -le $MaxRetries) {
        Write-Verbose "  GET [attempt=$attempt] $Uri  ($Description)"

        try {
            # Invoke-WebRequest (not Invoke-RestMethod) so we can read response headers
            $wr = Invoke-WebRequest `
                    -Uri         $Uri `
                    -Headers     $Headers `
                    -Method      Get `
                    -ContentType "application/json" `
                    -ErrorAction Stop

            return ($wr.Content | ConvertFrom-Json)
        }
        catch [System.Net.WebException] {
            $httpResp   = $_.Exception.Response
            $statusCode = [int]($httpResp?.StatusCode ?? 0)

            # ── HTTP 429 — rate-limited ───────────────────────────────────────
            if ($statusCode -eq 429) {
                $script:Stats.RateLimitHits++
                $script:Stats.TotalRetries++
                $attempt++

                if ($attempt -gt $MaxRetries) {
                    Write-Fail "429 rate-limited — max retries ($MaxRetries) exhausted  [$Description]"
                    return $null
                }

                $raHeader = $httpResp.Headers["Retry-After"]
                $raParsed = 0
                if ($raHeader -and [int]::TryParse($raHeader.Trim(), [ref]$raParsed)) {
                    $waitSec = $raParsed + $RetryJitter
                    Write-Retry ("HTTP 429 — Retry-After: {0}s +{1}s jitter = {2}s sleep" -f
                                  $raParsed, $RetryJitter, $waitSec) +
                                "  [attempt $attempt/$MaxRetries]  [$Description]"
                } else {
                    $waitSec = [Math]::Min([Math]::Pow(2, $attempt), $MaxBackoffSeconds)
                    Write-Retry ("HTTP 429 — no Retry-After header — exponential back-off {0}s" -f $waitSec) +
                                "  [attempt $attempt/$MaxRetries]  [$Description]"
                }

                $script:Stats.TotalThrottleMs += ($waitSec * 1000)
                Start-Sleep -Seconds $waitSec
                continue
            }

            # ── HTTP 503 / 504 — transient server errors ──────────────────────
            if ($statusCode -in @(503, 504)) {
                $script:Stats.TotalRetries++
                $attempt++

                if ($attempt -gt $MaxRetries) {
                    Write-Fail "HTTP $statusCode — max retries exhausted  [$Description]"
                    return $null
                }

                $waitSec = [Math]::Min([Math]::Pow(2, $attempt), $MaxBackoffSeconds)
                Write-Retry "HTTP $statusCode (transient) — back-off ${waitSec}s  [attempt $attempt/$MaxRetries]  [$Description]"
                $script:Stats.TotalThrottleMs += ($waitSec * 1000)
                Start-Sleep -Seconds $waitSec
                continue
            }

            # ── All other HTTP errors — not retryable ─────────────────────────
            Write-Warning "  HTTP $statusCode for: $Uri`n    $($_.Exception.Message)"
            return $null
        }
        catch {
            # Network/DNS/timeout errors — apply one back-off retry cycle
            $script:Stats.TotalRetries++
            $attempt++

            if ($attempt -gt $MaxRetries) {
                Write-Warning "  Non-HTTP exception (retries exhausted) [$Description]`n  $_"
                return $null
            }

            $waitSec = [Math]::Min([Math]::Pow(2, $attempt), $MaxBackoffSeconds)
            Write-Retry "Non-HTTP error — back-off ${waitSec}s  [attempt $attempt/$MaxRetries]  [$Description]"
            $script:Stats.TotalThrottleMs += ($waitSec * 1000)
            Start-Sleep -Seconds $waitSec
        }
    }

    return $null  # unreachable but required by strict mode
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 4 ─ Audit result factory
#endregion

function New-ProjectAuditResult {
    param([string]$Name)
    return [pscustomobject]@{
        ProjectName      = $Name
        Timestamp        = (Get-Date -Format "o")
        RoleFound        = $false
        PermissionsMatch = $false
        MembersMatch     = $false
        PermissionDrift  = [System.Collections.Generic.List[object]]::new()
        ExtraMembers     = [System.Collections.Generic.List[string]]::new()   # present, not expected
        MissingMembers   = [System.Collections.Generic.List[string]]::new()   # expected, not present
        ActualMembers    = [System.Collections.Generic.List[string]]::new()
        ExpectedMembers  = [System.Collections.Generic.List[string]]::new()
        Errors           = [System.Collections.Generic.List[string]]::new()
        Compliant        = $false
    }
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 5 ─ ADO REST API wrapper functions
#endregion

function Get-AllProjects {
    param([string]$Org, [hashtable]$Headers)
    $list = [System.Collections.Generic.List[object]]::new()
    $skip = 0; $top = 200
    do {
        $uri  = "https://dev.azure.com/$Org/_apis/projects?`$top=$top&`$skip=$skip&api-version=7.1"
        $page = Invoke-AdoApi -Uri $uri -Headers $Headers -Description "List projects (skip=$skip)"
        if ($null -eq $page -or $page.count -eq 0) { break }
        $list.AddRange($page.value)
        $skip += $top
    } while ($page.count -eq $top)
    return $list
}

function Get-ProjectScopeDescriptor {
    param([string]$Org, [string]$ProjectId, [hashtable]$Headers)
    $uri  = "https://vssps.dev.azure.com/$Org/_apis/graph/descriptors/$ProjectId`?api-version=7.1-preview.1"
    $resp = Invoke-AdoApi -Uri $uri -Headers $Headers -Description "Scope descriptor [$ProjectId]"
    return $resp?.value
}

function Get-ProjectSecurityGroups {
    param([string]$Org, [string]$ScopeDescriptor, [hashtable]$Headers)
    $groups       = [System.Collections.Generic.List[object]]::new()
    $continuation = $null
    do {
        $uri = "https://vssps.dev.azure.com/$Org/_apis/graph/groups" +
               "?scopeDescriptor=$ScopeDescriptor&api-version=7.1-preview.1"
        if ($continuation) { $uri += "&continuationToken=$continuation" }

        $resp = Invoke-AdoApi -Uri $uri -Headers $Headers -Description "Groups [$ScopeDescriptor]"
        if ($null -eq $resp) { break }
        if ($resp.value)     { $groups.AddRange($resp.value) }
        $continuation = $resp.continuationToken
    } while ($continuation)
    return $groups
}

function Get-GroupMembers {
    param([string]$Org, [string]$GroupDescriptor, [hashtable]$Headers)
    $uri  = "https://vssps.dev.azure.com/$Org/_apis/graph/memberships/$GroupDescriptor" +
            "?direction=down&api-version=7.1-preview.1"
    $resp = Invoke-AdoApi -Uri $uri -Headers $Headers -Description "Members [$GroupDescriptor]"
    return $resp?.value
}

function Resolve-SubjectDisplayName {
    param([string]$Org, [string]$SubjectDescriptor, [hashtable]$Headers)
    $uri  = "https://vssps.dev.azure.com/$Org/_apis/graph/subjects/$SubjectDescriptor" +
            "?api-version=7.1-preview.1"
    $resp = Invoke-AdoApi -Uri $uri -Headers $Headers -Description "Resolve [$SubjectDescriptor]"
    if ($resp) {
        # Prefer principalName (DOMAIN\group or user@tenant) for reliable comparison
        return ($resp.principalName ?? $resp.mailAddress ?? $resp.displayName ?? $SubjectDescriptor)
    }
    return $SubjectDescriptor
}

function Get-ProjectPermissionAce {
    <#
    Returns the ACE { allow: int, deny: int } for $GroupDescriptor on the project
    security namespace (52d39943-cb85-4d7f-8fa8-c6baac873819), or $null if absent.
    #>
    param(
        [string]$Org,
        [string]$ProjectId,
        [string]$GroupDescriptor,
        [hashtable]$Headers
    )

    # 1. Resolve group storage key (the SID used in ACL dictionaries)
    $keyUri  = "https://vssps.dev.azure.com/$Org/_apis/graph/storagekeys/$GroupDescriptor" +
               "?api-version=7.1-preview.1"
    $keyResp = Invoke-AdoApi -Uri $keyUri -Headers $Headers -Description "Storage key [$GroupDescriptor]"
    if ($null -eq $keyResp) { return $null }
    $sid = $keyResp.value

    # 2. Fetch project-level ACL for that SID
    $nsId    = "52d39943-cb85-4d7f-8fa8-c6baac873819"
    $token   = "`$PROJECT:vstfs:///Classification/TeamProject/$ProjectId"
    $aclUri  = "https://dev.azure.com/$Org/_apis/accesscontrollists/$nsId" +
               "?token=$([Uri]::EscapeDataString($token))" +
               "&descriptors=$([Uri]::EscapeDataString($sid))" +
               "&includeExtendedInfo=true&api-version=7.1"

    $aclResp = Invoke-AdoApi -Uri $aclUri -Headers $Headers -Description "ACL [$ProjectId]"
    if ($null -eq $aclResp -or $aclResp.count -eq 0) { return $null }

    $ace = $aclResp.value[0].acesDictionary.PSObject.Properties |
               Where-Object { $_.Name -eq $sid } |
               Select-Object -First 1
    return $ace?.Value
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 6 ─ Permission comparison engine
#endregion

# Built-in bit map for the ADO "Project" security namespace.
# Extend with additional permission names as needed.
$script:PermBits = @{
    GenericRead                  = 1
    GenericWrite                 = 2
    Delete                       = 4
    PublishTestResults           = 8
    ReadTestResults              = 16
    UpdateBuildInformation       = 32
    EditBuildStatus              = 64
    UpdateBuild                  = 128
    DeleteTestResults            = 256
    ViewBuilds                   = 512
    ManageBuildQueue             = 1024
    ManageBuildDefinitions       = 2048
    DestroyBuilds                = 4096
    AdministrateBuildPermissions = 8192
    ManageBuildQualityChecks     = 16384
}

function Compare-Permissions {
    param(
        [psobject]$Baseline,   # parsed from JSON baseline file
        [psobject]$Actual      # { allow: int, deny: int } or $null
    )

    $drift = [System.Collections.Generic.List[object]]::new()

    if ($null -eq $Actual) {
        $drift.Add([pscustomobject]@{
            Permission = "ACE"
            Expected   = "allow=$($Baseline.allow ?? 'n/a')  deny=$($Baseline.deny ?? 'n/a')"
            Actual     = "No ACE found for this group in the project security namespace"
        })
        return $drift
    }

    # Raw bitmask assertions
    if ($null -ne $Baseline.allow -and $Actual.allow -ne [int]$Baseline.allow) {
        $drift.Add([pscustomobject]@{
            Permission = "allow (bitmask)"
            Expected   = $Baseline.allow
            Actual     = $Actual.allow
        })
    }
    if ($null -ne $Baseline.deny -and $Actual.deny -ne [int]$Baseline.deny) {
        $drift.Add([pscustomobject]@{
            Permission = "deny (bitmask)"
            Expected   = $Baseline.deny
            Actual     = $Actual.deny
        })
    }

    # Named permission assertions
    if ($Baseline.PSObject.Properties.Name -contains "permissions") {
        foreach ($permName in $Baseline.permissions.PSObject.Properties.Name) {
            $expectedGrant = [bool]$Baseline.permissions.$permName
            $bit = $script:PermBits[$permName]

            if ($null -eq $bit) {
                $drift.Add([pscustomobject]@{
                    Permission = $permName
                    Expected   = "defined in baseline"
                    Actual     = "Bit name not in built-in map — verify namespace"
                })
                continue
            }

            $actualGrant = ($Actual.allow -band $bit) -ne 0
            if ($actualGrant -ne $expectedGrant) {
                $drift.Add([pscustomobject]@{
                    Permission = $permName
                    Expected   = $expectedGrant
                    Actual     = $actualGrant
                })
            }
        }
    }

    return $drift
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 7 ─ Main execution
#endregion

$scriptStart = Get-Date

Write-Section "Azure DevOps Permissions Audit  v2.0"
Write-Host "  Organization   : $Organization"
Write-Host "  Role target    : $RoleName"
Write-Host "  Baseline file  : $BaselineFile"
Write-Host "  Started        : $($scriptStart.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host ""
Write-Host "  Throttle / rate-limit settings:" -ForegroundColor DarkGray
Write-Host "    -ThrottleDelay      : ${ThrottleDelay} ms  (proactive, every call)"  -ForegroundColor DarkGray
Write-Host "    -RetryJitter        : +${RetryJitter} s   (added to Retry-After)"    -ForegroundColor DarkGray
Write-Host "    -MaxRetries         : $MaxRetries"                                    -ForegroundColor DarkGray
Write-Host "    -MaxBackoffSeconds  : ${MaxBackoffSeconds} s"                         -ForegroundColor DarkGray

# ── Parse inputs ───────────────────────────────────────────────────────────────
$headers      = New-AuthHeader $Pat
$baseline     = Get-Content $BaselineFile -Raw | ConvertFrom-Json
$expectedList = $ExpectedMembers -split "," |
                    ForEach-Object { $_.Trim() } |
                    Where-Object   { $_ -ne "" }

Write-Verbose "Expected members ($($expectedList.Count)): $($expectedList -join ' | ')"

# ── Enumerate projects ─────────────────────────────────────────────────────────
Write-Section "Fetching Projects"

$allProjects = Get-AllProjects -Org $Organization -Headers $headers
if ($null -eq $allProjects -or $allProjects.Count -eq 0) {
    Write-Error "No projects returned. Verify your PAT has 'vso.project' read scope."
    exit 1
}

if ($ProjectName -and $ProjectName.Count -gt 0) {
    $filtered = @($allProjects | Where-Object {
        $p = $_; $ProjectName | Where-Object { $p.name -like $_ }
    })
    if ($filtered.Count -eq 0) {
        Write-Warning "No projects matched filter(s): $($ProjectName -join ', ')"
        exit 0
    }
} else {
    $filtered = @($allProjects)
}

Write-Info "Auditing $($filtered.Count) of $($allProjects.Count) projects"

# ── Per-project audit loop ─────────────────────────────────────────────────────
$auditResults     = [System.Collections.Generic.List[psobject]]::new()
$overallCompliant = $true
$idx              = 0

foreach ($project in $filtered) {
    $idx++
    Write-Section "[$idx / $($filtered.Count)]  $($project.name)"

    $result = New-ProjectAuditResult -Name $project.name
    $result.ExpectedMembers.AddRange($expectedList)

    try {
        # A ── Get project scope descriptor
        $scope = Get-ProjectScopeDescriptor -Org $Organization `
                                             -ProjectId $project.id `
                                             -Headers $headers
        if (-not $scope) {
            $m = "Failed to retrieve scope descriptor"; Write-Fail $m
            $result.Errors.Add($m); $overallCompliant = $false
            $auditResults.Add($result); continue
        }

        # B ── List all security groups in project
        $groups = Get-ProjectSecurityGroups -Org $Organization `
                                             -ScopeDescriptor $scope `
                                             -Headers $headers
        if (-not $groups -or $groups.Count -eq 0) {
            $m = "Failed to retrieve security groups"; Write-Fail $m
            $result.Errors.Add($m); $overallCompliant = $false
            $auditResults.Add($result); continue
        }

        # C ── Locate the target role
        $targetGroup = $groups | Where-Object {
            $_.displayName     -eq $RoleName         -or
            $_.principalName   -like "*\$RoleName"   -or
            $_.principalName   -like "*/$RoleName"
        } | Select-Object -First 1

        if ($null -eq $targetGroup) {
            Write-Fail "Role '$RoleName' NOT FOUND"
            $result.Errors.Add("Role '$RoleName' not found"); $overallCompliant = $false
            $auditResults.Add($result); continue
        }

        $roleLabel = $targetGroup.principalName ?? $targetGroup.displayName
        Write-Pass "Role found  →  $roleLabel"
        Write-Verbose "  Descriptor: $($targetGroup.descriptor)"
        $result.RoleFound = $true

        # D ── Verify permissions
        $ace   = Get-ProjectPermissionAce -Org $Organization `
                                           -ProjectId $project.id `
                                           -GroupDescriptor $targetGroup.descriptor `
                                           -Headers $headers
        $drift = Compare-Permissions -Baseline $baseline -Actual $ace
        $result.PermissionDrift.AddRange($drift)

        if ($drift.Count -eq 0) {
            Write-Pass "Permissions match the baseline"
            $result.PermissionsMatch = $true
        } else {
            Write-Fail "Permission drift — $($drift.Count) discrepancy(ies):"
            foreach ($d in $drift) {
                Write-Host "      ┌ $($d.Permission)" -ForegroundColor Red
                Write-Host "      │ Expected : $($d.Expected)"  -ForegroundColor Yellow
                Write-Host "      └ Actual   : $($d.Actual)"    -ForegroundColor Yellow
            }
            $result.PermissionsMatch = $false; $overallCompliant = $false
        }

        # E ── Resolve group membership
        $memberships = Get-GroupMembers -Org $Organization `
                                         -GroupDescriptor $targetGroup.descriptor `
                                         -Headers $headers
        if ($memberships) {
            foreach ($m in $memberships) {
                $name = Resolve-SubjectDisplayName -Org $Organization `
                                                    -SubjectDescriptor $m.memberDescriptor `
                                                    -Headers $headers
                $result.ActualMembers.Add($name)
            }
        }

        # F ── Diff membership
        $extra   = @($result.ActualMembers | Where-Object { $_ -notin $expectedList })
        $missing = @($expectedList         | Where-Object { $_ -notin $result.ActualMembers })

        if ($extra.Count   -gt 0) { $result.ExtraMembers.AddRange($extra)     }
        if ($missing.Count -gt 0) { $result.MissingMembers.AddRange($missing)  }

        if ($extra.Count -eq 0 -and $missing.Count -eq 0) {
            Write-Pass "Membership matches  ($($result.ActualMembers.Count) member(s))"
            $result.MembersMatch = $true
        } else {
            Write-Fail "Membership drift:"
            if ($extra.Count -gt 0) {
                Write-Host "      Unexpected members (in role, NOT in expected list):" -ForegroundColor Red
                $extra   | ForEach-Object { Write-Host "        ✖ $_" -ForegroundColor Red    }
            }
            if ($missing.Count -gt 0) {
                Write-Host "      Missing members (in expected list, NOT in role):"   -ForegroundColor Yellow
                $missing | ForEach-Object { Write-Host "        ✖ $_" -ForegroundColor Yellow }
            }
            $result.MembersMatch = $false; $overallCompliant = $false
        }
    }
    catch {
        $m = "Unhandled exception: $_"
        Write-Warn $m
        $result.Errors.Add($m); $overallCompliant = $false
    }

    $result.Compliant = (
        $result.RoleFound        -and
        $result.PermissionsMatch -and
        $result.MembersMatch     -and
        $result.Errors.Count -eq 0
    )
    $auditResults.Add($result)
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 8 ─ Summary & JSON report
#endregion

$scriptEnd     = Get-Date
$elapsedSec    = [Math]::Round(($scriptEnd - $scriptStart).TotalSeconds, 1)
$compliantCnt  = ($auditResults | Where-Object {  $_.Compliant }).Count
$nonComplCnt   = ($auditResults | Where-Object { -not $_.Compliant }).Count

Write-Section "Audit Summary"
Write-Host "  Projects audited : $($auditResults.Count)"
Write-Host "  Compliant        : $compliantCnt"  -ForegroundColor $(if ($compliantCnt -gt 0)  { "Green" } else { "White" })
Write-Host "  Non-compliant    : $nonComplCnt"   -ForegroundColor $(if ($nonComplCnt  -gt 0)  { "Red"   } else { "Green" })
Write-Host "  Elapsed          : ${elapsedSec}s"
Write-Host ""
Write-Host "  API telemetry:" -ForegroundColor DarkGray
Write-Host "    Total calls      : $($script:Stats.TotalApiCalls)"                                                           -ForegroundColor DarkGray
Write-Host "    Rate-limit hits  : $($script:Stats.RateLimitHits)"   -ForegroundColor $(if ($script:Stats.RateLimitHits -gt 0) { "Magenta" } else { "DarkGray" })
Write-Host "    Total retries    : $($script:Stats.TotalRetries)"    -ForegroundColor $(if ($script:Stats.TotalRetries  -gt 0) { "Yellow"  } else { "DarkGray" })
Write-Host "    Reactive sleep   : $([Math]::Round($script:Stats.TotalThrottleMs/1000,1))s" -ForegroundColor DarkGray

if ($nonComplCnt -gt 0) {
    Write-Host ""
    Write-Host "  Non-compliant projects:" -ForegroundColor Red
    $auditResults | Where-Object { -not $_.Compliant } | ForEach-Object {
        $flags = @()
        if (-not $_.RoleFound)        { $flags += "RoleMissing"     }
        if (-not $_.PermissionsMatch) { $flags += "PermissionDrift" }
        if (-not $_.MembersMatch)     { $flags += "MemberDrift"     }
        if ($_.Errors.Count -gt 0)    { $flags += "Errors"          }
        Write-Host "    • $($_.ProjectName)  [$($flags -join ', ')]" -ForegroundColor Red
    }
}

# Write report
if (-not $OutputPath) {
    $OutputPath = ".\ADO-Audit-$($scriptStart.ToString('yyyyMMdd-HHmmss')).json"
}

[pscustomobject]@{
    AuditStart        = $scriptStart.ToString("o")
    AuditEnd          = $scriptEnd.ToString("o")
    ElapsedSeconds    = $elapsedSec
    Organization      = $Organization
    RoleName          = $RoleName
    BaselineFile      = $BaselineFile
    ExpectedMembers   = $expectedList
    TotalProjects     = $auditResults.Count
    CompliantCount    = $compliantCnt
    NonCompliantCount = $nonComplCnt
    OverallCompliant  = $overallCompliant
    ThrottleConfig    = [pscustomobject]@{
        ThrottleDelayMs = $ThrottleDelay
        RetryJitterSec  = $RetryJitter
        MaxRetries      = $MaxRetries
        MaxBackoffSec   = $MaxBackoffSeconds
    }
    ApiTelemetry      = $script:Stats
    Results           = $auditResults
} | ConvertTo-Json -Depth 12 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "  Report → $OutputPath" -ForegroundColor Cyan

exit $(if ($overallCompliant) { 0 } else { 1 })
