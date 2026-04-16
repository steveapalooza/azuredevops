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

    ── PARALLEL EXECUTION ───────────────────────────────────────────────────────
    Projects are audited concurrently using ForEach-Object -Parallel (PowerShell 7+).
    Each project runs in its own isolated runspace, making independent HTTP calls
    simultaneously.  The degree of concurrency is controlled by -ParallelThrottle
    (default: 10 concurrent projects).

    API functions are serialised into the parallel scope via $using: references.
    Console output is buffered per project and flushed atomically on completion
    to prevent interleaved output from concurrent workers.

    Thread-safe telemetry is maintained via System.Threading.Interlocked counters
    on a shared ConcurrentDictionary, aggregated into the final JSON report.

    ── PARALLELISM AND ADO API SUPPORT ─────────────────────────────────────────
    The following ADO REST APIs used by this script are stateless GET endpoints
    that fully support concurrent clients under the same PAT:

      • GET /_apis/projects                   (project enumeration — sequential)
      • GET /graph/descriptors/{id}           (scope descriptor lookup)
      • GET /graph/groups                     (group listing)
      • GET /graph/memberships/{descriptor}   (membership resolution)
      • GET /graph/subjects/{descriptor}      (subject display name resolution)
      • GET /graph/storagekeys/{descriptor}   (ACL SID resolution)
      • GET /accesscontrollists/{nsId}        (permission ACE retrieval)

    Project enumeration is performed sequentially before the parallel phase to
    avoid a burst of concurrent pagination calls to a single paginated endpoint.
    All per-project calls (scope → groups → role match → ACE → membership) are
    parallelised across the project set.

    ── RATE-LIMIT HANDLING ──────────────────────────────────────────────────────
    Each runspace independently manages throttling:

      Layer 1 — Proactive inter-call delay  (-ThrottleDelay, default 100 ms)
        Applied between every API call within a single runspace. Note: with
        N parallel workers the effective call rate is N × (1000/ThrottleDelay)
        calls/sec. Increase this if you see 429s under parallel load.

      Layer 2 — Reactive 429 back-off
        On HTTP 429 the Retry-After header is read and honoured. The runspace
        sleeps for (Retry-After + RetryJitter) seconds then retries. If no
        header is present, exponential back-off is used: min(2^attempt, MaxBackoffSeconds).
        HTTP 503/504 transient errors use the same exponential scheme.

      Layer 3 — Hard failure after MaxRetries
        All retry attempts exhausted → the call returns $null. The failure is
        recorded in the project's audit result; the runspace continues normally.

    Because ADO's per-organisation rate limit is shared across all parallel
    workers, a 429 received by any one runspace may indicate that another worker
    also needs to back off. The Retry-After value from the server accounts for
    this: all workers that receive a 429 simultaneously will respect it.

.PARAMETER Organization
    Azure DevOps organization name (e.g. "myorg" from https://dev.azure.com/myorg).

.PARAMETER ProjectName
    One or more project names to audit.  Accepts wildcards (e.g. "Team-*").
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

.PARAMETER ParallelThrottle
    Maximum number of projects to audit concurrently.
    Default: 10.  Reduce if you hit sustained 429 throttling; increase on
    tenants with many projects and a generous rate-limit budget.

.PARAMETER ThrottleDelay
    Milliseconds to sleep between every API call within a single runspace.
    Default: 100.  Effective org-wide call rate ≈ ParallelThrottle × (1000/ThrottleDelay).

.PARAMETER RetryJitter
    Extra seconds added on top of the server-supplied Retry-After value before
    retrying a 429 response.  Default: 2.

.PARAMETER MaxRetries
    Maximum retry attempts per API call before a hard failure is recorded.
    Default: 5.

.PARAMETER MaxBackoffSeconds
    Upper ceiling (seconds) for exponential back-off when no Retry-After header
    is present.  Default: 120.

.EXAMPLE
    $pat = Read-Host -AsSecureString "Enter PAT"

    .\Verify-ADOProjectPermissions.ps1 `
        -Organization    "contoso" `
        -RoleName        "Project Administrators" `
        -BaselineFile    ".\baseline-permissions.json" `
        -ExpectedMembers "Corp\ADO-Admins, Corp\DevOps-Leads" `
        -Pat             $pat

.EXAMPLE
    # Large tenant — 20 parallel workers, conservative per-worker throttle
    $pat = Read-Host -AsSecureString "Enter PAT"

    .\Verify-ADOProjectPermissions.ps1 `
        -Organization    "contoso" `
        -RoleName        "Project Administrators" `
        -BaselineFile    ".\baseline-permissions.json" `
        -ExpectedMembers "Corp\ADO-Admins, Corp\DevOps-Leads" `
        -Pat             $pat `
        -ParallelThrottle 20 `
        -ThrottleDelay    250 `
        -MaxRetries       8

.EXAMPLE
    # Single project — parallel overhead not needed, workers = 1
    $pat = Read-Host -AsSecureString "Enter PAT"

    .\Verify-ADOProjectPermissions.ps1 `
        -Organization    "contoso" `
        -ProjectName     "MyProject" `
        -RoleName        "Contributors" `
        -BaselineFile    ".\baseline-contributors.json" `
        -ExpectedMembers "Corp\Dev-Team" `
        -Pat             $pat `
        -ParallelThrottle 1

.NOTES
    Author   : Lead DevOps Engineer
    Version  : 3.0.0
    Requires : PowerShell 7.0+  |  No external modules  |  Invoke-WebRequest only
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

    # ── Parallelism ───────────────────────────────────────────────────────────
    [Parameter(HelpMessage = "Max concurrent project audits. Default: 10.")]
    [ValidateRange(1, 50)]
    [int] $ParallelThrottle = 10,

    # ── Rate-limit / throttle ─────────────────────────────────────────────────
    [Parameter(HelpMessage = "ms to sleep between every API call per runspace. Default: 100.")]
    [ValidateRange(0, 60000)]
    [int] $ThrottleDelay = 100,

    [Parameter(HelpMessage = "Extra seconds added to Retry-After on HTTP 429. Default: 2.")]
    [ValidateRange(0, 300)]
    [int] $RetryJitter = 2,

    [Parameter(HelpMessage = "Max retries per API call before hard failure. Default: 5.")]
    [ValidateRange(1, 20)]
    [int] $MaxRetries = 5,

    [Parameter(HelpMessage = "Ceiling (s) for exponential back-off when no Retry-After header. Default: 120.")]
    [ValidateRange(5, 600)]
    [int] $MaxBackoffSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ════════════════════════════════════════════════════════════════════════
#  SECTION 1 ─ Thread-safe telemetry
#
#  ForEach-Object -Parallel runs each project in an isolated runspace.
#  Ordinary $script: variables are NOT shared across runspaces.
#  We use a ConcurrentDictionary passed via $using: and
#  System.Threading.Interlocked for atomic increments.
#endregion

$sharedStats = [System.Collections.Concurrent.ConcurrentDictionary[string,long]]::new()
foreach ($key in @('TotalApiCalls','RateLimitHits','TotalRetries','TotalThrottleMs')) {
    $sharedStats[$key] = 0L
}

# Helper: atomic increment on the shared stats bag (called from within runspaces)
# Usage: Add-Stat -Bag $using:sharedStats -Key 'TotalApiCalls' -Value 1
$fnAddStat = {
    param(
        [System.Collections.Concurrent.ConcurrentDictionary[string,long]] $Bag,
        [string] $Key,
        [long]   $Value = 1L
    )
    [System.Threading.Interlocked]::Add(
        [ref] ($Bag.GetOrAdd($Key, 0L)),
        $Value
    ) | Out-Null
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 2 ─ Console helpers (main thread only)
#endregion

function Write-Section ([string]$Title) {
    Write-Host "`n$('─' * 72)" -ForegroundColor DarkGray
    Write-Host "  $Title"      -ForegroundColor Cyan
    Write-Host "$('─' * 72)"   -ForegroundColor DarkGray
}
function Write-Pass ([string]$Msg) { Write-Host "  ✔  $Msg" -ForegroundColor Green  }
function Write-Fail ([string]$Msg) { Write-Host "  ✖  $Msg" -ForegroundColor Red    }
function Write-Info ([string]$Msg) { Write-Host "  ℹ  $Msg" -ForegroundColor Yellow }
function Write-Warn ([string]$Msg) { Write-Host "  ⚠  $Msg" -ForegroundColor Magenta }


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 3 ─ PAT helpers
#endregion

function ConvertTo-PlainText {
    param([System.Security.SecureString]$Secure)
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
}

function New-AuthHeader {
    param([System.Security.SecureString]$SecurePat)
    $plain = ConvertTo-PlainText $SecurePat
    $b64   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$plain"))
    $plain = $null
    return @{ Authorization = "Basic $b64" }
}

# Derive the plain-text Authorization header value once in the main thread.
# The header string (not the SecureString) is passed into runspaces via $using:.
# This avoids passing the SecureString across runspace boundaries, which is
# not supported, and avoids reconstructing it per worker.
$authHeaderValue = (New-AuthHeader $Pat)['Authorization']


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 4 ─ API engine scriptblock
#
#  Defined as a scriptblock so it can be dot-sourced inside the parallel block
#  via  . $using:fnInvokeAdoApi  and then called normally.
#
#  Each runspace has its own copy; state (attempt counter, sleep) is local.
#  Telemetry is written back to the shared ConcurrentDictionary atomically.
#
#  Parameters available from the enclosing parallel scope via $using::
#    $using:ThrottleDelay, $using:RetryJitter,
#    $using:MaxRetries,    $using:MaxBackoffSeconds,
#    $using:sharedStats,   $using:fnAddStat
#endregion

$fnInvokeAdoApi = {
    param(
        [string]    $Uri,
        [hashtable] $Headers,
        [string]    $Description = ""
    )

    & $using:fnAddStat -Bag $using:sharedStats -Key 'TotalApiCalls' -Value 1

    if ($using:ThrottleDelay -gt 0) {
        Start-Sleep -Milliseconds $using:ThrottleDelay
    }

    $attempt = 0

    while ($attempt -le $using:MaxRetries) {
        try {
            $wr = Invoke-WebRequest `
                    -Uri         $Uri `
                    -Headers     $Headers `
                    -Method      Get `
                    -ContentType "application/json" `
                    -ErrorAction Stop

            return ($wr.Content | ConvertFrom-Json)
        }
        catch [System.Net.WebException] {
            $httpResp   = $_.Exception.Response
            $statusCode = [int]($httpResp?.StatusCode ?? 0)

            if ($statusCode -eq 429) {
                & $using:fnAddStat -Bag $using:sharedStats -Key 'RateLimitHits'  -Value 1
                & $using:fnAddStat -Bag $using:sharedStats -Key 'TotalRetries'   -Value 1
                $attempt++

                if ($attempt -gt $using:MaxRetries) {
                    $script:_workerLog += "  ↺  429 — max retries exhausted [$Description]`n"
                    return $null
                }

                $raHeader = $httpResp.Headers["Retry-After"]
                $raParsed = 0
                if ($raHeader -and [int]::TryParse($raHeader.Trim(), [ref]$raParsed)) {
                    $waitSec = $raParsed + $using:RetryJitter
                    $script:_workerLog += "  ↺  HTTP 429 — Retry-After ${raParsed}s +$($using:RetryJitter)s jitter = ${waitSec}s  [attempt $attempt/$($using:MaxRetries)]  [$Description]`n"
                } else {
                    $waitSec = [Math]::Min([Math]::Pow(2, $attempt), $using:MaxBackoffSeconds)
                    $script:_workerLog += "  ↺  HTTP 429 — exponential back-off ${waitSec}s  [attempt $attempt/$($using:MaxRetries)]  [$Description]`n"
                }

                & $using:fnAddStat -Bag $using:sharedStats -Key 'TotalThrottleMs' -Value ([long]($waitSec * 1000))
                Start-Sleep -Seconds $waitSec
                continue
            }

            if ($statusCode -in @(503, 504)) {
                & $using:fnAddStat -Bag $using:sharedStats -Key 'TotalRetries' -Value 1
                $attempt++

                if ($attempt -gt $using:MaxRetries) {
                    $script:_workerLog += "  ↺  HTTP $statusCode — max retries exhausted [$Description]`n"
                    return $null
                }

                $waitSec = [Math]::Min([Math]::Pow(2, $attempt), $using:MaxBackoffSeconds)
                $script:_workerLog += "  ↺  HTTP $statusCode — back-off ${waitSec}s  [attempt $attempt/$($using:MaxRetries)]  [$Description]`n"
                & $using:fnAddStat -Bag $using:sharedStats -Key 'TotalThrottleMs' -Value ([long]($waitSec * 1000))
                Start-Sleep -Seconds $waitSec
                continue
            }

            $script:_workerLog += "  ✖  HTTP $statusCode for: $Uri  [$Description]`n"
            return $null
        }
        catch {
            & $using:fnAddStat -Bag $using:sharedStats -Key 'TotalRetries' -Value 1
            $attempt++

            if ($attempt -gt $using:MaxRetries) {
                $script:_workerLog += "  ✖  Non-HTTP error (retries exhausted) [$Description]: $_`n"
                return $null
            }

            $waitSec = [Math]::Min([Math]::Pow(2, $attempt), $using:MaxBackoffSeconds)
            $script:_workerLog += "  ↺  Non-HTTP error — back-off ${waitSec}s  [attempt $attempt/$($using:MaxRetries)]  [$Description]`n"
            & $using:fnAddStat -Bag $using:sharedStats -Key 'TotalThrottleMs' -Value ([long]($waitSec * 1000))
            Start-Sleep -Seconds $waitSec
        }
    }

    return $null
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 5 ─ ADO API scriptblocks
#
#  Each ADO call is wrapped in a scriptblock stored in a variable.
#  Inside the parallel block these are dot-sourced then called normally.
#  All scriptblocks accept $Headers as a parameter — constructed once per
#  runspace from $using:authHeaderValue.
#endregion

$fnGetProjectScopeDescriptor = {
    param([string]$Org, [string]$ProjectId, [hashtable]$Headers)
    $uri  = "https://vssps.dev.azure.com/$Org/_apis/graph/descriptors/$ProjectId`?api-version=7.1-preview.1"
    $resp = & $using:fnInvokeAdoApi -Uri $uri -Headers $Headers -Description "Scope [$ProjectId]"
    return $resp?.value
}

$fnGetProjectSecurityGroups = {
    param([string]$Org, [string]$ScopeDescriptor, [hashtable]$Headers)
    $groups       = [System.Collections.Generic.List[object]]::new()
    $continuation = $null
    do {
        $uri = "https://vssps.dev.azure.com/$Org/_apis/graph/groups" +
               "?scopeDescriptor=$ScopeDescriptor&api-version=7.1-preview.1"
        if ($continuation) { $uri += "&continuationToken=$continuation" }
        $resp = & $using:fnInvokeAdoApi -Uri $uri -Headers $Headers -Description "Groups [$ScopeDescriptor]"
        if ($null -eq $resp) { break }
        if ($resp.value)     { $groups.AddRange($resp.value) }
        $continuation = $resp.continuationToken
    } while ($continuation)
    return $groups
}

$fnGetGroupMembers = {
    param([string]$Org, [string]$GroupDescriptor, [hashtable]$Headers)
    $uri  = "https://vssps.dev.azure.com/$Org/_apis/graph/memberships/$GroupDescriptor" +
            "?direction=down&api-version=7.1-preview.1"
    $resp = & $using:fnInvokeAdoApi -Uri $uri -Headers $Headers -Description "Members [$GroupDescriptor]"
    return $resp?.value
}

$fnResolveSubjectDisplayName = {
    param([string]$Org, [string]$SubjectDescriptor, [hashtable]$Headers)
    $uri  = "https://vssps.dev.azure.com/$Org/_apis/graph/subjects/$SubjectDescriptor" +
            "?api-version=7.1-preview.1"
    $resp = & $using:fnInvokeAdoApi -Uri $uri -Headers $Headers -Description "Resolve [$SubjectDescriptor]"
    if ($resp) { return ($resp.principalName ?? $resp.mailAddress ?? $resp.displayName ?? $SubjectDescriptor) }
    return $SubjectDescriptor
}

$fnGetProjectPermissionAce = {
    param([string]$Org, [string]$ProjectId, [string]$GroupDescriptor, [hashtable]$Headers)

    $keyUri  = "https://vssps.dev.azure.com/$Org/_apis/graph/storagekeys/$GroupDescriptor" +
               "?api-version=7.1-preview.1"
    $keyResp = & $using:fnInvokeAdoApi -Uri $keyUri -Headers $Headers -Description "StorageKey [$GroupDescriptor]"
    if ($null -eq $keyResp) { return $null }
    $sid = $keyResp.value

    $nsId   = "52d39943-cb85-4d7f-8fa8-c6baac873819"
    $token  = "`$PROJECT:vstfs:///Classification/TeamProject/$ProjectId"
    $aclUri = "https://dev.azure.com/$Org/_apis/accesscontrollists/$nsId" +
              "?token=$([Uri]::EscapeDataString($token))" +
              "&descriptors=$([Uri]::EscapeDataString($sid))" +
              "&includeExtendedInfo=true&api-version=7.1"

    $aclResp = & $using:fnInvokeAdoApi -Uri $aclUri -Headers $Headers -Description "ACL [$ProjectId]"
    if ($null -eq $aclResp -or $aclResp.count -eq 0) { return $null }

    $ace = $aclResp.value[0].acesDictionary.PSObject.Properties |
               Where-Object { $_.Name -eq $sid } |
               Select-Object -First 1
    return $ace?.Value
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 6 ─ Permission comparison (pure function — no API calls)
#
#  Serialised as a scriptblock so it is available inside runspaces.
#endregion

$permBitsMap = @{
    GenericRead                  = 1
    GenericWrite                 = 2
    Delete                       = 4
    PublishTestResults           = 8
    ReadTestResults              = 16
    UpdateBuildInformation       = 32
    EditBuildStatus              = 64
    UpdateBuild                  = 128
    DeleteTestResults            = 256
    ViewBuilds                   = 512
    ManageBuildQueue             = 1024
    ManageBuildDefinitions       = 2048
    DestroyBuilds                = 4096
    AdministrateBuildPermissions = 8192
    ManageBuildQualityChecks     = 16384
}

$fnComparePermissions = {
    param([psobject]$Baseline, [psobject]$Actual)

    $drift = [System.Collections.Generic.List[object]]::new()

    if ($null -eq $Actual) {
        $drift.Add([pscustomobject]@{
            Permission = "ACE"
            Expected   = "allow=$($Baseline.allow ?? 'n/a')  deny=$($Baseline.deny ?? 'n/a')"
            Actual     = "No ACE found for this group in the project security namespace"
        })
        return $drift
    }

    if ($null -ne $Baseline.allow -and $Actual.allow -ne [int]$Baseline.allow) {
        $drift.Add([pscustomobject]@{ Permission = "allow (bitmask)"; Expected = $Baseline.allow; Actual = $Actual.allow })
    }
    if ($null -ne $Baseline.deny -and $Actual.deny -ne [int]$Baseline.deny) {
        $drift.Add([pscustomobject]@{ Permission = "deny (bitmask)";  Expected = $Baseline.deny;  Actual = $Actual.deny  })
    }

    if ($Baseline.PSObject.Properties.Name -contains "permissions") {
        foreach ($permName in $Baseline.permissions.PSObject.Properties.Name) {
            $expectedGrant = [bool]$Baseline.permissions.$permName
            $bit = $using:permBitsMap[$permName]

            if ($null -eq $bit) {
                $drift.Add([pscustomobject]@{
                    Permission = $permName
                    Expected   = "defined in baseline"
                    Actual     = "Bit name not in built-in map — verify namespace"
                })
                continue
            }

            $actualGrant = ($Actual.allow -band $bit) -ne 0
            if ($actualGrant -ne $expectedGrant) {
                $drift.Add([pscustomobject]@{ Permission = $permName; Expected = $expectedGrant; Actual = $actualGrant })
            }
        }
    }

    return $drift
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 7 ─ Sequential project enumeration
#endregion

$scriptStart = Get-Date

Write-Section "Azure DevOps Permissions Audit  v3.0"
Write-Host "  Organization      : $Organization"
Write-Host "  Role target       : $RoleName"
Write-Host "  Baseline file     : $BaselineFile"
Write-Host "  Started           : $($scriptStart.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host ""
Write-Host "  Concurrency / throttle settings:" -ForegroundColor DarkGray
Write-Host "    -ParallelThrottle   : $ParallelThrottle concurrent projects"              -ForegroundColor DarkGray
Write-Host "    -ThrottleDelay      : ${ThrottleDelay} ms  (per-runspace, proactive)"    -ForegroundColor DarkGray
Write-Host "    -RetryJitter        : +${RetryJitter} s   (added to Retry-After)"        -ForegroundColor DarkGray
Write-Host "    -MaxRetries         : $MaxRetries"                                        -ForegroundColor DarkGray
Write-Host "    -MaxBackoffSeconds  : ${MaxBackoffSeconds} s"                             -ForegroundColor DarkGray

# Build header once — the plain string is safe to pass into runspaces
$mainHeaders  = @{ Authorization = $authHeaderValue }
$baseline     = Get-Content $BaselineFile -Raw | ConvertFrom-Json
$expectedList = $ExpectedMembers -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

Write-Verbose "Expected members ($($expectedList.Count)): $($expectedList -join ' | ')"

# ── Sequential project list fetch (single paginated endpoint) ─────────────────
Write-Section "Fetching Project List  (sequential)"

$allProjects  = [System.Collections.Generic.List[object]]::new()
$skip = 0; $top = 200
do {
    $uri  = "https://dev.azure.com/$Organization/_apis/projects?`$top=$top&`$skip=$skip&api-version=7.1"
    if ($ThrottleDelay -gt 0) { Start-Sleep -Milliseconds $ThrottleDelay }
    $page = Invoke-WebRequest -Uri $uri -Headers $mainHeaders -Method Get -ContentType "application/json" -ErrorAction Stop |
                Select-Object -ExpandProperty Content | ConvertFrom-Json
    if ($null -eq $page -or $page.count -eq 0) { break }
    $allProjects.AddRange($page.value)
    $skip += $top
} while ($page.count -eq $top)

if ($allProjects.Count -eq 0) {
    Write-Fail "No projects returned. Verify your PAT has 'vso.project' read scope."
    exit 1
}

# Filter by name/wildcard
if ($ProjectName -and $ProjectName.Count -gt 0) {
    $filtered = @($allProjects | Where-Object {
        $p = $_; $ProjectName | Where-Object { $p.name -like $_ }
    })
    if ($filtered.Count -eq 0) {
        Write-Warn "No projects matched filter(s): $($ProjectName -join ', ')"
        exit 0
    }
} else {
    $filtered = @($allProjects)
}

Write-Info "Projects to audit : $($filtered.Count) of $($allProjects.Count) total"
Write-Info "Parallel workers  : $([Math]::Min($ParallelThrottle, $filtered.Count)) (capped to project count)"


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 8 ─ Parallel audit
#
#  ForEach-Object -Parallel spins up to -ThrottleLimit runspaces.
#  Each runspace:
#    1. Reconstructs its local auth header from $using:authHeaderValue.
#    2. Dot-sources the API scriptblocks from $using: references.
#    3. Runs the full A→F audit pipeline for its assigned project.
#    4. Accumulates console output in $script:_workerLog (runspace-local).
#    5. Returns a hashtable  { Result: <audit obj>; Log: <string> }
#       back to the pipeline on the main thread.
#
#  The main thread receives results as they complete, flushes each project's
#  buffered log to the console, then accumulates into $auditResults.
#endregion

Write-Section "Parallel Audit  (workers = $([Math]::Min($ParallelThrottle, $filtered.Count)))"

$parallelResults = $filtered | ForEach-Object -ThrottleLimit $ParallelThrottle -Parallel {

    # ── Runspace-local log buffer ─────────────────────────────────────────────
    # Write-Host inside -Parallel goes to the host immediately but interleaves.
    # We buffer all output and return it so the main thread can print it atomically.
    $script:_workerLog = ""

    # ── Reconstruct auth header in this runspace ──────────────────────────────
    $localHeaders = @{ Authorization = $using:authHeaderValue }

    # ── Pull shared references into runspace-local variables ─────────────────
    $org           = $using:Organization
    $roleName      = $using:RoleName
    $expectedList  = $using:expectedList
    $baseline      = $using:baseline

    # ── Helper: append to the runspace log ───────────────────────────────────
    function Log  ([string]$Msg)                  { $script:_workerLog += "$Msg`n" }
    function LogPass ([string]$Msg)               { Log "  ✔  $Msg" }
    function LogFail ([string]$Msg)               { Log "  ✖  $Msg" }

    # ── Build the audit result object for this project ────────────────────────
    $project = $_
    $result  = [pscustomobject]@{
        ProjectName      = $project.name
        Timestamp        = (Get-Date -Format "o")
        RoleFound        = $false
        PermissionsMatch = $false
        MembersMatch     = $false
        PermissionDrift  = [System.Collections.Generic.List[object]]::new()
        ExtraMembers     = [System.Collections.Generic.List[string]]::new()
        MissingMembers   = [System.Collections.Generic.List[string]]::new()
        ActualMembers    = [System.Collections.Generic.List[string]]::new()
        ExpectedMembers  = $expectedList
        Errors           = [System.Collections.Generic.List[string]]::new()
        Compliant        = $false
    }

    try {
        # A ── Scope descriptor ────────────────────────────────────────────────
        $scope = & $using:fnGetProjectScopeDescriptor `
                        -Org $org -ProjectId $project.id -Headers $localHeaders
        if (-not $scope) {
            $m = "Failed to retrieve scope descriptor"
            LogFail $m; $result.Errors.Add($m)
            return @{ Result = $result; Log = $script:_workerLog }
        }

        # B ── Security groups ─────────────────────────────────────────────────
        $groups = & $using:fnGetProjectSecurityGroups `
                        -Org $org -ScopeDescriptor $scope -Headers $localHeaders
        if (-not $groups -or $groups.Count -eq 0) {
            $m = "Failed to retrieve security groups"
            LogFail $m; $result.Errors.Add($m)
            return @{ Result = $result; Log = $script:_workerLog }
        }

        # C ── Locate target role ──────────────────────────────────────────────
        $targetGroup = $groups | Where-Object {
            $_.displayName   -eq $roleName       -or
            $_.principalName -like "*\$roleName" -or
            $_.principalName -like "*/$roleName"
        } | Select-Object -First 1

        if ($null -eq $targetGroup) {
            LogFail "Role '$roleName' NOT FOUND"
            $result.Errors.Add("Role '$roleName' not found")
            return @{ Result = $result; Log = $script:_workerLog }
        }

        $roleLabel = $targetGroup.principalName ?? $targetGroup.displayName
        LogPass "Role found  →  $roleLabel"
        $result.RoleFound = $true

        # D ── Permissions and membership can be fetched concurrently.
        #      Within a single project runspace we use PowerShell jobs for
        #      the two independent calls: storagekey+ACL and memberships.
        #      This eliminates intra-project sequential wait on two I/O calls
        #      that have no data dependency on each other.

        $descriptor = $targetGroup.descriptor

        # Launch ACE retrieval as a background job
        $aceJob = Start-Job -ScriptBlock {
            param($fnGetAce, $fnInvoke, $fnAddStat, $sharedStats,
                  $org, $projectId, $descriptor, $localHeaders,
                  $throttleDelay, $retryJitter, $maxRetries, $maxBackoffSec, $permBitsMap)

            # Re-expose $using: bindings inside the job via plain params
            $using_fnInvokeAdoApi  = $fnInvoke
            $using_fnAddStat       = $fnAddStat
            $using_sharedStats     = $sharedStats
            $using_ThrottleDelay   = $throttleDelay
            $using_RetryJitter     = $retryJitter
            $using_MaxRetries      = $maxRetries
            $using_MaxBackoffSeconds = $maxBackoffSec
            $using_permBitsMap     = $permBitsMap
            $script:_workerLog     = ""

            & $fnGetAce -Org $org -ProjectId $projectId `
                        -GroupDescriptor $descriptor -Headers $localHeaders
        } -ArgumentList @(
            $using:fnGetProjectPermissionAce,
            $using:fnInvokeAdoApi,
            $using:fnAddStat,
            $using:sharedStats,
            $org, $project.id, $descriptor, $localHeaders,
            $using:ThrottleDelay, $using:RetryJitter,
            $using:MaxRetries, $using:MaxBackoffSeconds,
            $using:permBitsMap
        )

        # Launch membership retrieval as a background job
        $memberJob = Start-Job -ScriptBlock {
            param($fnGetMembers, $fnResolve, $fnInvoke, $fnAddStat, $sharedStats,
                  $org, $descriptor, $localHeaders,
                  $throttleDelay, $retryJitter, $maxRetries, $maxBackoffSec)

            $using_fnInvokeAdoApi    = $fnInvoke
            $using_fnAddStat         = $fnAddStat
            $using_sharedStats       = $sharedStats
            $using_ThrottleDelay     = $throttleDelay
            $using_RetryJitter       = $retryJitter
            $using_MaxRetries        = $maxRetries
            $using_MaxBackoffSeconds = $maxBackoffSec
            $script:_workerLog       = ""

            $memberships = & $fnGetMembers -Org $org -GroupDescriptor $descriptor -Headers $localHeaders
            $names = [System.Collections.Generic.List[string]]::new()
            if ($memberships) {
                foreach ($m in $memberships) {
                    $n = & $fnResolve -Org $org -SubjectDescriptor $m.memberDescriptor -Headers $localHeaders
                    $names.Add($n)
                }
            }
            return $names
        } -ArgumentList @(
            $using:fnGetGroupMembers,
            $using:fnResolveSubjectDisplayName,
            $using:fnInvokeAdoApi,
            $using:fnAddStat,
            $using:sharedStats,
            $org, $descriptor, $localHeaders,
            $using:ThrottleDelay, $using:RetryJitter,
            $using:MaxRetries, $using:MaxBackoffSeconds
        )

        # Wait for both jobs to finish, then collect results
        $null = Wait-Job -Job @($aceJob, $memberJob)
        $ace         = Receive-Job -Job $aceJob    -ErrorAction SilentlyContinue
        $memberNames = Receive-Job -Job $memberJob -ErrorAction SilentlyContinue
        Remove-Job -Job @($aceJob, $memberJob) -Force

        # E ── Permission comparison ───────────────────────────────────────────
        $drift = & $using:fnComparePermissions -Baseline $baseline -Actual $ace
        $result.PermissionDrift.AddRange($drift)

        if ($drift.Count -eq 0) {
            LogPass "Permissions match the baseline"
            $result.PermissionsMatch = $true
        } else {
            LogFail "Permission drift — $($drift.Count) discrepancy(ies):"
            foreach ($d in $drift) {
                Log "      ┌ $($d.Permission)"
                Log "      │ Expected : $($d.Expected)"
                Log "      └ Actual   : $($d.Actual)"
            }
            $result.PermissionsMatch = $false
        }

        # F ── Membership diff ─────────────────────────────────────────────────
        if ($memberNames) { $result.ActualMembers.AddRange($memberNames) }

        $extra   = @($result.ActualMembers | Where-Object { $_ -notin $expectedList })
        $missing = @($expectedList         | Where-Object { $_ -notin $result.ActualMembers })

        if ($extra.Count   -gt 0) { $result.ExtraMembers.AddRange($extra)    }
        if ($missing.Count -gt 0) { $result.MissingMembers.AddRange($missing) }

        if ($extra.Count -eq 0 -and $missing.Count -eq 0) {
            LogPass "Membership matches  ($($result.ActualMembers.Count) member(s))"
            $result.MembersMatch = $true
        } else {
            LogFail "Membership drift:"
            if ($extra.Count -gt 0) {
                Log "      Unexpected members (in role, NOT in expected list):"
                $extra   | ForEach-Object { Log "        ✖ $_" }
            }
            if ($missing.Count -gt 0) {
                Log "      Missing members (in expected list, NOT in role):"
                $missing | ForEach-Object { Log "        ✖ $_" }
            }
            $result.MembersMatch = $false
        }
    }
    catch {
        $m = "Unhandled exception: $_"
        Log "  ⚠  $m"
        $result.Errors.Add($m)
    }

    $result.Compliant = (
        $result.RoleFound        -and
        $result.PermissionsMatch -and
        $result.MembersMatch     -and
        $result.Errors.Count -eq 0
    )

    return @{ Result = $result; Log = $script:_workerLog }
}   # end ForEach-Object -Parallel


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 9 ─ Collect results & flush buffered console output
#endregion

$auditResults     = [System.Collections.Generic.List[psobject]]::new()
$overallCompliant = $true

foreach ($item in $parallelResults) {
    $r = $item.Result

    # Print the project's buffered log atomically
    Write-Host "`n$('─' * 72)" -ForegroundColor DarkGray
    Write-Host "  $($r.ProjectName)" -ForegroundColor Cyan
    Write-Host "$('─' * 72)" -ForegroundColor DarkGray

    if ($item.Log) { Write-Host $item.Log.TrimEnd() }

    if (-not $r.Compliant) { $overallCompliant = $false }
    $auditResults.Add($r)
}


#region ════════════════════════════════════════════════════════════════════════
#  SECTION 10 ─ Summary & JSON report
#endregion

$scriptEnd     = Get-Date
$elapsedSec    = [Math]::Round(($scriptEnd - $scriptStart).TotalSeconds, 1)
$compliantCnt  = ($auditResults | Where-Object {  $_.Compliant }).Count
$nonComplCnt   = ($auditResults | Where-Object { -not $_.Compliant }).Count

Write-Section "Audit Summary"
Write-Host "  Projects audited  : $($auditResults.Count)"
Write-Host "  Compliant         : $compliantCnt"  -ForegroundColor $(if ($compliantCnt -gt 0) { "Green"  } else { "White" })
Write-Host "  Non-compliant     : $nonComplCnt"   -ForegroundColor $(if ($nonComplCnt  -gt 0) { "Red"    } else { "Green" })
Write-Host "  Elapsed           : ${elapsedSec}s  (parallel, $([Math]::Min($ParallelThrottle, $filtered.Count)) workers)"
Write-Host ""
Write-Host "  API telemetry:" -ForegroundColor DarkGray
Write-Host "    Total calls      : $($sharedStats['TotalApiCalls'])"                                                                             -ForegroundColor DarkGray
Write-Host "    Rate-limit hits  : $($sharedStats['RateLimitHits'])"  -ForegroundColor $(if ($sharedStats['RateLimitHits'] -gt 0) { "Magenta" } else { "DarkGray" })
Write-Host "    Total retries    : $($sharedStats['TotalRetries'])"   -ForegroundColor $(if ($sharedStats['TotalRetries']  -gt 0) { "Yellow"  } else { "DarkGray" })
Write-Host "    Reactive sleep   : $([Math]::Round($sharedStats['TotalThrottleMs']/1000,1))s  (across all workers)"                              -ForegroundColor DarkGray

if ($nonComplCnt -gt 0) {
    Write-Host ""
    Write-Host "  Non-compliant projects:" -ForegroundColor Red
    $auditResults | Where-Object { -not $_.Compliant } | ForEach-Object {
        $flags = @()
        if (-not $_.RoleFound)        { $flags += "RoleMissing"     }
        if (-not $_.PermissionsMatch) { $flags += "PermissionDrift" }
        if (-not $_.MembersMatch)     { $flags += "MemberDrift"     }
        if ($_.Errors.Count -gt 0)    { $flags += "Errors"          }
        Write-Host "    • $($_.ProjectName)  [$($flags -join ', ')]" -ForegroundColor Red
    }
}

if (-not $OutputPath) {
    $OutputPath = ".\ADO-Audit-$($scriptStart.ToString('yyyyMMdd-HHmmss')).json"
}

[pscustomobject]@{
    AuditStart        = $scriptStart.ToString("o")
    AuditEnd          = $scriptEnd.ToString("o")
    ElapsedSeconds    = $elapsedSec
    Organization      = $Organization
    RoleName          = $RoleName
    BaselineFile      = $BaselineFile
    ExpectedMembers   = $expectedList
    TotalProjects     = $auditResults.Count
    CompliantCount    = $compliantCnt
    NonCompliantCount = $nonComplCnt
    OverallCompliant  = $overallCompliant
    ParallelConfig    = [pscustomobject]@{
        ParallelThrottle = $ParallelThrottle
        ThrottleDelayMs  = $ThrottleDelay
        RetryJitterSec   = $RetryJitter
        MaxRetries       = $MaxRetries
        MaxBackoffSec    = $MaxBackoffSeconds
    }
    ApiTelemetry      = [pscustomobject]@{
        TotalApiCalls   = $sharedStats['TotalApiCalls']
        RateLimitHits   = $sharedStats['RateLimitHits']
        TotalRetries    = $sharedStats['TotalRetries']
        TotalThrottleMs = $sharedStats['TotalThrottleMs']
    }
    Results           = $auditResults
} | ConvertTo-Json -Depth 12 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "  Report → $OutputPath" -ForegroundColor Cyan

exit $(if ($overallCompliant) { 0 } else { 1 })
