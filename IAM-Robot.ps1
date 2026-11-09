#Requires -Version 5.1
<#
.SYNOPSIS
    IAM-Robot - AWS IAM Attack Surface Mapper
    Enumerates ALL AWS resources and extracts every IAM identity
    (role, user, policy, trust, resource-based policy) attached to them.

.DESCRIPTION
    Phases:
      1   Credential check + account identity
      2   Region discovery (or use -Regions param)
      3   Resource collection across 30+ service families
      4   IAM role enrichment (Steps 3+4 of audit manual: policies + trust)
      4b  Optional cross-reference with sibling IAM-Audit output folder
      4c  Per-role detail pages with capability analysis (Rhino/Prisma/Wiz/Crowdstrike/CIS)
      4d  Per-resource detail pages
      5   Main reports (dashboard, resources, identities, assume, findings)
      5b  Index/catalog/attack-path pages (roles, resources-detail, findings-catalog, attack-paths)

    *** READ-ONLY - zero write/modify/delete operations. ***

.PARAMETER OutputDir
    Where to write reports. Default: .\IAM-Robot-<timestamp>

.PARAMETER Profile
    AWS CLI named profile. Leave blank for default credential chain.

.PARAMETER Regions
    Comma-separated list of regions to scan.
    If omitted, all enabled regions are auto-discovered.
    Example: -Regions "us-east-1,eu-west-1"

.PARAMETER TimeoutSeconds
    Per-command timeout in seconds. Default: 30.
    Press [S] to skip any running command.

.PARAMETER SkipRegionDiscovery
    Skip auto-discovery and use -Regions (or us-east-1 fallback).

.EXAMPLE
    # All regions, default credentials
    .\IAM-Robot.ps1

.EXAMPLE
    # Two regions, named profile
    .\IAM-Robot.ps1 -Profile audit-ro -Regions "us-east-1,us-west-2"

.EXAMPLE
    # Quick single-region scan
    .\IAM-Robot.ps1 -Regions "us-east-1" -TimeoutSeconds 20
#>
[CmdletBinding()]
param(
    [string]  $OutputDir          = ".\IAM-Robot-$(Get-Date -Format 'yyyyMMdd-HHmm')",
    [string]  $Profile            = "",
    [string]  $Regions            = "",
    [int]     $TimeoutSeconds     = 30,
    [switch]  $SkipRegionDiscovery,
    [int]     $MaxRolesToEnrich   = 200,
    [switch]  $SkipEnrichment,
    [string]  $IAMAuditDir        = "",
    [switch]  $SkipIAMAuditImport,
    [switch]  $Resume,
    [string]  $ResumeFrom         = ""
)

function Stop-ScriptGracefully {
    param([string]$Reason = "Script ending")
    Write-Host ""
    Write-Host "  $Reason" -ForegroundColor Yellow
    # Only pause if running interactively in a host that auto-closes
    if ($Host.Name -eq 'ConsoleHost' -and -not $env:CI) {
        Write-Host ""
        Write-Host "  Press Enter to close this window..." -ForegroundColor DarkGray
        try { [void](Read-Host) } catch { }
    }
}

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

#  Auto-unblock module files (no-op on Linux/Mac, no-op if already unblocked) 
# Avoids the "file is not digitally signed" error when files arrive via download
try {
    Get-ChildItem -Path $PSScriptRoot -Recurse -File -Include *.ps1 -ErrorAction SilentlyContinue |
        Unblock-File -ErrorAction SilentlyContinue
} catch { }

#  AWS CLI check 
$awsVer = $null
try { $awsVer = (& cmd.exe /c "aws --version 2>&1") -join "" } catch {}
if (-not $awsVer -or $awsVer -notmatch 'aws-cli') {
    Write-Host ""
    Write-Host "  [ERROR] AWS CLI not found via cmd.exe." -ForegroundColor Red
    Write-Host "  Install AWS CLI v2: https://aws.amazon.com/cli/" -ForegroundColor Yellow
    return
}

#  Dot-source modules 
$moduleDir = Join-Path $PSScriptRoot "Modules"
foreach ($mod in @('IR-Utils','IR-Collect','IR-Enrich','IR-Import','IR-ActionCatalog','IR-ActionDescriptions','IR-CapabilityLibrary','IR-RolePages','IR-ResourcePages','IR-IndexPages','IR-Report')) {
    $p = Join-Path $moduleDir "$mod.ps1"
    if (-not (Test-Path $p)) {
        Write-Host "  [ERROR] Module not found: $p" -ForegroundColor Red
        return
    }
    try {
        . $p
        Write-Host "  Loaded: $mod.ps1" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [ERROR] Failed to load $mod.ps1: $_" -ForegroundColor Red
        return
    }
}

#  Banner 
Write-Host ""
Write-Host "  +================================================================+" -ForegroundColor Cyan
Write-Host "  |   ___    _    __  __         ____        _           _        |" -ForegroundColor Cyan
Write-Host "  |  |_ _|  / \  |  \/  |       |  _ \  ___ | |__   ___ | |_      |" -ForegroundColor Cyan
Write-Host "  |   | |  / _ \ | |\/| |  ___  | |_) |/ _ \| '_ \ / _ \| __|     |" -ForegroundColor Cyan
Write-Host "  |   | | / ___ \| |  | | |___| |  _ <| (_) | |_) | (_) | |_      |" -ForegroundColor Cyan
Write-Host "  |  |___/_/   \_\_|  |_|       |_| \_\\___/|_.__/ \___/ \__|     |" -ForegroundColor Cyan
Write-Host "  |                                                                |" -ForegroundColor Cyan
Write-Host "  |       AWS IAM Attack Surface Mapper (read-only)                |" -ForegroundColor Cyan
Write-Host "  +================================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  AWS CLI      : $awsVer" -ForegroundColor DarkGray
Write-Host "  Output Dir   : $OutputDir" -ForegroundColor DarkGray
Write-Host "  Profile      : $(if ($Profile) { $Profile } else { '(default)' })" -ForegroundColor DarkGray
Write-Host "  Regions      : $(if ($Regions) { $Regions } else { 'auto-discover' })" -ForegroundColor DarkGray
Write-Host "  Timeout      : ${TimeoutSeconds}s  [press S to skip any command]" -ForegroundColor DarkGray
Write-Host ""

#  Parse region list 
$regionList = @()
if ($Regions) {
    $regionList = $Regions -split '[,;\s]+' | Where-Object { $_ }
}

#  Initialize context 
Initialize-IRContext -OutputDir $OutputDir -Profile $Profile `
    -Regions $regionList -TimeoutSeconds $TimeoutSeconds

#  PHASE 1: Credential check 
Write-Host "  [PHASE 1] Credential & identity verification" -ForegroundColor Magenta
Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray

$idCheck = Invoke-IRAWSCLI -Arguments @('sts','get-caller-identity') -Description "STS identity" -TimeoutSec 20

if (-not $idCheck.Success) {
    $errLine = ($idCheck.Error -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join " | "
    Write-Host ""
    Write-Host "  [ERROR] Credential check failed: $errLine" -ForegroundColor Red

    # Look for a cached state file to fall back to
    $stateCandidates = @()
    if ($ResumeFrom) {
        $stateCandidates += $ResumeFrom
        $stateCandidates += (Join-Path $ResumeFrom '.ir-state.json')
    }
    if ($Resume) {
        # Find newest IAM-Robot-* output dir under current dir
        $found = Get-ChildItem -Path . -Directory -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like 'IAM-Robot-*' } |
                 Sort-Object LastWriteTime -Descending
        foreach ($d in $found) {
            $stateCandidates += (Join-Path $d.FullName '.ir-state.json')
        }
    }

    $loadedFromCache = $false
    foreach ($cand in $stateCandidates) {
        if (-not $cand) { continue }
        if (-not (Test-Path $cand)) { continue }
        Write-Host ""
        Write-Host "  [FALLBACK] Loading cached state from $cand" -ForegroundColor Yellow
        try {
            $cached = Get-Content $cand -Raw -Encoding UTF8 | ConvertFrom-Json
            # Restore key context fields
            $Global:IR.AccountId    = $cached.AccountId
            $Global:IR.AccountAlias = $cached.AccountAlias
            $Global:IR.OutputDir    = $cached.OutputDir
            if ($cached.Stats) {
                $Global:IR.Stats.RegionsScanned = @($cached.Stats.RegionsScanned)
                $Global:IR.Stats.ResourcesScanned = $cached.Stats.ResourcesScanned
                $Global:IR.Stats.AttachmentsFound = $cached.Stats.AttachmentsFound
            }
            if ($cached.Attachments) {
                foreach ($a in $cached.Attachments) { $Global:IR.Attachments.Add($a) }
            }
            if ($cached.RoleCatalog) {
                foreach ($p in $cached.RoleCatalog.PSObject.Properties) {
                    $Global:IR.RoleCatalog[$p.Name] = $p.Value
                }
            }
            $loadedFromCache = $true
            Write-Host "  Loaded $($Global:IR.Attachments.Count) attachments, $($Global:IR.RoleCatalog.Count) roles from cache." -ForegroundColor Green
            break
        } catch {
            Write-Host "  [WARN] Failed to load cache: $_" -ForegroundColor DarkYellow
        }
    }

    if (-not $loadedFromCache) {
        Write-Host ""
        Write-Host "  Set credentials in this PowerShell window:" -ForegroundColor Yellow
        Write-Host "    `$env:AWS_ACCESS_KEY_ID     = 'ASIA...'" -ForegroundColor Gray
        Write-Host "    `$env:AWS_SECRET_ACCESS_KEY = 'your-secret'" -ForegroundColor Gray
        Write-Host "    `$env:AWS_SESSION_TOKEN     = 'your-token'" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Or pass -Resume to reuse a previous run's cached state:" -ForegroundColor Yellow
        Write-Host "    .\IAM-Robot.ps1 -Resume" -ForegroundColor Gray
        Write-Host ""
        Stop-ScriptGracefully "AWS credentials unavailable and no cached state found."
        return
    }
    # We have cached state - skip Phase 1 and continue to report generation
    $Global:IR.UsedCache = $true
    Write-Host ""
    Write-Host "  [CACHE] Skipping Phases 1-4 (using cached state)" -ForegroundColor Cyan
    Write-Host ""
    # Jump straight to report generation
    Invoke-GenerateReports
    Invoke-GenerateIndexPages
    Stop-ScriptGracefully "Done (cached run)."
    return
}

$Global:IR.AccountId    = $idCheck.Output.Account
$Global:IR.AccountAlias = $idCheck.Output.Account  # updated below if available

$aliasR = Invoke-IRAWSCLI -Arguments @('iam','list-account-aliases') -Description "Account alias"
if ($aliasR.Success -and $aliasR.Output.AccountAliases -and $aliasR.Output.AccountAliases.Count -gt 0) {
    $Global:IR.AccountAlias = $aliasR.Output.AccountAliases[0]
}

Write-IRLog "Account: $($Global:IR.AccountId)  Alias: $($Global:IR.AccountAlias)" -Level SUCCESS
Write-IRLog "Caller:  $($idCheck.Output.Arn)" -Level INFO

#  PHASE 2: Region discovery 
Write-Host ""
Write-Host "  [PHASE 2] Region setup" -ForegroundColor Magenta
Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray

if ($regionList.Count -eq 0 -and -not $SkipRegionDiscovery) {
    $regionList = Get-EnabledRegions
} elseif ($regionList.Count -eq 0) {
    $regionList = @('us-east-1')
    Write-IRLog "Fallback: using us-east-1" -Level WARN
}

$Global:IR.Regions = $regionList
Write-IRLog "Scanning $($regionList.Count) region(s): $($regionList -join ', ')" -Level INFO

#  PHASE 3: Resource collection 
Write-Host ""
Write-Host "  [PHASE 3] Collecting resource IAM attachments" -ForegroundColor Magenta
Write-Host "  Press [S] to skip any individual command." -ForegroundColor DarkGray

Invoke-AllCollectors -Regions $regionList

Write-Host ""
Write-IRLog "=== Collection Summary ===" -Level SUCCESS
Write-IRLog "  Resources scanned:   $($Global:IR.Stats.ResourcesScanned)" -Level INFO
Write-IRLog "  Attachments found:   $($Global:IR.Stats.AttachmentsFound)" -Level INFO
Write-IRLog "  Services failed:     $($Global:IR.Stats.ServicesFailed.Count)" -Level INFO

$bySev = @{}
foreach ($lv in @('CRITICAL','HIGH','MEDIUM','LOW','INFO')) {
    $bySev[$lv] = ($Global:IR.Attachments | Where-Object { $_.RiskLevel -eq $lv }).Count
    if ($bySev[$lv] -gt 0) {
        $col = @{CRITICAL='Red';HIGH='Yellow';MEDIUM='Cyan';LOW='Green';INFO='DarkGray'}[$lv]
        Write-Host "    ${lv}: $($bySev[$lv])" -ForegroundColor $col
    }
}

#  PHASE 4: Role enrichment (Steps 3 + 4 of audit manual) 
if (-not $SkipEnrichment) {
    Invoke-RoleEnrichment -MaxRoles $MaxRolesToEnrich
} else {
    Write-Host ""
    Write-Host "  [PHASE 4] Enrichment SKIPPED (-SkipEnrichment)" -ForegroundColor Yellow
}

#  PHASE 4b: IAM-Audit cross-reference (best-effort) 
if (-not $SkipIAMAuditImport) {
    Write-Host ""
    Write-Host "  [PHASE 4b] IAM-Audit cross-reference" -ForegroundColor Magenta
    Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray
    Import-IAMAuditFindings -IAMAuditDir $IAMAuditDir
}

#  PHASE 4c: Per-role detail pages with capability analysis 
if (-not $SkipEnrichment) {
    Write-Host ""
    Write-Host "  [PHASE 4c] Generating per-role pages + capability analysis" -ForegroundColor Magenta
    Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray
    Invoke-GenerateRolePages
}

#  PHASE 4d: Per-resource detail pages 
Write-Host ""
Write-Host "  [PHASE 4d] Generating per-resource detail pages" -ForegroundColor Magenta
Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray
Invoke-GenerateResourcePages

#  Save state for -Resume runs 
try {
    $stateFile = Join-Path $Global:IR.OutputDir '.ir-state.json'
    $stateBlob = [PSCustomObject]@{
        AccountId    = $Global:IR.AccountId
        AccountAlias = $Global:IR.AccountAlias
        OutputDir    = $Global:IR.OutputDir
        SavedAt      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Stats        = $Global:IR.Stats
        Attachments  = $Global:IR.Attachments.ToArray()
        RoleCatalog  = $Global:IR.RoleCatalog
    }
    $stateBlob | ConvertTo-Json -Depth 20 -Compress |
        Out-File $stateFile -Encoding UTF8
    Write-IRLog "State cached to $stateFile" -Level INFO
} catch {
    Write-IRLog "State save failed: $_" -Level WARN
}

#  PHASE 5: Reports 
Invoke-GenerateReports

#  PHASE 5b: Index pages (Roles index, Resources detail index, Findings catalog, Attack paths) 
Write-Host ""
Write-Host "  [PHASE 5b] Generating index + catalog + attack-path pages" -ForegroundColor Magenta
Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray
Invoke-GenerateIndexPages

#  Final summary 
$duration = [math]::Round(((Get-Date) - $Global:IR.StartTime).TotalMinutes, 1)
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor DarkGray
Write-Host "  Completed in $duration minutes  |  $($Global:IR.CommandLog.Count) commands  |  $($Global:IR.Stats.AttachmentsFound) attachments found" -ForegroundColor Green
Write-Host "  ============================================================" -ForegroundColor DarkGray
Write-Host ""
Stop-ScriptGracefully "Audit complete."
