# Modules/IR-Utils.ps1
# ============================================================
#  Shared utilities for IAM-Robot:
#  - Context init
#  - Invoke-AWSCommand (temp-file, timeout, skip key)
#  - Structured logging (console + file)
#  - New-Attachment record builder
# ============================================================

function Initialize-IRContext {
    param(
        [string]$OutputDir,
        [string]$Profile       = "",
        [string[]]$Regions     = @(),
        [int]$TimeoutSeconds   = 30
    )
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    $Global:IR = @{
        Profile         = $Profile
        Regions         = $Regions
        TimeoutSeconds  = $TimeoutSeconds
        OutputDir       = $OutputDir
        AuditLogPath    = (Join-Path $OutputDir "audit.log")
        ErrorLogPath    = (Join-Path $OutputDir "errors.log")
        AccountId       = "Unknown"
        AccountAlias    = "Unknown"
        Attachments     = [System.Collections.Generic.List[object]]::new()
        CommandLog      = [System.Collections.Generic.List[object]]::new()
        RoleCatalog     = @{}
        Stats           = @{
            ResourcesScanned  = 0
            AttachmentsFound  = 0
            ServicesFailed    = [System.Collections.Generic.List[string]]::new()
            RegionsScanned    = [System.Collections.Generic.List[string]]::new()
        }
        StartTime       = Get-Date
    }
    "[$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))] IAM-Robot started. Profile='$Profile' Regions=$($Regions -join ',')" |
        Out-File $Global:IR.AuditLogPath -Encoding UTF8
    "[$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))] Error log initialized." |
        Out-File $Global:IR.ErrorLogPath -Encoding UTF8
}

#  Logging 
function Write-IRLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','DEBUG')][string]$Level = 'INFO'
    )
    $ts     = Get-Date -Format 'HH:mm:ss'
    $colors = @{ INFO='Cyan'; WARN='Yellow'; ERROR='Red'; SUCCESS='Green'; DEBUG='DarkGray' }
    $prefix = @{ INFO='[*]'; WARN='[!]'; ERROR='[X]'; SUCCESS='[+]'; DEBUG='[~]' }
    $line   = "  $ts $($prefix[$Level]) $Message"
    Write-Host $line -ForegroundColor $colors[$Level]
    try { "[$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))][$Level] $Message" | Out-File $Global:IR.AuditLogPath -Append -Encoding UTF8 } catch {}
}

function Write-IRError {
    param([string]$Service, [string]$Region, [string]$Message)
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][ERROR][$Region][$Service] $Message"
    try   { $line | Out-File $Global:IR.ErrorLogPath -Append -Encoding UTF8 } catch {}
}

function Write-ServiceHeader {
    param([string]$Service, [string]$Region)
    Write-Host "    [$Region] $Service..." -ForegroundColor DarkGray -NoNewline
}
function Write-ServiceResult {
    param([int]$Count)
    Write-Host " $Count attachment(s)" -ForegroundColor $(if ($Count -gt 0) { 'Green' } else { 'DarkGray' })
}

#  AWS Command Wrapper 
function Invoke-IRAWSCLI {
    param(
        [string[]]$Arguments,
        [string]$Description  = "",
        [string]$Region       = "",
        [int]$TimeoutSec      = -1,
        [switch]$NoAutoPaginate
    )
    if ($TimeoutSec -lt 0) { $TimeoutSec = $Global:IR.TimeoutSeconds }

    $fullArgs = [System.Collections.Generic.List[string]]::new()
    if ($Global:IR.Profile) { $fullArgs.AddRange([string[]]@('--profile', $Global:IR.Profile)) }
    if ($Region)            { $fullArgs.AddRange([string[]]@('--region', $Region)) }
    foreach ($a in $Arguments) { $fullArgs.Add($a) }
    if (-not ($fullArgs -contains '--output')) { $fullArgs.AddRange([string[]]@('--output','json')) }
    if (-not $NoAutoPaginate -and -not ($fullArgs -contains '--no-paginate') -and
        -not ($fullArgs -contains '--max-items') -and -not ($fullArgs -contains '--starting-token')) {
        $fullArgs.Add('--no-paginate')
    }

    $cmdStr = "aws " + ($fullArgs -join " ")
    # We add the log entry at END so we can record success / output / interestingness
    $logEntry = [PSCustomObject]@{
        Time        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Command     = $cmdStr
        Description = $Description
        Success     = $false
        Interesting = $false
        ResultSize  = 0
        Error       = ''
    }
    [void]$Global:IR.CommandLog.Add($logEntry)

    $result = @{ Success=$false; Output=$null; RawOutput=""; Error=""; Command=$cmdStr; Duration=0; Skipped=$false; TimedOut=$false; ExitCode=-1 }

    $tmpOut = [System.IO.Path]::GetTempFileName()
    $tmpErr = [System.IO.Path]::GetTempFileName()
    $argStr = $fullArgs -join " "

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName        = "cmd.exe"
    $psi.Arguments       = "/c aws $argStr > `"$tmpOut`" 2> `"$tmpErr`""
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $psi.WindowStyle     = [System.Diagnostics.ProcessWindowStyle]::Hidden

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -eq $proc) { throw "Process.Start returned null" }
    } catch {
        $result.Error = "Failed to launch cmd.exe: $_"
        Remove-Item $tmpOut, $tmpErr -ErrorAction SilentlyContinue
        return $result
    }

    $pollMs  = 200
    $elapsed = 0
    $limitMs = $TimeoutSec * 1000

    while (-not $proc.HasExited) {
        Start-Sleep -Milliseconds $pollMs
        $elapsed += $pollMs
        if ($elapsed -ge $limitMs) {
            try { $proc.Kill() } catch {}
            $result.TimedOut = $true
            $result.Error    = "TIMEOUT after ${TimeoutSec}s"
            $sw.Stop()
            $result.Duration = [math]::Round($sw.Elapsed.TotalSeconds, 2)
            Remove-Item $tmpOut, $tmpErr -ErrorAction SilentlyContinue
            return $result
        }
        try {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.KeyChar -in @('s','S')) {
                    try { $proc.Kill() } catch {}
                    $result.Skipped  = $true
                    $result.Error    = "SKIPPED by user"
                    $sw.Stop()
                    $result.Duration = [math]::Round($sw.Elapsed.TotalSeconds, 2)
                    Remove-Item $tmpOut, $tmpErr -ErrorAction SilentlyContinue
                    return $result
                }
            }
        } catch {}
    }

    try { $proc.WaitForExit() } catch {}
    $sw.Stop()
    $result.Duration  = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    $result.ExitCode  = try { $proc.ExitCode } catch { -1 }
    $result.RawOutput = try { (Get-Content $tmpOut -Raw -Encoding UTF8).Trim() } catch { "" }
    $result.Error     = try { (Get-Content $tmpErr -Raw -Encoding UTF8).Trim() } catch { "" }
    Remove-Item $tmpOut, $tmpErr -ErrorAction SilentlyContinue

    if ($result.ExitCode -eq 0 -and $result.RawOutput) {
        $result.Success = $true
        try   { $result.Output = $result.RawOutput | ConvertFrom-Json }
        catch { $result.Output = $result.RawOutput }
    }

    # Update log entry: command was "interesting" if it returned meaningful data
    # (more than a trivial empty list / no results)
    $logEntry.Success    = $result.Success
    $logEntry.Error      = if ($result.Error) { ($result.Error -split "`n" | Select-Object -First 1) } else { '' }
    if ($result.Success -and $result.RawOutput) {
        $rawLen = $result.RawOutput.Length
        $logEntry.ResultSize = $rawLen
        # Heuristic: interesting if output > ~50 bytes and contains arrays/objects with content
        # (anything beyond "{}", "[]", '{"X":[]}', '{"X":null}', etc.)
        $compact = $result.RawOutput -replace '\s+',''
        $isEmpty = $compact -in @('{}','[]','null','""','""') -or
                   $compact -match '^\{"[^"]+":(\[\]|null|\{\})\}$'
        if (-not $isEmpty -and $rawLen -gt 30) {
            $logEntry.Interesting = $true
        }
    }
    return $result
}

#  Paginating wrapper 
function Invoke-IRAWSPaged {
    # Follows NextToken/nextToken pagination for commands that support it
    param(
        [string[]]$Arguments,
        [string]$Description = "",
        [string]$Region      = "",
        [string]$ResultKey   = "",   # top-level key holding the array (auto-detected if empty)
        [int]$MaxPages       = 20
    )
    $allItems = [System.Collections.Generic.List[object]]::new()
    $nextToken = $null
    $page = 0

    do {
        $page++
        $callArgs = $Arguments
        if ($nextToken) { $callArgs = $Arguments + @('--starting-token', $nextToken) }
        $r = Invoke-IRAWSCLI -Arguments ($callArgs + @('--max-items','200')) -Description "$Description (page $page)" -Region $Region -NoAutoPaginate
        if (-not $r.Success -or $r.Skipped -or $r.TimedOut) { break }

        # Auto-detect result key
        $key = $ResultKey
        if (-not $key -and $r.Output -is [PSCustomObject]) {
            $props = $r.Output.PSObject.Properties.Name | Where-Object { $_ -ne 'NextToken' -and $_ -ne 'nextToken' }
            if ($props) { $key = $props[0] }
        }

        $items = if ($key) { $r.Output.$key } else { $r.Output }
        if ($items) { foreach ($i in $items) { $allItems.Add($i) } }

        $nextToken = if ($r.Output.NextToken)  { $r.Output.NextToken }
                     elseif ($r.Output.nextToken) { $r.Output.nextToken }
                     else { $null }
    } while ($nextToken -and $page -lt $MaxPages)

    return $allItems
}

#  Attachment Record Builder 
function New-Attachment {
    param(
        [string]$Region,
        [string]$ResourceType,    # e.g. "EC2::Instance"
        [string]$ResourceId,
        [string]$ResourceName     = "",
        [string]$ResourceArn      = "",
        [string]$AttachmentType,  # InstanceProfile / ExecutionRole / TrustPolicy / ResourcePolicy / BucketPolicy / KeyPolicy / ServiceRole
        [string]$IdentityType,    # Role / User / Group / ServicePrincipal / FederatedPrincipal / AWSAccount / Public
        [string]$IdentityArn      = "",
        [string]$IdentityName     = "",
        [string]$Permissions      = "",  # comma-sep action summary, or "admin/*"
        [bool]$IsExternal         = $false,
        [bool]$IsPublic           = $false,
        [bool]$IsHighPrivilege    = $false,
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO')][string]$RiskLevel = 'LOW',
        [string]$Notes            = "",
        [ValidateSet('Allow','Deny','Unknown')][string]$Effect = 'Allow',
        [ValidateSet('ALL','SCOPED','UNKNOWN')][string]$ResourceScope = 'UNKNOWN'
    )

    $rec = [PSCustomObject]@{
        Timestamp       = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Region          = $Region
        ResourceType    = $ResourceType
        ResourceId      = $ResourceId
        ResourceName    = $ResourceName
        ResourceArn     = $ResourceArn
        AttachmentType  = $AttachmentType
        IdentityType    = $IdentityType
        IdentityArn     = $IdentityArn
        IdentityName    = $IdentityName
        Permissions     = $Permissions
        IsExternal      = $IsExternal
        IsPublic        = $IsPublic
        IsHighPrivilege = $IsHighPrivilege
        RiskLevel       = $RiskLevel
        Notes           = $Notes
        Effect          = $Effect
        ResourceScope   = $ResourceScope
    }
    $Global:IR.Attachments.Add($rec)
    $Global:IR.Stats.AttachmentsFound++
    return $rec
}

#  Helper: classify a principal string 
function Get-PrincipalInfo {
    param([string]$Principal, [string]$OwnAccountId = "")

    $result = @{
        IdentityType = 'Unknown'
        IdentityName = $Principal
        IdentityArn  = $Principal
        IsExternal   = $false
        IsPublic     = $false
    }

    if ($Principal -eq '*' -or $Principal -eq 'AWS:*') {
        $result.IdentityType = 'Public'
        $result.IdentityName = 'Anyone (*)'
        $result.IsPublic     = $true
        $result.IsExternal   = $true
        return $result
    }

    if ($Principal -match '^arn:aws:iam::(\d+):root$') {
        $acctNum = $Matches[1]
        $result.IdentityType = 'AWSAccount'
        $result.IdentityName = "Account $acctNum"
        $result.IsExternal   = ($OwnAccountId -and $acctNum -ne $OwnAccountId)
        return $result
    }

    if ($Principal -match '^arn:aws:iam::\d+:role/(.+)$') {
        $acctNum = ($Principal -split '::')[1].Split(':')[0]
        $result.IdentityType = 'Role'
        $result.IdentityName = $Matches[1]
        $result.IsExternal   = ($OwnAccountId -and $acctNum -ne $OwnAccountId)
        return $result
    }

    if ($Principal -match '^arn:aws:iam::\d+:user/(.+)$') {
        $acctNum = ($Principal -split '::')[1].Split(':')[0]
        $result.IdentityType = 'User'
        $result.IdentityName = $Matches[1]
        $result.IsExternal   = ($OwnAccountId -and $acctNum -ne $OwnAccountId)
        return $result
    }

    if ($Principal -match '^arn:aws:iam::\d+:group/(.+)$') {
        $result.IdentityType = 'Group'
        $result.IdentityName = $Matches[1]
        return $result
    }

    if ($Principal -match '\.amazonaws\.com$' -or $Principal -match '^arn:aws:iam::amazonaws') {
        $result.IdentityType = 'ServicePrincipal'
        $result.IdentityName = $Principal
        $result.IsExternal   = $false
        return $result
    }

    if ($Principal -match 'oidc\.|saml-provider|cognito-identity|accounts\.google\.com|github\.com') {
        $result.IdentityType = 'FederatedPrincipal'
        $result.IdentityName = $Principal
        $result.IsExternal   = $true
        return $result
    }

    return $result
}

#  Helper: parse resource-based policy JSON and emit attachments 
function Add-PolicyPrincipalAttachments {
    param(
        [object]$PolicyDoc,
        [string]$Region,
        [string]$ResourceType,
        [string]$ResourceId,
        [string]$ResourceName,
        [string]$ResourceArn,
        [string]$AttachmentType = 'ResourcePolicy'
    )
    if (-not $PolicyDoc) { return }

    $stmts = if ($PolicyDoc.Statement -is [array]) { $PolicyDoc.Statement } else { @($PolicyDoc.Statement) }

    foreach ($stmt in $stmts) {
        if (-not $stmt) { continue }
        $effect = if ($stmt.Effect) { $stmt.Effect } else { 'Allow' }

        $principals = @()
        $p = $stmt.Principal
        if ($p -eq '*')            { $principals += '*' }
        elseif ($p -is [string])   { $principals += $p }
        elseif ($p -is [PSCustomObject] -or $p -is [hashtable]) {
            $pobj = $p
            if ($pobj.AWS)       { $principals += if ($pobj.AWS -is [array]) { $pobj.AWS } else { @($pobj.AWS) } }
            if ($pobj.Service)   { $principals += if ($pobj.Service -is [array]) { $pobj.Service } else { @($pobj.Service) } }
            if ($pobj.Federated) { $principals += if ($pobj.Federated -is [array]) { $pobj.Federated } else { @($pobj.Federated) } }
        }

        $actions = @()
        if ($stmt.Action -is [array]) { $actions = $stmt.Action }
        elseif ($stmt.Action)         { $actions = @($stmt.Action) }
        $permSummary = ($actions | Select-Object -First 5) -join ','
        if ($actions.Count -gt 5) { $permSummary += ",+$($actions.Count - 5) more" }

        # Resource scope on this statement
        $resources = @()
        if ($stmt.Resource -is [array]) { $resources = $stmt.Resource }
        elseif ($stmt.Resource) { $resources = @($stmt.Resource) }
        $resourceScope = if ($resources.Count -eq 0 -or ($resources -contains '*')) { 'ALL' } else { 'SCOPED' }

        $isAdmin = $actions | Where-Object { $_ -eq '*' -or $_ -match ':\*$' }

        foreach ($prin in $principals) {
            if (-not $prin) { continue }
            $info = Get-PrincipalInfo -Principal $prin.ToString() -OwnAccountId $Global:IR.AccountId

            # Risk grading - Deny is protective, downgrade severely
            $risk = 'LOW'
            if ($effect -eq 'Deny') {
                $risk = 'INFO'   # Deny statements are guardrails, not risks
            } else {
                if ($info.IsPublic)    { $risk = 'CRITICAL' }
                elseif ($info.IsExternal -and $isAdmin) { $risk = 'CRITICAL' }
                elseif ($info.IsExternal) { $risk = 'HIGH' }
                elseif ($isAdmin -and $resourceScope -eq 'ALL') { $risk = 'HIGH' }
                elseif ($isAdmin) { $risk = 'MEDIUM' }  # admin but scoped to specific resources
                else { $risk = 'MEDIUM' }
            }

            $isHighPriv = ([bool]$isAdmin) -and ($effect -eq 'Allow')

            New-Attachment `
                -Region          $Region `
                -ResourceType    $ResourceType `
                -ResourceId      $ResourceId `
                -ResourceName    $ResourceName `
                -ResourceArn     $ResourceArn `
                -AttachmentType  $AttachmentType `
                -IdentityType    $info.IdentityType `
                -IdentityArn     $prin.ToString() `
                -IdentityName    $info.IdentityName `
                -Permissions     $permSummary `
                -IsExternal      $info.IsExternal `
                -IsPublic        $info.IsPublic `
                -IsHighPrivilege $isHighPriv `
                -RiskLevel       $risk `
                -Notes           "Effect=$effect Sid=$($stmt.Sid)" `
                -Effect          $effect `
                -ResourceScope   $resourceScope | Out-Null
        }
    }
}

#  Region discovery 
function Get-EnabledRegions {
    Write-IRLog "Discovering enabled regions..." -Level INFO
    $r = Invoke-IRAWSCLI -Arguments @('ec2','describe-regions','--all-regions','--query','Regions[?OptInStatus!=`not-opted-in`].RegionName') -Description "List enabled regions"
    if ($r.Success -and $r.Output) {
        $regions = @($r.Output)
        Write-IRLog "  Found $($regions.Count) enabled regions" -Level SUCCESS
        return $regions
    }
    Write-IRLog "  Could not auto-discover regions - using us-east-1 fallback" -Level WARN
    return @('us-east-1')
}
