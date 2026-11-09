# Modules/IR-Import.ps1
# ============================================================
#  Imports cross-reference data from a sibling IAM-Audit
#  output folder. Detects roles flagged by IAM-Audit and
#  attaches that context to our RoleCatalog and attachments.
#
#  Without knowing IAM-Audit's exact JSON schema, we take a
#  pragmatic approach: any role ARN from our catalog that
#  appears verbatim in IAM-Audit's JSON files gets cross-
#  referenced. Filenames matching privesc/admin/critical/risky
#  patterns are treated as high-confidence signals.
# ============================================================

function Find-IAMAuditDir {
    param([string]$ExplicitPath = "")

    if ($ExplicitPath -and (Test-Path $ExplicitPath)) {
        return (Resolve-Path $ExplicitPath).Path
    }

    $candidates = New-Object System.Collections.Generic.List[object]
    $here = (Get-Location).Path

    # Look in current directory and parent directory for sibling IAM-Audit folders
    foreach ($dir in @($here, (Split-Path -Parent $here))) {
        if (-not $dir -or -not (Test-Path $dir)) { continue }
        try {
            $found = Get-ChildItem -Path $dir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'IAM-Audit*' }
            foreach ($f in $found) { $candidates.Add($f) }
        } catch { }
    }

    # Also look one level deeper (e.g. current dir contains IAM-Audit/output-folders)
    try {
        $iamRoot = Get-ChildItem -Path $here -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'IAM-Audit' } | Select-Object -First 1
        if ($iamRoot) {
            $subOutputs = Get-ChildItem -Path $iamRoot.FullName -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'IAM-Audit-*' -or $_.Name -like 'output*' }
            foreach ($s in $subOutputs) { $candidates.Add($s) }
        }
    } catch { }

    if ($candidates.Count -eq 0) { return $null }

    # Most-recent first; prefer ones with HTML (real output) over empty folders
    $best = $candidates |
        Where-Object { (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0 } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($best) { return $best.FullName }
    return $null
}

function Import-IAMAuditFindings {
    param([string]$IAMAuditDir = "")

    $dir = Find-IAMAuditDir -ExplicitPath $IAMAuditDir
    if (-not $dir) {
        Write-IRLog "No IAM-Audit folder detected for cross-reference (looked for sibling 'IAM-Audit*' folders)" -Level INFO
        $Global:IR.IAMAuditDir = $null
        return
    }

    Write-IRLog "Cross-referencing IAM-Audit output: $dir" -Level INFO
    $Global:IR.IAMAuditDir = $dir

    if (-not $Global:IR.RoleCatalog -or $Global:IR.RoleCatalog.Count -eq 0) {
        Write-IRLog "Role catalog is empty - cross-reference skipped" -Level WARN
        return
    }

    # Look for the IAM-Audit index.html (so we can link to it from our report)
    $indexCandidate = Get-ChildItem -Path $dir -Filter "index.html" -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName | Select-Object -First 1
    if ($indexCandidate) {
        $Global:IR.IAMAuditIndexPath = $indexCandidate.FullName
        Write-IRLog "IAM-Audit report index: $($indexCandidate.FullName)" -Level INFO
    }

    # Scan every JSON file - any role ARN from our catalog mentioned in it
    # is a cross-reference signal. Filenames matching risk keywords are
    # treated as high-confidence findings.
    $jsonFiles = @(Get-ChildItem -Path $dir -Recurse -Filter "*.json" -ErrorAction SilentlyContinue)
    if ($jsonFiles.Count -eq 0) {
        Write-IRLog "No JSON files in IAM-Audit folder - cross-reference skipped" -Level WARN
        return
    }
    Write-IRLog "Scanning $($jsonFiles.Count) IAM-Audit JSON file(s)..." -Level INFO

    $roleRefs = @{}   # arn -> List[string] of filenames
    $catalogArns = @($Global:IR.RoleCatalog.Keys)

    foreach ($f in $jsonFiles) {
        try {
            $text = [System.IO.File]::ReadAllText($f.FullName)
        } catch {
            continue
        }
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        foreach ($arn in $catalogArns) {
            if ($text.IndexOf($arn) -ge 0) {
                if (-not $roleRefs.ContainsKey($arn)) {
                    $roleRefs[$arn] = New-Object System.Collections.Generic.HashSet[string]
                }
                [void]$roleRefs[$arn].Add($f.Name)
            }
        }
    }

    # Apply to catalog
    $highSignalRoles = 0
    foreach ($arn in $roleRefs.Keys) {
        $cat = $Global:IR.RoleCatalog[$arn]
        if (-not $cat) { continue }
        $files = ($roleRefs[$arn] | Sort-Object) -join ','

        # Mark as cross-referenced
        if (-not $cat.ContainsKey('IAMAuditRefs')) {
            $cat['IAMAuditRefs'] = $files
        } else {
            $cat['IAMAuditRefs'] = $files
        }

        # High-signal patterns in the filename(s)
        $highSignal = $false
        foreach ($file in $roleRefs[$arn]) {
            if ($file -match '(?i)privesc|admin|critical|risky|finding|exposure') {
                $highSignal = $true
                break
            }
        }
        $cat['IAMAuditHighSignal'] = $highSignal
        if ($highSignal) { $highSignalRoles++ }
    }

    Write-IRLog "Cross-ref: $($roleRefs.Count) roles found in IAM-Audit data ($highSignalRoles high-signal)" -Level SUCCESS

    # Boost risk for cross-referenced roles in our attachments
    $boosted = 0
    foreach ($att in $Global:IR.Attachments) {
        if (-not $att.IdentityArn) { continue }
        if (-not $Global:IR.RoleCatalog.ContainsKey($att.IdentityArn)) { continue }
        $cat = $Global:IR.RoleCatalog[$att.IdentityArn]
        if (-not $cat.ContainsKey('IAMAuditHighSignal')) { continue }
        if (-not $cat['IAMAuditHighSignal']) { continue }

        # Append a note tag
        if ($att.Notes -notmatch 'IAM-Audit-flagged') {
            $att.Notes = "$($att.Notes) [IAM-Audit-flagged]".Trim()
        }
        # Bump risk one level up (LOW->MEDIUM, MEDIUM->HIGH) but never above the resource's existing risk
        if ($att.Effect -ne 'Deny') {
            if ($att.RiskLevel -eq 'LOW') { $att.RiskLevel = 'MEDIUM'; $boosted++ }
            elseif ($att.RiskLevel -eq 'INFO') { $att.RiskLevel = 'LOW'; $boosted++ }
        }
    }
    if ($boosted -gt 0) {
        Write-IRLog "Boosted risk on $boosted attachments based on IAM-Audit cross-ref" -Level SUCCESS
    }
}
