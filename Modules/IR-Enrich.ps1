# Modules/IR-Enrich.ps1
# ============================================================
#  Phase 4: IAM Role Enrichment
#
#  Resource collectors record WHICH role a resource uses, but
#  they don't fetch what that role can DO or WHO can assume it.
#  This module:
#    Step 3: list-attached-role-policies + list-role-policies
#            for every unique role referenced by attachments,
#            then get-policy-version / get-role-policy to
#            collect the actual Action statements.
#    Step 4: get-role to extract AssumeRolePolicyDocument and
#            emit a new attachment per trust principal.
#
#  Output:
#    $Global:IR.RoleCatalog[$roleArn] = {
#       Trust            = parsed trust policy
#       AttachedPolicies = list of managed policies
#       InlinePolicies   = list of inline policy names
#       AllActions       = consolidated action list
#       HasAdmin         = wildcard Action:* anywhere
#       HasServiceStar   = any service:* anywhere
#       PolicySummary    = display string
#       TrustPrincipals  = parsed principals
#    }
#
#    Attachments with IdentityArn pointing to a known role get
#    their Permissions / IsHighPrivilege / RiskLevel updated.
#
#    New attachments are emitted from each trust policy:
#    one per principal so the trust relationships show up in
#    the report as first-class data.
# ============================================================

# ----------------------------------------------------------------
# Get unique role ARNs that are IN OUR ACCOUNT
# (cross-account roles can't be enumerated - we don't have IAM
#  permissions in the foreign account)
# ----------------------------------------------------------------
function Get-EnrichableRoles {
    $own = $Global:IR.AccountId
    $set = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($att in $Global:IR.Attachments) {
        if ($att.IdentityType -ne 'Role') { continue }
        if (-not $att.IdentityArn) { continue }
        if ($att.IdentityArn -notmatch '^arn:aws:iam::(\d+):role/') { continue }
        $acct = $Matches[1]
        if ($acct -ne $own) { continue }                # skip cross-account
        if ($att.IdentityArn -match 'aws-service-role/') { continue }  # skip SLRs
        [void]$set.Add($att.IdentityArn)
    }
    return @($set)
}

# ----------------------------------------------------------------
# Convert role ARN to the name expected by `iam get-role`
# Handles paths: arn:aws:iam::123:role/path/to/RoleName -> path/to/RoleName
# Actually `iam get-role --role-name` only wants the final segment,
# but for roles with a path the full name segment is what's needed.
# Best: strip "arn:aws:iam::ACCT:role/" prefix.
# ----------------------------------------------------------------
function Get-RoleNameFromArn {
    param([string]$Arn)
    if ($Arn -match '^arn:aws:iam::\d+:role/(.+)$') {
        $name = $Matches[1]
        # iam get-role wants just the name part for path-less roles,
        # but for path/Name it accepts the full thing on path-aware calls.
        # iam get-role accepts the NAME not path, so strip the path:
        return ($name -split '/')[-1]
    }
    return $Arn.Split('/')[-1]
}

# ----------------------------------------------------------------
# Extract Action[] from a single policy statement
# ----------------------------------------------------------------
function Get-StatementActions {
    param([object]$Statement)
    if (-not $Statement) { return @() }
    $actions = @()
    if ($Statement.Action -is [array]) {
        $actions = $Statement.Action
    } elseif ($Statement.Action) {
        $actions = @($Statement.Action)
    }
    return $actions
}

# ----------------------------------------------------------------
# Summarise actions: returns hashtable with HasAdmin, HasServiceStar,
# Services touched, top actions, total count
# ----------------------------------------------------------------
function Build-ActionSummary {
    param([object[]]$ActionList)
    $result = @{
        HasAdmin       = $false
        HasServiceStar = $false
        Services       = [System.Collections.Generic.HashSet[string]]::new()
        Actions        = [System.Collections.Generic.HashSet[string]]::new()
    }
    foreach ($a in $ActionList) {
        if (-not $a) { continue }
        $a = "$a"
        [void]$result.Actions.Add($a)
        if ($a -eq '*') {
            $result.HasAdmin = $true
            [void]$result.Services.Add('*')
            continue
        }
        # service:action or service:*
        if ($a -match '^([^:]+):(.+)$') {
            [void]$result.Services.Add($Matches[1])
            if ($Matches[2] -eq '*') { $result.HasServiceStar = $true }
        }
    }
    return $result
}

# ----------------------------------------------------------------
# Enrich one role - returns hashtable with trust, policies, actions
# ----------------------------------------------------------------
function Get-RoleEnrichment {
    param([string]$RoleArn)
    $roleName = Get-RoleNameFromArn $RoleArn

    $detail = @{
        RoleArn          = $RoleArn
        RoleName         = $roleName
        Trust            = $null
        TrustPrincipals  = @()
        AttachedPolicies = @()    # @( @{Name=...; Arn=...; Doc=...} )
        InlinePolicies   = @()    # @( @{Name=...; Doc=...} )
        AllActions       = @()
        HasAdmin         = $false
        HasServiceStar   = $false
        Services         = @()
        PolicySummary    = ""
        Fetched          = $false
    }

    # Step 4: get the role (trust policy)
    $rr = Invoke-IRAWSCLI -Arguments @('iam','get-role','--role-name',$roleName,'--query','Role') `
            -Description "iam get-role $roleName"
    if (-not $rr.Success -or -not $rr.Output) {
        return $detail   # role inaccessible or doesn't exist
    }
    $detail.Trust   = $rr.Output.AssumeRolePolicyDocument
    $detail.Fetched = $true

    # Step 3a: managed policies attached
    $ap = Invoke-IRAWSCLI -Arguments @('iam','list-attached-role-policies','--role-name',$roleName,'--query','AttachedPolicies') `
            -Description "iam list-attached-role-policies $roleName"
    if ($ap.Success -and $ap.Output) {
        foreach ($pol in $ap.Output) {
            $polInfo = @{
                Name = $pol.PolicyName
                Arn  = $pol.PolicyArn
                Doc  = $null
            }
            # get the default version document
            $pv = Invoke-IRAWSCLI -Arguments @('iam','get-policy','--policy-arn',$pol.PolicyArn,'--query','Policy') `
                    -Description "iam get-policy $($pol.PolicyName)"
            if ($pv.Success -and $pv.Output.DefaultVersionId) {
                $pvd = Invoke-IRAWSCLI -Arguments @('iam','get-policy-version','--policy-arn',$pol.PolicyArn,
                                                    '--version-id',$pv.Output.DefaultVersionId,
                                                    '--query','PolicyVersion.Document') `
                        -Description "iam get-policy-version $($pol.PolicyName)"
                if ($pvd.Success) { $polInfo.Doc = $pvd.Output }
            }
            $detail.AttachedPolicies += ,$polInfo
        }
    }

    # Step 3b: inline policies
    $il = Invoke-IRAWSCLI -Arguments @('iam','list-role-policies','--role-name',$roleName,'--query','PolicyNames') `
            -Description "iam list-role-policies $roleName"
    if ($il.Success -and $il.Output) {
        foreach ($inName in $il.Output) {
            $ir = Invoke-IRAWSCLI -Arguments @('iam','get-role-policy','--role-name',$roleName,'--policy-name',$inName,'--query','PolicyDocument') `
                    -Description "iam get-role-policy $roleName/$inName"
            $detail.InlinePolicies += ,@{
                Name = $inName
                Doc  = if ($ir.Success) { $ir.Output } else { $null }
            }
        }
    }

    # Collect every action across all policy docs
    $allActions = New-Object System.Collections.Generic.List[string]
    foreach ($p in $detail.AttachedPolicies) {
        if (-not $p.Doc) { continue }
        $stmts = if ($p.Doc.Statement -is [array]) { $p.Doc.Statement } else { @($p.Doc.Statement) }
        foreach ($s in $stmts) {
            if (-not $s -or $s.Effect -ne 'Allow') { continue }
            foreach ($a in (Get-StatementActions $s)) { $allActions.Add("$a") }
        }
    }
    foreach ($p in $detail.InlinePolicies) {
        if (-not $p.Doc) { continue }
        $stmts = if ($p.Doc.Statement -is [array]) { $p.Doc.Statement } else { @($p.Doc.Statement) }
        foreach ($s in $stmts) {
            if (-not $s -or $s.Effect -ne 'Allow') { continue }
            foreach ($a in (Get-StatementActions $s)) { $allActions.Add("$a") }
        }
    }
    $summary = Build-ActionSummary -ActionList $allActions
    $detail.AllActions     = @($allActions)
    $detail.HasAdmin       = $summary.HasAdmin
    $detail.HasServiceStar = $summary.HasServiceStar
    $detail.Services       = @($summary.Services)

    # Build display summary
    $pieces = New-Object System.Collections.Generic.List[string]
    if ($summary.HasAdmin) {
        $pieces.Add("ADMIN(*)")
    }
    # Highlight well-known managed admin policies
    foreach ($p in $detail.AttachedPolicies) {
        if ($p.Arn -match 'AdministratorAccess$|PowerUserAccess$|IAMFullAccess$') {
            $name = $p.Arn.Split('/')[-1]
            if (-not $pieces.Contains($name)) { $pieces.Add($name) }
        }
    }
    $svcStars = @($detail.AllActions | Where-Object { $_ -match ':\*$' -and $_ -ne '*' } | Sort-Object -Unique | Select-Object -First 5)
    foreach ($s in $svcStars) { $pieces.Add($s) }

    if ($pieces.Count -eq 0) {
        # Use top actions - guard against null collection
        $topActions = @($detail.AllActions | Sort-Object -Unique | Select-Object -First 4)
        if ($topActions -and $topActions.Count -gt 0) {
            foreach ($a in $topActions) {
                if ($a) { [void]$pieces.Add("$a") }
            }
            if ($detail.AllActions -and $detail.AllActions.Count -gt 4) {
                [void]$pieces.Add("+$($detail.AllActions.Count - 4) more")
            }
        } else {
            [void]$pieces.Add("(no Allow statements found)")
        }
    } else {
        $totalPols = $detail.AttachedPolicies.Count + $detail.InlinePolicies.Count
        if ($totalPols -gt 1) {
            $pieces.Add("($totalPols policies)")
        }
    }
    $detail.PolicySummary = ($pieces -join ', ')

    # Parse trust policy principals
    $detail.TrustPrincipals = @(Get-TrustPrincipals -TrustDoc $detail.Trust)

    return $detail
}

# ----------------------------------------------------------------
# Parse principals out of a trust policy document
# Returns array of hashtables: @{Type=..; Value=..; Conditions=..; Effect=..; Actions=..}
# ----------------------------------------------------------------
function Get-TrustPrincipals {
    param([object]$TrustDoc)
    if (-not $TrustDoc) { return @() }
    $result = New-Object System.Collections.Generic.List[object]

    $stmts = if ($TrustDoc.Statement -is [array]) { $TrustDoc.Statement } else { @($TrustDoc.Statement) }
    foreach ($s in $stmts) {
        if (-not $s) { continue }
        $effect    = if ($s.Effect)    { $s.Effect }    else { 'Allow' }
        $actions   = Get-StatementActions $s
        $hasExtId  = $false
        $hasMfa    = $false
        if ($s.Condition) {
            $condStr = $s.Condition | ConvertTo-Json -Compress -Depth 5
            if ($condStr -match 'sts:ExternalId|aws:ExternalId') { $hasExtId = $true }
            if ($condStr -match 'aws:MultiFactorAuthPresent|aws:MultiFactorAuthAge') { $hasMfa = $true }
        }

        $principals = @()
        $p = $s.Principal
        if ($p -eq '*') {
            $principals += @{ Type='Public'; Value='*' }
        } elseif ($p -is [string]) {
            $principals += @{ Type='Unknown'; Value=$p }
        } elseif ($p -is [PSCustomObject] -or $p -is [hashtable]) {
            foreach ($k in @('Service','AWS','Federated','CanonicalUser')) {
                $v = $p.$k
                if (-not $v) { continue }
                $arr = if ($v -is [array]) { $v } else { @($v) }
                foreach ($item in $arr) {
                    $principals += @{ Type=$k; Value="$item" }
                }
            }
        }
        foreach ($pp in $principals) {
            $result.Add([PSCustomObject]@{
                Type        = $pp.Type
                Value       = $pp.Value
                Effect      = $effect
                Actions     = ($actions -join ',')
                HasExternalId = $hasExtId
                HasMfa        = $hasMfa
            })
        }
    }
    return $result
}

# ----------------------------------------------------------------
# Apply enrichment to existing attachments (in place)
#  - Update Permissions, IsHighPrivilege, possibly RiskLevel
# ----------------------------------------------------------------
function Update-AttachmentsFromCatalog {
    foreach ($att in $Global:IR.Attachments) {
        if ($att.IdentityType -ne 'Role') { continue }
        if (-not $att.IdentityArn) { continue }
        if (-not $Global:IR.RoleCatalog.ContainsKey($att.IdentityArn)) { continue }

        $cat = $Global:IR.RoleCatalog[$att.IdentityArn]
        if (-not $cat.Fetched) { continue }

        # Only overwrite Permissions if it's currently empty
        # (resource-policy attachments already have their own Permissions
        #  from the resource policy and we shouldn't clobber that)
        if (-not $att.Permissions) {
            $att.Permissions = $cat.PolicySummary
        }

        # Upgrade IsHighPrivilege if the role has admin
        if ($cat.HasAdmin -or $cat.HasServiceStar) {
            $att.IsHighPrivilege = $true
            # bump risk if it was below HIGH
            if ($att.RiskLevel -in @('LOW','INFO','MEDIUM')) {
                $att.RiskLevel = if ($cat.HasAdmin) { 'CRITICAL' } else { 'HIGH' }
                $att.Notes = "$($att.Notes) [role grants $($cat.PolicySummary)]".Trim()
            }
        }
    }
}

# ----------------------------------------------------------------
# Emit trust-policy attachments for each enriched role
# (one new attachment per trust principal so they appear in reports)
# ----------------------------------------------------------------
function Add-TrustPolicyAttachments {
    $added = 0
    foreach ($arn in $Global:IR.RoleCatalog.Keys) {
        $cat = $Global:IR.RoleCatalog[$arn]
        if (-not $cat.Fetched) { continue }

        $roleArn  = $cat.RoleArn
        $roleName = $cat.RoleName

        foreach ($tp in $cat.TrustPrincipals) {
            $idType = switch ($tp.Type) {
                'Service'        { 'ServicePrincipal' }
                'Federated'      { 'FederatedPrincipal' }
                'Public'         { 'Public' }
                'CanonicalUser'  { 'CanonicalUser' }
                'AWS'            { $null }   # decide below
                default          { $tp.Type }
            }

            $isExt = $false; $isPub = $false
            if ($tp.Type -eq 'Public') { $isPub = $true; $isExt = $true }
            elseif ($tp.Type -eq 'AWS') {
                # AWS principals - can be account root, role, user
                if ($tp.Value -match '^arn:aws:iam::(\d+):root$') {
                    $idType = 'AWSAccount'
                    if ($Matches[1] -ne $Global:IR.AccountId) { $isExt = $true }
                } elseif ($tp.Value -match '^arn:aws:iam::(\d+):role/') {
                    $idType = 'Role'
                    if ($Matches[1] -ne $Global:IR.AccountId) { $isExt = $true }
                } elseif ($tp.Value -match '^arn:aws:iam::(\d+):user/') {
                    $idType = 'User'
                    if ($Matches[1] -ne $Global:IR.AccountId) { $isExt = $true }
                } elseif ($tp.Value -match '^\d{12}$') {
                    $idType = 'AWSAccount'
                    if ($tp.Value -ne $Global:IR.AccountId) { $isExt = $true }
                } else {
                    $idType = 'AWSAccount'
                }
            } elseif ($tp.Type -eq 'Federated') {
                $isExt = $true
            }

            # Risk grading for trust policies
            $risk = 'LOW'
            if ($isPub) { $risk = 'CRITICAL' }
            elseif ($isExt -and -not $tp.HasExternalId) { $risk = 'HIGH' }
            elseif ($isExt) { $risk = 'MEDIUM' }
            elseif ($idType -eq 'ServicePrincipal') { $risk = 'INFO' }
            else { $risk = 'LOW' }

            $note = "Effect=$($tp.Effect)"
            if ($tp.HasExternalId) { $note += " [ExternalId set]" }
            if ($tp.HasMfa)        { $note += " [MFA required]" }
            if ($cat.HasAdmin)     { $note += " [ROLE HAS ADMIN]"; if ($risk -eq 'LOW') { $risk = 'MEDIUM' } }

            New-Attachment `
                -Region          'global' `
                -ResourceType    'IAM::Role' `
                -ResourceId      $roleName `
                -ResourceName    $roleName `
                -ResourceArn     $roleArn `
                -AttachmentType  'TrustPolicy' `
                -IdentityType    $idType `
                -IdentityArn     $tp.Value `
                -IdentityName    $tp.Value `
                -Permissions     ($tp.Actions) `
                -IsExternal      $isExt `
                -IsPublic        $isPub `
                -IsHighPrivilege ([bool]$cat.HasAdmin) `
                -RiskLevel       $risk `
                -Notes           $note | Out-Null
            $added++
        }
    }
    return $added
}

# ----------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------
function Invoke-RoleEnrichment {
    param([int]$MaxRoles = 200)

    Write-Host ""
    Write-Host "  [PHASE 4] IAM Role enrichment" -ForegroundColor Magenta
    Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray

    if (-not $Global:IR.RoleCatalog) {
        $Global:IR.RoleCatalog = @{}
    }

    $roles = Get-EnrichableRoles
    Write-IRLog "Found $($roles.Count) unique in-account roles to enrich" -Level INFO
    if ($roles.Count -gt $MaxRoles) {
        Write-IRLog "Limiting to $MaxRoles roles (use -MaxRoles to increase)" -Level WARN
        $roles = $roles | Select-Object -First $MaxRoles
    }

    $i = 0
    foreach ($arn in $roles) {
        $i++
        $name = Get-RoleNameFromArn $arn
        Write-Host "    [$i/$($roles.Count)] $name" -ForegroundColor DarkGray -NoNewline
        try {
            $detail = Get-RoleEnrichment -RoleArn $arn
            $Global:IR.RoleCatalog[$arn] = $detail
            if ($detail.Fetched) {
                $flag = ""
                if ($detail.HasAdmin)       { $flag += " [ADMIN*]" }
                elseif ($detail.HasServiceStar) { $flag += " [SVC:*]" }
                $trustC = $detail.TrustPrincipals.Count
                Write-Host " policies=$($detail.AttachedPolicies.Count + $detail.InlinePolicies.Count) trust=$trustC$flag" -ForegroundColor $(if ($detail.HasAdmin) { 'Red' } elseif ($detail.HasServiceStar) { 'Yellow' } else { 'Green' })
            } else {
                Write-Host " [inaccessible]" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host " ERROR: $_" -ForegroundColor Red
            Write-IRError -Service 'Enrich' -Region 'global' -Message "$arn : $_"
        }
    }

    Write-IRLog "Applying enrichment to attachments..." -Level INFO
    Update-AttachmentsFromCatalog

    Write-IRLog "Emitting trust policy attachments..." -Level INFO
    $added = Add-TrustPolicyAttachments
    Write-IRLog "Added $added trust-policy attachments" -Level SUCCESS

    Write-Host ""
    Write-IRLog "Enrichment complete: $($Global:IR.RoleCatalog.Count) roles cataloged" -Level SUCCESS
}
