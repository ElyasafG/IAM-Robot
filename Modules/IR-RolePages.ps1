# Modules/IR-RolePages.ps1
# ============================================================
#  Per-role detail page: roles/role-<safe-name>.html
#
#  Enhancements:
#    - Action Table v2: shows EVERY catalog action across all 23 services,
#      with referenced actions highlighted and unreferenced ones dimmed.
#    - Resource ARN dropdowns with color-coded scope (unscoped/scoped/external).
#    - Source policy links jump to the raw policy block on the same page.
#    - Capability cards include MITRE tactic, reference URL, source policies,
#      and the list of resources that inherit this capability.
#    - Nav links use ../ prefix because pages live in roles/ subdir.
# ============================================================

function Get-RoleFileName {
    param([string]$RoleArn)
    if ($RoleArn -match ':role/(.+)$') {
        $name = $Matches[1] -replace '[^A-Za-z0-9._-]','_'
        return "role-$name.html"
    }
    return "role-unknown-$([guid]::NewGuid().ToString().Substring(0,8)).html"
}

# Build a stable HTML id from a policy name for in-page jump links
function Get-PolicyAnchor {
    param([string]$PolicyName)
    return ($PolicyName -replace '[^A-Za-z0-9._-]','-')
}

# Determine ARN scope class: 'all' (wildcard), 'external' (cross-account),
# 'public' (anyone), or 'scoped' (specific within this account)
function Get-ArnScopeClass {
    param([string]$Arn, [string]$OwnAccountId)
    if (-not $Arn -or $Arn -eq '*') { return 'all' }
    if ($Arn -match '^arn:aws:[^:]+::\*' -or $Arn -match '\*$' -and $Arn -notmatch '::\d+:') { return 'broad' }
    if ($Arn -match '^arn:aws:[^:]+:[^:]*:(\d+):') {
        $acct = $Matches[1]
        if ($acct -ne $OwnAccountId) { return 'external' }
        return 'scoped'
    }
    return 'scoped'
}

# ----------------------------------------------------------------
# Build the "full catalog" action table data for one role.
# Returns a list of PSCustomObject rows, where every action in
# $Global:IR_ActionCatalog appears - either referenced (Allow/Deny) or
# dimmed/unreferenced.
# ----------------------------------------------------------------
function Build-FullActionTable {
    param([hashtable]$Effective, [string]$OwnAccountId)

    $rows = New-Object System.Collections.Generic.List[object]
    $services = $Global:IR_ActionCatalog.Keys | Sort-Object

    # Collect every service referenced in effective permissions (catalog or not).
    # This is critical: if a policy mentions actions in a service that's not in
    # our catalog, we still want them visible in the action table - silently
    # dropping them means the auditor never sees that the policy grants them.
    $referencedSvcs = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($act in $Effective.Keys) {
        $svc = ($act -split ':')[0]
        [void]$referencedSvcs.Add($svc)
    }

    # Services to render: catalog services (always) PLUS any other service that
    # appears in the effective permissions (so non-catalog actions show up).
    # Catalog/referenced go first, then catalog/unreferenced, then non-catalog.
    $catalogRef = @($services | Where-Object { $referencedSvcs.Contains($_) } | Sort-Object)
    $catalogUnref = @($services | Where-Object { -not $referencedSvcs.Contains($_) } | Sort-Object)
    $nonCatalog = @($referencedSvcs | Where-Object { -not $Global:IR_ActionCatalog.ContainsKey($_) } | Sort-Object)
    $sortedSvcs = $catalogRef + $catalogUnref + $nonCatalog

    # Build a lookup of which services support resource-level ARNs.
    # Services where resource-level scoping is meaningful for most data-touching actions.
    $resourceScopableSvcs = @{
        's3'=$true;'lambda'=$true;'kms'=$true;'secretsmanager'=$true;'ssm'=$true;
        'dynamodb'=$true;'rds'=$true;'ec2'=$true;'sqs'=$true;'sns'=$true;
        'logs'=$true;'ecr'=$true;'ecs'=$true;'eks'=$true;'sagemaker'=$true;
        'glue'=$true;'cloudtrail'=$true;'codebuild'=$true;'codepipeline'=$true
    }
    # Actions that intrinsically operate on the whole service (no resource ARN needed)
    $resourcelessActions = @{
        'iam:ListUsers'=$true; 'iam:ListRoles'=$true; 'iam:ListPolicies'=$true;
        'iam:ListGroups'=$true; 'iam:GenerateCredentialReport'=$true;
        'sts:GetCallerIdentity'=$true; 'sts:DecodeAuthorizationMessage'=$true;
        'ec2:DescribeRegions'=$true; 'ec2:DescribeAvailabilityZones'=$true;
        'organizations:DescribeOrganization'=$true;
        's3:ListAllMyBuckets'=$true
    }

    foreach ($svc in $sortedSvcs) {
        $isCatalog = $Global:IR_ActionCatalog.ContainsKey($svc)
        if ($isCatalog) {
            $catActions = $Global:IR_ActionCatalog[$svc] | Sort-Object
        } else {
            # Non-catalog service: synthesize the "action list" from what the
            # policies actually granted. Unknown service won't have an exhaustive
            # action set; we show only the actions the policy mentions.
            $catActions = @($Effective.Keys |
                Where-Object { ($_ -split ':')[0] -eq $svc } |
                ForEach-Object { ($_ -split ':',2)[1] } |
                Sort-Object -Unique)
        }
        foreach ($act in $catActions) {
            $full = "${svc}:${act}"
            $rec = $Effective[$full]
            $actionNoResource = $false  # red action - has Allow but Resource:* / no resource
            $resourceNoAction = $false  # red resource cell - resource ARNs are specific but action doesn't suit them
            if ($rec) {
                # Build resource list with scope class
                $resScopes = New-Object System.Collections.Generic.List[object]
                $resources = if ($rec.Resources.Count -eq 0) { @('*') } else { $rec.Resources.ToArray() }
                $hasStar    = $false
                $hasSpecific = $false
                foreach ($r in $resources) {
                    if ("$r" -eq '*') { $hasStar = $true } else { $hasSpecific = $true }
                    $resScopes.Add(@{
                        arn = "$r"
                        scope = (Get-ArnScopeClass -Arn "$r" -OwnAccountId $OwnAccountId)
                    })
                }

                # Action is "red" if it can be scoped to specific resources, the action
                # is data-touching, but the only granted scope is "*" (no scoping at all)
                if ($rec.Effect -eq 'Allow' -and $hasStar -and -not $hasSpecific -and
                    -not $resourcelessActions.ContainsKey($full) -and
                    $resourceScopableSvcs.ContainsKey($svc) -and
                    $act -match '^(Get|Put|Delete|List|Describe|Create|Modify|Update|Read|Write|Invoke|Send|Receive|Decrypt|Encrypt|Sign|Assume)') {
                    $actionNoResource = $true
                }

                # Resource cell is "red" if specific resource ARNs were listed but the action
                # arguably shouldn't apply to that service-level resource type.
                # Cross-service ARN check: if action is for service X but ARN belongs to service Y
                if ($hasSpecific) {
                    $mismatchCount = 0
                    foreach ($r in $resources) {
                        if ("$r" -eq '*') { continue }
                        if ("$r" -match '^arn:aws:([^:]+):') {
                            $arnSvc = $Matches[1].ToLower()
                            # IAM ARNs are fine for many services (e.g., passrole)
                            if ($arnSvc -eq 'iam' -or $arnSvc -eq $svc) { continue }
                            # logs ARNs are fine when action is logs/cloudwatch related
                            if ($arnSvc -eq 'logs' -and $svc -in @('logs','cloudwatch')) { continue }
                            $mismatchCount++
                        }
                    }
                    if ($mismatchCount -gt 0 -and $mismatchCount -eq ($resources | Where-Object { "$_" -ne '*' }).Count) {
                        $resourceNoAction = $true
                    }
                }

                $rows.Add([PSCustomObject]@{
                    service        = $svc
                    action         = $full
                    actionShort    = $act
                    effect         = $rec.Effect
                    referenced     = $true
                    fromCatalog    = $isCatalog
                    resources      = $resScopes.ToArray()
                    hasCondition   = ($rec.Conditions.Count -gt 0)
                    conditionStr   = ($rec.Conditions -join ' ; ')
                    sourcePolicies = $rec.SourcePolicies.ToArray()
                    allowVia       = $rec.AllowVia.ToArray()
                    denyVia        = $rec.DenyVia.ToArray()
                    actionNoResource = $actionNoResource
                    resourceNoAction = $resourceNoAction
                })
            } else {
                # Catalog action not referenced - dimmed row, NotPermitted
                # (We never reach this branch for non-catalog services, since
                # we only enumerated their referenced actions.)
                $rows.Add([PSCustomObject]@{
                    service        = $svc
                    action         = $full
                    actionShort    = $act
                    effect         = 'NotPermitted'
                    referenced     = $false
                    fromCatalog    = $isCatalog
                    resources      = @()
                    hasCondition   = $false
                    conditionStr   = ''
                    sourcePolicies = @()
                    allowVia       = @()
                    denyVia        = @()
                    actionNoResource = $false
                    resourceNoAction = $false
                })
            }
        }
    }
    return $rows.ToArray()
}

# Helper: nav with ../ prefix for subdirectory pages
function Get-NavHTMLForSubdir {
    param([string]$Active)
    $links = @(
        @{ id='dash'; href='../index.html';       label='Dashboard' }
        @{ id='res';  href='../resources.html';   label='Resources' }
        @{ id='id';   href='../identities.html';  label='Identities' }
        @{ id='asm';  href='../assume.html';      label='Assume-Role and Federation' }
        @{ id='find'; href='../findings.html';    label='Findings' }
        @{ id='cat';  href='../findings-catalog.html'; label='Findings Catalog' }
        @{ id='roles';href='../roles.html';       label='Roles' }
        @{ id='rdet'; href='../resources-detail.html'; label='Resource Detail' }
        @{ id='atk';  href='../attack-paths.html';label='Attack Paths' }
        @{ id='log';  href='../command-log.html'; label='Command Log' }
        @{ id='csv';  href='../resource-attachments.csv'; label='Raw CSV' }
    )
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<nav class="nav">')
    foreach ($l in $links) {
        $cls = if ($l.id -eq $Active) { ' class="on"' } else { '' }
        [void]$sb.Append("<a href=`"$($l.href)`"$cls>$($l.label)</a>")
    }
    [void]$sb.Append('</nav>')
    return $sb.ToString()
}

function Get-PageHeaderForSubdir {
    param([string]$Active)
    $ts        = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $duration  = [math]::Round(((Get-Date) - $Global:IR.StartTime).TotalMinutes, 1)
    $regions   = $Global:IR.Stats.RegionsScanned -join ', '
    $acct      = "$($Global:IR.AccountId) ($($Global:IR.AccountAlias))"
    $nav       = Get-NavHTMLForSubdir -Active $Active

@"
<div class="hdr">
  <div>
    <div class="hdr-logo">IAM-Robot</div>
    <div class="hdr-meta">
      Account: <span>$acct</span> &nbsp;|&nbsp;
      Regions: <span>$regions</span> &nbsp;|&nbsp;
      Generated: <span>$ts</span> &nbsp;|&nbsp;
      Duration: <span>${duration}min</span>
    </div>
  </div>
  <div style="margin-left:auto;text-align:right">
    <div class="stat-pill">Resources: <strong>$($Global:IR.Stats.ResourcesScanned)</strong></div>
    <div class="stat-pill">Attachments: <strong>$($Global:IR.Stats.AttachmentsFound)</strong></div>
    <div class="stat-pill">Commands: <strong>$($Global:IR.CommandLog.Count)</strong></div>
  </div>
</div>
$nav
"@
}

# ----------------------------------------------------------------
# Generate one role page
# ----------------------------------------------------------------
function New-RolePage {
    param(
        [string]$RoleArn,
        [hashtable]$RoleDetail,
        [object[]]$ResourcesUsingRole
    )

    $roleName = $RoleDetail.RoleName
    $fileName = Get-RoleFileName -RoleArn $RoleArn
    $ownAcct  = $Global:IR.AccountId

    # Effective permissions
    $effective = Build-EffectivePermissions `
        -AttachedPolicies $RoleDetail.AttachedPolicies `
        -InlinePolicies   $RoleDetail.InlinePolicies

    # Full action table
    $actionRows = Build-FullActionTable -Effective $effective -OwnAccountId $ownAcct
    $jActions = ConvertTo-SafeJson $actionRows

    # Capabilities via new library
    $caps = Invoke-CapabilityChecks -Effective $effective -ResourcesUsingRole $ResourcesUsingRole

    # Build a small action-name -> capability info map so the action table can show
    # tooltips for what an action means and which capability uses it.
    $capByAction = @{}
    foreach ($capDef in $Global:IR_Capabilities) {
        foreach ($act in $capDef.Required) {
            if (-not $capByAction.ContainsKey($act)) {
                $capByAction[$act] = New-Object System.Collections.Generic.List[object]
            }
            $capByAction[$act].Add([PSCustomObject]@{
                id       = "$($capDef.Id)"
                name     = "$($capDef.Name)"
                severity = "$($capDef.Severity)"
                impact   = "$($capDef.Impact)"
                recommend= "$($capDef.Recommend)"
            })
        }
    }
    # Convert to a plain object for JSON
    $capMap = @{}
    foreach ($k in $capByAction.Keys) { $capMap[$k] = $capByAction[$k].ToArray() }
    $jCapMap = ConvertTo-SafeJson $capMap

    # Build action -> description map covering everything in this role's action table.
    # We resolve the description for every referenced action so the modal has
    # actual content instead of generic verb-prefix fallbacks.
    $descMap = @{}
    foreach ($r in $actionRows) {
        if ($r.referenced -and -not $descMap.ContainsKey($r.action)) {
            $descMap[$r.action] = (Get-ActionDescription -Action $r.action)
        }
    }
    $jDescMap = ConvertTo-SafeJson $descMap

    # Trust principals
    $trustRows = New-Object System.Collections.Generic.List[object]
    foreach ($tp in $RoleDetail.TrustPrincipals) {
        $trustRows.Add([PSCustomObject]@{
            type    = "$($tp.Type)"
            value   = "$($tp.Value)"
            effect  = "$($tp.Effect)"
            actions = "$($tp.Actions)"
            hasExtId = [bool]$tp.HasExternalId
            hasMfa   = [bool]$tp.HasMfa
        })
    }
    $jTrust = ConvertTo-SafeJson $trustRows

    # Resources using this role
    $resourceRows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $ResourcesUsingRole) {
        $resourceFileName = Get-ResourceFileName -ResourceArn $r.ResourceArn -ResourceType $r.ResourceType -ResourceId $r.ResourceId
        $resourceRows.Add([PSCustomObject]@{
            region   = "$($r.Region)"
            resType  = "$($r.ResourceType)"
            resName  = "$($r.ResourceName)"
            resArn   = "$($r.ResourceArn)"
            attType  = "$($r.AttachmentType)"
            risk     = "$($r.RiskLevel)"
            rcls     = (Get-RiskClass $r.RiskLevel)
            detailFile = $resourceFileName
        })
    }
    $jResources = ConvertTo-SafeJson $resourceRows

    # Raw policy docs
    $trustJson = if ($RoleDetail.Trust) {
        try { $RoleDetail.Trust | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 } catch { '<unparsable>' }
    } else { '<not fetched>' }
    $rawPolHtml = New-Object System.Text.StringBuilder
    [void]$rawPolHtml.Append('<details open id="pol-__trust__"><summary>Trust policy (AssumeRolePolicyDocument)</summary><pre class="codeblock">')
    [void]$rawPolHtml.Append((ConvertTo-HtmlText $trustJson))
    [void]$rawPolHtml.Append('</pre></details>')

    $allPols = @()
    foreach ($p in $RoleDetail.AttachedPolicies) { $allPols += @{ Name=$p.Name; Arn=$p.Arn; Doc=$p.Doc; Kind='Managed' } }
    foreach ($p in $RoleDetail.InlinePolicies)   { $allPols += @{ Name=$p.Name; Arn='';     Doc=$p.Doc; Kind='Inline'  } }
    foreach ($p in $allPols) {
        $anchor = Get-PolicyAnchor -PolicyName $p.Name
        $docJson = if ($p.Doc) {
            try { $p.Doc | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 } catch { '<unparsable>' }
        } else { '<not fetched>' }
        $arnLine = if ($p.Arn) { " <span class='muted mono' style='font-size:10px'>$($p.Arn)</span>" } else { "" }
        [void]$rawPolHtml.Append("<details id=`"pol-$anchor`"><summary>$($p.Kind) policy: $(ConvertTo-HtmlText $p.Name)$arnLine</summary><pre class=`"codeblock`">")
        [void]$rawPolHtml.Append((ConvertTo-HtmlText $docJson))
        [void]$rawPolHtml.Append('</pre></details>')
    }

    # Capability cards
    $capHtml = New-Object System.Text.StringBuilder
    if ($caps.Count -eq 0) {
        [void]$capHtml.Append('<div class="empty">No known dangerous-capability patterns detected for this role.</div>')
    } else {
        foreach ($cap in $caps) {
            $sev = $cap.Severity
            $cls = Get-RiskClass $sev
            $matched  = ($cap.MatchedActions | Select-Object -Unique) -join ', '
            $sources  = ($cap.SourcePolicies | Select-Object -Unique)
            $sourceHtml = if ($sources.Count -gt 0) {
                ($sources | ForEach-Object {
                    $anchor = Get-PolicyAnchor -PolicyName $_
                    "<a href=`"#pol-$anchor`" class=`"jumpPol`">$(ConvertTo-HtmlText $_)</a>"
                }) -join ', '
            } else { '-' }
            $affectedHtml = if ($cap.AffectedResources.Count -gt 0) {
                $li = ($cap.AffectedResources | ForEach-Object {
                    "<li><span class='mono muted'>[$(ConvertTo-HtmlText $_.Region)]</span> <strong>$(ConvertTo-HtmlText $_.ResourceType)</strong> $(ConvertTo-HtmlText $_.ResourceName) <span class='bx $(Get-RiskClass $_.RiskLevel)' style='font-size:9px'>$(ConvertTo-HtmlText $_.RiskLevel)</span></li>"
                }) -join ''
                "<ul class='affected-list'>$li</ul>"
            } else {
                '<p class="muted" style="font-size:11px">No resources in scan currently use this role - capability still exists but is not yet exposed via collected attachments.</p>'
            }
            $refLink = if ($cap.Reference) {
                "<a href=`"$($cap.Reference)`" target=`"_blank`" rel=`"noopener`">$(ConvertTo-HtmlText $cap.Reference)</a>"
            } else { '-' }
            # Show downgrade context if this finding was demoted because every matching
            # action was conditioned or specifically scoped
            $limitedBadge = ''
            if ($cap.LimitedReason) {
                $origCls = Get-RiskClass $cap.OriginalSeverity
                $limitedBadge = " <span class=`"bx $origCls`" style=`"text-decoration:line-through;opacity:.6;font-size:9px`">$($cap.OriginalSeverity)</span> <span class=`"bx in`" style=`"font-size:9px`" title=`"$($cap.LimitedReason)`">LIMITED</span>"
            }
            $limitedNote = if ($cap.LimitedReason) {
                "<p style=`"font-size:11px;color:var(--in);background:#4db8ff15;padding:.4rem .6rem;border-radius:4px;border-left:2px solid var(--in)`"><strong>Severity downgraded:</strong> $(ConvertTo-HtmlText $cap.LimitedReason). The original pattern would have rated this <strong>$($cap.OriginalSeverity)</strong>; the actual grants are narrower than the catalog pattern. Still worth reviewing.</p>"
            } else { '' }
            [void]$capHtml.Append(@"
<div class="fcard $cls">
  <h4>$(ConvertTo-HtmlText $cap.Name) <span class="bx $cls">$sev</span> <span class="bx pu">$($cap.Id)</span>$limitedBadge</h4>
  <p>$(ConvertTo-HtmlText $cap.Description)</p>
  $limitedNote
  <div class="cap-grid">
    <div><strong>MITRE ATT&amp;CK:</strong> $(ConvertTo-HtmlText $cap.MitreTactic)</div>
    <div><strong>Documented by:</strong> $(ConvertTo-HtmlText $cap.Vendor)</div>
    <div><strong>Reference:</strong> $refLink</div>
  </div>
  <p style="color:var(--mu);font-size:11px"><strong>Impact:</strong> $(ConvertTo-HtmlText $cap.Impact)</p>
  <p style="color:var(--mu);font-size:11px"><strong>Recommendation:</strong> $(ConvertTo-HtmlText $cap.Recommend)</p>
  <p class="mono" style="font-size:11px"><strong>Matched actions:</strong> $matched</p>
  <p style="font-size:11px"><strong>Granted by policies:</strong> $sourceHtml</p>
  <p style="font-size:11px"><strong>Affected resources (using this role):</strong></p>
  $affectedHtml
</div>
"@)
        }
    }

    # Counters
    $allowCount = ($actionRows | Where-Object { $_.effect -eq 'Allow' }).Count
    $denyCount  = ($actionRows | Where-Object { $_.effect -eq 'Deny' }).Count
    $overridCount = ($actionRows | Where-Object { $_.effect -eq 'AllowOverriddenByDeny' }).Count
    $refCount = ($actionRows | Where-Object { $_.referenced }).Count
    $totalActions = $actionRows.Count
    $capCount   = $caps.Count

    $css = Get-SharedCSS
    $sharedJS = Get-SharedTableJS

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Role: $roleName - IAM-Robot</title>
$css
<style>
pre.codeblock{background:var(--sf2);color:var(--tx);font-family:'Cascadia Code',Consolas,monospace;
  font-size:11px;padding:.75rem;border-radius:5px;border:1px solid var(--bd);
  overflow-x:auto;max-height:520px;white-space:pre;line-height:1.4}
details{background:var(--sf);border:1px solid var(--bd);border-radius:6px;padding:.6rem .85rem;margin-bottom:.6rem}
details summary{cursor:pointer;color:var(--te);font-weight:600;font-size:12px;outline:none}
details summary:hover{color:var(--lk)}
details[open]{padding-bottom:.85rem}
details[open] summary{margin-bottom:.5rem}
.cap-grid{display:grid;grid-template-columns:1fr 1fr 2fr;gap:.5rem;font-size:11px;color:var(--mu);
  background:var(--sf2);padding:.5rem .75rem;border-radius:5px;margin:.5rem 0}
.cap-grid strong{color:var(--tx)}
.affected-list{list-style:none;padding:.5rem .8rem;font-size:11px;max-height:200px;overflow-y:auto;
  background:var(--sf2);border:1px solid var(--bd);border-radius:5px;margin-top:.25rem}
.affected-list li{padding:3px 0}
.eff-allow{color:var(--lo);font-weight:700}
.eff-deny{color:var(--cr);font-weight:700}
.eff-override{color:var(--hi);font-weight:700}
.eff-none{color:var(--mu);font-style:italic}
/* Red highlights for problem patterns */
td.action-noresource{color:var(--cr) !important;font-weight:600;
  background:linear-gradient(90deg,#ff336620 0%,transparent 100%);
  border-left:2px solid var(--cr)}
td.action-noresource::after{content:" !";color:var(--cr);font-weight:800}
td.res-noaction{background:#ff336615;border-left:2px solid var(--cr)}
td.res-noaction::before{content:"[MISMATCH] ";color:var(--cr);font-size:9px;font-weight:700}
.svc-tag{display:inline-block;font-size:9px;font-weight:700;padding:2px 8px;border-radius:9px;
  background:var(--in2);color:var(--in);border:1px solid #4db8ff55;text-transform:uppercase}
.svc-tag.svc-noncat{background:#9d4edd22;color:#c77dff;border-color:#9d4edd}
tr.row-unref td{opacity:.45;background:transparent}
tr.row-unref td.action-cell .svc-tag{opacity:.55}
.arn-pill{display:inline-block;font-size:10px;padding:1px 8px;border-radius:9px;margin:1px 2px;
  border:1px solid;font-family:'Cascadia Code',Consolas,monospace}
.arn-pill.all{background:#ff336622;color:var(--cr);border-color:var(--cr)}
.arn-pill.scoped{background:#00d48822;color:var(--lo);border-color:#00d48855}
.arn-pill.external{background:#ff8c0022;color:var(--hi);border-color:var(--hi)}
.arn-pill.broad{background:#f0c04022;color:var(--me);border-color:#f0c04055}
.arn-pill.public{background:var(--cr);color:#fff;border-color:var(--cr);font-weight:700}
.arn-expand-btn{cursor:pointer;font-size:11px;color:var(--lk);text-decoration:underline;background:none;border:0;padding:0;font-family:inherit}
.arn-expand-btn:hover{color:var(--te)}
.arn-detail-row{background:var(--sf2)}
.arn-detail-row td{padding:.6rem 1rem !important;border-left:3px solid var(--in);white-space:normal !important}
.arn-detail-list{list-style:none;padding:0;font-size:11px;margin:0;max-height:240px;overflow-y:auto}
.arn-detail-list li{padding:3px 0;border-bottom:1px dashed #1a2540;display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.arn-detail-list li:last-child{border-bottom:0}
.jumpPol{color:var(--lk);text-decoration:underline}
/* clickable action name */
td.action-cell{cursor:pointer}
td.action-cell:hover{background:#1a2540}
td.action-cell.has-cap::after{content:" *";color:var(--hi);font-weight:700}
/* clickable ARN inside the expand list */
.arn-detail-list .mono{cursor:pointer; text-decoration:underline; text-decoration-style:dotted;
  text-decoration-color:#446; text-underline-offset:2px}
.arn-detail-list .mono:hover{color:var(--te); text-decoration-color:var(--te)}
/* action info modal */
.action-modal-backdrop{position:fixed;inset:0;background:#0008;z-index:50;display:none;
  align-items:center;justify-content:center}
.action-modal-backdrop.show{display:flex}
.action-modal{background:var(--sf);border:1px solid var(--bd);border-radius:8px;
  max-width:680px;width:90%;max-height:80vh;overflow-y:auto;padding:1.2rem 1.4rem;
  box-shadow:0 8px 30px #000a}
.action-modal h3{margin:0 0 .25rem;color:var(--te);font-size:15px;font-family:monospace}
.action-modal .am-sub{color:var(--mu);font-size:11px;margin-bottom:.7rem;border-bottom:1px solid var(--bd);padding-bottom:.5rem}
.action-modal .action-desc{background:var(--sf2);color:var(--tx);font-size:12px;line-height:1.5;
  padding:.7rem .9rem;border-radius:5px;border-left:3px solid var(--te);margin-bottom:.9rem}
.action-modal h4{color:var(--lk);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin:.9rem 0 .3rem}
.action-modal .cap-row{background:var(--sf2);padding:.5rem .7rem;border-radius:5px;margin-bottom:.4rem;border-left:3px solid var(--in)}
.action-modal .cap-row.cr{border-left-color:var(--cr)}
.action-modal .cap-row.hi{border-left-color:var(--hi)}
.action-modal .cap-row.me{border-left-color:var(--me)}
.action-modal .cap-row.lo{border-left-color:var(--lo)}
.action-modal .cap-row .cap-title{font-weight:600;color:var(--tx);font-size:12px}
.action-modal .cap-row .cap-meta{font-size:10px;color:var(--mu);margin-top:.2rem}
.action-modal p{font-size:11px;color:var(--tx);margin:.2rem 0}
.action-modal .close-x{float:right;background:none;border:0;color:var(--mu);font-size:20px;cursor:pointer;padding:0 6px}
.action-modal .close-x:hover{color:var(--cr)}
</style>
</head><body>
$(Get-PageHeaderForSubdir -Active 'roles')
<div class="wrap">

<div class="sec">Role: <span class="mono" style="color:var(--te);margin-left:.5rem">$(ConvertTo-HtmlText $roleName)</span></div>
<p class="mono muted" style="font-size:11px;margin-bottom:1rem">$(ConvertTo-HtmlText $RoleArn)</p>

<div class="g5">
  <div class="card te"><div class="lbl">Catalog Actions</div><div class="val">$totalActions</div></div>
  <div class="card in"><div class="lbl">Referenced</div><div class="val">$refCount</div></div>
  <div class="card lo"><div class="lbl">Effective Allow</div><div class="val">$allowCount</div></div>
  <div class="card cr"><div class="lbl">Deny / Overridden</div><div class="val">$($denyCount + $overridCount)</div></div>
  <div class="card hi"><div class="lbl">Dangerous Capabilities</div><div class="val">$capCount</div></div>
</div>

<div class="sec">Capability Analysis <span class="ct">based on Rhino Security Labs, Prisma Cloud, Wiz, Crowdstrike, CIS, MITRE ATT&amp;CK Cloud Matrix</span></div>
$($capHtml.ToString())

<div class="sec">Effective Action Table <span class="ct">$refCount of $totalActions catalog actions referenced</span></div>
<p class="muted" style="font-size:11px;margin-bottom:.5rem">
Shows EVERY catalog action across all 23 services. Actions actually referenced by attached/inline policies appear in normal text;
unreferenced actions are dimmed (effective state = NotPermitted by implicit deny). Wildcards in policies are expanded into the
concrete actions they would grant. Click a Source Policy name to jump to its raw JSON. Click ARN counts to see the full list.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Search action / resource / policy...">
  <select id="fEffect"><option value="">All states</option><option>Allow</option><option>Deny</option><option>AllowOverriddenByDeny</option><option>NotPermitted</option></select>
  <select id="fRef"><option value="">All</option><option value="ref">Referenced only</option><option value="unref">Unreferenced (dimmed)</option></select>
  <select id="fScope"><option value="">Any scope</option><option value="all">Resource:* only</option><option value="scoped">Scoped only</option></select>
  <select id="fCond"><option value="">Any condition</option><option value="yes">Has condition</option><option value="no">No condition</option></select>
  <button id="wrapBtn" type="button">Wrap: OFF</button>
</div>
<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tblActions">
      <thead><tr>
        <th data-col="service">Svc</th>
        <th data-col="action">Action</th>
        <th data-col="effect">Effect</th>
        <th>Resource ARNs</th>
        <th data-col="conditionStr">Conditions</th>
        <th>Source Policy</th>
      </tr></thead>
      <tbody id="tbActions"></tbody>
    </table>
  </div>
  <div class="tbl-footer"><span id="actCounter"></span></div>
</div>

<div class="sec">Trust Policy (who can assume this role) <span class="ct">$($trustRows.Count) principals</span></div>
<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tblTrust">
      <thead><tr>
        <th>Principal Type</th>
        <th>Principal</th>
        <th>Effect</th>
        <th>Actions</th>
        <th>ExternalId</th>
        <th>MFA</th>
      </tr></thead>
      <tbody id="tbTrust"></tbody>
    </table>
  </div>
</div>

<div class="sec">Resources Using This Role <span class="ct">$($resourceRows.Count) attachments</span></div>
<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tblRes">
      <thead><tr>
        <th>Region</th>
        <th>Resource Type</th>
        <th>Resource</th>
        <th>Attachment Type</th>
        <th>Risk</th>
      </tr></thead>
      <tbody id="tbRes"></tbody>
    </table>
  </div>
</div>

<div class="sec">Raw Policy Documents <span class="ct">click to expand</span></div>
$($rawPolHtml.ToString())

</div>
<script>
$sharedJS

// ===== Data =====
var ACTIONS = $jActions;
var TRUST   = $jTrust;
var RES     = $jResources;
var CAP_MAP = $jCapMap;
var DESC_MAP = $jDescMap;

function effClass(e){
  if(e === 'Allow') return 'eff-allow';
  if(e === 'Deny') return 'eff-deny';
  if(e === 'AllowOverriddenByDeny') return 'eff-override';
  return 'eff-none';
}
function effLabel(e){
  if(e === 'Allow') return 'ALLOW';
  if(e === 'Deny') return 'DENY';
  if(e === 'AllowOverriddenByDeny') return 'ALLOW (Deny overrides)';
  if(e === 'NotPermitted') return 'NOT PERMITTED';
  return e;
}

// Build ARN cell. For 0/1 ARNs, render inline.
// For multiple ARNs, render a button that toggles a detail row below.
// Returns a 2-element array: [cellHtml, detailRowHtml] where detailRowHtml
// may be '' if not needed. detailRow is appended after the action row by caller.
function arnCell(resources, rowIdx){
  if(!resources || resources.length === 0) return ['<span class="muted">none</span>', ''];
  if(resources.length === 1){
    var r = resources[0];
    var arnSafe = (r.arn||'').replace(/'/g,"\\'");
    var clk = (r.arn && r.arn !== '*')
      ? ' onclick="event.stopPropagation(); jumpToResourceSearch(\''+arnSafe+'\')" style="cursor:pointer" title="Click to find matching resources: '+escHtml(r.arn)+'"'
      : ' title="'+escHtml(r.arn)+'"';
    return ['<span class="arn-pill '+r.scope+'"'+clk+'>'+escHtml(r.arn.length > 60 ? r.arn.substring(0,60)+'...' : r.arn)+'</span>', ''];
  }
  // Multiple - inline expand
  var hasAll = resources.some(function(r){ return r.scope === 'all'; });
  var hasExt = resources.some(function(r){ return r.scope === 'external'; });
  var hasPub = resources.some(function(r){ return r.scope === 'public'; });
  var ddCls = hasPub ? 'public' : (hasAll ? 'all' : (hasExt ? 'external' : 'scoped'));
  var summary = resources.length + ' ARNs';
  if (hasAll) summary += ' [includes *]';
  else if (hasExt) summary += ' [includes external]';
  var label = '<span class="arn-pill '+ddCls+'">'+summary+'</span>';
  var detId = 'arnd-'+rowIdx;
  var cell = label + ' <button class="arn-expand-btn" onclick="document.getElementById(\''+detId+'\').style.display=document.getElementById(\''+detId+'\').style.display===\'table-row\'?\'none\':\'table-row\'; return false;">[expand]</button>';

  // Detail row content - will be inserted in a second <tr> after the main row
  var items = resources.map(function(r){
    var arnSafe = (r.arn||'').replace(/'/g,"\\'");
    var clk = (r.arn && r.arn !== '*')
      ? ' onclick="jumpToResourceSearch(\''+arnSafe+'\')" title="Click to find matching resources"'
      : '';
    return '<li><span class="arn-pill '+r.scope+'">'+escHtml(r.scope)+'</span> <span class="mono" style="word-break:break-all"'+clk+'>'+escHtml(r.arn)+'</span></li>';
  }).join('');
  var detail = '<tr id="'+detId+'" class="arn-detail-row" style="display:none">' +
               '<td colspan="6"><div style="font-size:11px;color:var(--mu);margin-bottom:4px">Resource ARNs granted for this action ('+resources.length+'). Click any ARN to search.</div>' +
               '<ul class="arn-detail-list">'+items+'</ul></td></tr>';
  return [cell, detail];
}

function srcPolicyCell(policies){
  if(!policies || policies.length === 0) return '<span class="muted">-</span>';
  return policies.map(function(p){
    var anchor = p.replace(/[^A-Za-z0-9._-]/g,'-');
    return '<a href="#pol-'+anchor+'" class="jumpPol" onclick="openPol(\''+anchor+'\')">' + escHtml(p) + '</a>';
  }).join(', ');
}

// Open a <details> by id (so jump-to-policy expands it)
function openPol(anchor){
  var el = document.getElementById('pol-'+anchor);
  if(el && el.tagName === 'DETAILS'){ el.open = true; }
}

var actFiltered = ACTIONS.slice();
var actSortCol = 'service', actSortDir = 1;

function applyActSort(){
  actFiltered.sort(function(a,b){
    // Referenced ones always come before unreferenced in default sort
    if(actSortCol === 'service'){
      if(a.referenced !== b.referenced) return a.referenced ? -1 : 1;
    }
    var av = String(a[actSortCol]||'').toLowerCase();
    var bv = String(b[actSortCol]||'').toLowerCase();
    return av.localeCompare(bv) * actSortDir;
  });
}

function renderActions(){
  var q  = document.getElementById('q').value.toLowerCase();
  var fe = document.getElementById('fEffect').value;
  var fr = document.getElementById('fRef').value;
  var fs = document.getElementById('fScope').value;
  var fc = document.getElementById('fCond').value;

  actFiltered = ACTIONS.filter(function(r){
    if(fe && r.effect !== fe) return false;
    if(fr === 'ref' && !r.referenced) return false;
    if(fr === 'unref' && r.referenced) return false;
    if(fs === 'all' && !(r.resources.length === 1 && r.resources[0].scope === 'all')) return false;
    if(fs === 'scoped' && (r.resources.length === 0 || (r.resources.length === 1 && r.resources[0].scope === 'all'))) return false;
    if(fc === 'yes' && !r.hasCondition) return false;
    if(fc === 'no'  && r.hasCondition) return false;
    if(q){
      var blob = (r.action+' '+r.conditionStr+' '+(r.sourcePolicies||[]).join(',')+' '+r.resources.map(function(x){return x.arn;}).join(' ')).toLowerCase();
      if(blob.indexOf(q) < 0) return false;
    }
    return true;
  });
  applyActSort();

  var tb = document.getElementById('tbActions');
  if(actFiltered.length === 0){
    tb.innerHTML = '<tr><td colspan="6" class="empty">No matching actions.</td></tr>';
  } else {
    var html = '';
    for(var i=0; i<actFiltered.length; i++){
      var r = actFiltered[i];
      var rowClass = r.referenced ? '' : 'row-unref';
      // Red highlights for problem patterns
      var actionClasses = ['mono','action-cell'];
      // (action with no appropriate resource is determined by user data, see below)
      if(r.actionNoResource) actionClasses.push('action-noresource');
      if(CAP_MAP && CAP_MAP[r.action]) actionClasses.push('has-cap');
      var condBadge = r.hasCondition ? '<span class="tag scope">CONDITION</span> ' : '';
      var arn = arnCell(r.resources, i);
      var arnCellHtml = arn[0];
      var arnDetailRow = arn[1];
      // Mark resource cell red if all resources for this row are problematic
      var arnTdClass = r.resourceNoAction ? 'arn-cell res-noaction' : 'arn-cell';
      // Action cell wraps text in a span we click - whole td also triggers
      var actSafe = (r.action||'').replace(/'/g,"\\'");
      // Mark non-catalog rows distinctly - these are policy-referenced actions
      // we didn't have built-in knowledge of, so capability detection doesn't
      // cover them. Auditor should still review them.
      var svcTag = r.fromCatalog === false
        ? '<span class="svc-tag svc-noncat" title="Not in built-in catalog - shown because the policy references it">'+escHtml(r.service)+'</span>'
        : '<span class="svc-tag">'+escHtml(r.service)+'</span>';
      html += '<tr class="'+rowClass+'">' +
        '<td>'+svcTag+'</td>' +
        '<td class="'+actionClasses.join(' ')+'" onclick="showActionInfo(\''+actSafe+'\')" title="Click for capability info">'+escHtml(r.actionShort)+'</td>' +
        '<td class="'+effClass(r.effect)+'">'+effLabel(r.effect)+'</td>' +
        '<td class="'+arnTdClass+'">'+arnCellHtml+'</td>' +
        '<td class="mono trunc" title="'+escHtml(r.conditionStr)+'">'+condBadge+escHtml(r.conditionStr || '-')+'</td>' +
        '<td>'+srcPolicyCell(r.sourcePolicies)+'</td>' +
      '</tr>' + arnDetailRow;
    }
    tb.innerHTML = html;
  }
  document.getElementById('actCounter').textContent = 'Showing ' + actFiltered.length + ' of ' + ACTIONS.length + ' actions';
}

['q','fEffect','fRef','fScope','fCond'].forEach(function(id){
  var el = document.getElementById(id);
  var evt = (el.tagName === 'SELECT') ? 'change' : 'input';
  el.addEventListener(evt, renderActions);
});
document.querySelectorAll('#tblActions th[data-col]').forEach(function(th){
  th.addEventListener('click', function(){
    var c = th.getAttribute('data-col');
    if(actSortCol === c) actSortDir = -actSortDir; else { actSortCol = c; actSortDir = 1; }
    document.querySelectorAll('#tblActions th').forEach(function(t){ t.classList.remove('sortasc','sortdesc'); });
    th.classList.add(actSortDir > 0 ? 'sortasc' : 'sortdesc');
    renderActions();
  });
});
attachResizers(document.getElementById('tblActions'));
attachResizers(document.getElementById('tblTrust'));
attachResizers(document.getElementById('tblRes'));
wireWrapToggle('wrapBtn','tblActions');

// Trust principals
function renderTrust(){
  var tb = document.getElementById('tbTrust');
  if(!TRUST.length){
    tb.innerHTML = '<tr><td colspan="6" class="empty">No trust principals parsed.</td></tr>';
    return;
  }
  var html = '';
  for(var i=0; i<TRUST.length; i++){
    var t = TRUST[i];
    var ext = t.hasExtId ? '<span class="bx lo">ExtId</span>' : '<span class="muted">no</span>';
    var mfa = t.hasMfa   ? '<span class="bx lo">MFA</span>'   : '<span class="muted">no</span>';
    var eff = t.effect === 'Deny' ? '<span class="tag deny">DENY</span>' : '<span class="bx in">ALLOW</span>';
    html += '<tr>'+
      '<td>'+escHtml(t.type)+'</td>'+
      '<td class="mono">'+escHtml(t.value)+'</td>'+
      '<td>'+eff+'</td>'+
      '<td class="mono">'+escHtml(t.actions)+'</td>'+
      '<td>'+ext+'</td>'+
      '<td>'+mfa+'</td>'+
    '</tr>';
  }
  tb.innerHTML = html;
}

// Resources using role
function renderResources(){
  var tb = document.getElementById('tbRes');
  if(!RES.length){
    tb.innerHTML = '<tr><td colspan="5" class="empty">No resources in scan reference this role.</td></tr>';
    return;
  }
  var html = '';
  for(var i=0; i<RES.length; i++){
    var r = RES[i];
    var resLink = '<a href="../resources/' + r.detailFile + '">' + escHtml(r.resName||r.resArn) + '</a>';
    html += '<tr>'+
      '<td class="mono">'+escHtml(r.region)+'</td>'+
      '<td>'+escHtml(r.resType)+'</td>'+
      '<td class="trunc" title="'+escHtml(r.resArn)+'">'+resLink+'</td>'+
      '<td>'+escHtml(r.attType)+'</td>'+
      '<td><span class="bx '+r.rcls+'">'+escHtml(r.risk)+'</span></td>'+
    '</tr>';
  }
  tb.innerHTML = html;
}

renderActions();
renderTrust();
renderResources();

// Handle in-page #pol- hash navigation that auto-opens the details
if(location.hash && location.hash.indexOf('#pol-') === 0){
  var anchor = location.hash.substring(5);
  openPol(anchor);
  setTimeout(function(){ document.getElementById('pol-'+anchor).scrollIntoView({behavior:'smooth',block:'start'}); }, 100);
}

// Action info modal - shows capability info + recommendation when clicking action name
function showActionInfo(fullAction){
  var caps = (CAP_MAP && CAP_MAP[fullAction]) || [];
  var desc = (DESC_MAP && DESC_MAP[fullAction]) || '';
  var modal = document.getElementById('actionModal');
  var body  = document.getElementById('actionModalBody');
  var html = '<button class="close-x" onclick="closeActionInfo()">&times;</button>' +
             '<h3>' + escHtml(fullAction) + '</h3>';
  if (desc) {
    html += '<div class="action-desc">' + escHtml(desc) + '</div>';
  } else {
    html += '<div class="am-sub">IAM action.</div>';
  }
  if (caps.length === 0) {
    html += '<h4>Capabilities</h4>' +
            '<p style="color:var(--mu);font-size:11px">No capability in the catalog requires this exact action by itself. It may still be sensitive in combination with others; review the role overall.</p>';
  } else {
    html += '<h4>Capabilities that require this action (' + caps.length + ')</h4>';
    caps.forEach(function(c){
      var cls = ({CRITICAL:'cr',HIGH:'hi',MEDIUM:'me',LOW:'lo',INFO:'in'})[c.severity] || 'in';
      html += '<div class="cap-row ' + cls + '">' +
        '<div class="cap-title">' + escHtml(c.name) + ' <span class="bx ' + cls + '" style="font-size:9px">' + escHtml(c.severity) + '</span> <span class="bx pu" style="font-size:9px">' + escHtml(c.id) + '</span></div>' +
        '<div class="cap-meta"><strong>Impact:</strong> ' + escHtml(c.impact || '-') + '</div>' +
        '<div class="cap-meta"><strong>Recommend:</strong> ' + escHtml(c.recommend || '-') + '</div>' +
      '</div>';
    });
  }
  body.innerHTML = html;
  modal.classList.add('show');
}
function closeActionInfo(){ document.getElementById('actionModal').classList.remove('show'); }
document.addEventListener('keydown', function(e){ if (e.key === 'Escape') closeActionInfo(); });

// Navigate to the resources page with a wildcard search for an ARN string
function jumpToResourceSearch(arnText){
  // Strip trailing wildcards / asterisks down to the meaningful prefix
  var q = encodeURIComponent(arnText);
  // Use the resources-detail page (which we know supports search)
  window.location.href = '../resources-detail.html?q=' + q + '&wild=1';
}
</script>
<div class="action-modal-backdrop" id="actionModal" onclick="if(event.target===this) closeActionInfo()">
  <div class="action-modal" id="actionModalBody"></div>
</div>
</body></html>
"@

    return @{ FileName = $fileName; Html = $html; Capabilities = $caps }
}

# ----------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------
function Invoke-GenerateRolePages {
    if (-not $Global:IR.RoleCatalog -or $Global:IR.RoleCatalog.Count -eq 0) {
        Write-IRLog "No enriched roles - skipping per-role pages" -Level WARN
        return
    }

    $out = Join-Path $Global:IR.OutputDir "roles"
    if (-not (Test-Path $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }

    # Build resources-by-role map
    $resByRole = @{}
    foreach ($att in $Global:IR.Attachments) {
        if (-not $att.IdentityArn) { continue }
        if ($att.AttachmentType -eq 'TrustPolicy') { continue }
        if ($att.IdentityType -ne 'Role') { continue }
        if (-not $resByRole.ContainsKey($att.IdentityArn)) {
            $resByRole[$att.IdentityArn] = New-Object System.Collections.Generic.List[object]
        }
        $resByRole[$att.IdentityArn].Add($att)
    }

    $Global:IR.RoleCapabilities = @{}
    $Global:IR.RoleFileMap = @{}

    $i = 0
    $total = $Global:IR.RoleCatalog.Count
    foreach ($arn in $Global:IR.RoleCatalog.Keys) {
        $i++
        $cat = $Global:IR.RoleCatalog[$arn]
        if (-not $cat.Fetched) { continue }
        $resources = if ($resByRole.ContainsKey($arn)) { $resByRole[$arn].ToArray() } else { @() }
        try {
            $page = New-RolePage -RoleArn $arn -RoleDetail $cat -ResourcesUsingRole $resources
            $path = Join-Path $out $page.FileName
            $page.Html | Out-File $path -Encoding UTF8
            $Global:IR.RoleFileMap[$arn] = "roles/$($page.FileName)"
            $Global:IR.RoleCapabilities[$arn] = $page.Capabilities
        } catch {
            Write-IRError -Service 'RolePage' -Region 'global' -Message "$arn : $_"
        }
        if ($i % 25 -eq 0) { Write-Host "    [$i/$total] role pages built..." -ForegroundColor DarkGray }
    }
    Write-IRLog "Generated $($Global:IR.RoleFileMap.Count) per-role HTML pages in $out" -Level SUCCESS
}
