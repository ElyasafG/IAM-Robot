# Modules/IR-ResourcePages.ps1
# ============================================================
#  Per-resource detail page: resources/res-<safe-id>.html
#
#  For each resource that has any IAM attachment, show:
#    - All IAM identities attached (roles, users, services, etc)
#    - The combined effective permissions FROM those identities
#      (e.g. an EC2 instance with role X inherits X's permissions)
#    - Capability cards for combined permissions
#    - Resource-policy entries (who else can access THIS resource)
#    - Trust/principal table for resource-based policy statements
#    - Raw policy documents for both attached identities and the
#      resource policy itself
# ============================================================

function Get-ResourceFileName {
    param([string]$ResourceArn, [string]$ResourceType, [string]$ResourceId)
    $seed = if ($ResourceArn) { $ResourceArn } else { "$ResourceType-$ResourceId" }
    $safe = $seed -replace '[^A-Za-z0-9._-]','_'
    if ($safe.Length -gt 120) {
        # Hash long ARNs to keep filenames manageable
        $sha = [System.Security.Cryptography.SHA1]::Create()
        $bytes = [Text.Encoding]::UTF8.GetBytes($seed)
        $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').Substring(0,10)
        $safe = $safe.Substring(0,100) + '_' + $hash
    }
    return "res-$safe.html"
}

function New-ResourcePage {
    param(
        [string]$ResourceKey,
        [object[]]$Attachments  # all attachments for this resource
    )

    $first = $Attachments[0]
    $resName = $first.ResourceName
    $resType = $first.ResourceType
    $resId   = $first.ResourceId
    $resArn  = $first.ResourceArn
    $region  = $first.Region
    $ownAcct = $Global:IR.AccountId
    $fileName = Get-ResourceFileName -ResourceArn $resArn -ResourceType $resType -ResourceId $resId

    # Two groups of attachments:
    #  A) Identities attached AS this resource's role (e.g. EC2 instance profile, Lambda exec role)
    #     -> their permissions apply when the resource runs
    #  B) Identities granted access TO this resource via resource policy (e.g. S3 bucket policy principal)
    #     -> they can act on the resource
    # Attachment types that attach an identity AS the resource's role/profile
    $roleAttachTypes = @(
        'InstanceProfile','ExecutionRole','TaskRole','ServiceRole','NotebookRole',
        'PipelineServiceRole','BuildServiceRole','TrustPolicy','DeliveryRole','TargetRole',
        'IntegrationRole','JobRole','ClusterRole','NodeInstanceRole','AccessEntry'
    )
    $resourcePolicyAttachTypes = @(
        'ResourcePolicy','BucketPolicy','KeyPolicy','TopicPolicy','QueuePolicy',
        'RepositoryPolicy','RegistryPolicy','LambdaResourcePolicy','PrivateLinkPolicy'
    )
    $identitiesUsedByResource = @($Attachments | Where-Object {
        ($_.IdentityType -eq 'Role') -and ($roleAttachTypes -contains $_.AttachmentType -or "$($_.AttachmentType)" -match 'Role$')
    })
    $identitiesGrantedAccess = @($Attachments | Where-Object {
        $resourcePolicyAttachTypes -contains $_.AttachmentType -or "$($_.AttachmentType)" -match 'Policy$'
    })

    # Any leftover attachments - put them in "other" so they're not invisible
    $otherAttachments = @($Attachments | Where-Object {
        -not ($roleAttachTypes -contains $_.AttachmentType) -and
        -not ($resourcePolicyAttachTypes -contains $_.AttachmentType) -and
        -not ("$($_.AttachmentType)" -match 'Role$|Policy$')
    })

    # Combined effective permissions = union of all role permissions (for roles attached AS this resource's identity)
    #   PLUS any resource policy on the resource itself (so even resources with only resource-policy
    #   attachments populate the Effective Action Table - the policy describes who can do what to this resource).
    $combinedEffective = @{}
    $rolesUsedByResource = New-Object System.Collections.Generic.List[object]
    foreach ($att in $identitiesUsedByResource) {
        if (-not $Global:IR.RoleCatalog) { continue }
        if (-not $Global:IR.RoleCatalog.ContainsKey($att.IdentityArn)) { continue }
        $cat = $Global:IR.RoleCatalog[$att.IdentityArn]
        if (-not $cat.Fetched) { continue }
        $rolesUsedByResource.Add($cat)
        $partial = Build-EffectivePermissions `
            -AttachedPolicies $cat.AttachedPolicies `
            -InlinePolicies   $cat.InlinePolicies
        # Merge into combined
        foreach ($act in $partial.Keys) {
            $rec = $partial[$act]
            if (-not $combinedEffective.ContainsKey($act)) {
                $combinedEffective[$act] = @{
                    Effect = $rec.Effect
                    Resources = New-Object System.Collections.Generic.List[string]
                    Conditions = New-Object System.Collections.Generic.List[string]
                    SourcePolicies = New-Object System.Collections.Generic.List[string]
                    AllowVia = New-Object System.Collections.Generic.List[string]
                    DenyVia = New-Object System.Collections.Generic.List[string]
                }
            }
            $c = $combinedEffective[$act]
            foreach ($r in $rec.Resources)      { if (-not $c.Resources.Contains("$r"))      { [void]$c.Resources.Add("$r") } }
            foreach ($x in $rec.Conditions)     { if (-not $c.Conditions.Contains("$x"))     { [void]$c.Conditions.Add("$x") } }
            foreach ($p in $rec.SourcePolicies) { if (-not $c.SourcePolicies.Contains("$p")) { [void]$c.SourcePolicies.Add("$($cat.RoleName) >> $p") } }
            foreach ($p in $rec.AllowVia)       { if (-not $c.AllowVia.Contains("$p"))       { [void]$c.AllowVia.Add("$($cat.RoleName) >> $p") } }
            foreach ($p in $rec.DenyVia)        { if (-not $c.DenyVia.Contains("$p"))        { [void]$c.DenyVia.Add("$($cat.RoleName) >> $p") } }
            # Effect: deny still wins
            if ($c.DenyVia.Count -gt 0 -and $c.AllowVia.Count -gt 0) { $c.Effect = 'AllowOverriddenByDeny' }
            elseif ($c.DenyVia.Count -gt 0) { $c.Effect = 'Deny' }
            else { $c.Effect = 'Allow' }
        }
    }

    # ALSO ingest resource policies (bucket policies, KMS key policies, ECR repo policies, etc.)
    # These describe who can act on this resource, so they belong in the effective action table.
    # We parse the Permissions string from each resource-policy attachment.
    foreach ($att in $identitiesGrantedAccess) {
        $perms = "$($att.Permissions)"
        if (-not $perms) { continue }
        $effect = if ($att.Effect) { "$($att.Effect)" } else { 'Allow' }
        $actionList = $perms -split '[,\s;]+' | Where-Object { $_ -and $_ -match ':' }
        $principal = if ($att.IdentityName) { $att.IdentityName } else { "$($att.IdentityType)" }
        $sourceLabel = "ResourcePolicy >> $principal"
        foreach ($a in $actionList) {
            # Expand wildcards
            $expanded = Expand-ActionPattern $a
            foreach ($act in $expanded) {
                if (-not $combinedEffective.ContainsKey($act)) {
                    $combinedEffective[$act] = @{
                        Effect = $effect
                        Resources = New-Object System.Collections.Generic.List[string]
                        Conditions = New-Object System.Collections.Generic.List[string]
                        SourcePolicies = New-Object System.Collections.Generic.List[string]
                        AllowVia = New-Object System.Collections.Generic.List[string]
                        DenyVia = New-Object System.Collections.Generic.List[string]
                    }
                }
                $c = $combinedEffective[$act]
                # Resource policies grant THIS resource's actions, so the resource is its own ARN
                $selfArn = "$ResourceArn"
                if ($selfArn -and -not $c.Resources.Contains($selfArn)) { [void]$c.Resources.Add($selfArn) }
                if (-not $c.SourcePolicies.Contains($sourceLabel)) { [void]$c.SourcePolicies.Add($sourceLabel) }
                if ($effect -eq 'Allow') {
                    if (-not $c.AllowVia.Contains($sourceLabel)) { [void]$c.AllowVia.Add($sourceLabel) }
                } else {
                    if (-not $c.DenyVia.Contains($sourceLabel)) { [void]$c.DenyVia.Add($sourceLabel) }
                }
                # Deny-wins resolution
                if ($c.DenyVia.Count -gt 0 -and $c.AllowVia.Count -gt 0) { $c.Effect = 'AllowOverriddenByDeny' }
                elseif ($c.DenyVia.Count -gt 0) { $c.Effect = 'Deny' }
                else { $c.Effect = 'Allow' }
            }
        }
    }

    # Build action table v2 (full catalog) using the combined permissions
    $actionRows = if ($combinedEffective.Count -gt 0) {
        Build-FullActionTable -Effective $combinedEffective -OwnAccountId $ownAcct
    } else {
        @()
    }
    $jActions = ConvertTo-SafeJson $actionRows

    # Build action -> capability lookup map for the action info modal
    $capByAction = @{}
    if ($Global:IR_Capabilities) {
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
    }
    $capMap = @{}
    foreach ($k in $capByAction.Keys) { $capMap[$k] = $capByAction[$k].ToArray() }
    $jCapMap = ConvertTo-SafeJson $capMap

    # Per-action descriptions for the modal
    $descMap = @{}
    foreach ($r in $actionRows) {
        if ($r.referenced -and -not $descMap.ContainsKey($r.action)) {
            $descMap[$r.action] = (Get-ActionDescription -Action $r.action)
        }
    }
    $jDescMap = ConvertTo-SafeJson $descMap

    # Capability checks
    $caps = if ($combinedEffective.Count -gt 0) {
        Invoke-CapabilityChecks -Effective $combinedEffective -ResourcesUsingRole @([PSCustomObject]@{
            ResourceType = $resType; ResourceName = $resName; ResourceArn = $resArn; Region = $region;
            AttachmentType = 'CombinedIdentities'; RiskLevel = $first.RiskLevel
        })
    } else {
        @()
    }

    # Identities used by resource (rows) - render every attached identity, even
    # if its policies weren't enriched (so the section never appears empty when
    # the resource has identity attachments).
    $idsUsedRows = New-Object System.Collections.Generic.List[object]
    foreach ($att in $identitiesUsedByResource) {
        $roleFile = if ($Global:IR.RoleFileMap -and $Global:IR.RoleFileMap.ContainsKey($att.IdentityArn)) {
            "../$($Global:IR.RoleFileMap[$att.IdentityArn])"
        } else { '' }
        $enriched = ($Global:IR.RoleCatalog -and $Global:IR.RoleCatalog.ContainsKey($att.IdentityArn) -and $Global:IR.RoleCatalog[$att.IdentityArn].Fetched)
        $idsUsedRows.Add([PSCustomObject]@{
            idType   = "$($att.IdentityType)"
            idName   = "$($att.IdentityName)"
            idArn    = "$($att.IdentityArn)"
            attType  = "$($att.AttachmentType)"
            risk     = "$($att.RiskLevel)"
            rcls     = (Get-RiskClass $att.RiskLevel)
            file     = $roleFile
            enriched = $enriched
        })
    }
    # Also include trust-policy entries from $identitiesGrantedAccess for IAM::Role resources
    # (Some role-resource attachments come through trust policy)
    if ($resType -eq 'IAM::Role') {
        foreach ($att in $identitiesGrantedAccess) {
            if ($att.IdentityArn -and $att.IdentityType) {
                $roleFile = if ($Global:IR.RoleFileMap -and $Global:IR.RoleFileMap.ContainsKey($att.IdentityArn)) {
                    "../$($Global:IR.RoleFileMap[$att.IdentityArn])"
                } else { '' }
                $idsUsedRows.Add([PSCustomObject]@{
                    idType   = "$($att.IdentityType)"
                    idName   = "$($att.IdentityName)"
                    idArn    = "$($att.IdentityArn)"
                    attType  = "trusted to assume"
                    risk     = "$($att.RiskLevel)"
                    rcls     = (Get-RiskClass $att.RiskLevel)
                    file     = $roleFile
                    enriched = $false
                })
            }
        }
    }
    $jIdsUsed = ConvertTo-SafeJson $idsUsedRows

    # Resource policy access (rows)
    $accessRows = New-Object System.Collections.Generic.List[object]
    foreach ($att in $identitiesGrantedAccess) {
        $accessRows.Add([PSCustomObject]@{
            idType   = "$($att.IdentityType)"
            idName   = "$($att.IdentityName)"
            idArn    = "$($att.IdentityArn)"
            attType  = "$($att.AttachmentType)"
            effect   = $(if ($att.Effect) { "$($att.Effect)" } else { 'Allow' })
            perms    = "$($att.Permissions)"
            ext      = [bool]$att.IsExternal
            pub      = [bool]$att.IsPublic
            risk     = "$($att.RiskLevel)"
            rcls     = (Get-RiskClass $att.RiskLevel)
        })
    }
    $jAccess = ConvertTo-SafeJson $accessRows

    # Capability cards HTML
    $capHtml = New-Object System.Text.StringBuilder
    if ($caps.Count -eq 0) {
        $reason = if ($identitiesUsedByResource.Count -eq 0 -and $identitiesGrantedAccess.Count -eq 0) {
            'This resource has no IAM identities attached and no resource policy.'
        } elseif ($identitiesUsedByResource.Count -eq 0) {
            'Only a resource policy is attached (no IAM identities run as this resource). Capability analysis applies to role identities; resource-policy principals are listed under "Identities Granted Access" below.'
        } elseif ($rolesUsedByResource.Count -eq 0) {
            "$($identitiesUsedByResource.Count) identity attachment(s) exist but the role(s) were not enriched (likely beyond -MaxRolesToEnrich). Increase the cap or run with -Resume after enriching them."
        } else {
            "$($rolesUsedByResource.Count) role(s) attached, but their combined permissions did not match any catalog pattern."
        }
        [void]$capHtml.Append("<div class=`"empty`">$reason</div>")
    } else {
        foreach ($cap in $caps) {
            $sev = $cap.Severity
            $cls = Get-RiskClass $sev
            $matched  = ($cap.MatchedActions | Select-Object -Unique) -join ', '
            $sources  = ($cap.SourcePolicies | Select-Object -Unique) -join ', '
            $refLink = if ($cap.Reference) {
                "<a href=`"$($cap.Reference)`" target=`"_blank`" rel=`"noopener`">$(ConvertTo-HtmlText $cap.Reference)</a>"
            } else { '-' }
            $limitedBadge = ''
            $limitedNote  = ''
            if ($cap.LimitedReason) {
                $origCls = Get-RiskClass $cap.OriginalSeverity
                $limitedBadge = " <span class=`"bx $origCls`" style=`"text-decoration:line-through;opacity:.6;font-size:9px`">$($cap.OriginalSeverity)</span> <span class=`"bx in`" style=`"font-size:9px`" title=`"$($cap.LimitedReason)`">LIMITED</span>"
                $limitedNote  = "<p style=`"font-size:11px;color:var(--in);background:#4db8ff15;padding:.4rem .6rem;border-radius:4px;border-left:2px solid var(--in)`"><strong>Severity downgraded:</strong> $(ConvertTo-HtmlText $cap.LimitedReason). Original pattern: <strong>$($cap.OriginalSeverity)</strong>.</p>"
            }
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
  <p style="font-size:11px"><strong>Granted by:</strong> $(ConvertTo-HtmlText $sources)</p>
</div>
"@)
        }
    }

    # Raw policy docs.
    # Three categories:
    #   A) Resource policy on this resource (bucket policy, KMS key policy, ECR repo policy, etc.)
    #   B) Trust policy and attached/inline policies for every role attached AS this resource's identity
    #   C) (if applicable) the resource's own trust policy when the resource is itself an IAM::Role
    $rawPolHtml = New-Object System.Text.StringBuilder
    $polCountTotal = 0

    # Category A: resource policy from $identitiesGrantedAccess attachments.
    # These are typically all the same resource policy, so dedupe by AttachmentType.
    $resPolDocs = $identitiesGrantedAccess |
        Where-Object { $_.PolicyDocument -or $_.RawPolicy } |
        Group-Object AttachmentType
    foreach ($g in $resPolDocs) {
        $first = $g.Group[0]
        $rawDoc = if ($first.PolicyDocument) { $first.PolicyDocument } else { $first.RawPolicy }
        if (-not $rawDoc) { continue }
        $docJson = try { $rawDoc | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 -ErrorAction Stop } catch { "$rawDoc" }
        [void]$rawPolHtml.Append("<details open><summary>Resource policy ($(ConvertTo-HtmlText $g.Name)) - directly on this resource</summary><pre class=`"codeblock`">")
        [void]$rawPolHtml.Append((ConvertTo-HtmlText $docJson))
        [void]$rawPolHtml.Append('</pre></details>')
        $polCountTotal++
    }
    # Also: if we don't have PolicyDocument but we DO have Permissions string, synthesize a
    # minimal display so the auditor sees what was extracted from the resource policy.
    if ($resPolDocs.Count -eq 0 -and $identitiesGrantedAccess.Count -gt 0) {
        foreach ($att in $identitiesGrantedAccess) {
            $synth = [PSCustomObject]@{
                AttachmentType = "$($att.AttachmentType)"
                Principal      = "$($att.IdentityType): $($att.IdentityName)"
                Effect         = if ($att.Effect) { "$($att.Effect)" } else { 'Allow' }
                Permissions    = "$($att.Permissions)"
                Conditions     = "$($att.Conditions)"
            }
            $synthJson = try { $synth | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 } catch { '<unparsable>' }
            [void]$rawPolHtml.Append("<details><summary>Resource policy statement ($(ConvertTo-HtmlText $att.AttachmentType)) - extracted summary, full document not collected</summary><pre class=`"codeblock`">")
            [void]$rawPolHtml.Append((ConvertTo-HtmlText $synthJson))
            [void]$rawPolHtml.Append('</pre></details>')
            $polCountTotal++
        }
    }

    # Category B: every attached role's trust + managed + inline policies.
    foreach ($cat in $rolesUsedByResource) {
        $trustJson = if ($cat.Trust) {
            try { $cat.Trust | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 } catch { '<unparsable>' }
        } else { '<not fetched>' }
        $anchor = "role-$($cat.RoleName -replace '[^A-Za-z0-9._-]','-')-trust"
        [void]$rawPolHtml.Append("<details id=`"$anchor`"><summary>Role &quot;$(ConvertTo-HtmlText $cat.RoleName)&quot;: trust policy</summary><pre class=`"codeblock`">")
        [void]$rawPolHtml.Append((ConvertTo-HtmlText $trustJson))
        [void]$rawPolHtml.Append('</pre></details>')
        $polCountTotal++

        foreach ($p in $cat.AttachedPolicies) {
            $docJson = if ($p.Doc) {
                try { $p.Doc | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 } catch { '<unparsable>' }
            } else { '<not fetched>' }
            $arnSuffix = if ($p.Arn) { " <span class='muted mono' style='font-size:10px'>$(ConvertTo-HtmlText $p.Arn)</span>" } else { '' }
            [void]$rawPolHtml.Append("<details><summary>Role &quot;$(ConvertTo-HtmlText $cat.RoleName)&quot; - Managed policy: $(ConvertTo-HtmlText $p.Name)$arnSuffix</summary><pre class=`"codeblock`">")
            [void]$rawPolHtml.Append((ConvertTo-HtmlText $docJson))
            [void]$rawPolHtml.Append('</pre></details>')
            $polCountTotal++
        }
        foreach ($p in $cat.InlinePolicies) {
            $docJson = if ($p.Doc) {
                try { $p.Doc | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 } catch { '<unparsable>' }
            } else { '<not fetched>' }
            [void]$rawPolHtml.Append("<details><summary>Role &quot;$(ConvertTo-HtmlText $cat.RoleName)&quot; - Inline policy: $(ConvertTo-HtmlText $p.Name)</summary><pre class=`"codeblock`">")
            [void]$rawPolHtml.Append((ConvertTo-HtmlText $docJson))
            [void]$rawPolHtml.Append('</pre></details>')
            $polCountTotal++
        }
    }

    # Note attachments that exist but couldn't be enriched.
    $unenrichedAttCount = @($identitiesUsedByResource | Where-Object {
        $_.IdentityArn -and (-not $Global:IR.RoleCatalog -or
                             -not $Global:IR.RoleCatalog.ContainsKey($_.IdentityArn) -or
                             -not $Global:IR.RoleCatalog[$_.IdentityArn].Fetched)
    }).Count

    if ($polCountTotal -eq 0) {
        $reason = if ($identitiesUsedByResource.Count -eq 0 -and $identitiesGrantedAccess.Count -eq 0) {
            'No policies to display - this resource has no IAM identities attached and no resource policy.'
        } elseif ($unenrichedAttCount -gt 0) {
            "$unenrichedAttCount attached identity/identities exist but their role policies were not fetched (likely beyond -MaxRolesToEnrich). Increase that cap or rerun with -Resume to populate them here."
        } else {
            'No policy documents available for the attached identities. They may not have been enriched yet.'
        }
        [void]$rawPolHtml.Append("<div class=`"empty`">$reason</div>")
    }

    # Counters
    $allowCount = ($actionRows | Where-Object { $_.effect -eq 'Allow' }).Count
    $denyCount  = ($actionRows | Where-Object { $_.effect -eq 'Deny' }).Count
    $overridCount = ($actionRows | Where-Object { $_.effect -eq 'AllowOverriddenByDeny' }).Count
    $refCount = ($actionRows | Where-Object { $_.referenced }).Count
    $totalActions = $actionRows.Count
    $capCount = $caps.Count

    $css = Get-SharedCSS
    $sharedJS = Get-SharedTableJS

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Resource: $(ConvertTo-HtmlText $resName) - IAM-Robot</title>
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
.eff-allow{color:var(--lo);font-weight:700}
.eff-deny{color:var(--cr);font-weight:700}
.eff-override{color:var(--hi);font-weight:700}
.eff-none{color:var(--mu);font-style:italic}
.svc-tag{display:inline-block;font-size:9px;font-weight:700;padding:2px 8px;border-radius:9px;
  background:var(--in2);color:var(--in);border:1px solid #4db8ff55;text-transform:uppercase}
.svc-tag.svc-noncat{background:#9d4edd22;color:#c77dff;border-color:#9d4edd}
tr.row-unref td{opacity:.45;background:transparent}
.arn-pill{display:inline-block;font-size:10px;padding:1px 8px;border-radius:9px;margin:1px 2px;
  border:1px solid var(--bd);font-family:'Cascadia Code',Consolas,monospace}
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
.arn-detail-list .mono{cursor:pointer; text-decoration:underline; text-decoration-style:dotted;
  text-decoration-color:#446; text-underline-offset:2px}
.arn-detail-list .mono:hover{color:var(--te); text-decoration-color:var(--te)}
td.action-cell{cursor:pointer}
td.action-cell:hover{background:#1a2540}
td.action-cell.has-cap::after{content:" *";color:var(--hi);font-weight:700}
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
$(Get-PageHeaderForSubdir -Active 'rdet')
<div class="wrap">

<div class="sec">Resource: <span class="mono" style="color:var(--te);margin-left:.5rem">$(ConvertTo-HtmlText $resName)</span></div>
<p class="mono muted" style="font-size:11px;margin-bottom:.25rem">$(ConvertTo-HtmlText $resArn)</p>
<p class="muted" style="font-size:11px;margin-bottom:1rem"><strong>Type:</strong> $(ConvertTo-HtmlText $resType) &nbsp;|&nbsp; <strong>Region:</strong> $(ConvertTo-HtmlText $region) &nbsp;|&nbsp; <strong>Roles attached:</strong> $($rolesUsedByResource.Count)</p>

<div class="g5">
  <div class="card te"><div class="lbl">Total Attachments</div><div class="val">$($Attachments.Count)</div></div>
  <div class="card in"><div class="lbl">Roles Inherited From</div><div class="val">$($rolesUsedByResource.Count)</div></div>
  <div class="card lo"><div class="lbl">Effective Allow</div><div class="val">$allowCount</div></div>
  <div class="card cr"><div class="lbl">Deny / Overridden</div><div class="val">$($denyCount + $overridCount)</div></div>
  <div class="card hi"><div class="lbl">Capability Findings</div><div class="val">$capCount</div></div>
</div>

<div class="sec">Capability Analysis <span class="ct">based on combined permissions from $($rolesUsedByResource.Count) attached role(s)</span></div>
$($capHtml.ToString())

<div class="sec">Identities This Resource Uses <span class="ct">$($idsUsedRows.Count)</span></div>
<p class="muted" style="font-size:11px;margin-bottom:.5rem">
The IAM identities this resource runs/operates under (e.g. EC2 instance profile, Lambda execution role, ECS task role).
When the resource executes code, it inherits the permissions of these identities. Click any role name for its full breakdown.
</p>
<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tblIdsUsed">
      <thead><tr>
        <th>Identity Type</th>
        <th>Identity / Role</th>
        <th>Attachment Type</th>
        <th>Risk</th>
      </tr></thead>
      <tbody id="tbIdsUsed"></tbody>
    </table>
  </div>
</div>

<div class="sec">Identities Granted Access to This Resource <span class="ct">$($accessRows.Count)</span></div>
<p class="muted" style="font-size:11px;margin-bottom:.5rem">
Principals that can act on this resource via its resource-based policy (e.g. S3 bucket policy, KMS key policy, Lambda resource policy).
</p>
<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tblAccess">
      <thead><tr>
        <th>Principal Type</th>
        <th>Principal</th>
        <th>Attachment Type</th>
        <th>Effect</th>
        <th>Permissions</th>
        <th>Flags</th>
        <th>Risk</th>
      </tr></thead>
      <tbody id="tbAccess"></tbody>
    </table>
  </div>
</div>

<div class="sec">Effective Action Table <span class="ct">union of permissions from all attached identities</span></div>
<p class="muted" style="font-size:11px;margin-bottom:.5rem">
The combined effective permissions this resource has through every role attached to it.
$totalActions catalog actions total, $refCount referenced by attached policies.
Unreferenced (dimmed) actions = NotPermitted by implicit deny.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Search action / resource...">
  <select id="fEffect"><option value="">All states</option><option>Allow</option><option>Deny</option><option>AllowOverriddenByDeny</option><option>NotPermitted</option></select>
  <select id="fRef"><option value="">All</option><option value="ref">Referenced only</option><option value="unref">Unreferenced (dimmed)</option></select>
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
        <th>Source Role &gt;&gt; Policy</th>
      </tr></thead>
      <tbody id="tbActions"></tbody>
    </table>
  </div>
  <div class="tbl-footer"><span id="actCounter"></span></div>
</div>

<div class="sec">Raw Policy Documents <span class="ct">$polCountTotal documents from attached identities and resource policies</span></div>
$($rawPolHtml.ToString())

</div>
<script>
$sharedJS

var ACTIONS = $jActions;
var IDS_USED = $jIdsUsed;
var ACCESS = $jAccess;
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

// Navigate to resources-detail.html with a wildcard search.
// Path is "../resources-detail.html" because resource detail pages live in /resources/.
function jumpToResourceSearch(arnText){
  var q = encodeURIComponent(arnText);
  window.location.href = '../resources-detail.html?q=' + q + '&wild=1';
}

// Action info modal
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
            '<p style="color:var(--mu);font-size:11px">No capability in the catalog requires this exact action by itself.</p>';
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

// arnCell returns [cellHtml, detailRowHtml]
function arnCell(resources, rowIdx){
  if(!resources || resources.length === 0) return ['<span class="muted">none</span>', ''];
  if(resources.length === 1){
    var r = resources[0];
    var arnSafe = (r.arn||'').replace(/'/g,"\\'");
    var clk = (r.arn && r.arn !== '*')
      ? ' onclick="event.stopPropagation(); jumpToResourceSearch(\''+arnSafe+'\')" style="cursor:pointer" title="Click to find matching resources"'
      : ' title="'+escHtml(r.arn)+'"';
    return ['<span class="arn-pill '+r.scope+'"'+clk+'>'+escHtml(r.arn.length > 60 ? r.arn.substring(0,60)+'...' : r.arn)+'</span>', ''];
  }
  var hasAll = resources.some(function(r){ return r.scope === 'all'; });
  var hasExt = resources.some(function(r){ return r.scope === 'external'; });
  var hasPub = resources.some(function(r){ return r.scope === 'public'; });
  var ddCls = hasPub ? 'public' : (hasAll ? 'all' : (hasExt ? 'external' : 'scoped'));
  var summary = resources.length + ' ARNs';
  if (hasAll) summary += ' [includes *]';
  else if (hasExt) summary += ' [includes external]';
  var label = '<span class="arn-pill '+ddCls+'">'+summary+'</span>';
  var detId = 'arnd-res-'+rowIdx;
  var cell = label + ' <button class="arn-expand-btn" onclick="document.getElementById(\''+detId+'\').style.display=document.getElementById(\''+detId+'\').style.display===\'table-row\'?\'none\':\'table-row\'; return false;">[expand]</button>';
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

var actFiltered = ACTIONS.slice();
var actSortCol = 'service', actSortDir = 1;

function renderActions(){
  var q  = document.getElementById('q').value.toLowerCase();
  var fe = document.getElementById('fEffect').value;
  var fr = document.getElementById('fRef').value;

  actFiltered = ACTIONS.filter(function(r){
    if(fe && r.effect !== fe) return false;
    if(fr === 'ref' && !r.referenced) return false;
    if(fr === 'unref' && r.referenced) return false;
    if(q){
      var blob = (r.action+' '+r.conditionStr+' '+(r.sourcePolicies||[]).join(',')+' '+r.resources.map(function(x){return x.arn;}).join(' ')).toLowerCase();
      if(blob.indexOf(q) < 0) return false;
    }
    return true;
  });
  actFiltered.sort(function(a,b){
    if(actSortCol === 'service' && a.referenced !== b.referenced) return a.referenced ? -1 : 1;
    var av = String(a[actSortCol]||'').toLowerCase();
    var bv = String(b[actSortCol]||'').toLowerCase();
    return av.localeCompare(bv) * actSortDir;
  });
  var tb = document.getElementById('tbActions');
  if(actFiltered.length === 0){
    tb.innerHTML = '<tr><td colspan="6" class="empty">No matching actions.</td></tr>';
  } else {
    var html = '';
    for(var i=0; i<actFiltered.length; i++){
      var r = actFiltered[i];
      var rowClass = r.referenced ? '' : 'row-unref';
      var actionClasses = ['mono','action-cell'];
      if(CAP_MAP && CAP_MAP[r.action]) actionClasses.push('has-cap');
      var condBadge = r.hasCondition ? '<span class="tag scope">CONDITION</span> ' : '';
      var srcHtml = (r.sourcePolicies && r.sourcePolicies.length > 0)
        ? r.sourcePolicies.map(function(s){ return escHtml(s); }).join(', ')
        : '<span class="muted">-</span>';
      var arn = arnCell(r.resources, i);
      var actSafe = (r.action||'').replace(/'/g,"\\'");
      var svcTag = r.fromCatalog === false
        ? '<span class="svc-tag svc-noncat" title="Not in built-in catalog - shown because the policy references it">'+escHtml(r.service)+'</span>'
        : '<span class="svc-tag">'+escHtml(r.service)+'</span>';
      html += '<tr class="'+rowClass+'">' +
        '<td>'+svcTag+'</td>' +
        '<td class="'+actionClasses.join(' ')+'" onclick="showActionInfo(\''+actSafe+'\')" title="Click for capability info">'+escHtml(r.actionShort)+'</td>' +
        '<td class="'+effClass(r.effect)+'">'+effLabel(r.effect)+'</td>' +
        '<td>'+arn[0]+'</td>' +
        '<td class="mono trunc" title="'+escHtml(r.conditionStr)+'">'+condBadge+escHtml(r.conditionStr || '-')+'</td>' +
        '<td class="trunc">'+srcHtml+'</td>' +
      '</tr>' + arn[1];
    }
    tb.innerHTML = html;
  }
  document.getElementById('actCounter').textContent = 'Showing ' + actFiltered.length + ' of ' + ACTIONS.length + ' actions';
}

['q','fEffect','fRef'].forEach(function(id){
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
attachResizers(document.getElementById('tblIdsUsed'));
attachResizers(document.getElementById('tblAccess'));
wireWrapToggle('wrapBtn','tblActions');

// Identities used by resource
(function(){
  var tb = document.getElementById('tbIdsUsed');
  if(!IDS_USED.length){
    tb.innerHTML = '<tr><td colspan="4" class="empty">No IAM identities attached as this resource\'s role.</td></tr>';
    return;
  }
  var html = '';
  for(var i=0; i<IDS_USED.length; i++){
    var r = IDS_USED[i];
    var link = r.file
      ? '<a href="'+r.file+'">'+escHtml(r.idName)+'</a> <span class="bx te" style="font-size:8px">DETAIL</span>'
      : escHtml(r.idName);
    var enrichBadge = r.enriched
      ? '<span class="bx lo" style="font-size:9px">ENRICHED</span>'
      : '<span class="bx me" style="font-size:9px" title="Role policies were not fetched - increase -MaxRolesToEnrich to include this role">NOT ENRICHED</span>';
    html += '<tr>'+
      '<td>'+escHtml(r.idType)+'</td>'+
      '<td>'+link+' '+enrichBadge+'<br><span class="mono muted" style="font-size:10px">'+escHtml(r.idArn)+'</span></td>'+
      '<td>'+escHtml(r.attType)+'</td>'+
      '<td><span class="bx '+r.rcls+'">'+escHtml(r.risk)+'</span></td>'+
    '</tr>';
  }
  tb.innerHTML = html;
})();

// Access (resource-policy) rows
(function(){
  var tb = document.getElementById('tbAccess');
  if(!ACCESS.length){
    tb.innerHTML = '<tr><td colspan="7" class="empty">No resource-policy entries for this resource.</td></tr>';
    return;
  }
  var html = '';
  for(var i=0; i<ACCESS.length; i++){
    var r = ACCESS[i];
    var ext = r.ext ? '<span class="tag ext">EXT</span>' : '';
    var pub = r.pub ? '<span class="tag pub">PUB</span>' : '';
    var eff = r.effect === 'Deny' ? '<span class="tag deny">DENY</span>' : '<span class="bx in">ALLOW</span>';
    html += '<tr>'+
      '<td>'+escHtml(r.idType)+'</td>'+
      '<td class="mono trunc" title="'+escHtml(r.idArn)+'">'+escHtml(r.idName)+'</td>'+
      '<td>'+escHtml(r.attType)+'</td>'+
      '<td>'+eff+'</td>'+
      '<td class="mono trunc" title="'+escHtml(r.perms)+'">'+escHtml(r.perms)+'</td>'+
      '<td>'+ext+pub+'</td>'+
      '<td><span class="bx '+r.rcls+'">'+escHtml(r.risk)+'</span></td>'+
    '</tr>';
  }
  tb.innerHTML = html;
})();

renderActions();
</script>
<div class="action-modal-backdrop" id="actionModal" onclick="if(event.target===this) closeActionInfo()">
  <div class="action-modal" id="actionModalBody"></div>
</div>
</body></html>
"@

    return @{ FileName = $fileName; Html = $html; Capabilities = $caps; ResourceKey = $ResourceKey }
}

# ----------------------------------------------------------------
# Orchestrator: generate one page per unique resource
# ----------------------------------------------------------------
function Invoke-GenerateResourcePages {
    if (-not $Global:IR.Attachments -or $Global:IR.Attachments.Count -eq 0) {
        Write-IRLog "No attachments - skipping per-resource pages" -Level WARN
        return
    }

    $out = Join-Path $Global:IR.OutputDir "resources"
    if (-not (Test-Path $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }

    # Group attachments by resource (ARN preferred, else type+id)
    $byResource = @{}
    foreach ($att in $Global:IR.Attachments) {
        $key = if ($att.ResourceArn) { $att.ResourceArn } else { "$($att.ResourceType):$($att.ResourceId)" }
        if (-not $byResource.ContainsKey($key)) {
            $byResource[$key] = New-Object System.Collections.Generic.List[object]
        }
        $byResource[$key].Add($att)
    }

    $Global:IR.ResourceFileMap = @{}
    $Global:IR.ResourceCapabilities = @{}

    $i = 0
    $total = $byResource.Count
    foreach ($key in $byResource.Keys) {
        $i++
        try {
            $page = New-ResourcePage -ResourceKey $key -Attachments $byResource[$key].ToArray()
            $path = Join-Path $out $page.FileName
            $page.Html | Out-File $path -Encoding UTF8
            $Global:IR.ResourceFileMap[$key] = "resources/$($page.FileName)"
            $Global:IR.ResourceCapabilities[$key] = $page.Capabilities
        } catch {
            Write-IRError -Service 'ResourcePage' -Region 'global' -Message "$key : $_"
        }
        if ($i % 50 -eq 0) { Write-Host "    [$i/$total] resource pages built..." -ForegroundColor DarkGray }
    }
    Write-IRLog "Generated $($Global:IR.ResourceFileMap.Count) per-resource HTML pages in $out" -Level SUCCESS
}
