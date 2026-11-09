# Modules/IR-IndexPages.ps1
# ============================================================
#  Four top-level navigation pages:
#    roles.html              - sortable table of every enriched role,
#                              link to roles/role-*.html detail page
#    resources-detail.html   - sortable table of every resource that
#                              has a detail page in resources/
#    findings-catalog.html   - every capability check the audit knows
#                              about; shows which roles triggered it
#                              and which it could not find
#    attack-paths.html       - interactive force-directed graph of
#                              roles, resources, capabilities, and
#                              trust edges that form attack chains
# ============================================================

# ----------------------------------------------------------------
# Page 7: roles.html  -  index of every per-role detail page
# ----------------------------------------------------------------
function New-RolesIndexPage {
    $rows = New-Object System.Collections.Generic.List[object]

    if ($Global:IR.RoleCatalog) {
        # Build a map roleArn -> count of resources using it
        $usageMap = @{}
        foreach ($att in $Global:IR.Attachments) {
            if (-not $att.IdentityArn) { continue }
            if ($att.IdentityType -ne 'Role') { continue }
            if ($att.AttachmentType -eq 'TrustPolicy') { continue }
            if (-not $usageMap.ContainsKey($att.IdentityArn)) {
                $usageMap[$att.IdentityArn] = 0
            }
            $usageMap[$att.IdentityArn]++
        }

        foreach ($arn in $Global:IR.RoleCatalog.Keys) {
            $cat = $Global:IR.RoleCatalog[$arn]
            if (-not $cat.Fetched) { continue }

            $caps = if ($Global:IR.RoleCapabilities -and $Global:IR.RoleCapabilities.ContainsKey($arn)) {
                $Global:IR.RoleCapabilities[$arn]
            } else { @() }

            $capByName = $caps | ForEach-Object { $_.Name } | Sort-Object -Unique
            $worstSev = 'INFO'
            $sevRank = @{'CRITICAL'=0;'HIGH'=1;'MEDIUM'=2;'LOW'=3;'INFO'=4}
            $worstRank = 99
            foreach ($c in $caps) {
                $r = if ($sevRank.ContainsKey($c.Severity)) { $sevRank[$c.Severity] } else { 99 }
                if ($r -lt $worstRank) { $worstRank = $r; $worstSev = $c.Severity }
            }

            $fileLink = if ($Global:IR.RoleFileMap -and $Global:IR.RoleFileMap.ContainsKey($arn)) {
                $Global:IR.RoleFileMap[$arn]
            } else { '' }

            $resUsing = if ($usageMap.ContainsKey($arn)) { $usageMap[$arn] } else { 0 }

            $trustCount = if ($cat.TrustPrincipals) { @($cat.TrustPrincipals).Count } else { 0 }
            $polCount = (@($cat.AttachedPolicies).Count) + (@($cat.InlinePolicies).Count)

            # Compute breadth - count unique services and total allowed actions in the role
            $allowSvcs = New-Object System.Collections.Generic.HashSet[string]
            $totalAllow = 0
            try {
                $eff = Build-EffectivePermissions -AttachedPolicies $cat.AttachedPolicies -InlinePolicies $cat.InlinePolicies
                foreach ($a in $eff.Keys) {
                    if ($eff[$a].Effect -eq 'Allow') {
                        $totalAllow++
                        $svc = ($a -split ':')[0]
                        [void]$allowSvcs.Add($svc)
                    }
                }
            } catch { }
            # BROAD = lots of actions across many service families
            $isBroad = ($totalAllow -ge 100 -and $allowSvcs.Count -ge 10)
            # MEGA-BROAD = absurdly wide policy
            $isMegaBroad = ($totalAllow -ge 500 -and $allowSvcs.Count -ge 25)

            $rows.Add([PSCustomObject]@{
                roleName    = "$($cat.RoleName)"
                roleArn     = "$arn"
                hasAdmin    = [bool]$cat.HasAdmin
                hasSvcStar  = [bool]$cat.HasServiceStar
                capCount    = [int]$caps.Count
                worstSev    = $worstSev
                worstSevCls = (Get-RiskClass $worstSev)
                polCount    = [int]$polCount
                resUsing    = [int]$resUsing
                trustCount  = [int]$trustCount
                pageLink    = $fileLink
                allowCount  = [int]$totalAllow
                svcCount    = [int]$allowSvcs.Count
                isBroad     = [bool]$isBroad
                isMegaBroad = [bool]$isMegaBroad
            })
        }
    }

    $jRows = ConvertTo-SafeJson $rows

    $css = Get-SharedCSS
    $hdr = Get-PageHeader -Active 'roles'
    $sharedJS = Get-SharedTableJS

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Roles - IAM-Robot</title>
$css
</head><body>
$hdr
<div class="wrap">

<div class="sec">Every Enriched Role <span class="ct" id="rcount"></span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
Every IAM role in this account that the audit enriched (Step 3 + Step 4: policies and trust).
Click a role name to open its detail page with capability analysis, action table, trust, and raw policy documents.
Sort columns by clicking headers; drag column borders to resize; use Wrap: ON to see long ARNs.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Search role name or ARN...">
  <select id="fSev">
    <option value="">Any severity</option>
    <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option>
  </select>
  <select id="fCapMin"><option value="0">Any capability count</option><option value="1">1+ capabilities</option><option value="3">3+ capabilities</option><option value="5">5+ capabilities</option><option value="10">10+ capabilities</option></select>
  <select id="fUsage"><option value="">Any usage</option><option value="used">Used by resources</option><option value="unused">Orphan (no resources)</option></select>
  <select id="fTrust"><option value="">Any trust</option><option value="0">No trust principals</option><option value="1">1+ trust principals</option><option value="3">3+ trust principals</option></select>
  <select id="fBroad"><option value="">Any breadth</option><option value="broad">BROAD (>=100 actions, >=10 svcs)</option><option value="mega">MEGA-BROAD (>=500/25)</option><option value="narrow">Narrow only</option></select>
  <label><input type="checkbox" id="fAdmin"> Has Admin (*)</label>
  <label><input type="checkbox" id="fSvcStar"> Has Svc:*</label>
  <label><input type="checkbox" id="fCaps"> Has Capabilities</label>
  <button id="wrapBtn" type="button">Wrap: OFF</button>
</div>

<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tbl">
      <thead><tr>
        <th data-col="roleName">Role</th>
        <th data-col="worstSev">Worst Severity</th>
        <th data-col="capCount">Capabilities</th>
        <th data-col="polCount">Policies</th>
        <th data-col="resUsing">Resources Using</th>
        <th data-col="trustCount">Trust Principals</th>
        <th data-col="allowCount">Allow Actions</th>
        <th>Flags</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
  <div class="tbl-footer">
    <span id="counter"></span>
    <div class="pager">
      <button id="pPrev">Prev</button>
      <span id="pInfo"></span>
      <button id="pNext">Next</button>
    </div>
  </div>
</div>

</div>
<script>
$sharedJS

var RAW = $jRows;
var RANK = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4};
var PAGE_SIZE = 75;
var filtered = RAW.slice();
var sortCol = 'capCount', sortDir = -1, curPage = 1;

function applySort(){
  filtered.sort(function(a,b){
    if(sortCol === 'worstSev') return (RANK[a.worstSev]-RANK[b.worstSev]) * sortDir;
    if(sortCol === 'capCount' || sortCol === 'polCount' || sortCol === 'resUsing' || sortCol === 'trustCount'){
      return (a[sortCol] - b[sortCol]) * sortDir;
    }
    var av = String(a[sortCol]||'').toLowerCase();
    var bv = String(b[sortCol]||'').toLowerCase();
    return av.localeCompare(bv) * sortDir;
  });
}

function render(){
  var q  = document.getElementById('q').value.toLowerCase();
  var sv = document.getElementById('fSev').value;
  var cm = parseInt(document.getElementById('fCapMin').value) || 0;
  var us = document.getElementById('fUsage').value;
  var tr = parseInt(document.getElementById('fTrust').value);
  var bd = document.getElementById('fBroad').value;
  var ad = document.getElementById('fAdmin').checked;
  var ss = document.getElementById('fSvcStar').checked;
  var fc = document.getElementById('fCaps').checked;

  filtered = RAW.filter(function(r){
    if(sv && r.worstSev !== sv) return false;
    if(cm > 0 && r.capCount < cm) return false;
    if(us === 'used'   && r.resUsing === 0) return false;
    if(us === 'unused' && r.resUsing > 0)  return false;
    if(!isNaN(tr)){
      if(tr === 0 && r.trustCount > 0) return false;
      if(tr === 1 && r.trustCount < 1) return false;
      if(tr === 3 && r.trustCount < 3) return false;
    }
    if(bd === 'broad'  && !r.isBroad) return false;
    if(bd === 'mega'   && !r.isMegaBroad) return false;
    if(bd === 'narrow' && r.isBroad) return false;
    if(ad && !r.hasAdmin) return false;
    if(ss && !r.hasSvcStar) return false;
    if(fc && r.capCount === 0) return false;
    if(q){
      var blob = (r.roleName + ' ' + r.roleArn).toLowerCase();
      if(blob.indexOf(q) < 0) return false;
    }
    return true;
  });
  applySort();
  curPage = 1;
  draw();
}

function draw(){
  var start = (curPage-1)*PAGE_SIZE;
  var end = Math.min(start+PAGE_SIZE, filtered.length);
  var slice = filtered.slice(start, end);
  var tb = document.getElementById('tbody');

  if(slice.length === 0){
    tb.innerHTML = '<tr><td colspan="8" class="empty">No matching roles.</td></tr>';
  } else {
    var html = '';
    for(var i=0; i<slice.length; i++){
      var r = slice[i];
      var nameCell = r.pageLink
        ? '<a href="' + r.pageLink + '"><strong>' + escHtml(r.roleName) + '</strong></a>'
        : '<strong>' + escHtml(r.roleName) + '</strong>';
      var flags = '';
      if(r.hasAdmin)   flags += '<span class="tag adm">ADMIN *</span>';
      if(r.hasSvcStar) flags += '<span class="tag scope">SVC:*</span>';
      if(r.isMegaBroad) flags += '<span class="tag mega-broad" title="'+r.allowCount+' allowed actions across '+r.svcCount+' services">MEGA-BROAD</span>';
      else if(r.isBroad) flags += '<span class="tag broad" title="'+r.allowCount+' allowed actions across '+r.svcCount+' services">BROAD</span>';
      var sevBadge = (r.worstSev === 'INFO' && r.capCount === 0)
        ? '<span class="muted">-</span>'
        : '<span class="bx '+r.worstSevCls+'">'+r.worstSev+'</span>';
      var capCell = (r.capCount > 0)
        ? '<strong style="color:var(--cr);font-size:14px">'+r.capCount+'</strong>'
        : '<span class="muted">0</span>';
      var breadthCell;
      if (r.isMegaBroad) breadthCell = '<strong style="color:var(--cr);font-size:13px">'+r.allowCount+'</strong><br><span class="muted" style="font-size:10px">'+r.svcCount+' svcs</span>';
      else if (r.isBroad) breadthCell = '<strong style="color:#c77dff;font-size:13px">'+r.allowCount+'</strong><br><span class="muted" style="font-size:10px">'+r.svcCount+' svcs</span>';
      else if (r.allowCount > 0) breadthCell = '<span style="color:var(--tx)">'+r.allowCount+'</span><br><span class="muted" style="font-size:10px">'+r.svcCount+' svcs</span>';
      else breadthCell = '<span class="muted">0</span>';
      html += '<tr>'+
        '<td>'+nameCell+'<br><span class="mono muted" style="font-size:10px">'+escHtml(r.roleArn)+'</span></td>'+
        '<td>'+sevBadge+'</td>'+
        '<td>'+capCell+'</td>'+
        '<td>'+r.polCount+'</td>'+
        '<td><strong style="color:var(--te)">'+r.resUsing+'</strong></td>'+
        '<td>'+r.trustCount+'</td>'+
        '<td>'+breadthCell+'</td>'+
        '<td>'+flags+'</td>'+
      '</tr>';
    }
    tb.innerHTML = html;
  }

  var pages = Math.max(1, Math.ceil(filtered.length/PAGE_SIZE));
  document.getElementById('counter').textContent = 'Showing '+(filtered.length?(start+1):0)+'-'+end+' of '+filtered.length;
  document.getElementById('pInfo').textContent = 'Page '+curPage+' / '+pages;
  document.getElementById('pPrev').disabled = (curPage <= 1);
  document.getElementById('pNext').disabled = (curPage >= pages);
  document.getElementById('rcount').textContent = '- ' + RAW.length + ' roles';
}

['q','fSev','fCapMin','fUsage','fTrust','fBroad','fAdmin','fSvcStar','fCaps'].forEach(function(id){
  var el = document.getElementById(id);
  var evt = (el.type === 'checkbox' || el.tagName === 'SELECT') ? 'change' : 'input';
  el.addEventListener(evt, render);
});
document.querySelectorAll('th[data-col]').forEach(function(th){
  th.addEventListener('click', function(){
    var c = th.getAttribute('data-col');
    if(sortCol === c) sortDir = -sortDir;
    else { sortCol = c; sortDir = (c === 'capCount' || c === 'polCount' || c === 'resUsing' || c === 'trustCount' || c === 'worstSev') ? -1 : 1; }
    document.querySelectorAll('th').forEach(function(t){ t.classList.remove('sortasc','sortdesc'); });
    th.classList.add(sortDir > 0 ? 'sortasc' : 'sortdesc');
    applySort();
    draw();
  });
});
document.getElementById('pPrev').addEventListener('click', function(){ curPage = Math.max(1, curPage-1); draw(); });
document.getElementById('pNext').addEventListener('click', function(){ var p = Math.ceil(filtered.length/PAGE_SIZE); curPage = Math.min(p, curPage+1); draw(); });

attachResizers(document.getElementById('tbl'));
wireWrapToggle('wrapBtn','tbl');
render();
</script>
</body></html>
"@
}

# ----------------------------------------------------------------
# Page 8: resources-detail.html  -  index of resources with detail pages
# ----------------------------------------------------------------
function New-ResourcesDetailIndexPage {
    $rows = New-Object System.Collections.Generic.List[object]

    if ($Global:IR.ResourceFileMap -and $Global:IR.ResourceFileMap.Count -gt 0) {
        # Group attachments by ResourceArn or fallback to ResourceType+ResourceId
        $byRes = @{}
        foreach ($att in $Global:IR.Attachments) {
            $key = if ($att.ResourceArn) { $att.ResourceArn } else { "$($att.ResourceType):$($att.ResourceId)" }
            if (-not $byRes.ContainsKey($key)) {
                $byRes[$key] = New-Object System.Collections.Generic.List[object]
            }
            $byRes[$key].Add($att)
        }

        foreach ($key in $Global:IR.ResourceFileMap.Keys) {
            $atts = if ($byRes.ContainsKey($key)) { $byRes[$key] } else { @() }
            if (-not $atts -or $atts.Count -eq 0) { continue }
            $first = $atts[0]

            # Worst risk across all attachments
            $sevRank = @{'CRITICAL'=0;'HIGH'=1;'MEDIUM'=2;'LOW'=3;'INFO'=4}
            $worstRank = 99
            $worstSev = 'INFO'
            foreach ($a in $atts) {
                $r = if ($sevRank.ContainsKey($a.RiskLevel)) { $sevRank[$a.RiskLevel] } else { 99 }
                if ($r -lt $worstRank) { $worstRank = $r; $worstSev = $a.RiskLevel }
            }

            $hasPublic = ($atts | Where-Object { $_.IsPublic }).Count -gt 0
            $hasExternal = ($atts | Where-Object { $_.IsExternal }).Count -gt 0
            $idCount = (@($atts | Select-Object -ExpandProperty IdentityArn -Unique)).Count

            # Build dropdown content for the Attachments column
            $attDetails = New-Object System.Collections.Generic.List[object]
            foreach ($a in $atts) {
                $attDetails.Add([PSCustomObject]@{
                    attType  = "$($a.AttachmentType)"
                    idType   = "$($a.IdentityType)"
                    idName   = "$($a.IdentityName)"
                    idArn    = "$($a.IdentityArn)"
                    perms    = "$($a.Permissions)"
                    effect   = if ($a.Effect) { "$($a.Effect)" } else { 'Allow' }
                    risk     = "$($a.RiskLevel)"
                    rcls     = (Get-RiskClass $a.RiskLevel)
                })
            }

            # Distinct identities dropdown content
            $distinctIds = $atts | Where-Object { $_.IdentityArn } |
                Group-Object IdentityArn |
                ForEach-Object {
                    $f = $_.Group[0]
                    [PSCustomObject]@{
                        idType  = "$($f.IdentityType)"
                        idName  = "$($f.IdentityName)"
                        idArn   = "$($_.Name)"
                        count   = [int]$_.Count
                    }
                }
            $idsArr = @($distinctIds)

            $rows.Add([PSCustomObject]@{
                region       = "$($first.Region)"
                resType      = "$($first.ResourceType)"
                resName      = "$($first.ResourceName)"
                resArn       = "$($first.ResourceArn)"
                attCount     = [int]$atts.Count
                idCount      = [int]$idCount
                worstSev     = $worstSev
                worstSevCls  = (Get-RiskClass $worstSev)
                hasPublic    = $hasPublic
                hasExternal  = $hasExternal
                pageLink     = "$($Global:IR.ResourceFileMap[$key])"
                attDetails   = $attDetails.ToArray()
                idDetails    = $idsArr
            })
        }
    }

    $jRows = ConvertTo-SafeJson $rows

    # Build resource type options for filter
    $resTypes = ($rows | Select-Object -ExpandProperty resType -Unique | Sort-Object) |
        ForEach-Object { "<option>$_</option>" }
    $resTypeOpts = $resTypes -join ''
    # Region options
    $resRegions = ($rows | Select-Object -ExpandProperty region -Unique | Sort-Object | Where-Object { $_ }) |
        ForEach-Object { "<option>$_</option>" }
    $resRegionOpts = $resRegions -join ''

    $css = Get-SharedCSS
    $hdr = Get-PageHeader -Active 'rdet'
    $sharedJS = Get-SharedTableJS

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Resource Detail - IAM-Robot</title>
$css
</head><body>
$hdr
<div class="wrap">

<div class="sec">Resources with Detail Pages <span class="ct" id="rcount"></span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
Each row links to a resource detail page that shows: combined effective permissions
inherited from attached roles, capability analysis on those permissions, the resource
policy (if any), all identities granted access, and raw policy documents.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Search... (use * as wildcard, e.g. arn:aws:lambda:*:function:)">
  <label style="font-size:10px;color:var(--mu)"><input type="checkbox" id="qWild" checked> Wildcard *</label>
  <select id="fType"><option value="">All resource types</option>$resTypeOpts</select>
  <select id="fRegion"><option value="">All regions</option>$resRegionOpts</select>
  <select id="fSev">
    <option value="">Any severity</option>
    <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option>
  </select>
  <select id="fAttMin"><option value="0">Any attachment count</option><option value="1">1+ attachments</option><option value="3">3+ attachments</option><option value="5">5+ attachments</option></select>
  <select id="fIdMin"><option value="0">Any identity count</option><option value="1">1+ identities</option><option value="3">3+ identities</option><option value="5">5+ identities</option></select>
  <label><input type="checkbox" id="fPub"> Public only</label>
  <label><input type="checkbox" id="fExt"> External only</label>
  <button id="wrapBtn" type="button">Wrap: OFF</button>
</div>

<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tbl">
      <thead><tr>
        <th data-col="region">Region</th>
        <th data-col="resType">Type</th>
        <th data-col="resName">Resource</th>
        <th data-col="worstSev">Worst Risk</th>
        <th data-col="attCount">Attachments</th>
        <th data-col="idCount">Distinct Identities</th>
        <th>Flags</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
  <div class="tbl-footer">
    <span id="counter"></span>
    <div class="pager">
      <button id="pPrev">Prev</button>
      <span id="pInfo"></span>
      <button id="pNext">Next</button>
    </div>
  </div>
</div>

</div>
<script>
$sharedJS

var RAW = $jRows;
var RANK = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4};
var PAGE_SIZE = 75;
var filtered = RAW.slice();
var sortCol = 'worstSev', sortDir = 1, curPage = 1;

function applySort(){
  filtered.sort(function(a,b){
    if(sortCol === 'worstSev') return (RANK[a.worstSev]-RANK[b.worstSev]) * sortDir;
    if(sortCol === 'attCount' || sortCol === 'idCount') return (a[sortCol]-b[sortCol]) * sortDir;
    var av = String(a[sortCol]||'').toLowerCase();
    var bv = String(b[sortCol]||'').toLowerCase();
    return av.localeCompare(bv) * sortDir;
  });
}

// Build a regex from search input. * = match any (including empty).
// Other regex special chars are escaped so the search string is a literal substring
// match except for asterisks.
function buildSearchMatcher(rawQuery, useWildcard){
  var q = (rawQuery || '').trim();
  if (!q) return null;
  if (!useWildcard) {
    var lc = q.toLowerCase();
    return function(blob){ return blob.indexOf(lc) >= 0; };
  }
  // Escape every regex metachar except '*'.
  // The metachar list is built via char codes to avoid any PowerShell
  // here-string interpolation traps.
  // Codes: . + ? ^ {dollar} { } ( ) | [ ] {backslash}
  var metaCodes = [46,43,63,94,36,123,125,40,41,124,91,93,92];
  var metaSet = '';
  for (var mi = 0; mi < metaCodes.length; mi++) { metaSet += String.fromCharCode(metaCodes[mi]); }
  // Build the character class. Escape ] and \ inside the class.
  var classBody = metaSet.replace(/[\]\\]/g, function(m){ return '\\' + m; });
  var escapeRe = new RegExp('[' + classBody + ']', 'g');
  var escaped = q.replace(escapeRe, function(m){ return '\\' + m; });
  // Replace literal asterisks with .*
  var pat = escaped.replace(/\*/g, '.*');
  var re;
  try { re = new RegExp(pat, 'i'); } catch (e) { return function(blob){ return blob.indexOf(q.toLowerCase()) >= 0; }; }
  return function(blob){ return re.test(blob); };
}

function render(){
  var qRaw = document.getElementById('q').value;
  var wild = document.getElementById('qWild') ? document.getElementById('qWild').checked : false;
  var matcher = buildSearchMatcher(qRaw, wild);
  var ty  = document.getElementById('fType').value;
  var rg  = document.getElementById('fRegion').value;
  var sv  = document.getElementById('fSev').value;
  var amn = parseInt(document.getElementById('fAttMin').value) || 0;
  var imn = parseInt(document.getElementById('fIdMin').value) || 0;
  var pb  = document.getElementById('fPub').checked;
  var ex  = document.getElementById('fExt').checked;

  filtered = RAW.filter(function(r){
    if(ty && r.resType !== ty) return false;
    if(rg && r.region !== rg) return false;
    if(sv && r.worstSev !== sv) return false;
    if(amn > 0 && r.attCount < amn) return false;
    if(imn > 0 && r.idCount < imn) return false;
    if(pb && !r.hasPublic) return false;
    if(ex && !r.hasExternal) return false;
    if(matcher){
      var blob = (r.resName+' '+r.resArn+' '+r.resType).toLowerCase();
      if(!matcher(blob)) return false;
    }
    return true;
  });
  applySort();
  curPage = 1;
  draw();
}

// On page load: read ?q= and ?wild= from URL for cross-page navigation
(function applyUrlQuery(){
  try {
    var params = new URLSearchParams(window.location.search);
    var q = params.get('q');
    if (q) document.getElementById('q').value = q;
    var w = params.get('wild');
    if (w === '1' && document.getElementById('qWild')) document.getElementById('qWild').checked = true;
  } catch (e) {}
})();

// Toggle the detail row under a resource row
function toggleResDetail(rowId){
  var el = document.getElementById(rowId);
  if(!el) return;
  el.style.display = (el.style.display === 'table-row') ? 'none' : 'table-row';
}

function draw(){
  var start = (curPage-1)*PAGE_SIZE;
  var end = Math.min(start+PAGE_SIZE, filtered.length);
  var slice = filtered.slice(start, end);
  var tb = document.getElementById('tbody');

  if(slice.length === 0){
    tb.innerHTML = '<tr><td colspan="7" class="empty">No matching resources.</td></tr>';
  } else {
    var html = '';
    for(var i=0; i<slice.length; i++){
      var r = slice[i];
      var resCell = r.pageLink
        ? '<a href="'+r.pageLink+'"><strong>'+escHtml(r.resName||r.resArn)+'</strong></a>'
        : '<strong>'+escHtml(r.resName||r.resArn)+'</strong>';
      var flags = '';
      if(r.hasPublic) flags += '<span class="tag pub">PUB</span>';
      if(r.hasExternal) flags += '<span class="tag ext">EXT</span>';

      // Attachments dropdown - click count to expand
      var attRowId = 'res-att-'+(start+i);
      var attCell = '<button class="arn-expand-btn" onclick="toggleResDetail(\''+attRowId+'\'); return false;"><strong style="color:var(--te);font-size:14px">'+r.attCount+'</strong> [expand]</button>';

      // Identities dropdown
      var idRowId = 'res-id-'+(start+i);
      var idCell  = '<button class="arn-expand-btn" onclick="toggleResDetail(\''+idRowId+'\'); return false;"><strong style="color:var(--te);font-size:14px">'+r.idCount+'</strong> [expand]</button>';

      // Build the detail rows
      var attDetailRow = '<tr id="'+attRowId+'" class="arn-detail-row" style="display:none">' +
        '<td colspan="7"><div style="font-size:11px;color:var(--mu);margin-bottom:4px">Attachments ('+r.attCount+'):</div>' +
        '<ul class="arn-detail-list">';
      for(var ai=0; ai<r.attDetails.length; ai++){
        var a = r.attDetails[ai];
        attDetailRow += '<li>' +
          '<span class="bx '+a.rcls+'" style="min-width:60px;display:inline-block;text-align:center">'+escHtml(a.risk)+'</span>' +
          '<strong>'+escHtml(a.attType)+'</strong>' +
          '<span class="muted">via</span>' +
          '<span>'+escHtml(a.idType)+': '+escHtml(a.idName||'')+'</span>' +
          '<span class="muted mono" style="font-size:10px">'+escHtml(a.idArn||'')+'</span>' +
          '<span class="bx in" style="font-size:9px">'+escHtml(a.effect)+'</span>' +
          '<span class="muted mono" style="font-size:10px">perms: '+escHtml(a.perms||'')+'</span>' +
        '</li>';
      }
      attDetailRow += '</ul></td></tr>';

      var idDetailRow = '<tr id="'+idRowId+'" class="arn-detail-row" style="display:none">' +
        '<td colspan="7"><div style="font-size:11px;color:var(--mu);margin-bottom:4px">Distinct identities attached ('+r.idCount+'):</div>' +
        '<ul class="arn-detail-list">';
      for(var di=0; di<r.idDetails.length; di++){
        var d = r.idDetails[di];
        var idLink = (typeof ROLE_PAGES !== 'undefined' && ROLE_PAGES[d.idArn])
          ? '<a href="'+ROLE_PAGES[d.idArn]+'">'+escHtml(d.idName||'')+'</a>'
          : escHtml(d.idName||'');
        idDetailRow += '<li>' +
          '<span class="bx pu" style="font-size:9px">'+escHtml(d.idType)+'</span>' +
          idLink +
          '<span class="muted mono" style="font-size:10px">'+escHtml(d.idArn||'')+'</span>' +
          '<span class="bx te" style="font-size:9px">'+d.count+' attachments</span>' +
        '</li>';
      }
      idDetailRow += '</ul></td></tr>';

      html += '<tr>'+
        '<td class="mono">'+escHtml(r.region)+'</td>'+
        '<td>'+escHtml(r.resType)+'</td>'+
        '<td>'+resCell+'<br><span class="mono muted" style="font-size:10px">'+escHtml(r.resArn)+'</span></td>'+
        '<td><span class="bx '+r.worstSevCls+'">'+r.worstSev+'</span></td>'+
        '<td>'+attCell+'</td>'+
        '<td>'+idCell+'</td>'+
        '<td>'+flags+'</td>'+
      '</tr>' + attDetailRow + idDetailRow;
    }
    tb.innerHTML = html;
  }

  var pages = Math.max(1, Math.ceil(filtered.length/PAGE_SIZE));
  document.getElementById('counter').textContent = 'Showing '+(filtered.length?(start+1):0)+'-'+end+' of '+filtered.length;
  document.getElementById('pInfo').textContent = 'Page '+curPage+' / '+pages;
  document.getElementById('pPrev').disabled = (curPage <= 1);
  document.getElementById('pNext').disabled = (curPage >= pages);
  document.getElementById('rcount').textContent = '- ' + RAW.length + ' resources with detail pages';
}

['q','qWild','fType','fRegion','fSev','fAttMin','fIdMin','fPub','fExt'].forEach(function(id){
  var el = document.getElementById(id);
  var evt = (el.type === 'checkbox' || el.tagName === 'SELECT') ? 'change' : 'input';
  el.addEventListener(evt, render);
});
document.querySelectorAll('th[data-col]').forEach(function(th){
  th.addEventListener('click', function(){
    var c = th.getAttribute('data-col');
    if(sortCol === c) sortDir = -sortDir;
    else { sortCol = c; sortDir = (c === 'attCount' || c === 'idCount') ? -1 : 1; }
    document.querySelectorAll('th').forEach(function(t){ t.classList.remove('sortasc','sortdesc'); });
    th.classList.add(sortDir > 0 ? 'sortasc' : 'sortdesc');
    applySort();
    draw();
  });
});
document.getElementById('pPrev').addEventListener('click', function(){ curPage = Math.max(1, curPage-1); draw(); });
document.getElementById('pNext').addEventListener('click', function(){ var p = Math.ceil(filtered.length/PAGE_SIZE); curPage = Math.min(p, curPage+1); draw(); });

attachResizers(document.getElementById('tbl'));
wireWrapToggle('wrapBtn','tbl');
render();
</script>
</body></html>
"@
}

# ----------------------------------------------------------------
# Page 9: findings-catalog.html
#   Every capability the audit knows about, grouped by primary
#   resource-type focus, with hit/miss status and matched roles.
# ----------------------------------------------------------------
function Get-CapabilityResourceFocus {
    # Infer "primary resource type" from a capability's required actions.
    # Used to group the catalog by service family.
    param([string[]]$Required)
    if (-not $Required -or $Required.Count -eq 0) { return 'GLOBAL' }
    $svcCounts = @{}
    foreach ($a in $Required) {
        $svc = ($a -split ':')[0]
        if (-not $svcCounts.ContainsKey($svc)) { $svcCounts[$svc] = 0 }
        $svcCounts[$svc]++
    }
    # Map services to human-readable groups
    $svcGroup = @{
        'iam' = 'IAM / Identity'; 'sts' = 'IAM / Identity'
        's3'  = 'S3'; 'ec2' = 'EC2 / Compute'; 'lambda' = 'Lambda / Compute'
        'kms' = 'KMS / Encryption'
        'secretsmanager' = 'Secrets / Parameter Store'; 'ssm' = 'Secrets / Parameter Store'
        'cloudtrail' = 'Logging / Audit'; 'config' = 'Logging / Audit'
        'logs' = 'Logging / Audit'; 'cloudwatch' = 'Logging / Audit'
        'organizations' = 'Organizations'
        'dynamodb' = 'Databases'; 'rds' = 'Databases'
        'sagemaker' = 'AI / ML'; 'glue' = 'Data / ETL'
        'ecr' = 'Container Registries'; 'ecs' = 'Container / Compute'; 'eks' = 'Container / Compute'
        'codebuild' = 'CI / CD'; 'codepipeline' = 'CI / CD'
        'sqs' = 'Messaging'; 'sns' = 'Messaging'
        'guardduty' = 'Security Services'; 'securityhub' = 'Security Services'
        'macie2' = 'Security Services'; 'inspector' = 'Security Services'
    }
    # Pick the dominant service
    $best = $svcCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    $svc = $best.Key
    if ($svcGroup.ContainsKey($svc)) { return $svcGroup[$svc] }
    return $svc.ToUpper()
}

function New-FindingsCatalogPage {
    if (-not $Global:IR_Capabilities -or $Global:IR_Capabilities.Count -eq 0) {
        return @"
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Findings Catalog</title>$(Get-SharedCSS)</head>
<body>$(Get-PageHeader -Active 'cat')<div class="wrap">
<div class="empty">Capability library not loaded. Cannot render catalog.</div>
</div></body></html>
"@
    }

    # Build catalog rows
    $catRows = New-Object System.Collections.Generic.List[object]
    foreach ($cap in $Global:IR_Capabilities) {
        # Find all roles that triggered this capability
        $matchedRoles = New-Object System.Collections.Generic.List[object]
        if ($Global:IR.RoleCapabilities) {
            foreach ($arn in $Global:IR.RoleCapabilities.Keys) {
                $roleCaps = $Global:IR.RoleCapabilities[$arn]
                foreach ($rc in $roleCaps) {
                    if ($rc.Id -eq $cap.Id) {
                        $roleName = $arn.Split('/')[-1]
                        $pageLink = if ($Global:IR.RoleFileMap -and $Global:IR.RoleFileMap.ContainsKey($arn)) {
                            $Global:IR.RoleFileMap[$arn]
                        } else { '' }
                        $matchedRoles.Add([PSCustomObject]@{
                            roleName = $roleName
                            roleArn  = $arn
                            pageLink = $pageLink
                        })
                        break
                    }
                }
            }
        }

        $focus = Get-CapabilityResourceFocus -Required $cap.Required

        $catRows.Add([PSCustomObject]@{
            id          = "$($cap.Id)"
            name        = "$($cap.Name)"
            severity    = "$($cap.Severity)"
            sevCls      = (Get-RiskClass $cap.Severity)
            mitreTactic = "$($cap.MitreTactic)"
            vendor      = "$($cap.Vendor)"
            reference   = "$($cap.Reference)"
            description = "$($cap.Description)"
            impact      = "$($cap.Impact)"
            recommend   = "$($cap.Recommend)"
            required    = ($cap.Required -join ', ')
            focus       = $focus
            found       = [bool]($matchedRoles.Count -gt 0)
            roleHits    = [int]$matchedRoles.Count
            roles       = $matchedRoles.ToArray()
        })
    }

    $jCat = ConvertTo-SafeJson $catRows

    # Dashboard counters
    $totalCaps    = $catRows.Count
    $foundCaps    = ($catRows | Where-Object { $_.found }).Count
    $notFoundCaps = $totalCaps - $foundCaps
    $criticalFound = ($catRows | Where-Object { $_.found -and $_.severity -eq 'CRITICAL' }).Count
    $highFound     = ($catRows | Where-Object { $_.found -and $_.severity -eq 'HIGH' }).Count

    # By focus group
    $byFocus = $catRows | Group-Object focus | Sort-Object Count -Descending
    $focusLabels = @($byFocus | ForEach-Object { $_.Name })
    $focusFound  = @($byFocus | ForEach-Object { ($_.Group | Where-Object { $_.found }).Count })
    $focusTotal  = @($byFocus | ForEach-Object { $_.Count })
    $jFocusLab   = ConvertTo-SafeJson $focusLabels
    $jFocusFound = ConvertTo-SafeJson $focusFound
    $jFocusTotal = ConvertTo-SafeJson $focusTotal

    # Focus options for filter
    $focusOpts = ($catRows | Select-Object -ExpandProperty focus -Unique | Sort-Object) |
        ForEach-Object { "<option>$_</option>" }
    $focusOptsHtml = $focusOpts -join ''

    $css = Get-SharedCSS
    $hdr = Get-PageHeader -Active 'cat'
    $sharedJS = Get-SharedTableJS

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Findings Catalog - IAM-Robot</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
$css
<style>
.mitre-grid{display:flex;gap:6px;overflow-x:auto;padding:.5rem 0 1rem;align-items:flex-start}
.mitre-col{min-width:180px;max-width:180px;display:flex;flex-direction:column;gap:4px}
.mitre-head{font-size:11px;font-weight:700;color:var(--tx);text-align:center;
  padding:.4rem;background:var(--sf2);border:1px solid var(--bd);border-radius:5px;
  min-height:40px;display:flex;flex-direction:column;justify-content:center}
.mitre-cell{display:block;text-decoration:none;color:inherit;
  padding:6px 8px;font-size:10px;border-radius:4px;border:1px solid var(--bd);
  transition:transform .1s, box-shadow .1s;cursor:pointer}
.mitre-cell:hover{transform:translateY(-1px);box-shadow:0 2px 6px #0006}
.mitre-cell-id{font-family:'Cascadia Code',Consolas,monospace;font-weight:700;font-size:9px;letter-spacing:.05em;opacity:.85}
.mitre-cell-name{font-size:10px;line-height:1.25;margin-top:2px}
.mitre-cell.notfound{background:var(--sf);color:var(--mu);border-color:#1a2540}
.mitre-cell.found.cr{background:#ff336622;color:var(--cr);border-color:var(--cr);font-weight:600}
.mitre-cell.found.hi{background:#ff8c0022;color:var(--hi);border-color:var(--hi);font-weight:600}
.mitre-cell.found.me{background:#f0c04022;color:var(--me);border-color:#f0c04055;font-weight:600}
.mitre-cell.found.lo{background:#00d48822;color:var(--lo);border-color:#00d48855;font-weight:600}
.mitre-cell.found.in{background:#4db8ff22;color:var(--in);border-color:#4db8ff55;font-weight:600}
.fcard{scroll-margin-top:80px}
</style>
</head><body>
$hdr
<div class="wrap">

<div class="g4">
  <div class="card te"><div class="lbl">Total Capability Checks</div><div class="val">$totalCaps</div></div>
  <div class="card cr"><div class="lbl">Found in Account</div><div class="val">$foundCaps</div></div>
  <div class="card lo"><div class="lbl">Not Found</div><div class="val">$notFoundCaps</div></div>
  <div class="card hi"><div class="lbl">Critical Hits</div><div class="val">$criticalFound</div></div>
</div>

<div class="g2">
  <div class="chart-wrap"><h3>Found vs Not-Found by Resource Focus</h3><canvas id="cFocus"></canvas></div>
  <div class="chart-wrap"><h3>Severity of Hits</h3><canvas id="cSev"></canvas></div>
</div>

<div class="sec">MITRE ATT&amp;CK Matrix <span class="ct">tactics + matched capabilities</span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
Each column is a MITRE Cloud tactic. Each box is a capability check.
<span style="color:var(--cr);font-weight:600">Red/orange</span> = found in this account.
<span style="color:var(--mu)">Grey</span> = not detected.
Click any box to jump to its detail card below.
</p>
<div id="mitreGrid"></div>

<div class="sec">Capability Catalog <span class="ct">$totalCaps checks across $($byFocus.Count) focus areas</span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
Every capability pattern this audit knows about. Cards where "Found" is yes link to the roles that triggered the pattern;
cards where "Found" is no are still useful as preventative reminders. Filter by focus area or severity.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Search name, MITRE, vendor, actions...">
  <select id="fFocus"><option value="">All focus areas</option>$focusOptsHtml</select>
  <select id="fSev"><option value="">Any severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
  <select id="fStatus"><option value="">Any status</option><option value="found">Found only</option><option value="notfound">Not found only</option></select>
</div>

<div id="catBody"></div>

</div>
<script>
$sharedJS

var CAT = $jCat;
var FOCUS_LAB = $jFocusLab;
var FOCUS_FOUND = $jFocusFound;
var FOCUS_TOTAL = $jFocusTotal;

var palette = {cr:'#ff3366',hi:'#ff8c00',me:'#f0c040',lo:'#00d488',in:'#4db8ff',pu:'#a855f7',te:'#00d4aa'};

// Stacked bar: found / not-found per focus
new Chart(document.getElementById('cFocus'),{
  type:'bar',
  data:{
    labels: FOCUS_LAB,
    datasets:[
      {label:'Found', data: FOCUS_FOUND, backgroundColor: palette.cr+'aa', borderColor: palette.cr, borderWidth:1.5},
      {label:'Not found', data: FOCUS_TOTAL.map(function(t,i){return t - FOCUS_FOUND[i];}), backgroundColor: palette.lo+'55', borderColor: palette.lo, borderWidth:1.5}
    ]
  },
  options:{
    responsive:true, maintainAspectRatio:false, indexAxis:'y',
    scales:{x:{stacked:true,grid:{color:'#1e2d4a'},ticks:{color:'#6b82b0',font:{size:10}}},
            y:{stacked:true,grid:{color:'#1e2d4a'},ticks:{color:'#6b82b0',font:{size:10}}}},
    plugins:{legend:{labels:{color:'#6b82b0',font:{size:11}}}}
  }
});

// Doughnut: severity of hits
var foundCaps = CAT.filter(function(c){ return c.found; });
var sevCounts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'INFO':0};
foundCaps.forEach(function(c){ sevCounts[c.severity] = (sevCounts[c.severity]||0)+1; });
new Chart(document.getElementById('cSev'),{
  type:'doughnut',
  data:{
    labels:['CRITICAL','HIGH','MEDIUM','LOW','INFO'],
    datasets:[{
      data:[sevCounts.CRITICAL,sevCounts.HIGH,sevCounts.MEDIUM,sevCounts.LOW,sevCounts.INFO],
      backgroundColor:[palette.cr+'aa',palette.hi+'aa',palette.me+'aa',palette.lo+'aa',palette.in+'aa'],
      borderColor:[palette.cr,palette.hi,palette.me,palette.lo,palette.in], borderWidth:2
    }]
  },
  options:{responsive:true,maintainAspectRatio:false,cutout:'58%',
    plugins:{legend:{position:'right',labels:{color:'#6b82b0',font:{size:11}}}}}
});

function renderCat(){
  var q = document.getElementById('q').value.toLowerCase();
  var fo = document.getElementById('fFocus').value;
  var fs = document.getElementById('fSev').value;
  var st = document.getElementById('fStatus').value;

  var filtered = CAT.filter(function(c){
    if(fo && c.focus !== fo) return false;
    if(fs && c.severity !== fs) return false;
    if(st === 'found' && !c.found) return false;
    if(st === 'notfound' && c.found) return false;
    if(q){
      var blob = (c.id+' '+c.name+' '+c.mitreTactic+' '+c.vendor+' '+c.required+' '+c.description).toLowerCase();
      if(blob.indexOf(q) < 0) return false;
    }
    return true;
  });

  // Group by focus
  var groups = {};
  filtered.forEach(function(c){
    if(!groups[c.focus]) groups[c.focus] = [];
    groups[c.focus].push(c);
  });
  var focusList = Object.keys(groups).sort();

  var html = '';
  for(var fi=0; fi<focusList.length; fi++){
    var focus = focusList[fi];
    var items = groups[focus];
    items.sort(function(a,b){
      var ra = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[a.severity];
      var rb = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[b.severity];
      if(ra !== rb) return ra - rb;
      return a.id.localeCompare(b.id);
    });

    html += '<div class="sec">'+escHtml(focus)+' <span class="ct">'+items.length+' checks ('+
            items.filter(function(c){return c.found;}).length+' found)</span></div>';

    for(var i=0; i<items.length; i++){
      var c = items[i];
      var foundBadge = c.found
        ? '<span class="bx cr">FOUND ('+c.roleHits+' roles)</span>'
        : '<span class="bx lo">not found</span>';
      var refLink = c.reference
        ? '<a href="'+escHtml(c.reference)+'" target="_blank" rel="noopener">'+escHtml(c.reference)+'</a>'
        : '-';
      var rolesList = '';
      if(c.found && c.roles && c.roles.length > 0){
        rolesList = '<p style="font-size:11px;margin-top:.5rem"><strong>Matched roles:</strong></p><ul class="affected-list">';
        for(var k=0; k<c.roles.length; k++){
          var r = c.roles[k];
          var roleLink = r.pageLink
            ? '<a href="'+r.pageLink+'">'+escHtml(r.roleName)+'</a>'
            : escHtml(r.roleName);
          rolesList += '<li>'+roleLink+' <span class="mono muted" style="font-size:10px">'+escHtml(r.roleArn)+'</span></li>';
        }
        rolesList += '</ul>';
      }

      html += '<div class="fcard '+c.sevCls+'" id="cap-'+escHtml(c.id)+'" data-cap-id="'+escHtml(c.id)+'">' +
        '<h4>'+escHtml(c.name)+' <span class="bx '+c.sevCls+'">'+c.severity+'</span> <span class="bx pu">'+escHtml(c.id)+'</span> '+foundBadge+'</h4>' +
        '<p>'+escHtml(c.description)+'</p>' +
        '<div class="cap-grid">' +
          '<div><strong>MITRE ATT&amp;CK:</strong> '+escHtml(c.mitreTactic)+'</div>' +
          '<div><strong>Documented by:</strong> '+escHtml(c.vendor)+'</div>' +
          '<div><strong>Reference:</strong> '+refLink+'</div>' +
        '</div>' +
        '<p style="color:var(--mu);font-size:11px"><strong>Impact:</strong> '+escHtml(c.impact)+'</p>' +
        '<p style="color:var(--mu);font-size:11px"><strong>Recommendation:</strong> '+escHtml(c.recommend)+'</p>' +
        '<p class="mono" style="font-size:11px"><strong>Required actions:</strong> '+escHtml(c.required)+'</p>' +
        rolesList +
      '</div>';
    }
  }

  if(filtered.length === 0){
    html = '<div class="empty">No matching capabilities.</div>';
  }
  document.getElementById('catBody').innerHTML = html;
}

['q','fFocus','fSev','fStatus'].forEach(function(id){
  var el = document.getElementById(id);
  var evt = (el.tagName === 'SELECT') ? 'change' : 'input';
  el.addEventListener(evt, renderCat);
});

// MITRE matrix - group capabilities by tactic
function renderMitre(){
  var tactics = {};
  CAT.forEach(function(c){
    // Extract tactic prefix: "TA0004 Privilege Escalation (T1098)" -> "TA0004 Privilege Escalation"
    var m = (c.mitreTactic||'').match(/^(TA\d+\s+[^(]+?)(?:\s*\(|$)/);
    var key = m ? m[1].trim() : (c.mitreTactic || 'Unmapped');
    if (!tactics[key]) tactics[key] = [];
    tactics[key].push(c);
  });

  // Order tactics by their TA number
  var orderedKeys = Object.keys(tactics).sort(function(a,b){
    var na = (a.match(/TA(\d+)/)||[0,99])[1];
    var nb = (b.match(/TA(\d+)/)||[0,99])[1];
    return parseInt(na) - parseInt(nb);
  });

  // Build column structure
  var html = '<div class="mitre-grid">';
  orderedKeys.forEach(function(tac){
    var items = tactics[tac];
    var foundN = items.filter(function(x){return x.found;}).length;
    html += '<div class="mitre-col">' +
      '<div class="mitre-head">' + escHtml(tac) + '<br><span style="font-size:9px;font-weight:400">' + foundN + '/' + items.length + ' found</span></div>';
    // Sort items: found first, by severity
    items.sort(function(a,b){
      if (a.found !== b.found) return a.found ? -1 : 1;
      return {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[a.severity] - {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[b.severity];
    });
    items.forEach(function(c){
      var cls = c.found ? ('mitre-cell found ' + c.sevCls) : 'mitre-cell notfound';
      var anchor = 'cap-' + c.id;
      html += '<a href="#' + anchor + '" class="' + cls + '" onclick="jumpToCap(\'' + c.id + '\')" title="' + escHtml(c.name) + (c.found ? ' (found: ' + c.roleHits + ' roles)' : ' (not detected)') + '">' +
        '<div class="mitre-cell-id">' + escHtml(c.id) + (c.found ? ' &#x2713;' : '') + '</div>' +
        '<div class="mitre-cell-name">' + escHtml(c.name.replace(/^[^:]+:\s*/,'')) + '</div>' +
      '</a>';
    });
    html += '</div>';
  });
  html += '</div>';
  document.getElementById('mitreGrid').innerHTML = html;
}

function jumpToCap(id){
  // Force filters off so the card is visible
  document.getElementById('q').value = id;
  renderCat();
  // After re-render, scroll to the card
  setTimeout(function(){
    var el = document.querySelector('[data-cap-id="'+id+'"]');
    if(el) el.scrollIntoView({behavior:'smooth', block:'center'});
  }, 100);
}

renderMitre();
renderCat();
</script>
</body></html>
"@
}

# ----------------------------------------------------------------
# Page 10: attack-paths.html
#   Interactive force-directed graph of roles, resources, and
#   capabilities. Nodes are clickable - they jump to their detail page.
# ----------------------------------------------------------------
function New-AttackPathsPage {
    # Build nodes + edges
    $nodes = New-Object System.Collections.Generic.List[object]
    $edges = New-Object System.Collections.Generic.List[object]
    $seen  = @{}

    function Add-AtkNode {
        param($Id, $Label, $Type, $Severity = 'INFO', $Link = '')
        if ($seen.ContainsKey($Id)) { return }
        $seen[$Id] = $true
        $nodes.Add([PSCustomObject]@{
            id       = "$Id"
            label    = "$Label"
            type     = "$Type"
            severity = "$Severity"
            sevCls   = (Get-RiskClass $Severity)
            link     = "$Link"
        }) | Out-Null
    }

    # Add role nodes (only those with capabilities)
    if ($Global:IR.RoleCapabilities) {
        foreach ($arn in $Global:IR.RoleCapabilities.Keys) {
            $caps = $Global:IR.RoleCapabilities[$arn]
            if (-not $caps -or $caps.Count -eq 0) { continue }
            $cat = $Global:IR.RoleCatalog[$arn]
            $roleName = if ($cat) { $cat.RoleName } else { $arn.Split('/')[-1] }

            # Worst severity for the role
            $sevRank = @{'CRITICAL'=0;'HIGH'=1;'MEDIUM'=2;'LOW'=3;'INFO'=4}
            $worstRank = 99; $worstSev = 'INFO'
            foreach ($c in $caps) {
                $r = if ($sevRank.ContainsKey($c.Severity)) { $sevRank[$c.Severity] } else { 99 }
                if ($r -lt $worstRank) { $worstRank = $r; $worstSev = $c.Severity }
            }

            $link = if ($Global:IR.RoleFileMap -and $Global:IR.RoleFileMap.ContainsKey($arn)) {
                $Global:IR.RoleFileMap[$arn]
            } else { '' }
            Add-AtkNode -Id "role::$arn" -Label $roleName -Type 'role' -Severity $worstSev -Link $link

            # Add capability nodes and edges from role -> capability
            $catInfo = if ($Global:IR.RoleCatalog -and $Global:IR.RoleCatalog.ContainsKey($arn)) { $Global:IR.RoleCatalog[$arn] } else { $null }
            $effective = $null
            if ($catInfo -and $catInfo.Fetched) {
                try {
                    $effective = Build-EffectivePermissions `
                        -AttachedPolicies $catInfo.AttachedPolicies `
                        -InlinePolicies   $catInfo.InlinePolicies
                } catch { $effective = $null }
            }
            foreach ($c in $caps) {
                $capId = "cap::$($c.Id)"
                Add-AtkNode -Id $capId -Label $c.Name -Type 'capability' -Severity $c.Severity -Link 'findings-catalog.html'
                # Determine if any of the required matched actions was conditioned or ARN-specific
                $conditioned = $false
                $arnSpecific = $false
                if ($effective -and $c.MatchedActions) {
                    foreach ($ma in $c.MatchedActions) {
                        if ($effective.ContainsKey("$ma")) {
                            $rec = $effective["$ma"]
                            if ($rec.Conditions -and $rec.Conditions.Count -gt 0) { $conditioned = $true }
                            foreach ($r in $rec.Resources) {
                                if ("$r" -ne '*' -and "$r" -notmatch '^arn:aws:[^:]+:::?\*$') { $arnSpecific = $true }
                            }
                        }
                    }
                }
                $edges.Add([PSCustomObject]@{
                    source = "role::$arn"
                    target = $capId
                    type   = 'enables'
                    severity = "$($c.Severity)"
                    sevCls = (Get-RiskClass $c.Severity)
                    conditioned = $conditioned
                    arnSpecific = $arnSpecific
                }) | Out-Null
            }
        }
    }

    # Add resource nodes - only resources whose attached roles are in the graph
    if ($Global:IR.RoleCapabilities -and $Global:IR.ResourceFileMap) {
        foreach ($att in $Global:IR.Attachments) {
            if (-not $att.IdentityArn) { continue }
            if ($att.IdentityType -ne 'Role') { continue }
            if ($att.AttachmentType -eq 'TrustPolicy') { continue }
            $roleArn = $att.IdentityArn
            $roleNodeId = "role::$roleArn"
            if (-not $seen.ContainsKey($roleNodeId)) { continue }

            $resKey = if ($att.ResourceArn) { $att.ResourceArn } else { "$($att.ResourceType):$($att.ResourceId)" }
            $resNodeId = "res::$resKey"
            $resLink = if ($Global:IR.ResourceFileMap.ContainsKey($resKey)) {
                "$($Global:IR.ResourceFileMap[$resKey])"
            } else { '' }
            $resName = if ($att.ResourceName) { $att.ResourceName } else { $att.ResourceId }
            Add-AtkNode -Id $resNodeId -Label "$resName" -Type 'resource' -Severity $att.RiskLevel -Link $resLink

            $edges.Add([PSCustomObject]@{
                source = $roleNodeId
                target = $resNodeId
                type   = 'attached-to'
                severity = "$($att.RiskLevel)"
                sevCls = (Get-RiskClass $att.RiskLevel)
            }) | Out-Null
        }
    }

    # Add trust edges - role X can be assumed by principal Y (Y -> X)
    if ($Global:IR.RoleCatalog) {
        foreach ($arn in $Global:IR.RoleCatalog.Keys) {
            $cat = $Global:IR.RoleCatalog[$arn]
            if (-not $cat.Fetched) { continue }
            $targetNodeId = "role::$arn"
            if (-not $seen.ContainsKey($targetNodeId)) { continue }
            foreach ($tp in $cat.TrustPrincipals) {
                # Only inter-role trust edges visualize well; skip service principals to reduce noise
                if ($tp.Type -ne 'AWS' -and $tp.Type -ne 'Federated' -and $tp.Type -ne 'Public') { continue }
                $srcId = "trust::$($tp.Value)"
                $sev = if ($tp.Type -eq 'Public') { 'CRITICAL' }
                       elseif (-not $tp.HasExternalId -and $tp.Value -match '^arn:aws:iam::(\d+):' -and $Matches[1] -ne $Global:IR.AccountId) { 'HIGH' }
                       else { 'MEDIUM' }
                Add-AtkNode -Id $srcId -Label $tp.Value -Type 'trust-principal' -Severity $sev
                $edges.Add([PSCustomObject]@{
                    source = $srcId
                    target = $targetNodeId
                    type   = 'can-assume'
                    severity = $sev
                    sevCls = (Get-RiskClass $sev)
                }) | Out-Null
            }
        }
    }

    $jNodes = ConvertTo-SafeJson $nodes
    $jEdges = ConvertTo-SafeJson $edges

    # Summary
    $totalNodes = $nodes.Count
    $totalEdges = $edges.Count
    $roleNodes  = ($nodes | Where-Object { $_.type -eq 'role' }).Count
    $resNodes   = ($nodes | Where-Object { $_.type -eq 'resource' }).Count
    $capNodes   = ($nodes | Where-Object { $_.type -eq 'capability' }).Count
    $trustNodes = ($nodes | Where-Object { $_.type -eq 'trust-principal' }).Count

    $css = Get-SharedCSS
    $hdr = Get-PageHeader -Active 'atk'
    $sharedJS = Get-SharedTableJS

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Paths - IAM-Robot</title>
<script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
$css
<style>
#graph { width:100%; height:780px; background:var(--sf); border:1px solid var(--bd); border-radius:8px;
         position:relative; overflow:hidden; cursor:grab }
#graph.dragging { cursor:grabbing }
#graph svg { width:100%; height:100%; display:block }
.node-role      { fill:#a855f7; stroke:#a855f7 }
.node-resource  { fill:#00d4aa; stroke:#00d4aa }
.node-capability{ fill:#ff8c00; stroke:#ff8c00 }
.node-trust-principal{ fill:#ff3366; stroke:#ff3366 }
.node-CRITICAL  { stroke:#ff3366; stroke-width:3 }
.node-HIGH      { stroke:#ff8c00; stroke-width:2.5 }
.node-MEDIUM    { stroke:#f0c040; stroke-width:2 }
.node-LOW       { stroke:#00d488; stroke-width:1.5 }
.node-INFO      { stroke:#4db8ff; stroke-width:1.5 }
.edge { stroke:#2a3a5c; stroke-opacity:.5; fill:none; pointer-events:none }
.edge.CRITICAL { stroke:#ff3366; stroke-opacity:.7 }
.edge.HIGH     { stroke:#ff8c00; stroke-opacity:.6 }
.edge.MEDIUM   { stroke:#f0c040; stroke-opacity:.5 }
.edge.LOW      { stroke:#00d488; stroke-opacity:.5 }
.edge.attached-to { stroke-dasharray: 4 2 }
.edge.can-assume  { stroke-dasharray: 1 3 }
/* Conditioned enables-edges - light orange overrides severity color */
.edge.conditioned { stroke:#ffb86c !important; stroke-opacity:.55 !important; stroke-dasharray: 2 2 }
.edge.conditioned.highlight { stroke:#ffd9a8 !important; stroke-opacity:1 !important }
.edge.dimmed { stroke-opacity:.07 !important }
.edge.highlight { stroke-opacity:1 !important; stroke-width:2.5 !important }
.node-label { font-size:10px; fill:#d4e0ff; pointer-events:none; font-family:'Segoe UI',sans-serif }
.node:hover circle { stroke-width:4 !important; cursor:pointer }
.node.dimmed { opacity:.12 }
.node.highlight circle { stroke-width:4 !important; filter:drop-shadow(0 0 4px currentColor) }
.legend { position:absolute; top:.75rem; right:.75rem; background:var(--sf2);
          border:1px solid var(--bd); padding:.5rem .75rem; border-radius:6px;
          font-size:11px; z-index:5 }
.legend-item { display:flex; align-items:center; gap:6px; margin:2px 0 }
.legend-dot { width:12px; height:12px; border-radius:50%; display:inline-block }
#searchHit { position:absolute; top:.75rem; left:.75rem; background:var(--sf2);
             border:1px solid var(--bd); padding:.4rem .6rem; border-radius:6px;
             font-size:11px; color:var(--mu); z-index:5; display:none }
.graph-container { display:grid; grid-template-columns: 1fr 320px; gap:.75rem; align-items:stretch; min-height:780px }
.side-panel { background:var(--sf); border:1px solid var(--bd); border-radius:8px;
              padding:.75rem .9rem; overflow-y:auto; max-height:780px; font-size:12px }
.side-panel h3 { font-size:13px; margin:0 0 .5rem; color:var(--te); border-bottom:1px solid var(--bd); padding-bottom:4px }
.side-panel h4 { font-size:11px; margin:.7rem 0 .25rem; color:#1a2540; background:var(--te);
  padding:3px 8px; border-radius:3px; text-transform:uppercase; letter-spacing:.05em; font-weight:700 }
.side-panel h4.inc-h { background:var(--hi); }
.side-panel ul { list-style:none; padding:0 0 0 .3rem; margin:.2rem 0 .5rem;
  font-size:11px; border-left:2px solid #1a2540 }
.side-panel ul li { padding:4px 6px; border-bottom:1px dashed #1a2540; color:var(--tx) }
.side-panel ul li:hover { background:var(--sf2) }
.side-panel ul li:last-child { border-bottom:0 }
.side-panel ul li a { color:var(--lk); text-decoration:none; font-weight:500 }
.side-panel ul li a:hover { color:var(--te); text-decoration:underline }
.side-panel ul li .nt { color:var(--mu); font-size:10px; font-style:italic; margin-left:6px }
.side-panel .cond-pill { background:#ffb86c33; color:#ffb86c; border:1px solid #ffb86c66;
  padding:0 6px; border-radius:8px; font-size:9px; margin-left:4px; font-weight:600 }
.side-panel .arn-pill { background:var(--in2); color:var(--in); border:1px solid #4db8ff55;
  padding:0 6px; border-radius:8px; font-size:9px; margin-left:4px; font-family:'Cascadia Code',monospace }
.side-panel .meta { color:var(--mu); font-size:10px; font-family:'Cascadia Code',Consolas,monospace; margin-bottom:.5rem; word-break:break-all }
.side-empty { padding:1rem 0; text-align:center }
.hover-panel { position:absolute; background:var(--sf2); border:1px solid var(--bd);
               border-radius:6px; padding:.5rem .75rem; font-size:11px;
               z-index:10; display:none; max-width:340px; box-shadow:0 4px 12px #000a;
               pointer-events:none; line-height:1.4 }
.hover-panel strong { color:var(--te) }
</style>
</head><body>
$hdr
<div class="wrap">

<div class="g4">
  <div class="card te"><div class="lbl">Nodes</div><div class="val">$totalNodes</div></div>
  <div class="card in"><div class="lbl">Edges</div><div class="val">$totalEdges</div></div>
  <div class="card pu"><div class="lbl">Roles in Graph</div><div class="val">$roleNodes</div></div>
  <div class="card hi"><div class="lbl">Capabilities</div><div class="val">$capNodes</div></div>
</div>

<div class="sec">Attack Path Graph <span class="ct">force-directed, click a node to highlight paths and see detail</span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
Nodes: roles (purple), resources (teal), capabilities (orange), trust principals (red).
Edges: <strong>enables</strong> (solid) = role grants capability; <strong>attached-to</strong> (dashed) = role attached to resource; <strong>can-assume</strong> (dotted) = principal can assume role.
Edge color follows the most severe link in the chain. Drag the canvas to pan; scroll to zoom; drag nodes to rearrange. Hover any node for explanation; click to highlight all paths from/to it.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Search to highlight matching nodes...">
  <select id="fNode">
    <option value="">All node types</option>
    <option value="role">Roles only</option>
    <option value="resource">Resources only</option>
    <option value="capability">Capabilities only</option>
    <option value="trust-principal">Trust principals only</option>
  </select>
  <select id="fSev">
    <option value="">Any severity</option>
    <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option>
  </select>
  <select id="presetFlow">
    <option value="">Preset attack flows...</option>
    <option value="cryptomining">Cryptomining (compute hijack)</option>
    <option value="dataexfil">Data exfiltration (S3 / DB)</option>
    <option value="privesc">Privilege escalation</option>
    <option value="logTamper">Log tampering / defense evasion</option>
    <option value="credAccess">Credential access</option>
    <option value="lateralMov">Lateral movement</option>
  </select>
  <button id="btnReset" type="button">Reset highlight</button>
  <button id="btnRelayout" type="button">Re-layout</button>
</div>

<div class="graph-container">
  <div id="graph">
    <div class="legend">
      <div class="legend-item"><span class="legend-dot" style="background:#a855f7"></span>Role</div>
      <div class="legend-item"><span class="legend-dot" style="background:#00d4aa"></span>Resource</div>
      <div class="legend-item"><span class="legend-dot" style="background:#ff8c00"></span>Capability</div>
      <div class="legend-item"><span class="legend-dot" style="background:#ff3366"></span>Trust Principal</div>
      <div class="legend-item" style="margin-top:.4rem;padding-top:.4rem;border-top:1px solid var(--bd)">
        <span style="display:inline-block;width:18px;height:2px;background:#ffb86c;margin-right:6px"></span>Conditioned edge
      </div>
    </div>
    <div id="searchHit"></div>
    <div id="hoverPanel" class="hover-panel"></div>
  </div>
  <div id="sidePanel" class="side-panel">
    <div class="side-empty">
      <p style="color:var(--mu);font-size:11px">Click any node in the graph to see its details and the attack paths flowing through it here.</p>
      <p style="color:var(--mu);font-size:11px;margin-top:1rem">Or pick a preset attack flow from the dropdown above to highlight a specific kill-chain.</p>
    </div>
  </div>
</div>

</div>
<script>
$sharedJS

var NODES = $jNodes;
var EDGES = $jEdges;

if (NODES.length === 0) {
  document.getElementById('graph').innerHTML = '<div class="empty" style="padding:3rem">No graph data - run enrichment first (roles need capabilities to be plotted).</div>';
} else {

var width  = document.getElementById('graph').clientWidth;
var height = 780;

var svg = d3.select('#graph').append('svg')
  .attr('viewBox', [0,0,width,height]);
var g = svg.append('g');

// Zoom + pan
svg.call(d3.zoom()
  .scaleExtent([0.1, 5])
  .on('zoom', function(event){ g.attr('transform', event.transform); }));

// Build live arrays
var nodes = NODES.map(function(n){ return Object.assign({}, n); });
var edges = EDGES.map(function(e){ return Object.assign({}, e); });

var simulation = d3.forceSimulation(nodes)
  .force('link', d3.forceLink(edges).id(function(d){return d.id;}).distance(60).strength(0.5))
  .force('charge', d3.forceManyBody().strength(-180))
  .force('center', d3.forceCenter(width/2, height/2))
  .force('collide', d3.forceCollide().radius(14));

var link = g.append('g')
  .selectAll('line')
  .data(edges)
  .join('line')
  .attr('class', function(d){ return 'edge ' + d.sevCls.toUpperCase() + ' ' + d.type + (d.conditioned ? ' conditioned' : ''); })
  .attr('stroke-width', 1.4);

// Map sevCls (cr/hi/me/lo/in) to severity name for edge class
edges.forEach(function(e){ e.sevName = ({cr:'CRITICAL',hi:'HIGH',me:'MEDIUM',lo:'LOW',in:'INFO'})[e.sevCls] || 'INFO'; });
link.attr('class', function(d){ return 'edge ' + d.sevName + ' ' + d.type + (d.conditioned ? ' conditioned' : ''); });

var node = g.append('g')
  .selectAll('g')
  .data(nodes)
  .join('g')
  .attr('class', 'node')
  .call(d3.drag()
    .on('start', function(event,d){
      if(!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x; d.fy = d.y;
    })
    .on('drag', function(event,d){ d.fx = event.x; d.fy = event.y; })
    .on('end', function(event,d){
      if(!event.active) simulation.alphaTarget(0);
      d.fx = null; d.fy = null;
    }));

node.append('circle')
  .attr('r', function(d){ return d.type === 'role' ? 9 : (d.type === 'capability' ? 7 : 6); })
  .attr('class', function(d){ return 'node-'+d.type + ' node-'+d.severity; })
  .on('click', function(event, d){
    event.stopPropagation();
    selectNode(d);
  })
  .on('mouseover', function(event, d){
    showHover(event, d);
  })
  .on('mouseout', function(event, d){
    hideHover();
  });

node.append('title').text(function(d){ return d.label + ' (' + d.type + ', ' + d.severity + ')'; });

node.append('text')
  .attr('class','node-label')
  .attr('dx', 12).attr('dy', 4)
  .text(function(d){ return d.label.length > 32 ? d.label.substring(0,32)+'...' : d.label; });

simulation.on('tick', function(){
  link
    .attr('x1', function(d){ return d.source.x; })
    .attr('y1', function(d){ return d.source.y; })
    .attr('x2', function(d){ return d.target.x; })
    .attr('y2', function(d){ return d.target.y; });
  node.attr('transform', function(d){ return 'translate('+d.x+','+d.y+')'; });
});

// ============== Hover panel ==============
var hoverEl = document.getElementById('hoverPanel');
function nodeExplanation(d){
  if (d.type === 'role') {
    return '<strong>' + escHtml(d.label) + '</strong> (IAM Role)<br>' +
      'Severity: <strong>' + escHtml(d.severity) + '</strong><br>' +
      'This role has been enriched and shows the worst capability severity it can perform. ' +
      'Click for the side-panel breakdown of every capability and resource path connected to it.';
  }
  if (d.type === 'resource') {
    return '<strong>' + escHtml(d.label) + '</strong> (AWS Resource)<br>' +
      'Severity: <strong>' + escHtml(d.severity) + '</strong><br>' +
      'This resource has an IAM identity attached to it. Clicking shows which roles flow into it ' +
      'and what those roles can do.';
  }
  if (d.type === 'capability') {
    return '<strong>' + escHtml(d.label) + '</strong> (Capability)<br>' +
      'Severity: <strong>' + escHtml(d.severity) + '</strong><br>' +
      'A documented attack pattern. Roles connected by "enables" edges can perform this. ' +
      'Click to see every role that triggers it.';
  }
  if (d.type === 'trust-principal') {
    return '<strong>' + escHtml(d.label) + '</strong> (Trust Principal)<br>' +
      'Severity: <strong>' + escHtml(d.severity) + '</strong><br>' +
      'A principal allowed to assume one or more roles. Higher severity = external or unscoped ' +
      'trust (no ExternalId, cross-account, or Principal:*).';
  }
  return escHtml(d.label);
}
function showHover(event, d){
  hoverEl.innerHTML = nodeExplanation(d);
  hoverEl.style.display = 'block';
  // Position relative to graph container
  var gRect = document.getElementById('graph').getBoundingClientRect();
  hoverEl.style.left = (event.clientX - gRect.left + 12) + 'px';
  hoverEl.style.top  = (event.clientY - gRect.top + 12) + 'px';
}
function hideHover(){ hoverEl.style.display = 'none'; }

// ============== Click highlight + side panel ==============
var selectedId = null;

// Build adjacency map: nodeId -> {incoming:[edges], outgoing:[edges]}
var adj = {};
nodes.forEach(function(n){ adj[n.id] = {incoming:[], outgoing:[]}; });
edges.forEach(function(e){
  var s = (typeof e.source === 'object') ? e.source.id : e.source;
  var t = (typeof e.target === 'object') ? e.target.id : e.target;
  if (adj[s]) adj[s].outgoing.push(e);
  if (adj[t]) adj[t].incoming.push(e);
});

function bfsReachable(startId, direction){
  // direction: 'out' = follow outgoing edges; 'in' = follow incoming
  var visited = {}; visited[startId] = true;
  var queue = [startId];
  var collectedEdges = [];
  while (queue.length){
    var cur = queue.shift();
    var es = direction === 'out' ? adj[cur].outgoing : adj[cur].incoming;
    es.forEach(function(e){
      collectedEdges.push(e);
      var next = direction === 'out' ? ((typeof e.target === 'object') ? e.target.id : e.target)
                                     : ((typeof e.source === 'object') ? e.source.id : e.source);
      if (!visited[next]) { visited[next] = true; queue.push(next); }
    });
  }
  return {visited:visited, edges:collectedEdges};
}

function selectNode(d){
  selectedId = d.id;
  // Find all nodes/edges reachable both upstream and downstream
  var outRes = bfsReachable(d.id, 'out');
  var inRes  = bfsReachable(d.id, 'in');
  var keep = {};
  Object.keys(outRes.visited).forEach(function(k){ keep[k] = true; });
  Object.keys(inRes.visited).forEach(function(k){ keep[k] = true; });

  var edgeSet = new Set();
  outRes.edges.forEach(function(e){ edgeSet.add(e); });
  inRes.edges.forEach(function(e){ edgeSet.add(e); });

  // Dim non-related nodes / edges
  node.classed('dimmed', function(n){ return !keep[n.id]; });
  node.classed('highlight', function(n){ return n.id === d.id; });
  link.classed('dimmed', function(e){ return !edgeSet.has(e); });
  link.classed('highlight', function(e){ return edgeSet.has(e); });

  // Build side panel
  renderSidePanel(d, outRes, inRes);
}

function clearHighlight(){
  selectedId = null;
  node.classed('dimmed', false);
  node.classed('highlight', false);
  link.classed('dimmed', false);
  link.classed('highlight', false);
  document.getElementById('sidePanel').innerHTML = '<div class="side-empty"><p style="color:var(--mu);font-size:11px">Click any node in the graph to see its details and the attack paths flowing through it here.</p></div>';
}

function renderSidePanel(d, outRes, inRes){
  var html = '<h3>' + escHtml(d.label) + '</h3>' +
    '<div class="meta">' + escHtml(d.id) + '</div>' +
    '<p><strong>Type:</strong> ' + escHtml(d.type) + ' &nbsp; <strong>Severity:</strong> ' +
    '<span class="bx ' + d.sevCls + '">' + escHtml(d.severity) + '</span></p>';
  if (d.link) {
    html += '<p><a href="' + escHtml(d.link) + '">Open full detail page &raquo;</a></p>';
  }
  html += '<p style="font-size:11px;color:var(--mu)">' + nodeExplanation(d).split('<br>').slice(2).join('<br>') + '</p>';

  // Group outgoing edges by type
  var outByType = {};
  outRes.edges.forEach(function(e){
    if (!outByType[e.type]) outByType[e.type] = [];
    outByType[e.type].push(e);
  });
  Object.keys(outByType).forEach(function(t){
    html += '<h4>Outgoing: ' + escHtml(t) + ' (' + outByType[t].length + ')</h4><ul>';
    outByType[t].slice(0, 40).forEach(function(e){
      var tgtNode = nodes.find(function(n){ return n.id === ((typeof e.target === 'object') ? e.target.id : e.target); });
      if (tgtNode) {
        var pills = '';
        if (e.conditioned) pills += '<span class="cond-pill">COND</span>';
        if (e.arnSpecific) pills += '<span class="arn-pill">ARN</span>';
        html += '<li><a href="javascript:void(0)" onclick="selectNodeById(\'' + tgtNode.id.replace(/'/g, "\\'") + '\')">' + escHtml(tgtNode.label) + '</a><span class="nt">(' + escHtml(tgtNode.type) + ')</span>' + pills + '</li>';
      }
    });
    html += '</ul>';
  });

  var inByType = {};
  inRes.edges.forEach(function(e){
    if (!inByType[e.type]) inByType[e.type] = [];
    inByType[e.type].push(e);
  });
  Object.keys(inByType).forEach(function(t){
    html += '<h4 class="inc-h">Incoming: ' + escHtml(t) + ' (' + inByType[t].length + ')</h4><ul>';
    inByType[t].slice(0, 40).forEach(function(e){
      var srcNode = nodes.find(function(n){ return n.id === ((typeof e.source === 'object') ? e.source.id : e.source); });
      if (srcNode) {
        var pills = '';
        if (e.conditioned) pills += '<span class="cond-pill">COND</span>';
        if (e.arnSpecific) pills += '<span class="arn-pill">ARN</span>';
        html += '<li><a href="javascript:void(0)" onclick="selectNodeById(\'' + srcNode.id.replace(/'/g, "\\'") + '\')">' + escHtml(srcNode.label) + '</a><span class="nt">(' + escHtml(srcNode.type) + ')</span>' + pills + '</li>';
      }
    });
    html += '</ul>';
  });

  document.getElementById('sidePanel').innerHTML = html;
}

window.selectNodeById = function(id){
  var n = nodes.find(function(x){ return x.id === id; });
  if (n) selectNode(n);
};

// Click empty background -> clear highlight
svg.on('click', function(){ clearHighlight(); });

// ============== Preset flows ==============
// Each preset filters capabilities by category and highlights all paths from/to them.
var presetFilters = {
  cryptomining: function(cap){ return /Cryptomining|ResourceAbuse|RunInstances/i.test(cap.label); },
  dataexfil:    function(cap){ return /DataExfil|GetObject|Snapshot|Export/i.test(cap.label); },
  privesc:      function(cap){ return /PrivilegeEscalation|PassRole|CreatePolicy|UpdateAssumeRole/i.test(cap.label); },
  logTamper:    function(cap){ return /DefenseEvasion|CloudTrail|Config|GuardDuty/i.test(cap.label); },
  credAccess:   function(cap){ return /CredentialExposure|SecretsManager|SSM|KMS|GetPassword/i.test(cap.label); },
  lateralMov:   function(cap){ return /LateralMovement|AssumeRole|InstanceProfile|SendCommand/i.test(cap.label); }
};

document.getElementById('presetFlow').addEventListener('change', function(){
  var v = this.value;
  if (!v || !presetFilters[v]) { clearHighlight(); return; }
  var matched = nodes.filter(function(n){ return n.type === 'capability' && presetFilters[v](n); });
  if (matched.length === 0) {
    document.getElementById('sidePanel').innerHTML = '<div class="side-empty"><p style="color:var(--mu);font-size:11px">No capabilities found in this attack flow category.</p></div>';
    return;
  }
  // Highlight the union of paths from all matched capabilities
  var keep = {};
  var edgeSet = new Set();
  matched.forEach(function(m){
    keep[m.id] = true;
    var inRes  = bfsReachable(m.id, 'in');
    var outRes = bfsReachable(m.id, 'out');
    Object.keys(inRes.visited).forEach(function(k){ keep[k] = true; });
    Object.keys(outRes.visited).forEach(function(k){ keep[k] = true; });
    inRes.edges.forEach(function(e){ edgeSet.add(e); });
    outRes.edges.forEach(function(e){ edgeSet.add(e); });
  });
  node.classed('dimmed', function(n){ return !keep[n.id]; });
  node.classed('highlight', function(n){ return matched.indexOf(n) >= 0; });
  link.classed('dimmed', function(e){ return !edgeSet.has(e); });
  link.classed('highlight', function(e){ return edgeSet.has(e); });

  // Side panel summary
  var html = '<h3>Preset: ' + escHtml(this.options[this.selectedIndex].text) + '</h3>' +
    '<p style="font-size:11px;color:var(--mu)">' + matched.length + ' matching capability node(s). Highlighted nodes are reachable from or to these capabilities.</p>' +
    '<h4>Matched capabilities</h4><ul>';
  matched.forEach(function(m){
    html += '<li><a href="javascript:void(0)" onclick="selectNodeById(\'' + m.id.replace(/'/g, "\\'") + '\')">' + escHtml(m.label) + '</a> <span class="bx ' + m.sevCls + '">' + escHtml(m.severity) + '</span></li>';
  });
  html += '</ul>';
  document.getElementById('sidePanel').innerHTML = html;
});

// Filtering
function applyFilters(){
  var q = document.getElementById('q').value.toLowerCase();
  var ft = document.getElementById('fNode').value;
  var fs = document.getElementById('fSev').value;

  var visibleIds = {};
  nodes.forEach(function(n){
    var keep = true;
    if(ft && n.type !== ft) keep = false;
    if(fs && n.severity !== fs) keep = false;
    if(q && n.label.toLowerCase().indexOf(q) < 0) keep = false;
    if(keep){ visibleIds[n.id] = true; }
  });

  node.style('opacity', function(d){ return visibleIds[d.id] ? 1 : 0.12; });
  link.style('opacity', function(d){
    return (visibleIds[d.source.id] && visibleIds[d.target.id]) ? 0.7 : 0.05;
  });

  var count = Object.keys(visibleIds).length;
  var hit = document.getElementById('searchHit');
  if (q || ft || fs) {
    hit.style.display = 'block';
    hit.textContent = count + ' / ' + nodes.length + ' nodes match filters';
  } else {
    hit.style.display = 'none';
  }
}
['q','fNode','fSev'].forEach(function(id){
  var el = document.getElementById(id);
  var evt = (el.tagName === 'SELECT') ? 'change' : 'input';
  el.addEventListener(evt, applyFilters);
});
document.getElementById('btnReset').addEventListener('click', function(){
  nodes.forEach(function(n){ n.fx = null; n.fy = null; });
  simulation.alpha(1).restart();
  svg.transition().duration(500).call(
    d3.zoom().transform,
    d3.zoomIdentity.translate(0,0).scale(1)
  );
});

}
</script>
</body></html>
"@
}

# ----------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------
function Invoke-GenerateIndexPages {
    $out = $Global:IR.OutputDir
    Write-IRLog "Generating Roles index page..." -Level INFO
    (New-RolesIndexPage) | Out-File (Join-Path $out "roles.html") -Encoding UTF8

    Write-IRLog "Generating Resources Detail index page..." -Level INFO
    (New-ResourcesDetailIndexPage) | Out-File (Join-Path $out "resources-detail.html") -Encoding UTF8

    Write-IRLog "Generating Findings Catalog page..." -Level INFO
    (New-FindingsCatalogPage) | Out-File (Join-Path $out "findings-catalog.html") -Encoding UTF8

    Write-IRLog "Generating Attack Paths page..." -Level INFO
    (New-AttackPathsPage) | Out-File (Join-Path $out "attack-paths.html") -Encoding UTF8
}
