# Modules/IR-Report.ps1
# ============================================================
#  Multi-page interactive HTML report
#    index.html         - dashboard with metrics + charts
#    resources.html     - every resource and the identities attached to it
#                         (broad-perm and admin-perm flagged)
#    identities.html    - every identity sorted by attachment count
#                         (click to expand and see every resource it touches)
#    assume.html        - assume-role / trust / federation focus
#    findings.html      - broad permissions, public, external admins, etc
#    command-log.html   - every AWS CLI command run
#  Raw data
#    resource-attachments.csv   - one row per attachment
#    command-log.json           - command log
# ============================================================

# ----------------------------------------------------------------
# JSON helper - MUST use -InputObject to prevent pipeline unwrap
# ----------------------------------------------------------------
function ConvertTo-SafeJson {
    param($Data, [int]$Depth = 8)
    if ($null -eq $Data) { return '[]' }

    # Use an explicit ArrayList + foreach to avoid PS array-subexpression failures
    # on generic List<T> collections that contain nested Lists.
    $items = New-Object System.Collections.ArrayList

    if ($Data -is [string]) {
        [void]$items.Add($Data)
    } elseif ($Data -is [System.Collections.IEnumerable]) {
        foreach ($x in $Data) {
            [void]$items.Add($x)
        }
    } else {
        [void]$items.Add($Data)
    }

    if ($items.Count -eq 0) { return '[]' }
    $arr = $items.ToArray()

    $j = Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $arr -Compress -Depth $Depth
    if (-not $j.StartsWith('[')) { $j = "[$j]" }
    return $j
}

function ConvertTo-HtmlText {
    param([string]$Text)
    if (-not $Text) { return "" }
    return ($Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function Get-RiskClass {
    param([string]$Risk)
    switch ($Risk) {
        'CRITICAL' { 'cr' }
        'HIGH'     { 'hi' }
        'MEDIUM'   { 'me' }
        'LOW'      { 'lo' }
        default    { 'in' }
    }
}

function Get-PermissionBreadth {
    # Returns a permission-scope code based on actions and Effect:
    #   'ADMIN-ALLOW' = Allow Action:*    -> very dangerous
    #   'BROAD-ALLOW' = Allow service:*   -> dangerous
    #   'ADMIN-DENY'  = Deny Action:*     -> protective (good)
    #   'BROAD-DENY'  = Deny service:*    -> protective (good)
    #   'DENY-SCOPED' = Deny (scoped)     -> protective (good)
    #   ''            = scoped Allow      -> nothing notable
    param([string]$Permissions, [string]$Effect = 'Allow')
    if (-not $Permissions) { return "" }

    $isAdmin = ($Permissions -match '(^|,)\s*\*\s*(,|$)' -or $Permissions.Trim() -eq '*')
    $isBroad = ($Permissions -match ':\*')

    if ($Effect -eq 'Deny') {
        if ($isAdmin) { return 'ADMIN-DENY' }
        if ($isBroad) { return 'BROAD-DENY' }
        return 'DENY-SCOPED'
    }
    # Allow
    if ($isAdmin) { return 'ADMIN-ALLOW' }
    if ($isBroad) { return 'BROAD-ALLOW' }
    return ""
}

function Test-BroadPerm {
    # Helper: does a code indicate Allow + wildcard?
    param([string]$Code)
    return ($Code -eq 'ADMIN-ALLOW' -or $Code -eq 'BROAD-ALLOW')
}

# ----------------------------------------------------------------
# CSV export
# ----------------------------------------------------------------
function Export-AttachmentsCSV {
    $path = Join-Path $Global:IR.OutputDir "resource-attachments.csv"
    $Global:IR.Attachments |
        Microsoft.PowerShell.Utility\Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-IRLog "CSV exported: $path ($($Global:IR.Attachments.Count) rows)" -Level SUCCESS
    return $path
}

# ----------------------------------------------------------------
# Shared CSS
# ----------------------------------------------------------------
function Get-SharedCSS {
@'
<style>
:root{
  --bg:#080d1a;--sf:#0e1628;--sf2:#16203a;--sf3:#1e2d4a;
  --bd:#2a3a5c;--tx:#d4e0ff;--mu:#6b82b0;
  --lk:#4db8ff;
  --cr:#ff3366;--cr2:#ff336622;
  --hi:#ff8c00;--hi2:#ff8c0022;
  --me:#f0c040;--me2:#f0c04022;
  --lo:#00d488;--lo2:#00d48822;
  --in:#4db8ff;--in2:#4db8ff22;
  --pu:#a855f7;--pu2:#a855f722;
  --te:#00d4aa;--te2:#00d4aa22;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--tx);font-size:14px;line-height:1.55}
a{color:var(--lk);text-decoration:none}a:hover{text-decoration:underline}
.hdr{background:linear-gradient(135deg,var(--sf) 0%,var(--sf3) 100%);
     border-bottom:1px solid var(--bd);padding:.85rem 2rem;display:flex;align-items:center;gap:2rem;flex-wrap:wrap}
.hdr-logo{font-size:18px;font-weight:800;letter-spacing:-.3px;
          background:linear-gradient(90deg,var(--te),var(--lk));
          -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hdr-meta{font-size:11px;color:var(--mu)}
.hdr-meta span{color:var(--tx);font-weight:600}
.stat-pill{display:inline-flex;align-items:center;gap:4px;background:var(--sf2);
           border:1px solid var(--bd);border-radius:14px;padding:2px 10px;font-size:11px;color:var(--mu);margin:2px}
.nav{background:var(--sf);border-bottom:1px solid var(--bd);display:flex;
     padding:0 2rem;gap:0;overflow-x:auto}
.nav a{padding:10px 18px;font-size:13px;color:var(--mu);
       border-bottom:2px solid transparent;white-space:nowrap;transition:.15s}
.nav a:hover{color:var(--tx);text-decoration:none}
.nav a.on{color:var(--te);border-bottom-color:var(--te)}
.wrap{max-width:1700px;margin:0 auto;padding:1.25rem 2rem}
.g5{display:grid;grid-template-columns:repeat(5,1fr);gap:.8rem;margin-bottom:1.25rem}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:.8rem;margin-bottom:1.25rem}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.25rem}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.25rem}
@media(max-width:1100px){.g5,.g4{grid-template-columns:repeat(2,1fr)}.g3,.g2{grid-template-columns:1fr}}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:.9rem 1.1rem}
.card .lbl{font-size:10px;color:var(--mu);text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px}
.card .val{font-size:24px;font-weight:800}
.card.cr{border-top:3px solid var(--cr)}.card.cr .val{color:var(--cr)}
.card.hi{border-top:3px solid var(--hi)}.card.hi .val{color:var(--hi)}
.card.me{border-top:3px solid var(--me)}.card.me .val{color:var(--me)}
.card.lo{border-top:3px solid var(--lo)}.card.lo .val{color:var(--lo)}
.card.te{border-top:3px solid var(--te)}.card.te .val{color:var(--te)}
.card.pu{border-top:3px solid var(--pu)}.card.pu .val{color:var(--pu)}
.card.in{border-top:3px solid var(--in)}.card.in .val{color:var(--in)}
.sec{font-size:14px;font-weight:700;color:var(--tx);margin:1.25rem 0 .6rem;
     padding-bottom:5px;border-bottom:1px solid var(--bd);
     display:flex;align-items:center;gap:.5rem}
.sec::before{content:'';display:block;width:3px;height:14px;border-radius:2px;background:var(--te)}
.sec .ct{font-size:12px;color:var(--mu);font-weight:400;margin-left:auto}
.chart-wrap{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:1rem;min-height:320px;position:relative}
.chart-wrap h3{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--mu);margin-bottom:.75rem}
.chart-wrap canvas{max-height:260px}
.bx{display:inline-block;font-size:9px;font-weight:700;padding:2px 7px;border-radius:9px;
    text-transform:uppercase;letter-spacing:.04em}
.bx.cr{background:var(--cr2);color:var(--cr);border:1px solid #ff336655}
.bx.hi{background:var(--hi2);color:var(--hi);border:1px solid #ff8c0055}
.bx.me{background:var(--me2);color:var(--me);border:1px solid #f0c04055}
.bx.lo{background:var(--lo2);color:var(--lo);border:1px solid #00d48855}
.bx.in{background:var(--in2);color:var(--in);border:1px solid #4db8ff55}
.bx.pu{background:var(--pu2);color:var(--pu);border:1px solid #a855f755}
.bx.te{background:var(--te2);color:var(--te);border:1px solid #00d4aa55}
.tag{display:inline-block;font-size:9px;font-weight:700;padding:1px 6px;border-radius:7px;
     text-transform:uppercase;letter-spacing:.03em;margin:0 1px}
.tag.ext{background:var(--hi2);color:var(--hi);border:1px solid var(--hi)}
.tag.pub{background:var(--cr2);color:var(--cr);border:1px solid var(--cr)}
.tag.adm{background:var(--cr2);color:var(--cr);border:1px solid var(--cr)}
.tag.scope{background:var(--me2);color:var(--me);border:1px solid #f0c04055}
.tag.deny{background:var(--lo2);color:var(--lo);border:1px solid var(--lo)}
.tag.scopedres{background:var(--in2);color:var(--in);border:1px solid #4db8ff55}
.tag.allres{background:var(--cr2);color:var(--cr);border:1px solid #ff336655}
.tag.awsknown{background:var(--lo2);color:var(--lo);border:1px solid var(--lo)}
.tag.modified{background:var(--pu2);color:var(--pu);border:1px solid var(--pu)}
.tag.privid{background:var(--cr2);color:var(--cr);border:1px solid var(--cr);font-weight:800}
.tag.wildres{background:var(--hi2);color:var(--hi);border:1px solid var(--hi)}
.tag.broad{background:#9d4edd22;color:#c77dff;border:1px solid #9d4edd;font-weight:700;
  letter-spacing:.04em}
.tag.mega-broad{background:#ff3366;color:#fff;border:1px solid #ff3366;font-weight:800;
  letter-spacing:.04em;animation:pulseMegaBroad 2s ease-in-out infinite}
@keyframes pulseMegaBroad{0%,100%{box-shadow:0 0 0 0 #ff336688}50%{box-shadow:0 0 0 4px #ff336600}}
tr.row-muted td{opacity:.45;background:#0a0f1a !important}
tr.row-muted:hover td{opacity:.85;background:var(--sf2) !important}
tr.cmd-interesting td{background:linear-gradient(90deg,#00d48818 0%,transparent 100%);border-left:2px solid var(--lo)}
tr.cmd-interesting td:first-child{border-left:3px solid var(--lo)}
tr.cmd-error td{background:linear-gradient(90deg,#ff336620 0%,transparent 100%);border-left:2px solid var(--cr)}
.filter-bar{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:.75rem;align-items:center}
.filter-bar input,.filter-bar select,.filter-bar button{background:var(--sf2);border:1px solid var(--bd);border-radius:5px;
  color:var(--tx);padding:5px 10px;font-size:12px;outline:none}
.filter-bar input:focus,.filter-bar select:focus{border-color:var(--te)}
.filter-bar input[type=text]{flex:1;min-width:220px}
.filter-bar button{cursor:pointer}
.filter-bar button.on{border-color:var(--te);color:var(--te)}
.filter-bar label{font-size:11px;color:var(--mu);cursor:pointer;user-select:none}
.filter-bar label input{vertical-align:middle;margin-right:3px}
.tbl-wrap{background:var(--sf);border:1px solid var(--bd);border-radius:8px;overflow:hidden}
.tbl-scroll{overflow-x:auto;max-height:620px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed}
th{background:var(--sf2);color:var(--mu);font-size:10px;text-transform:uppercase;
   letter-spacing:.05em;padding:8px 10px;text-align:left;border-bottom:1px solid var(--bd);
   cursor:pointer;white-space:nowrap;user-select:none;position:sticky;top:0;z-index:1;
   overflow:hidden;text-overflow:ellipsis}
th:hover{color:var(--tx)}
th.sortasc::after{content:' [up]';font-size:8px;color:var(--te)}
th.sortdesc::after{content:' [dn]';font-size:8px;color:var(--te)}
.col-resizer{position:absolute;top:0;right:0;bottom:0;width:6px;cursor:col-resize;z-index:3;
             background:transparent}
.col-resizer:hover{background:var(--te)}
.col-resizer.dragging{background:var(--te)}
td{padding:6px 10px;border-bottom:1px solid #1a2540;vertical-align:top;
   overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td.trunc{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
table.wrap-mode td{white-space:normal;word-break:break-word;overflow:visible}
table.wrap-mode td.mono{word-break:break-all}
tr:hover td{background:var(--sf2)}
.tbl-footer{padding:7px 14px;font-size:11px;color:var(--mu);
            border-top:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center}
.pager{display:flex;gap:5px;align-items:center}
.pager button{background:var(--sf3);border:1px solid var(--bd);color:var(--tx);
              padding:3px 9px;border-radius:3px;cursor:pointer;font-size:11px}
.pager button:hover{border-color:var(--te)}
.pager button:disabled{opacity:.4;cursor:default}
.mono{font-family:'Cascadia Code',Consolas,monospace;font-size:11px}
.muted{color:var(--mu)}
.fcard{background:var(--sf);border:1px solid var(--bd);border-radius:8px;
       padding:1rem 1.2rem;margin-bottom:.85rem;border-left:3px solid var(--mu)}
.fcard.cr{border-left-color:var(--cr)}
.fcard.hi{border-left-color:var(--hi)}
.fcard.me{border-left-color:var(--me)}
.fcard h4{font-size:14px;font-weight:700;margin-bottom:.5rem;display:flex;align-items:center;gap:.4rem;flex-wrap:wrap}
.fcard .findmeta{font-size:11px;color:var(--mu);margin-bottom:.5rem}
.fcard p{font-size:12px;margin-bottom:.4rem}
.fcard ul{list-style:none;padding:.5rem .8rem;font-size:11px;max-height:500px;overflow-y:auto;
         background:var(--sf2);border:1px solid var(--bd);border-radius:5px;margin-top:.5rem}
.fcard ul li{padding:3px 0;color:var(--tx);font-family:'Cascadia Code',Consolas,monospace}
.fcard ul li::before{content:'> ';color:var(--mu)}
.expand-btn{font-size:10px;color:var(--lk);cursor:pointer;text-decoration:underline;margin-left:6px;font-family:inherit}
.detail-row{background:var(--sf2)}
.detail-row td{padding:.8rem 1.4rem;border-left:3px solid var(--te)}
.detail-list{list-style:none;padding:0;font-size:11px}
.detail-list li{padding:4px 0;border-bottom:1px dashed #1a2540;display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.detail-list li:last-child{border-bottom:0}
.empty{padding:2rem;text-align:center;color:var(--mu);font-size:13px}
</style>
'@
}

function Get-NavHTML {
    param([string]$Active)
    $links = @(
        @{ id='dash'; href='index.html';      label='Dashboard' }
        @{ id='res';  href='resources.html';  label='Resources' }
        @{ id='id';   href='identities.html'; label='Identities' }
        @{ id='asm';  href='assume.html';     label='Assume-Role and Federation' }
        @{ id='find'; href='findings.html';   label='Findings' }
        @{ id='cat';  href='findings-catalog.html'; label='Findings Catalog' }
        @{ id='roles';href='roles.html';      label='Roles' }
        @{ id='rdet'; href='resources-detail.html'; label='Resource Detail' }
        @{ id='atk';  href='attack-paths.html';label='Attack Paths' }
        @{ id='log';  href='command-log.html';label='Command Log' }
        @{ id='csv';  href='resource-attachments.csv'; label='Raw CSV' }
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

# ----------------------------------------------------------------
# Shared JS helpers used by every table page:
#  - badgeBroad(): render Effect-aware permission scope badge
#  - badgeScope(): render Resource scope badge
#  - attachResizers(): make every <th> drag-resizable
#  - applyWrapMode(): toggle word-wrap on td cells
#  - getUrlParam(): read URL ?q=... for cross-page filtering
# ----------------------------------------------------------------

# Emits a JS object literal: ROLE_PAGES = {"arn":"file.html",...}
# Empty object if no role pages were generated.
function Get-RolePagesJS {
    if (-not $Global:IR.RoleFileMap -or $Global:IR.RoleFileMap.Count -eq 0) {
        return "var ROLE_PAGES = {};"
    }
    $obj = New-Object PSCustomObject
    foreach ($k in $Global:IR.RoleFileMap.Keys) {
        Add-Member -InputObject $obj -NotePropertyName $k -NotePropertyValue $Global:IR.RoleFileMap[$k] -Force
    }
    $json = ConvertTo-SafeJson $obj
    # ConvertTo-SafeJson wraps in [] - undo for object
    if ($json.StartsWith('[') -and $json.EndsWith(']')) {
        $json = $json.Substring(1, $json.Length - 2)
    }
    return "var ROLE_PAGES = $json;"
}

# Emits RESOURCE_PAGES = {"arn":"resources/file.html",...}
function Get-ResourcePagesJS {
    if (-not $Global:IR.ResourceFileMap -or $Global:IR.ResourceFileMap.Count -eq 0) {
        return "var RESOURCE_PAGES = {};"
    }
    $obj = New-Object PSCustomObject
    foreach ($k in $Global:IR.ResourceFileMap.Keys) {
        Add-Member -InputObject $obj -NotePropertyName $k -NotePropertyValue $Global:IR.ResourceFileMap[$k] -Force
    }
    $json = ConvertTo-SafeJson $obj
    if ($json.StartsWith('[') -and $json.EndsWith(']')) {
        $json = $json.Substring(1, $json.Length - 2)
    }
    return "var RESOURCE_PAGES = $json;"
}

function Get-SharedTableJS {
    $rolePagesJs = Get-RolePagesJS
    $resourcePagesJs = Get-ResourcePagesJS
    $core = @'
// Effect-aware permission scope badge.
// Codes: ADMIN-ALLOW, BROAD-ALLOW, ADMIN-DENY, BROAD-DENY, DENY-SCOPED, ''
function badgeBroad(code){
  if (!code) return '';
  if (code === 'ADMIN-ALLOW') return '<span class="tag adm" title="Allow Action:*  - DANGEROUS">ALLOW *</span>';
  if (code === 'BROAD-ALLOW') return '<span class="tag scope" title="Allow service:* - service-wide">SVC:*</span>';
  if (code === 'ADMIN-DENY')  return '<span class="tag deny" title="Deny Action:* - protective">DENY *</span>';
  if (code === 'BROAD-DENY')  return '<span class="tag deny" title="Deny service:* - protective">DENY SVC:*</span>';
  if (code === 'DENY-SCOPED') return '<span class="tag deny" title="Deny (scoped) - protective">DENY</span>';
  return '';
}

// Resource scope badge - shows whether the statement applies to all resources or specific ARNs
function badgeRScope(rscope){
  if (rscope === 'ALL')    return '<span class="tag allres" title="Resource: *">ALL RES</span>';
  if (rscope === 'SCOPED') return '<span class="tag scopedres" title="Specific resource ARN(s)">SCOPED</span>';
  return '';
}

// Make every TH in `table` resizable via drag handle.
function attachResizers(table){
  if (!table) return;
  const ths = table.querySelectorAll('th');
  ths.forEach((th) => {
    if (th.querySelector('.col-resizer')) return; // already attached
    const r = document.createElement('div');
    r.className = 'col-resizer';
    th.appendChild(r);
    r.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const startX = e.pageX;
      const startW = th.offsetWidth;
      r.classList.add('dragging');
      const onMove = (ev) => {
        const w = Math.max(40, startW + ev.pageX - startX);
        th.style.width = w + 'px';
        th.style.minWidth = w + 'px';
        th.style.maxWidth = w + 'px';
      };
      const onUp = () => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        r.classList.remove('dragging');
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
    // double-click resets the column to auto
    r.addEventListener('dblclick', (e) => {
      e.preventDefault();
      th.style.width = '';
      th.style.minWidth = '';
      th.style.maxWidth = '';
    });
  });
}

function wireWrapToggle(buttonId, tableId){
  const btn = document.getElementById(buttonId);
  const tbl = document.getElementById(tableId);
  if (!btn || !tbl) return;
  btn.addEventListener('click', () => {
    tbl.classList.toggle('wrap-mode');
    btn.classList.toggle('on');
    btn.textContent = tbl.classList.contains('wrap-mode') ? 'Wrap: ON' : 'Wrap: OFF';
  });
}

function getUrlParam(name){
  return new URLSearchParams(window.location.search).get(name);
}

function idLink(idName){
  if (!idName) return '';
  return '<a href="identities.html?q=' + encodeURIComponent(idName) + '">' + escHtml(idName) + '</a>';
}
// Resolve a role ARN/name to its per-role page (if generated)
function rolePageLink(roleArn, displayName){
  if (typeof ROLE_PAGES !== 'undefined' && roleArn && ROLE_PAGES[roleArn]) {
    return '<a href="' + ROLE_PAGES[roleArn] + '">' + escHtml(displayName || roleArn) + '</a>';
  }
  return escHtml(displayName || roleArn || '');
}
function resLink(resName, resType){
  if (!resName) return '';
  const q = resName;
  return '<a href="resources.html?q=' + encodeURIComponent(q) + '">' + escHtml(resName) + '</a>';
}
// Link to resource detail page if mapping exists, fall back to search filter
function resPageLink(resArn, displayName){
  if (typeof RESOURCE_PAGES !== 'undefined' && resArn && RESOURCE_PAGES[resArn]) {
    return '<a href="' + RESOURCE_PAGES[resArn] + '">' + escHtml(displayName || resArn) + '</a>';
  }
  if (displayName) {
    return '<a href="resources.html?q=' + encodeURIComponent(displayName) + '">' + escHtml(displayName) + '</a>';
  }
  return escHtml(displayName || resArn || '');
}
function escHtml(s){
  return String(s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
'@
    return "$rolePagesJs`n$resourcePagesJs`n$core"
}

function Get-PageHeader {
    param([string]$Active)
    $ts        = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $duration  = [math]::Round(((Get-Date) - $Global:IR.StartTime).TotalMinutes, 1)
    $regions   = $Global:IR.Stats.RegionsScanned -join ', '
    $acct      = "$($Global:IR.AccountId) ($($Global:IR.AccountAlias))"
    $nav       = Get-NavHTML -Active $Active

    $iamAuditBadge = ""
    if ($Global:IR.IAMAuditDir) {
        $linkTarget = ""
        if ($Global:IR.IAMAuditIndexPath) {
            # Build a file:/// URL the user can click
            $p = $Global:IR.IAMAuditIndexPath -replace '\\','/'
            $linkTarget = "file:///$p"
        }
        $crossXrefCount = 0
        if ($Global:IR.RoleCatalog) {
            foreach ($cat in $Global:IR.RoleCatalog.Values) {
                if ($cat.ContainsKey('IAMAuditRefs') -and $cat['IAMAuditRefs']) { $crossXrefCount++ }
            }
        }
        $label = if ($linkTarget) {
            "<a href=`"$linkTarget`" target=`"_blank`">IAM-Audit cross-ref: $crossXrefCount roles</a>"
        } else {
            "IAM-Audit cross-ref: $crossXrefCount roles"
        }
        $iamAuditBadge = "<div class=`"stat-pill`" style=`"border-color:var(--pu);color:var(--pu)`">$label</div>"
    }

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
    $iamAuditBadge
  </div>
</div>
$nav
"@
}

# ----------------------------------------------------------------
# Build a "flat row" object per attachment. Returns array of PSCustomObjects
# (so ConvertTo-Json -InputObject produces a clean array of objects)
# ----------------------------------------------------------------
function Build-AttachmentRows {
    param([object[]]$Attachments)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Attachments) {
        $effect = if ($r.Effect) { "$($r.Effect)" } else { 'Allow' }
        $rscope = if ($r.ResourceScope) { "$($r.ResourceScope)" } else { 'UNKNOWN' }
        $broad  = Get-PermissionBreadth -Permissions $r.Permissions -Effect $effect

        $row = [PSCustomObject]@{
            region    = "$($r.Region)"
            resType   = "$($r.ResourceType)"
            resId     = "$($r.ResourceId)"
            resName   = "$($r.ResourceName)"
            resArn    = "$($r.ResourceArn)"
            attType   = "$($r.AttachmentType)"
            idType    = "$($r.IdentityType)"
            idName    = "$($r.IdentityName)"
            idArn     = "$($r.IdentityArn)"
            perms     = "$($r.Permissions)"
            ext       = [bool]$r.IsExternal
            pub       = [bool]$r.IsPublic
            hp        = [bool]$r.IsHighPrivilege
            risk      = "$($r.RiskLevel)"
            rcls      = (Get-RiskClass $r.RiskLevel)
            notes     = "$($r.Notes)"
            broad     = $broad     # '', 'ADMIN-ALLOW', 'BROAD-ALLOW', 'ADMIN-DENY', 'BROAD-DENY', 'DENY-SCOPED'
            effect    = $effect
            rscope    = $rscope
        }
        $rows.Add($row)
    }
    return $rows
}

# ----------------------------------------------------------------
# PAGE 1: index.html  -  Dashboard
# ----------------------------------------------------------------
function New-DashboardPage {
    $atts = @($Global:IR.Attachments)
    $total    = $atts.Count
    $critical = ($atts | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count
    $high     = ($atts | Where-Object { $_.RiskLevel -eq 'HIGH'     }).Count
    $medium   = ($atts | Where-Object { $_.RiskLevel -eq 'MEDIUM'   }).Count
    $low      = ($atts | Where-Object { $_.RiskLevel -in @('LOW','INFO') }).Count
    $external = ($atts | Where-Object { $_.IsExternal }).Count
    $public   = ($atts | Where-Object { $_.IsPublic   }).Count
    $highpriv = ($atts | Where-Object { $_.IsHighPrivilege }).Count
    $resCount = ($atts | Group-Object ResourceArn).Count
    $idCount  = ($atts | Where-Object { $_.IdentityArn } | Group-Object IdentityArn).Count

    $broadCount = ($atts | Where-Object {
        $e = if ($_.Effect) { $_.Effect } else { 'Allow' }
        (Get-PermissionBreadth -Permissions $_.Permissions -Effect $e) -eq 'BROAD-ALLOW'
    }).Count
    $adminCount = ($atts | Where-Object {
        $e = if ($_.Effect) { $_.Effect } else { 'Allow' }
        (Get-PermissionBreadth -Permissions $_.Permissions -Effect $e) -eq 'ADMIN-ALLOW'
    }).Count

    $byRisk = @(
        ($atts | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count,
        ($atts | Where-Object { $_.RiskLevel -eq 'HIGH'     }).Count,
        ($atts | Where-Object { $_.RiskLevel -eq 'MEDIUM'   }).Count,
        ($atts | Where-Object { $_.RiskLevel -eq 'LOW'      }).Count,
        ($atts | Where-Object { $_.RiskLevel -eq 'INFO'     }).Count
    )

    $byServiceG = $atts |
        Group-Object { $_.ResourceType.Split('::')[0] } |
        Sort-Object Count -Descending |
        Select-Object -First 12
    $svcLabels = @($byServiceG | ForEach-Object { $_.Name })
    $svcValues = @($byServiceG | ForEach-Object { $_.Count })

    $byIdG = $atts | Where-Object { $_.IdentityType } |
        Group-Object IdentityType |
        Sort-Object Count -Descending
    $idLabels = @($byIdG | ForEach-Object { $_.Name })
    $idValues = @($byIdG | ForEach-Object { $_.Count })

    $byAtG = $atts | Group-Object AttachmentType | Sort-Object Count -Descending | Select-Object -First 10
    $atLabels = @($byAtG | ForEach-Object { $_.Name })
    $atValues = @($byAtG | ForEach-Object { $_.Count })

    $byRgG = $atts | Group-Object Region | Sort-Object Count -Descending
    $rgLabels = @($byRgG | ForEach-Object { $_.Name })
    $rgValues = @($byRgG | ForEach-Object { $_.Count })

    $jByRisk = ConvertTo-SafeJson $byRisk
    $jSvcL   = ConvertTo-SafeJson $svcLabels
    $jSvcV   = ConvertTo-SafeJson $svcValues
    $jIdL    = ConvertTo-SafeJson $idLabels
    $jIdV    = ConvertTo-SafeJson $idValues
    $jAtL    = ConvertTo-SafeJson $atLabels
    $jAtV    = ConvertTo-SafeJson $atValues
    $jRgL    = ConvertTo-SafeJson $rgLabels
    $jRgV    = ConvertTo-SafeJson $rgValues

    $css  = Get-SharedCSS
    $hdr  = Get-PageHeader -Active 'dash'

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard - IAM-Robot</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
$css
</head><body>
$hdr
<div class="wrap">

<div class="g5">
  <div class="card te"><div class="lbl">Total Attachments</div><div class="val">$total</div></div>
  <div class="card cr"><div class="lbl">Critical</div><div class="val">$critical</div></div>
  <div class="card hi"><div class="lbl">High</div><div class="val">$high</div></div>
  <div class="card me"><div class="lbl">Medium</div><div class="val">$medium</div></div>
  <div class="card lo"><div class="lbl">Low+Info</div><div class="val">$low</div></div>
</div>

<div class="g5">
  <div class="card in"><div class="lbl">Unique Resources</div><div class="val">$resCount</div></div>
  <div class="card pu"><div class="lbl">Unique Identities</div><div class="val">$idCount</div></div>
  <div class="card hi"><div class="lbl">External Identities</div><div class="val">$external</div></div>
  <div class="card cr"><div class="lbl">Public Exposed</div><div class="val">$public</div></div>
  <div class="card cr"><div class="lbl">Wildcard (*) Perms</div><div class="val">$adminCount</div></div>
</div>

<div class="g3">
  <div class="chart-wrap"><h3>By Risk Level</h3><canvas id="cRisk"></canvas></div>
  <div class="chart-wrap"><h3>Top Services (count of attachments)</h3><canvas id="cSvc"></canvas></div>
  <div class="chart-wrap"><h3>Identity Type Distribution</h3><canvas id="cId"></canvas></div>
</div>

<div class="g2">
  <div class="chart-wrap"><h3>Top Attachment Types</h3><canvas id="cAtt"></canvas></div>
  <div class="chart-wrap"><h3>Attachments per Region</h3><canvas id="cReg"></canvas></div>
</div>

<div class="sec">Jump To <span class="ct">drill-down pages</span></div>
<div class="g4">
  <a href="resources.html" class="card te" style="display:block">
    <div class="lbl">Resources Page</div>
    <div style="font-size:14px;font-weight:600;color:var(--tx);margin-top:6px">All resources and their identities</div>
    <div class="muted" style="font-size:11px;margin-top:4px">Filter by service, region, risk; wildcard perms flagged.</div>
  </a>
  <a href="identities.html" class="card pu" style="display:block">
    <div class="lbl">Identities Page</div>
    <div style="font-size:14px;font-weight:600;color:var(--tx);margin-top:6px">Identities ranked by reach</div>
    <div class="muted" style="font-size:11px;margin-top:4px">Click a row to see every resource that identity touches.</div>
  </a>
  <a href="assume.html" class="card hi" style="display:block">
    <div class="lbl">Assume-Role Page</div>
    <div style="font-size:14px;font-weight:600;color:var(--tx);margin-top:6px">Trusts and federation</div>
    <div class="muted" style="font-size:11px;margin-top:4px">Cross-account, federated, public principals.</div>
  </a>
  <a href="findings.html" class="card cr" style="display:block">
    <div class="lbl">Findings Page</div>
    <div style="font-size:14px;font-weight:600;color:var(--tx);margin-top:6px">Broad / dangerous perms</div>
    <div class="muted" style="font-size:11px;margin-top:4px">Wildcards, admin, public, external admins.</div>
  </a>
</div>

</div>
<script>
var palette = {cr:'#ff3366',hi:'#ff8c00',me:'#f0c040',lo:'#00d488',in:'#4db8ff',pu:'#a855f7',te:'#00d4aa'};
var mu='#6b82b0', gd='#1e2d4a';

new Chart(document.getElementById('cRisk'),{
  type:'doughnut',
  data:{
    labels:['CRITICAL','HIGH','MEDIUM','LOW','INFO'],
    datasets:[{data:$jByRisk,
      backgroundColor:[palette.cr+'aa',palette.hi+'aa',palette.me+'aa',palette.lo+'aa',palette.in+'aa'],
      borderColor:[palette.cr,palette.hi,palette.me,palette.lo,palette.in],borderWidth:2}]
  },
  options:{responsive:true,maintainAspectRatio:false,cutout:'58%',
    plugins:{legend:{position:'right',labels:{color:mu,font:{size:11},padding:10}}}}
});

new Chart(document.getElementById('cSvc'),{
  type:'bar',
  data:{labels:$jSvcL,
    datasets:[{label:'Attachments',data:$jSvcV,
      backgroundColor:palette.te+'55',borderColor:palette.te,borderWidth:1.5,borderRadius:3}]},
  options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',
    plugins:{legend:{display:false}},
    scales:{x:{grid:{color:gd},ticks:{color:mu,font:{size:10}}},
            y:{grid:{color:gd},ticks:{color:mu,font:{size:10}}}}}
});

new Chart(document.getElementById('cId'),{
  type:'doughnut',
  data:{labels:$jIdL,
    datasets:[{data:$jIdV,
      backgroundColor:[palette.pu+'aa',palette.in+'aa',palette.te+'aa',palette.hi+'aa',palette.me+'aa',palette.cr+'aa',palette.lo+'aa'],
      borderColor:[palette.pu,palette.in,palette.te,palette.hi,palette.me,palette.cr,palette.lo],borderWidth:2}]},
  options:{responsive:true,maintainAspectRatio:false,cutout:'58%',
    plugins:{legend:{position:'right',labels:{color:mu,font:{size:11},padding:6}}}}
});

new Chart(document.getElementById('cAtt'),{
  type:'bar',
  data:{labels:$jAtL,
    datasets:[{label:'Count',data:$jAtV,
      backgroundColor:palette.pu+'55',borderColor:palette.pu,borderWidth:1.5,borderRadius:3}]},
  options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',
    plugins:{legend:{display:false}},
    scales:{x:{grid:{color:gd},ticks:{color:mu,font:{size:10}}},
            y:{grid:{color:gd},ticks:{color:mu,font:{size:10}}}}}
});

new Chart(document.getElementById('cReg'),{
  type:'bar',
  data:{labels:$jRgL,
    datasets:[{label:'Attachments',data:$jRgV,
      backgroundColor:palette.in+'55',borderColor:palette.in,borderWidth:1.5,borderRadius:3}]},
  options:{responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:false}},
    scales:{x:{grid:{color:gd},ticks:{color:mu,font:{size:10}}},
            y:{grid:{color:gd},ticks:{color:mu,font:{size:10}}}}}
});
</script>
</body></html>
"@
}

# ----------------------------------------------------------------
# PAGE 2: resources.html  -  every attachment row, broad/admin flagged
# ----------------------------------------------------------------
function New-ResourcesPage {
    $atts = @($Global:IR.Attachments)
    $rows = Build-AttachmentRows -Attachments $atts
    $jRows = ConvertTo-SafeJson $rows

    $regionOpts = (@($Global:IR.Stats.RegionsScanned) + 'global' | Sort-Object -Unique | Where-Object { $_ } |
        ForEach-Object { "<option>$_</option>" }) -join ""
    $typeOpts = ($atts | Select-Object -ExpandProperty ResourceType -Unique | Sort-Object |
        ForEach-Object { "<option>$_</option>" }) -join ""
    $idTypeOpts = ($atts | Where-Object { $_.IdentityType } | Select-Object -ExpandProperty IdentityType -Unique | Sort-Object |
        ForEach-Object { "<option>$_</option>" }) -join ""
    $attTypeOpts = ($atts | Select-Object -ExpandProperty AttachmentType -Unique | Sort-Object |
        ForEach-Object { "<option>$_</option>" }) -join ""

    $css = Get-SharedCSS
    $hdr = Get-PageHeader -Active 'res'

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Resources - IAM-Robot</title>
$css
</head><body>
$hdr
<div class="wrap">

<div class="sec">All Resources and Their Attached Identities <span class="ct" id="rcount"></span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
One row = one IAM identity attached to one resource. Permissions are flagged
<span class="tag adm">ADMIN *</span> (wildcard Action:*) or <span class="tag scope">SVC:*</span>
(service-wide like s3:*). Click any column header to sort.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Search any column...">
  <select id="fRisk"><option value="">All Risk</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
  <select id="fRegion"><option value="">All Regions</option>$regionOpts</select>
  <select id="fType"><option value="">All Resource Types</option>$typeOpts</select>
  <select id="fAtt"><option value="">All Attachment Types</option>$attTypeOpts</select>
  <select id="fIdType"><option value="">All Identity Types</option>$idTypeOpts</select>
  <select id="fBroad"><option value="">Any Perms</option><option value="ADMIN-ALLOW">Allow * (admin)</option><option value="BROAD-ALLOW">Allow service:*</option><option value="ANY-ALLOW">Either (Allow only)</option><option value="DENY">Deny (any scope)</option></select>
  <select id="fEffect"><option value="">Any Effect</option><option>Allow</option><option>Deny</option></select>
  <select id="fRscope"><option value="">Any resources</option><option value="ALL">Resource: *</option><option value="SCOPED">Scoped resources</option></select>
  <label><input type="checkbox" id="fExt"> External</label>
  <label><input type="checkbox" id="fPub"> Public</label>
  <label><input type="checkbox" id="fHp"> High-Priv</label>
  <button id="wrapBtn" type="button">Wrap: OFF</button>
</div>

<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tbl">
      <thead><tr>
        <th data-col="region">Region</th>
        <th data-col="resType">Resource Type</th>
        <th data-col="resName">Resource</th>
        <th data-col="attType">Attachment</th>
        <th data-col="idType">Identity Type</th>
        <th data-col="idName">Identity</th>
        <th data-col="perms">Permissions</th>
        <th data-col="effect">Effect</th>
        <th data-col="broad">Action Scope</th>
        <th data-col="rscope">Resource Scope</th>
        <th>Flags</th>
        <th data-col="risk">Risk</th>
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
$(Get-SharedTableJS)

var RAW = $jRows;

var PAGE_SIZE = 75;
var RANK = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4};
var filtered = RAW.slice();
var sortCol = 'risk';
var sortDir = 1;
var curPage = 1;

function trunc(s,n){ s=String(s||''); return (s.length>n) ? (s.substring(0,n)+'...') : s; }
function riskBadge(rcls,r){ return '<span class="bx '+rcls+'">'+r+'</span>'; }

function applySort(){
  filtered.sort(function(a,b){
    if (sortCol === 'risk') return (RANK[a.risk]-RANK[b.risk]) * sortDir;
    var av = String(a[sortCol]||'').toLowerCase();
    var bv = String(b[sortCol]||'').toLowerCase();
    return av.localeCompare(bv) * sortDir;
  });
}

function render(){
  var q  = document.getElementById('q').value.toLowerCase();
  var rs = document.getElementById('fRisk').value;
  var rg = document.getElementById('fRegion').value;
  var ty = document.getElementById('fType').value;
  var at = document.getElementById('fAtt').value;
  var it = document.getElementById('fIdType').value;
  var bd = document.getElementById('fBroad').value;
  var eff= document.getElementById('fEffect').value;
  var rsc= document.getElementById('fRscope').value;
  var ex = document.getElementById('fExt').checked;
  var pb = document.getElementById('fPub').checked;
  var hp = document.getElementById('fHp').checked;

  filtered = RAW.filter(function(r){
    if (rs && r.risk    !== rs) return false;
    if (rg && r.region  !== rg) return false;
    if (ty && r.resType !== ty) return false;
    if (at && r.attType !== at) return false;
    if (it && r.idType  !== it) return false;
    if (eff && r.effect !== eff) return false;
    if (rsc && r.rscope !== rsc) return false;
    if (bd === 'ADMIN-ALLOW' && r.broad !== 'ADMIN-ALLOW') return false;
    if (bd === 'BROAD-ALLOW' && r.broad !== 'BROAD-ALLOW') return false;
    if (bd === 'ANY-ALLOW'   && r.broad !== 'ADMIN-ALLOW' && r.broad !== 'BROAD-ALLOW') return false;
    if (bd === 'DENY' && !(r.broad === 'ADMIN-DENY' || r.broad === 'BROAD-DENY' || r.broad === 'DENY-SCOPED')) return false;
    if (ex && !r.ext) return false;
    if (pb && !r.pub) return false;
    if (hp && !r.hp)  return false;
    if (q) {
      var blob = (r.region+' '+r.resType+' '+r.resId+' '+r.resName+' '+r.attType+' '+
                  r.idType+' '+r.idName+' '+r.perms+' '+r.notes).toLowerCase();
      if (blob.indexOf(q) < 0) return false;
    }
    return true;
  });
  applySort();
  curPage = 1;
  draw();
}

function effectBadge(eff){
  if (eff === 'Deny') return '<span class="tag deny">DENY</span>';
  if (eff === 'Allow') return '<span class="bx in" style="font-size:9px">ALLOW</span>';
  return '<span class="muted" style="font-size:10px">-</span>';
}

function draw(){
  var start = (curPage-1)*PAGE_SIZE;
  var end   = Math.min(start+PAGE_SIZE, filtered.length);
  var slice = filtered.slice(start, end);
  var tb    = document.getElementById('tbody');

  if (slice.length === 0) {
    tb.innerHTML = '<tr><td colspan="12" class="empty">No matching attachments.</td></tr>';
  } else {
    var html = '';
    for (var i=0; i<slice.length; i++) {
      var r = slice[i];
      var ext = r.ext ? '<span class="tag ext">EXT</span>' : '';
      var pub = r.pub ? '<span class="tag pub">PUB</span>' : '';
      var hpb = r.hp  ? '<span class="bx cr">HP</span>'    : '';
      // Resource cell: link to detail page if available, else search-filter
      var resDisplay = r.resName || r.resId;
      var resCellInner = resPageLink(r.resArn, resDisplay);
      var resCell = resCellInner + (r.resName && r.resId && r.resName !== r.resId
        ? ' <span class="muted mono" style="font-size:10px">/' + escHtml(trunc(r.resId,28)) + '</span>'
        : '');
      html += '<tr>' +
        '<td class="mono">' + escHtml(r.region) + '</td>' +
        '<td>' + escHtml(r.resType) + '</td>' +
        '<td class="trunc" title="' + escHtml(r.resArn) + '">' + resCell + '</td>' +
        '<td>' + escHtml(r.attType) + '</td>' +
        '<td>' + escHtml(r.idType) + '</td>' +
        '<td class="trunc" title="' + escHtml(r.idArn) + '">' + idLink(r.idName) + '</td>' +
        '<td class="trunc mono" title="' + escHtml(r.perms) + '">' + escHtml(r.perms) + '</td>' +
        '<td>' + effectBadge(r.effect) + '</td>' +
        '<td>' + badgeBroad(r.broad) + '</td>' +
        '<td>' + badgeRScope(r.rscope) + '</td>' +
        '<td>' + ext + pub + hpb + '</td>' +
        '<td>' + riskBadge(r.rcls, r.risk) + '</td>' +
      '</tr>';
    }
    tb.innerHTML = html;
  }

  var pages = Math.max(1, Math.ceil(filtered.length/PAGE_SIZE));
  document.getElementById('counter').textContent = 'Showing ' + (filtered.length?(start+1):0) + '-' + end + ' of ' + filtered.length + ' (total: ' + RAW.length + ')';
  document.getElementById('pInfo').textContent = 'Page ' + curPage + ' / ' + pages;
  document.getElementById('pPrev').disabled = (curPage <= 1);
  document.getElementById('pNext').disabled = (curPage >= pages);
  document.getElementById('rcount').textContent = '- ' + RAW.length + ' total rows';
}

// wire filters
['q','fRisk','fRegion','fType','fAtt','fIdType','fBroad','fEffect','fRscope','fExt','fPub','fHp'].forEach(function(id){
  var el = document.getElementById(id);
  var evt = (el.type === 'checkbox' || el.tagName === 'SELECT') ? 'change' : 'input';
  el.addEventListener(evt, render);
});
// wire sorts
document.querySelectorAll('th[data-col]').forEach(function(th){
  th.addEventListener('click', function(){
    var c = th.getAttribute('data-col');
    if (sortCol === c) sortDir = -sortDir; else { sortCol = c; sortDir = 1; }
    document.querySelectorAll('th').forEach(function(t){ t.classList.remove('sortasc','sortdesc'); });
    th.classList.add(sortDir > 0 ? 'sortasc' : 'sortdesc');
    applySort();
    draw();
  });
});
// pager
document.getElementById('pPrev').addEventListener('click', function(){ curPage = Math.max(1, curPage-1); draw(); });
document.getElementById('pNext').addEventListener('click', function(){ var p = Math.ceil(filtered.length/PAGE_SIZE); curPage = Math.min(p, curPage+1); draw(); });

// resizers + wrap + URL filter
attachResizers(document.getElementById('tbl'));
wireWrapToggle('wrapBtn','tbl');
var initialQ = getUrlParam('q');
if (initialQ) document.getElementById('q').value = initialQ;

render();
</script>
</body></html>
"@
}

# ----------------------------------------------------------------
# PAGE 3: identities.html  -  identities ranked by attachment count
# ----------------------------------------------------------------
function New-IdentitiesPage {
    $atts = @($Global:IR.Attachments | Where-Object { $_.IdentityArn -or $_.IdentityName })

    # Group by identity ARN (fall back to name when ARN is missing)
    $groups = $atts | Group-Object { if ($_.IdentityArn) { $_.IdentityArn } else { "name:$($_.IdentityName)" } } |
        Sort-Object Count -Descending

    # AWS-known / well-known identity patterns - these are AWS-managed and
    # generally safe defaults if untouched.
    $awsKnownPatterns = @(
        'AWSServiceRoleFor',           # all AWS service-linked roles
        'AWSReservedSSO_',              # IAM Identity Center
        'OrganizationAccountAccessRole',# Organizations cross-account
        'aws-controltower-',
        'AWSControlTowerExecution',
        'stacksets-exec-',              # CloudFormation StackSets
        'AWSCloudFormationStackSetExecutionRole'
    )
    # AWS Service principals (Identity is a service, not a user/role)
    $awsServicePrincipals = @(
        'amazonaws.com', '.amazonaws.com', 'aws.internal'
    )
    # Map services to their "natural" peer services - touching anything outside
    # this set is potentially anomalous and worth highlighting.
    $naturalCoServices = @{
        'AWS::Lambda'         = @('Lambda','IAM','Logs','SNS','SQS','S3','DynamoDB','KMS','SecretsManager','EventBridge','APIGateway','CloudWatch','VPC')
        'AWS::EC2'            = @('EC2','VPC','S3','IAM','KMS','SSM','Logs','CloudWatch','AutoScaling','ELB','SNS')
        'AWS::ECS'            = @('ECS','EC2','IAM','Logs','ECR','S3','SecretsManager','SSM','CloudWatch','SNS','SQS','VPC','APIGateway')
        'AWS::EKS'            = @('EKS','EC2','IAM','VPC','Logs','CloudWatch','KMS')
        'AWS::CodeBuild'      = @('CodeBuild','S3','Logs','CodeCommit','ECR','SecretsManager','SSM','IAM','CloudWatch','SNS')
        'AWS::CodePipeline'   = @('CodePipeline','CodeBuild','CodeDeploy','CodeCommit','S3','Lambda','SNS','IAM')
        'AWS::SageMaker'      = @('SageMaker','S3','Logs','IAM','ECR','KMS','CloudWatch','VPC')
        'AWS::Glue'           = @('Glue','S3','Logs','IAM','KMS','CloudWatch','Athena','RDS','Redshift')
        'AWS::RDS'            = @('RDS','EC2','KMS','S3','SecretsManager','IAM','SNS','CloudWatch','Logs')
        'AWS::S3'             = @('S3','IAM','KMS','CloudTrail','Logs','SNS','SQS','Lambda')
        'AWS::APIGateway'     = @('APIGateway','Lambda','Logs','IAM','CloudWatch','SNS','SQS')
    }

    function Get-IdentityClass {
        param([string]$IdName, [string]$IdArn, [string]$IdType)
        if (-not $IdName -and -not $IdArn) { return @{ Cls='unknown'; Reason='No identity info' } }
        $name = "$IdName"
        $arn  = "$IdArn"

        # AWS service principals
        if ($IdType -eq 'ServicePrincipal' -or $name -match '\.amazonaws\.com$|\.aws\.internal$') {
            return @{ Cls='aws-known'; Reason='AWS service principal' }
        }
        # AWS-managed role name patterns
        foreach ($p in $awsKnownPatterns) {
            if ($name -like "$p*" -or $arn -like "*role/$p*") {
                return @{ Cls='aws-known'; Reason="Matches AWS-managed pattern: $p*" }
            }
        }
        # Federated principals (typically OIDC/SAML provider ARNs)
        if ($IdType -eq 'FederatedPrincipal') {
            return @{ Cls='aws-known'; Reason='Federated identity provider' }
        }
        # AWSReservedSSO is a strong indicator of Identity Center role
        if ($name -match 'AWSReservedSSO|AWS_SSO_|sso-' ) {
            return @{ Cls='aws-known'; Reason='IAM Identity Center managed role' }
        }
        return @{ Cls='custom'; Reason='Customer-managed identity' }
    }

    function Test-IsModifiedDefault {
        param([string]$IdName, [string]$IdArn, [object[]]$Group)
        # A modified default is an AWS-known identity that has been given extra
        # resource attachments beyond what its service-linked role normally does.
        # Heuristic: AWSServiceRoleFor* roles should only have ONE resource type
        # match (the service they were created for). If they touch >2 service
        # families, the role has been customized.
        if (-not ($IdName -like 'AWSServiceRoleFor*')) { return $false }
        $svcs = @($Group | ForEach-Object { $_.ResourceType.Split('::')[0] } | Sort-Object -Unique)
        return ($svcs.Count -gt 2)
    }

    $idData = New-Object System.Collections.Generic.List[object]

    foreach ($g in $groups) {
        $first = $g.Group[0]

        # Find max risk
        $maxRiskRank = 99
        $maxRisk     = 'INFO'
        foreach ($it in $g.Group) {
            $rank = switch ($it.RiskLevel) {
                'CRITICAL' { 0 } 'HIGH' { 1 } 'MEDIUM' { 2 } 'LOW' { 3 } default { 4 }
            }
            if ($rank -lt $maxRiskRank) { $maxRiskRank = $rank; $maxRisk = $it.RiskLevel }
        }

        # Detect flag states - use Effect-aware breadth
        $hasExt = $false; $hasPub = $false; $hasHP = $false
        $hasAdminAllow = $false; $hasBroadAllow = $false
        foreach ($it in $g.Group) {
            if ($it.IsExternal)      { $hasExt = $true }
            if ($it.IsPublic)        { $hasPub = $true }
            if ($it.IsHighPrivilege) { $hasHP  = $true }
            $eff = if ($it.Effect) { $it.Effect } else { 'Allow' }
            $b = Get-PermissionBreadth -Permissions $it.Permissions -Effect $eff
            if ($b -eq 'ADMIN-ALLOW') { $hasAdminAllow = $true }
            if ($b -eq 'ADMIN-ALLOW' -or $b -eq 'BROAD-ALLOW') { $hasBroadAllow = $true }
        }

        # Classify identity
        $cls = Get-IdentityClass -IdName $first.IdentityName -IdArn "$($g.Name)" -IdType $first.IdentityType
        $isModified = Test-IsModifiedDefault -IdName $first.IdentityName -IdArn "$($g.Name)" -Group $g.Group
        $isAwsKnown = ($cls.Cls -eq 'aws-known') -and -not $isModified

        # Service touch analysis - find anomalous services
        $touchedSvcs = @($g.Group | ForEach-Object { $_.ResourceType } | Sort-Object -Unique)
        $touchedSvcShort = @($touchedSvcs | ForEach-Object { $_.Split('::')[0] } | Sort-Object -Unique)
        # If the identity's name hints at a primary service (e.g. "lambda-exec-role",
        # "S3-Backup"), flag any touched service NOT in that service's natural co-services
        $primaryHint = $null
        $idLower = "$($first.IdentityName)".ToLower()
        foreach ($svc in @('lambda','ec2','ecs','eks','codebuild','codepipeline','sagemaker','glue','rds','s3','apigateway')) {
            if ($idLower -match "(^|[-_])$svc([-_]|$)") { $primaryHint = "AWS::$($svc.ToUpper())"; break }
        }
        $anomalousSvcs = @()
        if ($primaryHint -and $naturalCoServices.ContainsKey($primaryHint)) {
            $expected = $naturalCoServices[$primaryHint]
            foreach ($svc in $touchedSvcShort) {
                # Normalise to lower for matching
                $found = $false
                foreach ($e in $expected) {
                    if ($svc -ieq $e) { $found = $true; break }
                }
                if (-not $found) { $anomalousSvcs += $svc }
            }
        }

        $services = $touchedSvcShort -join ', '

        $details = New-Object System.Collections.Generic.List[object]
        foreach ($it in $g.Group) {
            $eff = if ($it.Effect) { $it.Effect } else { 'Allow' }
            $rsc = if ($it.ResourceScope) { $it.ResourceScope } else { 'UNKNOWN' }
            $details.Add([PSCustomObject]@{
                region  = "$($it.Region)"
                resType = "$($it.ResourceType)"
                resName = "$($it.ResourceName)"
                resId   = "$($it.ResourceId)"
                resArn  = "$($it.ResourceArn)"
                attType = "$($it.AttachmentType)"
                perms   = "$($it.Permissions)"
                risk    = "$($it.RiskLevel)"
                rcls    = (Get-RiskClass $it.RiskLevel)
                broad   = (Get-PermissionBreadth -Permissions $it.Permissions -Effect $eff)
                effect  = $eff
                rscope  = $rsc
            })
        }

        $broadFlag = if ($hasAdminAllow) { 'ADMIN-ALLOW' } elseif ($hasBroadAllow) { 'BROAD-ALLOW' } else { '' }

        $idData.Add([PSCustomObject]@{
            idType        = "$($first.IdentityType)"
            idName        = "$($first.IdentityName)"
            idArn         = "$($g.Name)"
            count         = [int]$g.Count
            maxRisk       = $maxRisk
            rcls          = (Get-RiskClass $maxRisk)
            services      = $services
            ext           = $hasExt
            pub           = $hasPub
            hp            = $hasHP
            broad         = $broadFlag
            details       = $details
            isAwsKnown    = $isAwsKnown
            isModifiedDef = $isModified
            classification= $cls.Cls
            classReason   = $cls.Reason
            primaryHint   = $primaryHint
            anomalousSvcs = ($anomalousSvcs -join ',')
        })
    }

    $jData = ConvertTo-SafeJson $idData

    $idTypeOpts = ($atts | Where-Object { $_.IdentityType } | Select-Object -ExpandProperty IdentityType -Unique | Sort-Object |
        ForEach-Object { "<option>$_</option>" }) -join ""

    $css = Get-SharedCSS
    $hdr = Get-PageHeader -Active 'id'

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Identities - IAM-Robot</title>
$css
</head><body>
$hdr
<div class="wrap">

<div class="sec">All Identities Ranked by Resource Reach <span class="ct" id="rcount"></span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
Each row = one IAM identity (role, user, service, federated principal) and how many resources reference it.
Sorted by count (most reach first). Click a row to expand and see every resource attached to that identity.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Search identity name, ARN, or service...">
  <select id="fType"><option value="">All Identity Types</option>$idTypeOpts</select>
  <select id="fRisk"><option value="">Any max risk</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
  <select id="fPerm"><option value="">Any perms</option><option value="ADMIN-ALLOW">Has Allow *</option><option value="BROAD-ALLOW">Has Allow service:*</option><option value="ANY-ALLOW">Either Allow</option></select>
  <select id="fAwsKnown"><option value="">All identities</option><option value="known">AWS-Known only</option><option value="custom">Customer-managed only</option><option value="modified">Modified default only</option></select>
  <select id="fAnomaly"><option value="">Any service touch</option><option value="anom">Has anomalous services</option><option value="clean">No anomalies</option></select>
  <label><input type="checkbox" id="fExt"> External</label>
  <label><input type="checkbox" id="fPub"> Public</label>
  <label><input type="checkbox" id="fHp"> High-Priv</label>
  <button id="wrapBtn" type="button">Wrap: OFF</button>
</div>

<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tbl">
      <thead><tr>
        <th data-col="idType">Type</th>
        <th data-col="idName">Identity</th>
        <th data-col="count">Resources Using It</th>
        <th>Services Touched</th>
        <th data-col="maxRisk">Max Risk</th>
        <th data-col="broad">Top Perm Scope</th>
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
$(Get-SharedTableJS)

var RAW = $jData;
var PAGE_SIZE = 50;
var RANK = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4};
var filtered = RAW.slice();
var sortCol = 'count';
var sortDir = -1;  // default: most reach first
var curPage = 1;

function trunc(s,n){ s=String(s||''); return (s.length>n) ? (s.substring(0,n)+'...') : s; }
function riskBadge(rcls,r){ return '<span class="bx '+rcls+'">'+r+'</span>'; }

function applySort(){
  filtered.sort(function(a,b){
    if (sortCol === 'maxRisk') return (RANK[a.maxRisk]-RANK[b.maxRisk]) * sortDir;
    if (sortCol === 'count')   return (a.count - b.count) * sortDir;
    var av = String(a[sortCol]||'').toLowerCase();
    var bv = String(b[sortCol]||'').toLowerCase();
    return av.localeCompare(bv) * sortDir;
  });
}

function render(){
  var q  = document.getElementById('q').value.toLowerCase();
  var ty = document.getElementById('fType').value;
  var rs = document.getElementById('fRisk').value;
  var pm = document.getElementById('fPerm').value;
  var ak = document.getElementById('fAwsKnown').value;
  var an = document.getElementById('fAnomaly').value;
  var ex = document.getElementById('fExt').checked;
  var pb = document.getElementById('fPub').checked;
  var hp = document.getElementById('fHp').checked;

  filtered = RAW.filter(function(r){
    if (ty && r.idType !== ty) return false;
    if (rs && r.maxRisk !== rs) return false;
    if (pm === 'ADMIN-ALLOW' && r.broad !== 'ADMIN-ALLOW') return false;
    if (pm === 'BROAD-ALLOW' && r.broad !== 'BROAD-ALLOW') return false;
    if (pm === 'ANY-ALLOW'   && r.broad !== 'ADMIN-ALLOW' && r.broad !== 'BROAD-ALLOW') return false;
    if (ak === 'known'    && !r.isAwsKnown) return false;
    if (ak === 'custom'   && r.isAwsKnown) return false;
    if (ak === 'modified' && !r.isModifiedDef) return false;
    var hasAnom = (r.anomalousSvcs || '').length > 0;
    if (an === 'anom'  && !hasAnom) return false;
    if (an === 'clean' &&  hasAnom) return false;
    if (ex && !r.ext) return false;
    if (pb && !r.pub) return false;
    if (hp && !r.hp)  return false;
    if (q) {
      var blob = (r.idType+' '+r.idName+' '+r.idArn+' '+r.services).toLowerCase();
      if (blob.indexOf(q) < 0) return false;
    }
    return true;
  });
  applySort();
  curPage = 1;
  draw();
}

function toggleDetail(idx){
  var row = document.getElementById('det-'+idx);
  if (!row) return;
  row.style.display = (row.style.display === 'table-row') ? 'none' : 'table-row';
}

function draw(){
  var start = (curPage-1)*PAGE_SIZE;
  var end   = Math.min(start+PAGE_SIZE, filtered.length);
  var slice = filtered.slice(start, end);
  var tb    = document.getElementById('tbody');

  if (slice.length === 0) {
    tb.innerHTML = '<tr><td colspan="7" class="empty">No matching identities.</td></tr>';
  } else {
    var html = '';
    for (var i=0; i<slice.length; i++) {
      var r = slice[i];
      var ext = r.ext ? '<span class="tag ext">EXT</span>' : '';
      var pub = r.pub ? '<span class="tag pub">PUB</span>' : '';
      var hpb = r.hp  ? '<span class="bx cr">HP</span>'    : '';
      // Identity classification badges
      var awsBadge = r.isAwsKnown ? '<span class="tag awsknown" title="'+escHtml(r.classReason)+'">AWS-KNOWN</span>' : '';
      var modBadge = r.isModifiedDef ? '<span class="tag modified" title="Default identity touching unusual services">MODIFIED</span>' : '';

      // Build detail rows showing every resource using this identity
      var detHtml = '';
      if (r.details && r.details.length) {
        detHtml = '<tr id="det-'+i+'" class="detail-row" style="display:none"><td colspan="7">' +
          '<div style="font-size:11px;color:var(--mu);margin-bottom:6px">Every resource this identity is attached to (' + r.details.length + '):</div>' +
          '<ul class="detail-list">';
        for (var k=0; k<r.details.length; k++) {
          var d = r.details[k];
          var dResLink = '<a href="resources.html?q=' + encodeURIComponent(d.resName||d.resId) + '">' + escHtml(d.resName||d.resId) + '</a>';
          detHtml += '<li>' +
            '<span class="bx '+d.rcls+'" style="min-width:60px;display:inline-block;text-align:center">'+d.risk+'</span>' +
            '<span class="mono muted">['+escHtml(d.region)+']</span>' +
            '<strong>'+escHtml(d.resType)+'</strong>' +
            dResLink +
            '<span class="muted">- '+escHtml(d.attType)+'</span>' +
            badgeBroad(d.broad) +
            badgeRScope(d.rscope) +
            '<span class="muted mono" style="font-size:10px">perms: '+escHtml(d.perms)+'</span>' +
          '</li>';
        }
        detHtml += '</ul></td></tr>';
      }

      // Highlight anomalous services in red if any
      var anomList = (r.anomalousSvcs || '').split(',').filter(function(s){return s;});
      var servicesHtml = '';
      if (anomList.length > 0) {
        var svcArr = (r.services||'').split(', ');
        var rendered = svcArr.map(function(s){
          var anomalous = anomList.indexOf(s) >= 0;
          return anomalous
            ? '<span style="color:var(--cr);font-weight:600" title="Anomalous for primary purpose ' + escHtml(r.primaryHint||'') + '">'+escHtml(s)+'</span>'
            : escHtml(s);
        });
        servicesHtml = rendered.join(', ');
      } else {
        servicesHtml = escHtml(r.services);
      }

      var nameCell = (ROLE_PAGES[r.idArn])
        ? '<a href="' + ROLE_PAGES[r.idArn] + '"><strong>' + escHtml(r.idName) + '</strong></a> <span class="bx te" style="font-size:8px">DETAIL</span>'
        : '<strong>' + escHtml(r.idName) + '</strong>';
      html += '<tr style="cursor:pointer" onclick="toggleDetail('+i+')">' +
        '<td>' + escHtml(r.idType) + '</td>' +
        '<td>' + nameCell + ' ' + awsBadge + ' ' + modBadge + ' <span class="expand-btn">[expand]</span><br>' +
        '<span class="mono muted" style="font-size:10px">' + escHtml(r.idArn) + '</span></td>' +
        '<td><strong style="color:var(--te);font-size:15px">' + r.count + '</strong></td>' +
        '<td class="trunc" title="' + escHtml(r.services) + '">' + servicesHtml + '</td>' +
        '<td>' + riskBadge(r.rcls, r.maxRisk) + '</td>' +
        '<td>' + badgeBroad(r.broad) + '</td>' +
        '<td>' + ext + pub + hpb + '</td>' +
      '</tr>' + detHtml;
    }
    tb.innerHTML = html;
  }

  var pages = Math.max(1, Math.ceil(filtered.length/PAGE_SIZE));
  document.getElementById('counter').textContent = 'Showing ' + (filtered.length?(start+1):0) + '-' + end + ' of ' + filtered.length + ' identities';
  document.getElementById('pInfo').textContent = 'Page ' + curPage + ' / ' + pages;
  document.getElementById('pPrev').disabled = (curPage <= 1);
  document.getElementById('pNext').disabled = (curPage >= pages);
  document.getElementById('rcount').textContent = '- ' + RAW.length + ' unique identities';
}

['q','fType','fRisk','fPerm','fAwsKnown','fAnomaly','fExt','fPub','fHp'].forEach(function(id){
  var el = document.getElementById(id);
  var evt = (el.type === 'checkbox' || el.tagName === 'SELECT') ? 'change' : 'input';
  el.addEventListener(evt, render);
});
document.querySelectorAll('th[data-col]').forEach(function(th){
  th.addEventListener('click', function(){
    var c = th.getAttribute('data-col');
    if (sortCol === c) sortDir = -sortDir;
    else { sortCol = c; sortDir = (c==='count' || c==='maxRisk') ? -1 : 1; }
    document.querySelectorAll('th').forEach(function(t){ t.classList.remove('sortasc','sortdesc'); });
    th.classList.add(sortDir > 0 ? 'sortasc' : 'sortdesc');
    applySort();
    draw();
  });
});
document.getElementById('pPrev').addEventListener('click', function(){ curPage = Math.max(1, curPage-1); draw(); });
document.getElementById('pNext').addEventListener('click', function(){ var p = Math.ceil(filtered.length/PAGE_SIZE); curPage = Math.min(p, curPage+1); draw(); });

// resizers + wrap + URL filter
attachResizers(document.getElementById('tbl'));
wireWrapToggle('wrapBtn','tbl');
var initialQ = getUrlParam('q');
if (initialQ) {
  document.getElementById('q').value = initialQ;
  render();
  // Auto-expand if there's only one match
  setTimeout(function(){
    var detRows = document.querySelectorAll('.detail-row');
    if (detRows.length === 1) detRows[0].style.display = 'table-row';
  }, 50);
} else {
  render();
}
</script>
</body></html>
"@
}

# ----------------------------------------------------------------
# PAGE 4: assume.html  -  assume-role / trust / federation focus
# ----------------------------------------------------------------
function New-AssumePage {
    $atts = @($Global:IR.Attachments)

    # Anything that represents a trust relationship between an IAM identity and a resource:
    #  - All attachment types ending in Role
    #  - Trust policy / resource policy entries
    #  - Cross-account or federated principals
    $assume = $atts | Where-Object {
        ($_.AttachmentType -match '(?i)Role$|Trust|InstanceProfile|AssumeRole') -or
        ($_.IdentityType -in @('AWSAccount','FederatedPrincipal','Public','ServicePrincipal'))
    }
    $assume = @($assume)

    # Pre-compute: for each role ARN, how many resources use it as identity?
    # And what does the role grant? (lookup RoleCatalog).
    $resourcesByRole = @{}
    foreach ($a in $atts) {
        if ($a.IdentityType -eq 'Role' -and $a.IdentityArn -and $a.AttachmentType -ne 'TrustPolicy') {
            if (-not $resourcesByRole.ContainsKey($a.IdentityArn)) {
                $resourcesByRole[$a.IdentityArn] = New-Object System.Collections.Generic.List[string]
            }
            $resourcesByRole[$a.IdentityArn].Add("$($a.ResourceType):$($a.ResourceName)")
        }
    }

    # Build rich rows with role-catalog enrichment
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $assume) {
        $effect = if ($r.Effect) { "$($r.Effect)" } else { 'Allow' }
        $rscope = if ($r.ResourceScope) { "$($r.ResourceScope)" } else { 'UNKNOWN' }
        $broad  = Get-PermissionBreadth -Permissions $r.Permissions -Effect $effect

        # If the Resource is an IAM Role (TrustPolicy attachment), look up the role's permissions
        $assumeRoleName = ""
        $roleSummary    = ""
        $roleAdmin      = $false
        $roleServices   = ""
        $resourcesUsing = 0
        $iamAuditFlag   = $false

        if ($r.ResourceType -eq 'IAM::Role' -and $r.ResourceArn -and $Global:IR.RoleCatalog) {
            $cat = $Global:IR.RoleCatalog[$r.ResourceArn]
            if ($cat -and $cat.Fetched) {
                $assumeRoleName = $cat.RoleName
                $roleSummary    = $cat.PolicySummary
                $roleAdmin      = [bool]$cat.HasAdmin
                if ($cat.Services -and $cat.Services.Count -gt 0) {
                    $roleServices = ($cat.Services | Sort-Object | Select-Object -First 8) -join ','
                    if ($cat.Services.Count -gt 8) { $roleServices += "+$($cat.Services.Count - 8)" }
                }
                if ($cat.ContainsKey('IAMAuditHighSignal') -and $cat['IAMAuditHighSignal']) {
                    $iamAuditFlag = $true
                }
            }
            if ($resourcesByRole.ContainsKey($r.ResourceArn)) {
                $resourcesUsing = $resourcesByRole[$r.ResourceArn].Count
            }
        }

        # Logic for the "Assume Role" column:
        #  - TrustPolicy attachment: Resource IS the role; the principal in IdentityArn is who can assume it
        #    -> "Resource" = Resource (the role being assumed), "Assume Role" cell is the IDENTITY (who assumes)
        #    Actually flip: Resource cell shows the trust subject; Assume Role cell shows the role itself
        #  - Non-trust attachment (e.g. EC2 InstanceProfile pointing to role): Resource = EC2 instance,
        #    Identity = the role it uses. So "Resource" = EC2 instance, "Assume Role" = the role it can become.

        $isTrustRow = ($r.AttachmentType -eq 'TrustPolicy')
        if ($isTrustRow) {
            # The role being assumed IS the resource itself
            if ($r.ResourceType -eq 'IAM::Role' -and $r.ResourceArn -match ':role/(.+)$') {
                $assumeRoleName = $Matches[1]
            }
        } else {
            # The role the resource can assume is the IdentityArn (when it's a Role)
            if ($r.IdentityType -eq 'Role' -and $r.IdentityArn -match ':role/(.+)$') {
                $assumeRoleName = $Matches[1]
            }
        }

        # Mark the row as "actually assuming a role" vs not (for grey-out / sorting)
        $hasAssumeRole = [bool]$assumeRoleName

        $row = [PSCustomObject]@{
            region        = "$($r.Region)"
            resType       = "$($r.ResourceType)"
            resId         = "$($r.ResourceId)"
            resName       = "$($r.ResourceName)"
            resArn        = "$($r.ResourceArn)"
            attType       = "$($r.AttachmentType)"
            idType        = "$($r.IdentityType)"
            idName        = "$($r.IdentityName)"
            idArn         = "$($r.IdentityArn)"
            perms         = "$($r.Permissions)"
            ext           = [bool]$r.IsExternal
            pub           = [bool]$r.IsPublic
            hp            = [bool]$r.IsHighPrivilege
            risk          = "$($r.RiskLevel)"
            rcls          = (Get-RiskClass $r.RiskLevel)
            notes         = "$($r.Notes)"
            broad         = $broad
            effect        = $effect
            rscope        = $rscope
            roleName      = $assumeRoleName
            roleSummary   = $roleSummary
            roleAdmin     = $roleAdmin
            roleServices  = $roleServices
            resourcesUsing= [int]$resourcesUsing
            iamAuditFlag  = [bool]$iamAuditFlag
            isTrustRow    = [bool]$isTrustRow
            hasAssumeRole = [bool]$hasAssumeRole
        }
        $rows.Add($row)
    }
    $jRows = ConvertTo-SafeJson $rows

    $total      = $assume.Count
    $external   = ($assume | Where-Object { $_.IsExternal }).Count
    $public     = ($assume | Where-Object { $_.IsPublic }).Count
    $fed        = ($assume | Where-Object { $_.IdentityType -eq 'FederatedPrincipal' }).Count
    $crossacct  = ($assume | Where-Object { $_.IdentityType -eq 'AWSAccount' -and $_.IsExternal }).Count
    $svcPrins   = ($assume | Where-Object { $_.IdentityType -eq 'ServicePrincipal' }).Count
    $broadCount = ($assume | Where-Object {
        $e = if ($_.Effect) { $_.Effect } else { 'Allow' }
        Test-BroadPerm (Get-PermissionBreadth -Permissions $_.Permissions -Effect $e)
    }).Count

    # Charts
    $byIdG = $assume | Where-Object { $_.IdentityType } | Group-Object IdentityType | Sort-Object Count -Descending
    $aiL = @($byIdG | ForEach-Object { $_.Name })
    $aiV = @($byIdG | ForEach-Object { $_.Count })
    $jAiL = ConvertTo-SafeJson $aiL
    $jAiV = ConvertTo-SafeJson $aiV

    $byAtG = $assume | Group-Object AttachmentType | Sort-Object Count -Descending | Select-Object -First 10
    $atL = @($byAtG | ForEach-Object { $_.Name })
    $atV = @($byAtG | ForEach-Object { $_.Count })
    $jAtL = ConvertTo-SafeJson $atL
    $jAtV = ConvertTo-SafeJson $atV

    $css = Get-SharedCSS
    $hdr = Get-PageHeader -Active 'asm'

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Assume-Role and Federation - IAM-Robot</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
$css
</head><body>
$hdr
<div class="wrap">

<div class="g5">
  <div class="card te"><div class="lbl">Trust Relationships</div><div class="val">$total</div></div>
  <div class="card hi"><div class="lbl">External Principals</div><div class="val">$external</div></div>
  <div class="card cr"><div class="lbl">Public (*)</div><div class="val">$public</div></div>
  <div class="card pu"><div class="lbl">Federated (OIDC/SAML)</div><div class="val">$fed</div></div>
  <div class="card hi"><div class="lbl">Cross-Account Roots</div><div class="val">$crossacct</div></div>
</div>

<div class="g2">
  <div class="chart-wrap"><h3>Principal Types</h3><canvas id="cIdType"></canvas></div>
  <div class="chart-wrap"><h3>Attachment Types</h3><canvas id="cAt"></canvas></div>
</div>

<div class="sec">All Trust and Assume-Role Attachments <span class="ct" id="rcount"></span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
Shows where IAM trust is established: role assumed by another role, service-principal trusts,
cross-account trusts, federated identity providers (OIDC/SAML), and public (*) trusts.
Wildcard permissions on these are flagged - they extend the scope of any compromise of the trusted principal.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Search...">
  <select id="fIdType">
    <option value="">All Identity Types</option>
    <option>Role</option><option>AWSAccount</option><option>ServicePrincipal</option>
    <option>FederatedPrincipal</option><option>User</option><option>Public</option>
  </select>
  <select id="fAttType"><option value="">All Attachment Types</option><option>TrustPolicy</option><option>InstanceProfile</option><option>ExecutionRole</option><option>TaskRole</option><option>ServiceRole</option><option>JobRole</option></select>
  <select id="fRisk"><option value="">All Risk</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
  <select id="fBroad"><option value="">Any perms</option><option value="ADMIN-ALLOW">Allow *</option><option value="BROAD-ALLOW">Allow service:*</option><option value="ANY-ALLOW">Either Allow</option><option value="DENY">Deny (any)</option></select>
  <select id="fRoleAdmin"><option value="">Any role</option><option value="yes">Role has Admin</option><option value="no">Role NOT admin</option></select>
  <select id="fAssumes"><option value="">Any assume status</option><option value="yes">Actually assumes</option><option value="no">Non-assuming rows</option></select>
  <label><input type="checkbox" id="fExt"> External</label>
  <label><input type="checkbox" id="fPub"> Public</label>
  <button id="wrapBtn" type="button">Wrap: OFF</button>
</div>

<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table id="tbl">
      <thead><tr>
        <th data-col="resType">Resource Type</th>
        <th data-col="resName">Resource (role assumed)</th>
        <th data-col="attType">Trust Type</th>
        <th data-col="idType">Principal Type</th>
        <th data-col="idName">Trusted Principal</th>
        <th data-col="roleName">Assume Role</th>
        <th data-col="roleSummary">Role Permissions Summary</th>
        <th data-col="roleServices">Role Services</th>
        <th data-col="resourcesUsing">Resources Using Role</th>
        <th data-col="effect">Effect</th>
        <th data-col="broad">Trust Scope</th>
        <th>Flags</th>
        <th data-col="risk">Risk</th>
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
$(Get-SharedTableJS)

var palette = {cr:'#ff3366',hi:'#ff8c00',me:'#f0c040',lo:'#00d488',in:'#4db8ff',pu:'#a855f7',te:'#00d4aa'};
var mu='#6b82b0', gd='#1e2d4a';

new Chart(document.getElementById('cIdType'),{
  type:'doughnut',
  data:{labels:$jAiL,datasets:[{data:$jAiV,
    backgroundColor:[palette.hi+'aa',palette.pu+'aa',palette.te+'aa',palette.cr+'aa',palette.in+'aa',palette.me+'aa',palette.lo+'aa'],
    borderColor:[palette.hi,palette.pu,palette.te,palette.cr,palette.in,palette.me,palette.lo],borderWidth:2}]},
  options:{responsive:true,maintainAspectRatio:false,cutout:'58%',
    plugins:{legend:{position:'right',labels:{color:mu,font:{size:11},padding:8}}}}
});

new Chart(document.getElementById('cAt'),{
  type:'bar',
  data:{labels:$jAtL,datasets:[{label:'Count',data:$jAtV,
    backgroundColor:palette.hi+'55',borderColor:palette.hi,borderWidth:1.5,borderRadius:3}]},
  options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',
    plugins:{legend:{display:false}},
    scales:{x:{grid:{color:gd},ticks:{color:mu,font:{size:10}}},
            y:{grid:{color:gd},ticks:{color:mu,font:{size:10}}}}}
});

var RAW = $jRows;
var PAGE_SIZE = 75;
var RANK = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4};
var filtered = RAW.slice();
var sortCol = 'risk', sortDir = 1, curPage = 1;

function trunc(s,n){ s=String(s||''); return (s.length>n) ? (s.substring(0,n)+'...') : s; }
function riskBadge(rcls,r){ return '<span class="bx '+rcls+'">'+r+'</span>'; }
function effectBadge(eff){
  if (eff === 'Deny') return '<span class="tag deny">DENY</span>';
  if (eff === 'Allow') return '<span class="bx in" style="font-size:9px">ALLOW</span>';
  return '<span class="muted" style="font-size:10px">-</span>';
}

function applySort(){
  filtered.sort(function(a,b){
    // Always put non-assuming rows at the bottom (after primary sort)
    if (a.hasAssumeRole !== b.hasAssumeRole) {
      return a.hasAssumeRole ? -1 : 1;
    }
    if (sortCol === 'risk') return (RANK[a.risk]-RANK[b.risk]) * sortDir;
    if (sortCol === 'resourcesUsing') return (a.resourcesUsing - b.resourcesUsing) * sortDir;
    var av = String(a[sortCol]||'').toLowerCase();
    var bv = String(b[sortCol]||'').toLowerCase();
    return av.localeCompare(bv) * sortDir;
  });
}

function render(){
  var q  = document.getElementById('q').value.toLowerCase();
  var it = document.getElementById('fIdType').value;
  var at = document.getElementById('fAttType').value;
  var rs = document.getElementById('fRisk').value;
  var bd = document.getElementById('fBroad').value;
  var ra = document.getElementById('fRoleAdmin').value;
  var as = document.getElementById('fAssumes').value;
  var ex = document.getElementById('fExt').checked;
  var pb = document.getElementById('fPub').checked;

  filtered = RAW.filter(function(r){
    if (it && r.idType !== it) return false;
    if (at && r.attType !== at) return false;
    if (rs && r.risk   !== rs) return false;
    if (bd === 'ADMIN-ALLOW' && r.broad !== 'ADMIN-ALLOW') return false;
    if (bd === 'BROAD-ALLOW' && r.broad !== 'BROAD-ALLOW') return false;
    if (bd === 'ANY-ALLOW'   && r.broad !== 'ADMIN-ALLOW' && r.broad !== 'BROAD-ALLOW') return false;
    if (bd === 'DENY' && !(r.broad === 'ADMIN-DENY' || r.broad === 'BROAD-DENY' || r.broad === 'DENY-SCOPED')) return false;
    if (ra === 'yes' && !r.roleAdmin) return false;
    if (ra === 'no'  && r.roleAdmin)  return false;
    if (as === 'yes' && !r.hasAssumeRole) return false;
    if (as === 'no'  &&  r.hasAssumeRole) return false;
    if (ex && !r.ext) return false;
    if (pb && !r.pub) return false;
    if (q) {
      var blob = (r.resType+' '+r.resName+' '+r.idType+' '+r.idName+' '+r.idArn+' '+r.attType+' '+r.perms+' '+(r.roleName||'')+' '+(r.roleSummary||'')+' '+(r.roleServices||'')).toLowerCase();
      if (blob.indexOf(q) < 0) return false;
    }
    return true;
  });
  applySort();
  curPage = 1;
  draw();
}

function draw(){
  var start = (curPage-1)*PAGE_SIZE;
  var end   = Math.min(start+PAGE_SIZE, filtered.length);
  var slice = filtered.slice(start, end);
  var tb    = document.getElementById('tbody');

  if (slice.length === 0) {
    tb.innerHTML = '<tr><td colspan="13" class="empty">No matching trust relationships.</td></tr>';
  } else {
    var html = '';
    for (var i=0; i<slice.length; i++) {
      var r = slice[i];
      var ext = r.ext ? '<span class="tag ext">EXT</span>' : '';
      var pub = r.pub ? '<span class="tag pub">PUB</span>' : '';
      var hpb = r.hp  ? '<span class="bx cr">HP</span>'    : '';
      var resName = r.resName || r.resId;

      // Resource cell:
      //  - Trust row: resource is the IAM Role itself. Show "(trust policy on <RoleName>)" with link
      //  - Non-trust row: resource is the actual AWS resource. Link to its detail page.
      var resCell;
      if (r.isTrustRow) {
        resCell = '<span class="muted" style="font-size:10px">(trust on)</span> ' +
          (r.resArn && ROLE_PAGES[r.resArn]
            ? '<a href="' + ROLE_PAGES[r.resArn] + '">' + escHtml(resName) + '</a>'
            : escHtml(resName));
      } else {
        resCell = resPageLink(r.resArn, resName);
      }

      // Assume Role cell - the role being assumed (or '-' if none)
      var roleNameCell;
      if (!r.hasAssumeRole) {
        roleNameCell = '<span class="muted">(no role assumed)</span>';
      } else {
        // Look up role page link via either resArn (trust row) or idArn (non-trust)
        var lookupArn = r.isTrustRow ? r.resArn : r.idArn;
        var lookupName = r.roleName;
        roleNameCell = (lookupArn && ROLE_PAGES[lookupArn])
          ? '<a href="' + ROLE_PAGES[lookupArn] + '">' + escHtml(lookupName) + '</a>'
          : '<a href="identities.html?q=' + encodeURIComponent(lookupName) + '">' + escHtml(lookupName) + '</a>';
        if (r.roleAdmin) roleNameCell += ' <span class="tag adm">ADMIN</span>';
      }

      var idCell = r.idName
        ? (r.idType === 'Role' || r.idType === 'User'
            ? (r.idArn && ROLE_PAGES[r.idArn]
                ? '<a href="' + ROLE_PAGES[r.idArn] + '">' + escHtml(r.idName) + '</a>'
                : '<a href="identities.html?q=' + encodeURIComponent(r.idName) + '">' + escHtml(r.idName) + '</a>')
            : escHtml(r.idName))
        : '';
      var resCount = r.resourcesUsing
        ? '<strong style="color:var(--te)">' + r.resourcesUsing + '</strong>'
        : '<span class="muted">0</span>';

      // Grey-out rows that don't actually involve a role assume
      var rowClass = r.hasAssumeRole ? '' : ' class="row-muted"';
      html += '<tr' + rowClass + '>' +
        '<td>' + escHtml(r.resType) + '</td>' +
        '<td class="trunc" title="' + escHtml(r.resArn) + '">' + resCell + '</td>' +
        '<td>' + escHtml(r.attType) + '</td>' +
        '<td>' + escHtml(r.idType) + '</td>' +
        '<td class="trunc" title="' + escHtml(r.idArn) + '">' + idCell + '</td>' +
        '<td>' + roleNameCell + '</td>' +
        '<td class="trunc mono" title="' + escHtml(r.roleSummary||'') + '">' + escHtml(r.roleSummary||'-') + '</td>' +
        '<td class="trunc mono" title="' + escHtml(r.roleServices||'') + '">' + escHtml(r.roleServices||'-') + '</td>' +
        '<td>' + resCount + '</td>' +
        '<td>' + effectBadge(r.effect) + '</td>' +
        '<td>' + badgeBroad(r.broad) + '</td>' +
        '<td>' + ext + pub + hpb + '</td>' +
        '<td>' + riskBadge(r.rcls, r.risk) + '</td>' +
      '</tr>';
    }
    tb.innerHTML = html;
  }

  var pages = Math.max(1, Math.ceil(filtered.length/PAGE_SIZE));
  document.getElementById('counter').textContent = 'Showing ' + (filtered.length?(start+1):0) + '-' + end + ' of ' + filtered.length;
  document.getElementById('pInfo').textContent = 'Page ' + curPage + ' / ' + pages;
  document.getElementById('pPrev').disabled = (curPage <= 1);
  document.getElementById('pNext').disabled = (curPage >= pages);
  document.getElementById('rcount').textContent = '- ' + RAW.length + ' total';
}

['q','fIdType','fAttType','fRisk','fBroad','fRoleAdmin','fAssumes','fExt','fPub'].forEach(function(id){
  var el = document.getElementById(id);
  var evt = (el.type === 'checkbox' || el.tagName === 'SELECT') ? 'change' : 'input';
  el.addEventListener(evt, render);
});
document.querySelectorAll('th[data-col]').forEach(function(th){
  th.addEventListener('click', function(){
    var c = th.getAttribute('data-col');
    if (sortCol === c) sortDir = -sortDir; else { sortCol = c; sortDir = 1; }
    document.querySelectorAll('th').forEach(function(t){ t.classList.remove('sortasc','sortdesc'); });
    th.classList.add(sortDir > 0 ? 'sortasc' : 'sortdesc');
    applySort();
    draw();
  });
});
document.getElementById('pPrev').addEventListener('click', function(){ curPage = Math.max(1, curPage-1); draw(); });
document.getElementById('pNext').addEventListener('click', function(){ var p = Math.ceil(filtered.length/PAGE_SIZE); curPage = Math.min(p, curPage+1); draw(); });

// resizers + wrap + URL filter
attachResizers(document.getElementById('tbl'));
wireWrapToggle('wrapBtn','tbl');
var initialQ = getUrlParam('q');
if (initialQ) document.getElementById('q').value = initialQ;

render();
</script>
</body></html>
"@
}

# ----------------------------------------------------------------
# Findings card helper (module-scope to avoid PS 5.1 nesting issues)
# ----------------------------------------------------------------
function Build-FindingCard {
    param(
        [string]$Id, [string]$Title, [string]$Risk,
        [string]$Description, [string]$Impact, [string]$Recommend,
        [object[]]$Items
    )
    if (-not $Items -or $Items.Count -eq 0) { return "" }
    $cls = Get-RiskClass $Risk

    # Show ALL items, no truncation. ul has overflow-y:auto so it scrolls.
    $liHtml = New-Object System.Text.StringBuilder
    foreach ($r in $Items) {
        $flags = @()
        if ($r.IsExternal)      { $flags += "EXTERNAL" }
        if ($r.IsPublic)        { $flags += "PUBLIC" }
        if ($r.IsHighPrivilege) { $flags += "HIGH-PRIV" }
        if ($r.Effect -eq 'Deny') { $flags += "DENY" }
        $flagStr = if ($flags.Count -gt 0) { " [$($flags -join ',')]" } else { "" }
        $permStr = if ($r.Permissions) { " perms=" + (ConvertTo-HtmlText $r.Permissions) } else { "" }
        $scope   = if ($r.ResourceScope -eq 'SCOPED') { " (scoped)" } else { "" }
        $line = "[$(ConvertTo-HtmlText $r.Region)] $(ConvertTo-HtmlText $r.ResourceType) " +
                "<strong>$(ConvertTo-HtmlText $r.ResourceName)</strong> &rarr; " +
                "$(ConvertTo-HtmlText $r.IdentityType): " +
                "<a href=`"identities.html?q=$([Uri]::EscapeDataString("$($r.IdentityName)"))`">$(ConvertTo-HtmlText $r.IdentityName)</a>" +
                $flagStr + $scope + $permStr
        [void]$liHtml.Append("<li>$line</li>")
    }

    $titleEnc = ConvertTo-HtmlText $Title
    $descEnc  = ConvertTo-HtmlText $Description
    $impEnc   = ConvertTo-HtmlText $Impact
    $recEnc   = ConvertTo-HtmlText $Recommend
    $count    = $Items.Count

@"
<div class="fcard $cls">
  <h4>$titleEnc <span class="bx $cls">$Risk</span> <span class="bx te">$count items</span></h4>
  <div class="findmeta"><strong>ID:</strong> $Id</div>
  <p>$descEnc</p>
  <p style="color:var(--mu)"><strong>Impact:</strong> $impEnc</p>
  <p style="color:var(--mu)"><strong>Recommendation:</strong> $recEnc</p>
  <ul>$($liHtml.ToString())</ul>
</div>
"@
}

# ----------------------------------------------------------------
# PAGE 5: findings.html  -  broad / dangerous permissions
# ----------------------------------------------------------------
function New-FindingsPage {
    $atts = @($Global:IR.Attachments)

    # Buckets of interest - use new Effect-aware breadth codes
    # ADMIN-ALLOW = Allow Action:* (BAD)
    # BROAD-ALLOW = Allow service:* (BAD)
    # ADMIN-DENY  = Deny Action:* (GOOD - protective)
    # BROAD-DENY  = Deny service:* (GOOD - protective)
    $wildcardActions = @($atts | Where-Object {
        $e = if ($_.Effect) { $_.Effect } else { 'Allow' }
        (Get-PermissionBreadth -Permissions $_.Permissions -Effect $e) -eq 'ADMIN-ALLOW'
    })
    $broadServices   = @($atts | Where-Object {
        $e = if ($_.Effect) { $_.Effect } else { 'Allow' }
        (Get-PermissionBreadth -Permissions $_.Permissions -Effect $e) -eq 'BROAD-ALLOW'
    })
    $protectiveDeny  = @($atts | Where-Object {
        $e = if ($_.Effect) { $_.Effect } else { 'Allow' }
        $c = Get-PermissionBreadth -Permissions $_.Permissions -Effect $e
        $c -eq 'ADMIN-DENY' -or $c -eq 'BROAD-DENY'
    })
    $publicResources = @($atts | Where-Object { $_.IsPublic -and $_.Effect -ne 'Deny' })
    $externalAdmins  = @($atts | Where-Object { $_.IsExternal -and $_.IsHighPrivilege -and $_.Effect -ne 'Deny' })
    $externalAccess  = @($atts | Where-Object { $_.IsExternal -and -not $_.IsHighPrivilege -and $_.Effect -ne 'Deny' })
    $ciCdRoles       = @($atts | Where-Object { $_.ResourceType -match 'CodeBuild|CodePipeline|CodeDeploy' })
    $passThrough     = @($atts | Where-Object {
        $_.AttachmentType -match 'ExecutionRole|TaskRole|InstanceProfile' -and $_.IsHighPrivilege
    })

    # Enrichment-based findings (only if catalog exists)
    $rolesWithAdmin = @()
    $riskyTrusts    = @()
    $extIdMissing   = @()
    if ($Global:IR.RoleCatalog -and $Global:IR.RoleCatalog.Count -gt 0) {
        foreach ($arn in $Global:IR.RoleCatalog.Keys) {
            $cat = $Global:IR.RoleCatalog[$arn]
            if (-not $cat.Fetched) { continue }
            if ($cat.HasAdmin) {
                # Find one attachment representing this role to display
                $sample = $atts | Where-Object { $_.IdentityArn -eq $arn -and $_.AttachmentType -ne 'TrustPolicy' } | Select-Object -First 1
                if ($sample) { $rolesWithAdmin += $sample }
                else {
                    # synthesize
                    $rolesWithAdmin += [PSCustomObject]@{
                        Region          = 'global'
                        ResourceType    = 'IAM::Role'
                        ResourceName    = $cat.RoleName
                        IdentityType    = 'Role'
                        IdentityName    = $cat.RoleName
                        IsExternal      = $false
                        IsPublic        = $false
                        IsHighPrivilege = $true
                        Permissions     = $cat.PolicySummary
                    }
                }
            }
        }
    }

    # Trust-policy attachments with concerning shapes
    $trustAtts = $atts | Where-Object { $_.AttachmentType -eq 'TrustPolicy' }
    $riskyTrusts = @($trustAtts | Where-Object {
        $_.IsPublic -or ($_.IsExternal -and $_.Notes -notmatch 'ExternalId set')
    })

    # ============================================================
    # Capability-based findings - aggregate per-role detections
    # from IR-RolePages capability analysis.
    # ============================================================
    $capByName = @{}
    if ($Global:IR.RoleCapabilities) {
        foreach ($arn in $Global:IR.RoleCapabilities.Keys) {
            $caps = $Global:IR.RoleCapabilities[$arn]
            if (-not $caps) { continue }
            $cat = $Global:IR.RoleCatalog[$arn]
            $roleName = if ($cat) { $cat.RoleName } else { $arn.Split('/')[-1] }
            foreach ($cap in $caps) {
                if (-not $capByName.ContainsKey($cap.Name)) {
                    $capByName[$cap.Name] = @{
                        Severity = $cap.Severity
                        Description = $cap.Description
                        Vendor = $cap.Vendor
                        Roles = New-Object System.Collections.Generic.List[object]
                    }
                }
                $capByName[$cap.Name].Roles.Add([PSCustomObject]@{
                    RoleArn = $arn
                    RoleName = $roleName
                    MatchedActions = ($cap.MatchedActions -join ', ')
                })
            }
        }
    }

    # Identity sprawl: same identity referenced by >= 3 different service families
    $sprawlSeeds = New-Object System.Collections.Generic.List[object]
    $byId = $atts | Where-Object { $_.IdentityArn -and $_.AttachmentType -ne 'TrustPolicy' } | Group-Object IdentityArn
    foreach ($g in $byId) {
        $svcCount = ($g.Group | ForEach-Object { $_.ResourceType.Split('::')[0] } | Sort-Object -Unique | Measure-Object).Count
        if ($svcCount -ge 3) {
            $sprawlSeeds.Add($g.Group[0])
        }
    }
    $crossSvc = $sprawlSeeds.ToArray()

    # Build capability finding cards FIRST (they're the most actionable signals)
    $capCards = New-Object System.Text.StringBuilder
    $sevRank = @{ 'CRITICAL'=0; 'HIGH'=1; 'MEDIUM'=2; 'LOW'=3; 'INFO'=4 }
    $sortedCapNames = $capByName.Keys | Sort-Object {
        $sevRank[$capByName[$_].Severity]
    }, { -$capByName[$_].Roles.Count }
    $capIdx = 0
    foreach ($name in $sortedCapNames) {
        $capIdx++
        $info = $capByName[$name]
        $cls = Get-RiskClass $info.Severity
        $roleCount = $info.Roles.Count
        $items = New-Object System.Text.StringBuilder
        foreach ($r in $info.Roles) {
            $rl = if ($Global:IR.RoleFileMap -and $Global:IR.RoleFileMap.ContainsKey($r.RoleArn)) {
                "<a href=`"$($Global:IR.RoleFileMap[$r.RoleArn])`">$(ConvertTo-HtmlText $r.RoleName)</a>"
            } else {
                ConvertTo-HtmlText $r.RoleName
            }
            [void]$items.Append("<li>$rl <span class='muted mono' style='font-size:10px'>$(ConvertTo-HtmlText $r.RoleArn)</span> &mdash; matched: <span class='mono'>$(ConvertTo-HtmlText $r.MatchedActions)</span></li>")
        }
        $cid = "C{0:D3}" -f $capIdx
        [void]$capCards.Append(@"
<div class="fcard $cls">
  <h4>$(ConvertTo-HtmlText $name) <span class="bx $cls">$($info.Severity)</span> <span class="bx te">$roleCount roles</span></h4>
  <div class="findmeta"><strong>ID:</strong> $cid</div>
  <p>$(ConvertTo-HtmlText $info.Description)</p>
  <p style="color:var(--mu);font-size:11px"><strong>Documented by:</strong> $(ConvertTo-HtmlText $info.Vendor)</p>
  <p style="color:var(--mu)"><strong>Affected roles:</strong></p>
  <ul>$($items.ToString())</ul>
</div>
"@)
    }

    $cards = New-Object System.Text.StringBuilder

    [void]$cards.Append((Build-FindingCard `
        -Id "F001" -Risk "CRITICAL" `
        -Title "Roles with admin permissions (* or AdministratorAccess)" `
        -Description "These IAM roles have Action:* or are attached to AdministratorAccess. Anything that uses these roles inherits full account control." `
        -Impact "Any compute resource (EC2, Lambda, ECS container) running under one of these roles inherits admin AWS access. SSRF, RCE, or env-var leak from the running code becomes account takeover." `
        -Recommend "Replace * with least-privilege explicit action lists. Detach AdministratorAccess from anything that isn't an emergency break-glass user with MFA." `
        -Items $rolesWithAdmin))

    [void]$cards.Append((Build-FindingCard `
        -Id "F002" -Risk "CRITICAL" `
        -Title "Wildcard permissions (Action:*) in resource policies" `
        -Description "These resources grant Action:* in their resource-based policy, meaning the trusted principal has unrestricted access to the resource itself." `
        -Impact "Any trusted principal has FULL control over the resource. If the principal is external or public, this is a direct compromise vector." `
        -Recommend "Replace * with the minimum required actions. For S3 typically GetObject/PutObject; for KMS typically Encrypt/Decrypt; scope to specific prefixes/keys." `
        -Items $wildcardActions))

    [void]$cards.Append((Build-FindingCard `
        -Id "F003" -Risk "HIGH" `
        -Title "Risky trust policies (public / external without ExternalId)" `
        -Description "These IAM roles can be assumed by external accounts, federated identities, or anyone (*), without an sts:ExternalId condition that would prevent the confused-deputy attack pattern." `
        -Impact "External principals can assume these roles. Without ExternalId, a third party could trick a different external account into assuming on their behalf. Public (*) trusts are immediately exploitable." `
        -Recommend "Add sts:ExternalId condition for third-party trusts. For cross-org trusts add aws:PrincipalOrgID. Replace Principal:'*' with explicit account ARNs and conditions." `
        -Items $riskyTrusts))

    [void]$cards.Append((Build-FindingCard `
        -Id "F004" -Risk "HIGH" `
        -Title "Service-wide wildcards (s3:*, kms:*) in resource policies" `
        -Description "These resources grant service:* in resource-based policy. While narrower than Action:*, this still gives the trusted principal complete control over that service's actions on this resource." `
        -Impact "Trusted principals can perform any action - including destructive ones (Delete*, Put*) - on this resource." `
        -Recommend "Replace service:* with explicit action lists (e.g. s3:GetObject, s3:ListBucket only)." `
        -Items $broadServices))

    [void]$cards.Append((Build-FindingCard `
        -Id "F005" -Risk "CRITICAL" `
        -Title "Publicly accessible resources (Principal: '*')" `
        -Description "These resources are accessible by ANYONE (Principal set to '*' without Condition restrictions tying it to specific accounts/VPCs/IPs)." `
        -Impact "Data exposure, credential leakage, unauthorized usage incurring AWS costs. Single most common source of cloud data breaches." `
        -Recommend "Add Condition restrictions (aws:SourceVpce, aws:SourceIp, aws:PrincipalOrgID) or replace Principal:'*' with specific ARNs. Enable account-level S3 Block Public Access." `
        -Items $publicResources))

    [void]$cards.Append((Build-FindingCard `
        -Id "F006" -Risk "CRITICAL" `
        -Title "External principals granted admin-equivalent access" `
        -Description "Identities from OTHER AWS accounts or federated providers have admin or wildcard permissions on these resources." `
        -Impact "Cross-account takeover. Compromise of the external account = full control of these resources (data exfil or destruction)." `
        -Recommend "Scope external access to specific actions and resource ARNs. Add aws:PrincipalOrgID where applicable. Add sts:ExternalId for third-party integrations." `
        -Items $externalAdmins))

    [void]$cards.Append((Build-FindingCard `
        -Id "F007" -Risk "HIGH" `
        -Title "External principals with scoped access (review for least-privilege)" `
        -Description "External accounts/federated identities have access to these resources. Permissions appear scoped but should each be reviewed against least-privilege." `
        -Impact "Risk depends on granted actions. Cross-account chains enable lateral movement when permissions aren't tightly scoped." `
        -Recommend "Verify each external trust is intentional. Add aws:PrincipalOrgID, sts:ExternalId, or aws:SourceVpce conditions to reduce confused-deputy risk." `
        -Items $externalAccess))

    [void]$cards.Append((Build-FindingCard `
        -Id "F008" -Risk "HIGH" `
        -Title "CI/CD service roles (CodeBuild, CodePipeline, CodeDeploy)" `
        -Description "CI/CD pipelines execute arbitrary code with these service roles. Pipeline compromise = arbitrary AWS API access." `
        -Impact "Supply-chain attack via malicious commit, dependency confusion, or compromised pipeline source. CI/CD roles are a primary lateral-movement target." `
        -Recommend "Apply permission boundaries to CI/CD roles. Use OIDC federation instead of stored access keys. Enable CloudTrail data events on build artifact buckets." `
        -Items $ciCdRoles))

    [void]$cards.Append((Build-FindingCard `
        -Id "F009" -Risk "HIGH" `
        -Title "Pass-through high-privilege roles (Lambda/ECS/EC2)" `
        -Description "These compute resources execute code under high-privilege roles. Any RCE, SSRF, or code-injection in the running code escalates immediately to those role permissions." `
        -Impact "Web-app vuln &rarr; IMDS or env credential theft &rarr; admin AWS access. Lambda and ECS containers are particularly exposed." `
        -Recommend "Apply least-privilege to execution roles. Force IMDSv2 on EC2. Use permission boundaries to cap escalation potential." `
        -Items $passThrough))

    [void]$cards.Append((Build-FindingCard `
        -Id "F010" -Risk "MEDIUM" `
        -Title "Identities used across 3+ different service families (sprawl)" `
        -Description "These IAM identities are referenced by 3 or more different AWS service types. Wide reach increases blast radius if the identity is compromised." `
        -Impact "Compromise of a widely-used identity affects many services simultaneously. Detection is harder as the same identity appears in many service logs." `
        -Recommend "Split into purpose-specific roles. One role per service-type/function is easier to audit and constrains incident scope." `
        -Items $crossSvc))

    $cardsHtml = $cards.ToString()
    if (-not $cardsHtml.Trim()) {
        $cardsHtml = '<div class="empty">No findings detected in any category. (Either the account is genuinely clean, or no resource-based policies were collected.)</div>'
    }

    $css = Get-SharedCSS
    $hdr = Get-PageHeader -Active 'find'

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Findings - IAM-Robot</title>
$css
</head><body>
$hdr
<div class="wrap">

<div class="g5">
  <div class="card cr"><div class="lbl">Roles w/ Admin (*)</div><div class="val">$($rolesWithAdmin.Count)</div></div>
  <div class="card cr"><div class="lbl">Risky Trust Policies</div><div class="val">$($riskyTrusts.Count)</div></div>
  <div class="card cr"><div class="lbl">Wildcard Resource Perms</div><div class="val">$($wildcardActions.Count)</div></div>
  <div class="card cr"><div class="lbl">Public Resources</div><div class="val">$($publicResources.Count)</div></div>
  <div class="card cr"><div class="lbl">External Admins</div><div class="val">$($externalAdmins.Count)</div></div>
</div>
<div class="g5">
  <div class="card hi"><div class="lbl">Service:* Perms</div><div class="val">$($broadServices.Count)</div></div>
  <div class="card hi"><div class="lbl">External (Scoped)</div><div class="val">$($externalAccess.Count)</div></div>
  <div class="card hi"><div class="lbl">CI/CD Roles</div><div class="val">$($ciCdRoles.Count)</div></div>
  <div class="card hi"><div class="lbl">High-Priv Compute</div><div class="val">$($passThrough.Count)</div></div>
  <div class="card me"><div class="lbl">Identity Sprawl</div><div class="val">$($crossSvc.Count)</div></div>
</div>

<div class="sec">Role Capability Findings <span class="ct">$($capByName.Count) capability patterns - sourced from Rhino Security Labs / Prisma Cloud / Wiz / Crowdstrike / CIS</span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
These findings are based on the smart logic that examines each role's effective permissions
(after expanding wildcards and applying Deny overrides), then matches against
documented privilege escalation, defense-evasion, data exfiltration, and credential exposure patterns.
Each card lists every role that matches the pattern; click a role name to jump to its detail page.
</p>
$($capCards.ToString())

<div class="sec">Resource-Level Findings <span class="ct">grouped by category, sorted by severity</span></div>

$cardsHtml

</div></body></html>
"@
}

# ----------------------------------------------------------------
# PAGE 6: command-log.html
# ----------------------------------------------------------------
function New-CommandLogPage {
    $log = $Global:IR.CommandLog

    $rows = New-Object System.Collections.Generic.List[object]
    $intCount = 0
    $errCount = 0
    foreach ($entry in $log) {
        $isInt = if ($entry.PSObject.Properties.Match('Interesting').Count -gt 0) { [bool]$entry.Interesting } else { $false }
        $isOk  = if ($entry.PSObject.Properties.Match('Success').Count     -gt 0) { [bool]$entry.Success     } else { $true }
        $sz    = if ($entry.PSObject.Properties.Match('ResultSize').Count  -gt 0) { [int]$entry.ResultSize    } else { 0 }
        $err   = if ($entry.PSObject.Properties.Match('Error').Count       -gt 0) { "$($entry.Error)"         } else { '' }
        if ($isInt) { $intCount++ }
        if (-not $isOk) { $errCount++ }
        $rows.Add([PSCustomObject]@{
            time        = "$($entry.Time)"
            desc        = "$($entry.Description)"
            cmd         = "$($entry.Command)"
            interesting = $isInt
            success     = $isOk
            sz          = $sz
            err         = $err
        })
    }
    $jRows = ConvertTo-SafeJson $rows
    $totalLog = $rows.Count
    $okCount  = $totalLog - $errCount

    $css = Get-SharedCSS
    $hdr = Get-PageHeader -Active 'log'

@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Command Log - IAM-Robot</title>
$css
</head><body>
$hdr
<div class="wrap">

<div class="g4">
  <div class="card te"><div class="lbl">Total Commands</div><div class="val">$totalLog</div></div>
  <div class="card lo"><div class="lbl">Interesting Output</div><div class="val">$intCount</div></div>
  <div class="card in"><div class="lbl">Successful</div><div class="val">$okCount</div></div>
  <div class="card cr"><div class="lbl">Errors</div><div class="val">$errCount</div></div>
</div>

<div class="sec">AWS CLI Command Log <span class="ct">$totalLog commands, $intCount with interesting output</span></div>
<p class="muted" style="font-size:11px;margin-bottom:.75rem">
Every AWS CLI command executed by this audit, in order.
<span style="color:var(--lo);font-weight:600">Green rows</span> returned interesting output (resources were found).
<span style="color:var(--cr);font-weight:600">Red rows</span> failed.
</p>

<div class="filter-bar">
  <input type="text" id="q" placeholder="Filter by command, service, or description...">
  <select id="fStatus">
    <option value="">All commands</option>
    <option value="int">Interesting only</option>
    <option value="ok">Successful (boring)</option>
    <option value="err">Errors only</option>
  </select>
</div>

<div class="tbl-wrap">
  <div class="tbl-scroll">
    <table>
      <thead><tr><th>Time</th><th>Description</th><th>Result</th><th>Command</th></tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
  <div class="tbl-footer"><span id="counter"></span></div>
</div>

</div>
<script>
var RAW = $jRows;
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }

function render(){
  var q = document.getElementById('q').value.toLowerCase();
  var st = document.getElementById('fStatus').value;
  var f = RAW.filter(function(r){
    if (st === 'int' && !r.interesting) return false;
    if (st === 'ok'  && (r.interesting || !r.success)) return false;
    if (st === 'err' && r.success) return false;
    if (q) {
      var blob = (r.time+' '+r.desc+' '+r.cmd+' '+(r.err||'')).toLowerCase();
      if (blob.indexOf(q) < 0) return false;
    }
    return true;
  });
  var html = '';
  for (var i=0; i<f.length; i++) {
    var r = f[i];
    var cls = !r.success ? 'cmd-error' : (r.interesting ? 'cmd-interesting' : '');
    var status;
    if (!r.success) status = '<span class="bx cr">ERROR</span>';
    else if (r.interesting) status = '<span class="bx lo">'+ r.sz +' bytes</span>';
    else status = '<span class="muted">empty</span>';
    html += '<tr class="'+cls+'">' +
      '<td class="mono">' + esc(r.time) + '</td>' +
      '<td>' + esc(r.desc) + '</td>' +
      '<td>' + status + (r.err ? '<br><span class="mono muted" style="font-size:9px">'+esc(r.err)+'</span>' : '') + '</td>' +
      '<td class="mono" style="font-size:10px;word-break:break-all">' + esc(r.cmd) + '</td>' +
    '</tr>';
  }
  document.getElementById('tbody').innerHTML = html;
  document.getElementById('counter').textContent = 'Showing ' + f.length + ' of ' + RAW.length;
}
document.getElementById('q').addEventListener('input', render);
document.getElementById('fStatus').addEventListener('change', render);
render();
</script>
</body></html>
"@
}

# ----------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------
function Invoke-GenerateReports {
    Write-Host ""
    Write-Host "  [PHASE 4] Generating reports" -ForegroundColor Magenta
    Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray

    $out = $Global:IR.OutputDir
    if (-not (Test-Path $out)) {
        New-Item -ItemType Directory -Path $out -Force | Out-Null
    }

    # CSV
    Export-AttachmentsCSV | Out-Null

    # HTML pages
    Write-IRLog "Generating dashboard..." -Level INFO
    (New-DashboardPage)  | Out-File (Join-Path $out "index.html") -Encoding UTF8
    Write-IRLog "Generating resources page..." -Level INFO
    (New-ResourcesPage)  | Out-File (Join-Path $out "resources.html") -Encoding UTF8
    Write-IRLog "Generating identities page..." -Level INFO
    (New-IdentitiesPage) | Out-File (Join-Path $out "identities.html") -Encoding UTF8
    Write-IRLog "Generating assume-role page..." -Level INFO
    (New-AssumePage)     | Out-File (Join-Path $out "assume.html") -Encoding UTF8
    Write-IRLog "Generating findings page..." -Level INFO
    (New-FindingsPage)   | Out-File (Join-Path $out "findings.html") -Encoding UTF8
    Write-IRLog "Generating command log..." -Level INFO
    (New-CommandLogPage) | Out-File (Join-Path $out "command-log.html") -Encoding UTF8

    # Command log JSON
    $Global:IR.CommandLog | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4 |
        Out-File (Join-Path $out "command-log.json") -Encoding UTF8

    Write-Host ""
    Write-Host "  +-----------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |  Output: $($out.PadRight(43)) |" -ForegroundColor Cyan
    Write-Host "  |  index.html             - dashboard                 |" -ForegroundColor Cyan
    Write-Host "  |  resources.html         - all attachments table     |" -ForegroundColor Cyan
    Write-Host "  |  identities.html        - identities by reach       |" -ForegroundColor Cyan
    Write-Host "  |  assume.html            - assume-role + federation  |" -ForegroundColor Cyan
    Write-Host "  |  findings.html          - broad / risky perms       |" -ForegroundColor Cyan
    Write-Host "  |  findings-catalog.html  - every capability check    |" -ForegroundColor Cyan
    Write-Host "  |  roles.html             - index of role detail pages|" -ForegroundColor Cyan
    Write-Host "  |  resources-detail.html  - index of resource details |" -ForegroundColor Cyan
    Write-Host "  |  attack-paths.html      - interactive attack graph  |" -ForegroundColor Cyan
    Write-Host "  |  roles/role-*.html      - per-role detail pages     |" -ForegroundColor Cyan
    Write-Host "  |  resources/res-*.html   - per-resource detail pages |" -ForegroundColor Cyan
    Write-Host "  |  command-log.html       - all AWS commands run      |" -ForegroundColor Cyan
    Write-Host "  +-----------------------------------------------------+" -ForegroundColor Cyan
}
