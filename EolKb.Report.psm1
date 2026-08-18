<#
.SYNOPSIS
    Restitution : rapport HTML autonome (aucune ressource externe),
    exports CSV pour Excel, export JSON pour outillage, synthese console.
#>

function Get-EolKbCveStatusLabel {
    [CmdletBinding()]
    param([string]$Status)
    switch ($Status) {
        'affecte'      { return 'APPLICATION CONCERNEE' }
        'non-affecte'  { return 'NON CONCERNEE' }
        'absent'       { return 'COMPOSANT ABSENT DU SBOM' }
        'indetermine'  { return 'INDETERMINE' }
        'cve-inconnue' { return 'VULNERABILITE INCONNUE DES SOURCES' }
        default        { return $Status }
    }
}

function Write-EolKbCveConsoleReport {
    <# Reponse directe a la question "suis-je concerne par cette CVE ?" #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Checks, $Sbom)
    $line = '=' * 74
    foreach ($c in $Checks) {
        Write-Host ''
        Write-Host $line -ForegroundColor DarkGray
        $color = 'Gray'
        switch ($c.Status) {
            'affecte'     { $color = 'Red' }
            'non-affecte' { $color = 'Green' }
            'absent'      { $color = 'Green' }
            'indetermine' { $color = 'Yellow' }
            default       { $color = 'Yellow' }
        }
        Write-Host (" {0} : {1}" -f $c.Id, (Get-EolKbCveStatusLabel -Status $c.Status)) -ForegroundColor $color
        Write-Host $line -ForegroundColor DarkGray
        if ($c.Summary) { Write-Host (" {0}" -f $c.Summary) }
        if ($null -ne $c.Cvss) { Write-Host (" CVSS   : {0} ({1})" -f $c.Cvss, $c.Severity) }
        if ($c.Source) { Write-Host (" Source : {0}  {1}" -f $c.Source, $c.Url) }
        Write-Host (" {0}" -f $c.Note)
        if (@($c.Matches).Count -gt 0) {
            Write-Host ' Composants concernes :' -ForegroundColor Red
            $rows = foreach ($m in $c.Matches) {
                [pscustomobject]@{
                    Composant = $m.Finding.Name
                    Groupe    = $m.Finding.Group
                    Version   = $m.Finding.Version
                    Corrigee  = (@($m.Fixed) -join ', ')
                    Occurrences = $m.Finding.Occurrences
                }
            }
            Write-Host (($rows | Format-Table -AutoSize | Out-String -Width 200).Trim())
        }
        if (@($c.Present).Count -gt 0 -and @($c.Matches).Count -eq 0) {
            Write-Host ' Paquet present, non concerne :' -ForegroundColor Green
            foreach ($p in @($c.Present | Select-Object -First 10)) {
                Write-Host ("   {0} {1} - {2}" -f $p.Finding.Name, $p.Finding.Version, $p.Reason)
            }
        }
    }
}

function Get-EolKbComponentUrl {
    <# Page de reference du composant, cliquable depuis le rapport. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding)
    if ($Finding.RegistryUrl) { return [string]$Finding.RegistryUrl }
    if ($Finding.Product) { return "https://endoflife.date/$($Finding.Product)" }
    $full = $Finding.Name
    if ($Finding.Group) { $full = "$($Finding.Group)/$($Finding.Name)" }
    switch ($Finding.PurlType) {
        'npm'      { return "https://www.npmjs.com/package/$full" }
        'pypi'     { return "https://pypi.org/project/$($Finding.Name)/" }
        'maven'    { if ($Finding.Group) { return "https://central.sonatype.com/artifact/$($Finding.Group)/$($Finding.Name)" } }
        'nuget'    { return "https://www.nuget.org/packages/$($Finding.Name)" }
        'gem'      { return "https://rubygems.org/gems/$($Finding.Name)" }
        'cargo'    { return "https://crates.io/crates/$($Finding.Name)" }
        'composer' { return "https://packagist.org/packages/$full" }
        'golang'   { return "https://pkg.go.dev/$full" }
    }
    if ($Finding.DepsDevSystem) {
        $pkg = $Finding.Name
        if ($Finding.PurlType -eq 'maven' -and $Finding.Group) { $pkg = "$($Finding.Group):$($Finding.Name)" }
        return "https://deps.dev/$($Finding.DepsDevSystem)/$([uri]::EscapeDataString($pkg))"
    }
    return ''
}

function Get-EolKbVersionUrl {
    <# Page publiant precisement la version proposee. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding, [string]$Version)
    if (-not $Version) { return (Get-EolKbComponentUrl -Finding $Finding) }
    $full = $Finding.Name
    if ($Finding.Group) { $full = "$($Finding.Group)/$($Finding.Name)" }
    switch ($Finding.PurlType) {
        'npm'      { return "https://www.npmjs.com/package/$full/v/$Version" }
        'pypi'     { return "https://pypi.org/project/$($Finding.Name)/$Version/" }
        'maven'    { if ($Finding.Group) { return "https://central.sonatype.com/artifact/$($Finding.Group)/$($Finding.Name)/$Version" } }
        'nuget'    { return "https://www.nuget.org/packages/$($Finding.Name)/$Version" }
        'gem'      { return "https://rubygems.org/gems/$($Finding.Name)/versions/$Version" }
        'cargo'    { return "https://crates.io/crates/$($Finding.Name)/$Version" }
        'composer' { return "https://packagist.org/packages/$full#v$Version" }
        'golang'   { return "https://pkg.go.dev/$full@$Version" }
    }
    return (Get-EolKbComponentUrl -Finding $Finding)
}

function Get-EolKbRecommendationUrl {
    <# Source qui publie la version proposee : editeur ou registre. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding, [Parameter(Mandatory)]$Recommendation)
    if ($Recommendation.Source -eq 'endoflife.date') {
        if ($Recommendation.Link) { return [string]$Recommendation.Link }
        if ($Finding.Product) { return "https://endoflife.date/$($Finding.Product)" }
    }
    return (Get-EolKbVersionUrl -Finding $Finding -Version ([string]$Recommendation.Version))
}

function Get-EolKbLinkHtml {
    [CmdletBinding()]
    param([string]$Url, [string]$Text, [string]$Class)
    $t = Get-EolKbHtmlEncode -Text $Text
    if (-not $Url) { return $t }
    $c = ''
    if ($Class) { $c = " class=""$Class""" }
    return "<a href=""$(Get-EolKbHtmlEncode -Text $Url)""$c target=""_blank"" rel=""noopener"">$t</a>"
}

function Get-EolKbStatusLabel {
    [CmdletBinding()]
    param([string]$Status)
    switch ($Status) {
        'eol'                     { return 'Fin de support atteinte' }
        'eol_soon'                { return 'Fin de support proche' }
        'supported'               { return 'Supporte par l''editeur' }
        'deprecated'              { return 'Deprecie par l''editeur' }
        'dormant'                 { return 'Plus publie (dormant)' }
        'outdated_major'          { return 'Retard majeur' }
        'outdated_minor'          { return 'Retard mineur' }
        'low_activity'            { return 'Publie, activite faible' }
        'maintained'              { return 'A jour et maintenu' }
        'version_unknown'         { return 'Version absente du SBOM' }
        'internal_or_unpublished' { return 'Composant interne / non publie' }
        'internal_excluded'       { return 'Interne : non transmis a l''exterieur' }
        'collect_failed'          { return 'Collecte impossible' }
        'cycle_unknown'           { return 'Cycle non identifie' }
        'product_unmapped'        { return 'Produit non rattache' }
        default                   { return $Status }
    }
}

function Get-EolKbHtmlEncode {
    [CmdletBinding()]
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

function Format-EolKbDate {
    [CmdletBinding()]
    param([AllowNull()]$Date)
    if ($null -eq $Date) { return '' }
    try { return ([datetime]$Date).ToString('dd/MM/yyyy') } catch { return [string]$Date }
}

function Get-EolKbRecommendationHtml {
    <# Versions proposees, chacune liee a la source qui la publie. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding)
    $parts = @()
    foreach ($r in $Finding.Recommendations) {
        $v = [string]$r.Version
        if (-not $v -and $r.Cycle) { $v = "cycle $($r.Cycle)" }
        if (-not $v) { continue }
        $url = Get-EolKbRecommendationUrl -Finding $Finding -Recommendation $r
        $link = Get-EolKbLinkHtml -Url $url -Text $v
        $suffix = @()
        if ($r.IsLts) { $suffix += 'LTS' }
        if ($r.EolDate) { $suffix += "support jusqu'au " + (Format-EolKbDate $r.EolDate) }
        elseif ($r.Kind -eq 'correctif-securite') { $suffix += 'corrige les CVE detectees' }
        elseif ($r.Kind -eq 'derniere-version-publiee') { $suffix += 'derniere publication' }
        $tag = ''
        if ($r.PSObject.Properties['IsActive']) {
            if ($r.IsActive -eq $true) { $tag = ' <span class="tag t-ok">ACTIVE</span>' }
            elseif ($r.IsActive -eq $false) { $tag = ' <span class="tag t-eol">NON ACTIVE</span>' }
        }
        $note = ''
        if ($r.ActivityNote) { $note = "<span class=""grp"">$(Get-EolKbHtmlEncode -Text ([string]$r.ActivityNote))</span>" }
        $txt = $link
        if ($suffix.Count -gt 0) { $txt += ' (' + (Get-EolKbHtmlEncode -Text ($suffix -join ', ')) + ')' }
        $parts += "$txt$tag$note"
    }
    if ($parts.Count -eq 0) { return '' }
    return ($parts -join '<br>')
}

function Get-EolKbRecommendationText {
    [CmdletBinding()]
    param($Finding, [switch]$Plain)
    $parts = @()
    foreach ($r in $Finding.Recommendations) {
        $v = [string]$r.Version
        if (-not $v -and $r.Cycle) { $v = "cycle $($r.Cycle)" }
        if (-not $v) { continue }
        $suffix = @()
        if ($r.IsLts) { $suffix += 'LTS' }
        if ($r.EolDate) { $suffix += "support jusqu'au " + (Format-EolKbDate $r.EolDate) }
        elseif ($r.Kind -eq 'correctif-securite') { $suffix += 'corrige les CVE detectees' }
        elseif ($r.Kind -eq 'derniere-version-publiee') { $suffix += 'derniere publication' }
        if ($r.PSObject.Properties['IsActive'] -and $r.IsActive -eq $false) { $suffix += 'NON ACTIVE' }
        elseif ($r.PSObject.Properties['IsActive'] -and $r.IsActive -eq $true -and $r.Kind -eq 'derniere-version-publiee') { $suffix += 'branche active' }
        $s = $v
        if ($suffix.Count -gt 0) { $s = "$v (" + ($suffix -join ', ') + ")" }
        $parts += $s
    }
    if ($parts.Count -eq 0) { return '' }
    return ($parts -join ' | ')
}

# ===================================================================
# Exports plats
# ===================================================================
function Export-EolKbCsv {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$OutDir, [string]$Prefix)

    $rows = foreach ($f in ($Result.Findings | Sort-Object Priority, @{Expression={$_.DaysToEol}}, Name)) {
        [pscustomobject]@{
            Priorite          = $f.Priority
            AActionner        = $f.ActionRequired
            MotifAction       = ($f.ActionReasons -join ' ; ')
            Levier            = $f.LeverName
            Statut            = Get-EolKbStatusLabel -Status $f.SupportStatus
            Ecosysteme        = $f.PurlType
            Groupe            = $f.Group
            Composant         = $f.Name
            VersionActuelle   = $f.Version
            Occurrences       = $f.Occurrences
            DependanceDirecte = $f.IsDirect
            Profondeur        = $f.Depth
            ProduitEol        = $f.Product
            ConfianceRattachement = $f.ProductConfidence
            Cycle             = $f.Cycle
            FinDeSupport      = (Format-EolKbDate $f.EolDate)
            JoursRestants     = $f.DaysToEol
            VersionsProposees = (Get-EolKbRecommendationText -Finding $f -Plain)
            CibleActive       = $(if (@($f.Recommendations).Count -gt 0) { @($f.Recommendations)[0].IsActive } else { $null })
            LienComposant     = (Get-EolKbComponentUrl -Finding $f)
            LienVersionCible  = $(if (@($f.Recommendations).Count -gt 0) { Get-EolKbRecommendationUrl -Finding $f -Recommendation @($f.Recommendations)[0] } else { '' })
            EtatMaintenance   = $f.MaintenanceStatus
            DernierePublication = (Format-EolKbDate $f.LatestPublished)
            PublicationVersionActuelle = (Format-EolKbDate $f.CurrentPublished)
            VersionsDeRetard  = $f.VersionsBehind
            MajeuresDeRetard  = $f.MajorBehind
            SourceVerdict     = $f.VerdictSource
            EnProduction      = $f.InProduction
            ForceDuSignal     = $f.SignalStrength
            CveExploitees     = $f.KevCount
            EpssMax           = $f.MaxEpss
            Correspondance    = $f.MatchMethod
            NbCve             = $f.VulnCount
            CvssMax           = $f.MaxCvss
            SeveriteMax       = $f.MaxSeverity
            DerniereVersionRegistre = $f.RegistryLatest
            Depreciee         = $f.RegistryDeprecated
            Remarques         = ($f.Notes -join ' ')
            SourceSupport     = $f.ProductUrl
        }
    }
    $p1 = Join-Path $OutDir "$Prefix-obsolescence.csv"
    $rows | Export-Csv -LiteralPath $p1 -NoTypeInformation -Delimiter ';' -Encoding UTF8

    $vrows = foreach ($f in $Result.Findings) {
        foreach ($v in $f.Vulns) {
            [pscustomobject]@{
                Composant       = $f.Name
                Groupe          = $f.Group
                VersionActuelle = $f.Version
                Ecosysteme      = $f.PurlType
                Cve             = $v.Cve
                IdOsv           = $v.Id
                Severite        = $v.Severity
                Cvss            = $v.Cvss
                VecteurCvss     = $v.CvssVector
                VersionCvss     = $v.CvssVersion
                Resume          = $v.Summary
                VersionsCorrigees = ($v.FixedVersions -join ' ')
                ConfianceCorrespondance = $v.MatchConfidence
                Publiee         = $v.Published
                Fiche           = $v.Url
            }
        }
    }
    $lrows = foreach ($lv in @($Result.Levers)) {
        $pj = $lv.Projection
        $vf = $lv.Verification
        $vd = $lv.Vendor
        [pscustomobject]@{
            Levier              = $lv.Name
            Groupe              = $lv.Group
            VersionActuelle     = $lv.Version
            Ecosysteme          = $lv.PurlType
            Motif               = (Get-EolKbLeverSummaryText -Lever $lv)
            ComposantsCouverts  = $lv.CoveredCount
            DetailCouverts      = (@($lv.Covered | ForEach-Object { "$($_.Name) $($_.Version)" }) -join ' | ')
            CveElevees          = $lv.HighCveCount
            CvssMax             = $lv.MaxCvss
            VersionCible        = $(if ($pj) { $pj.TargetVersion } else { '' })
            Echeance            = $(if ($pj) { $pj.DeadlineText } else { '' })
            Urgence             = $(if ($pj) { $pj.Urgency } else { '' })
            SupportRestantJours = $(if ($pj) { $pj.TargetSupportDays } else { $null })
            CibleTenable1An     = $(if ($pj) { $pj.Sustainable } else { $null })
            Consequence         = $(if ($pj) { $pj.Verdict } else { '' })
            Controle            = $(if ($vf) { $vf.Status } else { '' })
            DetailControle      = $(if ($vf) { $vf.Detail } else { '' })
            SourcesCroisees     = $(if ($vf) { ($vf.Sources -join ' + ') } else { '' })
            Editeur             = $(if ($vd) { $vd.Editor } else { '' })
            PageEditeur         = $(if ($vd) { $vd.SupportUrl } else { '' })
            FaitsEditeur        = $(if ($vd) { ($vd.Facts -join ' ') } else { '' })
        }
    }
    $p3 = Join-Path $OutDir "$Prefix-plan-action.csv"
    if ($lrows) { $lrows | Export-Csv -LiteralPath $p3 -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
    else { 'Aucun composant levier' | Set-Content -LiteralPath $p3 -Encoding UTF8 }

    $p2 = Join-Path $OutDir "$Prefix-cve.csv"
    if ($vrows) { $vrows | Export-Csv -LiteralPath $p2 -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
    else { 'Aucune vulnerabilite detectee' | Set-Content -LiteralPath $p2 -Encoding UTF8 }
    return @($p3, $p1, $p2)
}

function Export-EolKbJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$OutDir, [string]$Prefix)
    $doc = [ordered]@{
        schema      = 1
        generatedAt = $Result.GeneratedAt.ToString('o')
        sbom        = [ordered]@{
            file = $Result.Sbom.FileName; specVersion = $Result.Sbom.SpecVersion
            serialNumber = $Result.Sbom.SerialNumber; timestamp = $Result.Sbom.Timestamp
            application = $Result.Sbom.AppName; applicationVersion = $Result.Sbom.AppVersion
            tools = $Result.Sbom.Tools; components = $Result.ComponentCount
            dependencyGraph = $Result.GraphPresent
        }
        analysis    = [ordered]@{
            durationSeconds = $Result.DurationSeconds; offline = $Result.Offline
            online = $Result.Online; vulnQueryMode = $Result.VulnQueryMode; privacyMode = $Result.PrivacyMode
            registryLookup = $Result.RegistryLookup; summary = $Result.Summary
        }
        levers      = @($Result.Levers | ForEach-Object {
            [ordered]@{
                name = $_.Name; group = $_.Group; version = $_.Version; ecosystem = $_.PurlType
                consolidated = $_.Consolidated; coveredCount = $_.CoveredCount; highCve = $_.HighCveCount
                maxCvss = $_.MaxCvss; reasons = @($_.Reasons)
                covered = @($_.Covered | ForEach-Object { $_.Key })
                recommendations = @($_.Recommendations | ForEach-Object { $_.Version })
                projection = $_.Projection
                verification = $_.Verification
                vendor = $_.Vendor
            }
        })
        findings    = @($Result.Findings | ForEach-Object {
            [ordered]@{
                key = $_.Key; ecosystem = $_.PurlType; group = $_.Group; name = $_.Name
                version = $_.Version; occurrences = $_.Occurrences; direct = $_.IsDirect; depth = $_.Depth
                supportStatus = $_.SupportStatus; eolProduct = $_.Product; productConfidence = $_.ProductConfidence
                cycle = $_.Cycle; eolDate = (Format-EolKbDate $_.EolDate); daysToEol = $_.DaysToEol
                priority = $_.Priority; actionRequired = $_.ActionRequired
                actionReasons = @($_.ActionReasons); lever = $_.LeverName
                registryLatest = $_.RegistryLatest; deprecated = $_.RegistryDeprecated
                maintenanceStatus = $_.MaintenanceStatus; verdictSource = $_.VerdictSource
                latestPublished = (Format-EolKbDate $_.LatestPublished)
                currentPublished = (Format-EolKbDate $_.CurrentPublished)
                versionsBehind = $_.VersionsBehind; majorBehind = $_.MajorBehind
                maxCvss = $_.MaxCvss; vulnCount = $_.VulnCount
                recommendations = @($_.Recommendations | ForEach-Object {
                    [ordered]@{ kind = $_.Kind; cycle = $_.Cycle; version = $_.Version; lts = $_.IsLts
                                eol = (Format-EolKbDate $_.EolDate); source = $_.Source; url = $_.Link
                                active = $_.IsActive; activityNote = $_.ActivityNote; note = $_.Note }
                })
                vulnerabilities = @($_.Vulns | ForEach-Object {
                    [ordered]@{ id = $_.Id; cve = $_.Cve; cvss = $_.Cvss; vector = $_.CvssVector
                                severity = $_.Severity; fixed = $_.FixedVersions; match = $_.MatchConfidence
                                exploitee = $_.Kev; epss = $_.Epss }
                })
                notes = @($_.Notes)
            }
        })
    }
    $p = Join-Path $OutDir "$Prefix-analyse.json"
    (ConvertTo-JsonCompat -InputObject $doc -Depth 32) | Set-Content -LiteralPath $p -Encoding UTF8
    return $p
}

# ===================================================================
# Rapport HTML autonome
# ===================================================================
function New-EolKbHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$OutDir,
        [string]$Prefix,
        [switch]$IncludeAll
    )
    $s = $Result.Summary
    $sb = New-Object System.Text.StringBuilder

    $selection = @($Result.Findings | Where-Object { $_.ActionRequired })
    if ($IncludeAll) { $selection = @($Result.Findings) }
    $selection = @($selection | Sort-Object Priority, @{ Expression = { if ($null -eq $_.DaysToEol) { 99999 } else { $_.DaysToEol } } }, Name)

    # --- vague d'obsolescence : nombre de constats par trimestre -----
    $buckets = [ordered]@{}
    $now = (Get-Date).Date
    $buckets['Deja hors support'] = 0
    for ($q = 0; $q -lt 8; $q++) {
        $d = $now.AddMonths(3 * $q)
        $buckets[("T{0} {1}" -f ([Math]::Floor(($d.Month - 1) / 3) + 1), $d.Year)] = 0
    }
    foreach ($f in $Result.Findings) {
        if ($f.SupportStatus -eq 'eol') { $buckets['Deja hors support']++; continue }
        if ($null -eq $f.EolDate) { continue }
        $d = [datetime]$f.EolDate
        if ($d -lt $now) { $buckets['Deja hors support']++; continue }
        $lbl = "T{0} {1}" -f ([Math]::Floor(($d.Month - 1) / 3) + 1), $d.Year
        if ($buckets.Contains($lbl)) { $buckets[$lbl]++ }
    }
    $maxBucket = 1
    foreach ($k in $buckets.Keys) { if ($buckets[$k] -gt $maxBucket) { $maxBucket = $buckets[$k] } }

    $css = @'
:root{
  --paper:#F2F4F7; --card:#FFFFFF; --ink:#12212E; --ink-soft:#4A5B6A;
  --rule:#C9D3DC; --accent:#1F5673; --accent-soft:#E4EDF3;
  --eol:#A6272E; --soon:#B7791F; --ok:#2E6F55; --unknown:#6B7A87;
  --mono:"Cascadia Mono","Consolas","Lucida Console",monospace;
  --sans:"Segoe UI","Segoe UI Variable Text",system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.5}
.wrap{max-width:1240px;margin:0 auto;padding:28px 20px 80px}
header.dossier{border-top:3px solid var(--ink);padding-top:14px}
.eyebrow{font-family:var(--mono);font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-soft)}
h1{font-size:29px;font-weight:600;letter-spacing:-.02em;margin:6px 0 4px}
h2{font-size:17px;font-weight:600;letter-spacing:.01em;margin:38px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--rule)}
h3{font-size:14px;font-weight:600;margin:22px 0 8px}
p{margin:6px 0}
.sub{color:var(--ink-soft);font-size:13.5px}
.ident{display:flex;flex-wrap:wrap;gap:26px;margin-top:14px;padding:14px 16px;background:var(--card);border:1px solid var(--rule)}
.ident div{min-width:150px}
.ident dt{font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-soft)}
.ident dd{margin:2px 0 0;font-size:14px;font-family:var(--mono)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:18px}
.kpi{background:var(--card);border:1px solid var(--rule);border-left:3px solid var(--unknown);padding:12px 14px}
.kpi.eol{border-left-color:var(--eol)} .kpi.soon{border-left-color:var(--soon)}
.kpi.ok{border-left-color:var(--ok)} .kpi.acc{border-left-color:var(--accent)}
.kpi b{display:block;font-family:var(--mono);font-size:26px;font-weight:600;letter-spacing:-.03em}
.kpi span{font-size:12px;color:var(--ink-soft)}
.wave{display:flex;align-items:flex-end;gap:8px;height:132px;padding:14px 16px 0;background:var(--card);border:1px solid var(--rule)}
.wave .col{flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:100%}
.wave .bar{width:100%;background:var(--accent);transition:height .5s ease}
.wave .col.past .bar{background:var(--eol)}
.wave .n{font-family:var(--mono);font-size:12px;margin-bottom:4px}
.wave .lbl{font-family:var(--mono);font-size:10px;color:var(--ink-soft);margin-top:6px;transform:rotate(-32deg);white-space:nowrap;height:26px}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:16px 0 10px}
.chip{font:inherit;font-size:12.5px;padding:5px 11px;border:1px solid var(--rule);background:var(--card);color:var(--ink-soft);cursor:pointer}
.chip[aria-pressed="true"]{background:var(--ink);color:#fff;border-color:var(--ink)}
.chip:focus-visible,input:focus-visible,th button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
input[type=search]{font:inherit;font-size:13px;padding:6px 10px;border:1px solid var(--rule);background:var(--card);min-width:230px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--rule);font-size:13.5px}
th{text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-soft);
   font-weight:600;padding:9px 10px;border-bottom:1px solid var(--rule);background:#EDF1F5;white-space:nowrap}
th button{all:unset;cursor:pointer;font:inherit;letter-spacing:inherit;text-transform:inherit;color:inherit}
td{padding:9px 10px;border-bottom:1px solid #E8EDF1;vertical-align:top}
tbody tr:hover{background:#F7F9FB}
.mono{font-family:var(--mono);font-size:12.5px}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid var(--rule)}
a:hover{border-bottom-color:var(--accent)}
a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
a.name{color:inherit;font-weight:600;border-bottom:1px solid var(--rule)}
.name{font-weight:600}
.grp{display:block;font-family:var(--mono);font-size:11px;color:var(--ink-soft)}
.tag{display:inline-block;font-family:var(--mono);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;
     padding:2px 6px;border:1px solid currentColor}
.t-eol{color:var(--eol)} .t-soon{color:var(--soon)} .t-ok{color:var(--ok)} .t-unk{color:var(--unknown)}
.p1{border-left:3px solid var(--eol)} .p2{border-left:3px solid var(--soon)} .p3{border-left:3px solid var(--accent)}
.runway{position:relative;height:9px;background:#E8EDF1;min-width:110px;margin-top:5px}
.runway i{position:absolute;left:0;top:0;bottom:0;background:var(--ok);transition:width .5s ease}
.runway.soon i{background:var(--soon)} .runway.past i{background:var(--eol)}
.rw-l{font-family:var(--mono);font-size:11px;color:var(--ink-soft)}
.reco{font-family:var(--mono);font-size:12px}
.reco b{color:var(--ok)}
.cvss{font-family:var(--mono);font-weight:600}
.c-crit{color:var(--eol)} .c-high{color:#C05621} .c-med{color:var(--soon)} .c-low{color:var(--ink-soft)}
details{background:var(--card);border:1px solid var(--rule);margin:8px 0;padding:0}
details>summary{cursor:pointer;padding:10px 12px;font-size:13.5px}
details>div{padding:0 12px 12px}
.note{font-size:12.5px;color:var(--ink-soft);margin-top:4px}
footer{margin-top:44px;border-top:1px solid var(--rule);padding-top:14px;font-size:12.5px;color:var(--ink-soft)}
footer code{font-family:var(--mono)}
.empty{padding:22px;background:var(--card);border:1px dashed var(--rule);color:var(--ink-soft)}
.banner{margin-top:12px;padding:10px 14px;background:var(--card);border:1px solid var(--rule);
        border-left:3px solid var(--accent);font-size:13.5px}
.banner.warn{border-left-color:var(--soon)} .banner.ok{border-left-color:var(--ok)}
@media (max-width:760px){
  .wave{height:110px}.wave .lbl{display:none}
  table{font-size:12.5px}th:nth-child(6),td:nth-child(6){display:none}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media print{.controls{display:none}body{background:#fff}}
'@

    $js = @'
(function(){
  var rows=[].slice.call(document.querySelectorAll("#tbl tbody tr"));
  var chips=[].slice.call(document.querySelectorAll(".chip[data-filter]"));
  var q=document.getElementById("q");
  var active="all";
  function apply(){
    var t=(q.value||"").toLowerCase();
    var n=0;
    rows.forEach(function(r){
      var okF = active==="all" ||
        (active==="eol"&&r.dataset.status==="eol") ||
        (active==="soon"&&r.dataset.status==="eol_soon") ||
        (active==="cve"&&r.dataset.cve!=="0") ||
        (active==="direct"&&r.dataset.direct==="1");
      var okT = !t || r.dataset.search.indexOf(t)>-1;
      var show = okF&&okT;
      r.style.display = show?"":"none";
      if(show)n++;
    });
    document.getElementById("count").textContent=n;
  }
  chips.forEach(function(c){c.addEventListener("click",function(){
    chips.forEach(function(x){x.setAttribute("aria-pressed","false")});
    c.setAttribute("aria-pressed","true"); active=c.dataset.filter; apply();
  })});
  q.addEventListener("input",apply);
  [].slice.call(document.querySelectorAll("th button[data-sort]")).forEach(function(b){
    b.addEventListener("click",function(){
      var k=b.dataset.sort, dir=b.dataset.dir==="asc"?-1:1; b.dataset.dir=dir===1?"asc":"desc";
      var tb=document.querySelector("#tbl tbody");
      rows.sort(function(a,c){
        var x=a.dataset[k], y=c.dataset[k];
        var nx=parseFloat(x), ny=parseFloat(y);
        if(!isNaN(nx)&&!isNaN(ny)) return (nx-ny)*dir;
        return String(x).localeCompare(String(y))*dir;
      });
      rows.forEach(function(r){tb.appendChild(r)});
    });
  });
  apply();
})();
'@

    $enc = { param($t) Get-EolKbHtmlEncode -Text ([string]$t) }
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.AppendLine("<title>Obsolescence - $(& $enc $Result.Sbom.AppName)</title>")
    [void]$sb.AppendLine("<style>$css</style></head><body><div class=""wrap"">")

    # ---- en-tete -------------------------------------------------
    [void]$sb.AppendLine('<header class="dossier">')
    [void]$sb.AppendLine('<div class="eyebrow">Analyse d''obsolescence &middot; SBOM CycloneDX</div>')
    $title = $Result.Sbom.AppName
    if (-not $title) { $title = $Result.Sbom.FileName }
    [void]$sb.AppendLine("<h1>$(& $enc $title)</h1>")
    [void]$sb.AppendLine("<p class=""sub"">Analyse locale du $($Result.GeneratedAt.ToString('dd/MM/yyyy a HH:mm')) &middot; $($Result.DurationSeconds) s &middot; aucune version transmise a l'exterieur</p>")
    $graphTxt = 'absent'
    if ($Result.GraphPresent) { $graphTxt = 'present' }
    [void]$sb.AppendLine('<dl class="ident">')
    $identity = [ordered]@{
        'Fichier'        = $Result.Sbom.FileName
        'Version applicative' = $Result.Sbom.AppVersion
        'CycloneDX'      = $Result.Sbom.SpecVersion
        'Horodatage SBOM' = $Result.Sbom.Timestamp
        'Generateur'     = ($Result.Sbom.Tools -join ', ')
        'Composants declares' = $Result.ComponentCount
        'Graphe de dependances' = $graphTxt
    }
    foreach ($k in $identity.Keys) {
        $v = [string]$identity[$k]
        if (-not $v) { $v = 'non renseigne' }
        [void]$sb.AppendLine("<div><dt>$(& $enc $k)</dt><dd>$(& $enc $v)</dd></div>")
    }
    [void]$sb.AppendLine('</dl>')
    if ($Result.Offline) {
        $ages = @($Result.Findings | Where-Object { $null -ne $_.LatestPublished })
        [void]$sb.AppendLine('<p class="banner warn"><b>Analyse hors ligne.</b> Aucune source n''a ete interrogee : le rapport repose sur la base de connaissance locale. Les elements dont le cache avait expire sont signales "collecte impossible" plutot que supposes. Relancer en mode En ligne pour un rapport a jour.</p>')
    } else {
        $mm = 'correspondance de version etablie sur le poste'
        if ($Result.VulnQueryMode -eq 'Precise') { $mm = 'correspondance des vulnerabilites etablie par OSV puis recoupee localement' }
        [void]$sb.AppendLine("<p class=""banner ok""><b>Analyse en ligne.</b> Sources interrogees ce jour ; $(& $enc $mm). Confidentialite : mode $(& $enc ([string]$Result.PrivacyMode)).</p>")
    }
    [void]$sb.AppendLine('</header>')

    # ---- reponse aux CVE demandees en parametre ------------------
    $cveChecks = @()
    if ($Result.PSObject.Properties['CveChecks']) { $cveChecks = @($Result.CveChecks) }
    foreach ($c in $cveChecks) {
        $cls = 't-unk'
        switch ($c.Status) {
            'affecte'     { $cls = 't-eol' }
            'non-affecte' { $cls = 't-ok' }
            'absent'      { $cls = 't-ok' }
            default       { $cls = 't-soon' }
        }
        [void]$sb.AppendLine("<h2>Question posee : $(& $enc $c.Id)</h2>")
        [void]$sb.AppendLine("<p><span class=""tag $cls"">$(& $enc (Get-EolKbCveStatusLabel -Status $c.Status))</span></p>")
        $meta = @()
        if ($null -ne $c.Cvss) { $meta += "CVSS $($c.Cvss) ($($c.Severity))" }
        if ($c.Source) { $meta += "source : $($c.Source)" }
        [void]$sb.AppendLine("<p class=""sub"">$(& $enc $c.Summary) $(& $enc ($meta -join ' - '))</p>")
        [void]$sb.AppendLine("<p class=""sub"">$(& $enc $c.Note)</p>")
        if (@($c.Matches).Count -gt 0) {
            [void]$sb.AppendLine('<table><thead><tr><th>Composant concerne</th><th>Version presente</th><th>Corrigee en</th><th>Occurrences</th></tr></thead><tbody>')
            foreach ($m in $c.Matches) {
                $fx = (@($m.Fixed) -join ', ')
                if (-not $fx) { $fx = 'non publiee' }
                $grp = ''
                if ($m.Finding.Group) { $grp = "<span class=""grp"">$(& $enc $m.Finding.Group)</span>" }
                $cn = Get-EolKbLinkHtml -Url (Get-EolKbComponentUrl -Finding $m.Finding) -Text $m.Finding.Name -Class 'name'
                $cv = Get-EolKbLinkHtml -Url (Get-EolKbVersionUrl -Finding $m.Finding -Version $m.Finding.Version) -Text $m.Finding.Version
                [void]$sb.AppendLine("<tr><td>$cn$grp</td><td class=""mono"">$cv</td><td class=""mono"">$(& $enc $fx)</td><td class=""mono"">$($m.Finding.Occurrences)</td></tr>")
            }
            [void]$sb.AppendLine('</tbody></table>')
        } elseif (@($c.Present).Count -gt 0) {
            [void]$sb.AppendLine('<table><thead><tr><th>Paquet vise present</th><th>Version presente</th><th>Constat</th></tr></thead><tbody>')
            foreach ($pz in @($c.Present | Select-Object -First 20)) {
                [void]$sb.AppendLine("<tr><td>$(& $enc $pz.Finding.Name)</td><td class=""mono"">$(& $enc $pz.Finding.Version)</td><td class=""rw-l"">$(& $enc $pz.Reason)</td></tr>")
            }
            [void]$sb.AppendLine('</tbody></table>')
        }
        if ($c.Url) { [void]$sb.AppendLine("<p class=""note"">Fiche de reference : <a href=""$(& $enc $c.Url)"">$(& $enc $c.Url)</a></p>") }
    }

    # ---- KPI -----------------------------------------------------
    [void]$sb.AppendLine('<div class="kpis">')
    [void]$sb.AppendLine("<div class=""kpi acc""><b>$($s.Findings)</b><span>constats uniques (composant@version)</span></div>")
    [void]$sb.AppendLine("<div class=""kpi eol""><b>$($s.Eol)</b><span>hors support</span></div>")
    [void]$sb.AppendLine("<div class=""kpi soon""><b>$($s.EolSoon)</b><span>fin de support &lt; $($Config.Thresholds.EolSoonDays) j</span></div>")
    [void]$sb.AppendLine("<div class=""kpi ok""><b>$($s.Supported + $s.Maintained)</b><span>a jour (editeur ou publication)</span></div>")
    [void]$sb.AppendLine("<div class=""kpi soon""><b>$($s.Dormant + $s.OutdatedMajor + $s.DeprecatedStatus)</b><span>deprecies, dormants ou en retard majeur</span></div>")
    [void]$sb.AppendLine("<div class=""kpi eol""><b>$($s.KevFindings)</b><span>composants portant une CVE exploitee (CISA KEV)</span></div>")
    [void]$sb.AppendLine("<div class=""kpi eol""><b>$($s.HighCveTotal)</b><span>CVE elevees ou critiques ($($s.VulnTotal) au total)</span></div>")
    [void]$sb.AppendLine("<div class=""kpi acc""><b>$(@($Result.Levers).Count)</b><span>composants leviers a piloter</span></div>")
    [void]$sb.AppendLine('</div>')

    # ---- vague d'obsolescence ------------------------------------
    [void]$sb.AppendLine('<h2>Vague d''obsolescence a venir</h2>')
    [void]$sb.AppendLine('<p class="sub">Nombre de constats atteignant leur fin de support par trimestre, d''apres les dates publiees par endoflife.date.</p>')
    [void]$sb.AppendLine('<div class="wave">')
    foreach ($k in $buckets.Keys) {
        $n = [int]$buckets[$k]
        $h = [int](100 * $n / $maxBucket)
        if ($n -gt 0 -and $h -lt 3) { $h = 3 }
        $cls = ''
        if ($k -eq 'Deja hors support') { $cls = ' past' }
        [void]$sb.AppendLine("<div class=""col$cls""><span class=""n"">$n</span><i class=""bar"" style=""height:$h%""></i><span class=""lbl"">$(& $enc $k)</span></div>")
    }
    [void]$sb.AppendLine('</div>')

    # ---- plan d'action : composants leviers ---------------------
    $levers = @($Result.Levers)
    [void]$sb.AppendLine('<h2>Plan d''action : composants a piloter</h2>')
    if ($levers.Count -eq 0) {
        [void]$sb.AppendLine("<div class=""empty"">Aucun composant ne remplit les criteres de materialite : ni obsolescence averee, ni CVE de score >= $($Config.Thresholds.ActionableCvss). Les $($s.Findings) constats de l''inventaire restent consultables dans les exports.</div>")
    } else {
        $consolidated = @($levers | Where-Object { $_.Consolidated }).Count
        $intro = "$($s.ActionRequired) constat(s) materiel(s) sur $($s.Findings), regroupes sous $($levers.Count) composant(s) a piloter."
        if ($Result.GraphPresent) {
            $intro += " Le regroupement suit le graphe de dependances : un levier est la dependance de premier niveau qui domine les composants concernes, donc celle dont la montee de version conditionne leur mise a niveau."
        } else {
            $intro += " Le SBOM ne porte pas de graphe de dependances : aucun regroupement parent/enfant n''est affirme, chaque constat est presente pour lui-meme."
        }
        [void]$sb.AppendLine("<p class=""sub"">$(& $enc $intro)</p>")
        $tri = "Retenus : vulnerabilite exploitee (CISA KEV), CVE de score >= $($Config.Thresholds.ActionableCvss), fin de support publiee, depreciation ou archivage par l'editeur. Un composant qui ne presente que des indices (plus publie depuis longtemps, retard de version) n'est retenu qu'a partir de $($Config.Thresholds.WeakSignalsRequired) indices cumules : sur un SBOM de plusieurs milliers de bibliotheques, une seule de ces caracteristiques designe le plus souvent une bibliotheque stable, pas une obsolescence."
        if ($s.OutOfProduction -gt 0) {
            $tri += " $($s.OutOfProduction) composant(s) de portee test ou 'provided' sont exclus du plan d'action : ils ne sont pas embarques a l'execution."
        }
        [void]$sb.AppendLine("<p class=""note"">$(& $enc $tri)</p>")
        [void]$sb.AppendLine('<table><thead><tr><th>Levier</th><th>Version</th><th>Pourquoi</th><th>Montee de version</th><th>Echeance / horizon</th><th>Verification</th><th>Couverts</th></tr></thead><tbody>')
        foreach ($lv in ($levers | Select-Object -First ([int]$Config.Thresholds.MaxLevers))) {
            $reco = Get-EolKbRecommendationText -Finding $lv.Finding
            if (-not $reco) { $reco = 'aucune cible verifiee par les sources' }
            $why = (Get-EolKbLeverSummaryText -Lever $lv)
            if (-not $why) { $why = 'constat materiel' }
            $cvssTag = ''
            if ($null -ne $lv.MaxCvss) {
                $cls = 'c-low'
                if ([double]$lv.MaxCvss -ge 9) { $cls = 'c-crit' } elseif ([double]$lv.MaxCvss -ge 7) { $cls = 'c-high' }
                elseif ([double]$lv.MaxCvss -ge 4) { $cls = 'c-med' }
                $cvssTag = " <span class=""cvss $cls"">CVSS max $($lv.MaxCvss)</span>"
            }
            $grpLine = ''
            if ($lv.Group) { $grpLine = "<span class=""grp"">$(& $enc $lv.Group)</span>" }
            $covered = ''
            if ($lv.LeverKind -eq 'famille') {
                $covered = "<span class=""grp"">regroupement par famille de coordonnees (pas de graphe de dependances)</span>"
            }
            if ($lv.CoveredCount -gt 1 -or $lv.Consolidated) {
                $names = @($lv.Covered | Where-Object { $_.Key -ne $lv.Finding.Key } | Select-Object -First 8 | ForEach-Object { "$($_.Name) $($_.Version)" })
                $extra = ''
                if ($lv.CoveredCount -gt 9) { $extra = " (+$($lv.CoveredCount - 9) autres)" }
                $covered = "<span class=""grp"">$(& $enc (($names -join ', ') + $extra))</span>"
            }
            $lvName = Get-EolKbLinkHtml -Url (Get-EolKbComponentUrl -Finding $lv.Finding) -Text $lv.Name -Class 'name'
            [void]$sb.AppendLine("<tr class=""p$($lv.WorstPriority)""><td>$lvName$grpLine<span class=""grp"">$(& $enc $lv.PurlType)</span></td>")
            $lvVer = $(if ($lv.Version) { Get-EolKbLinkHtml -Url (Get-EolKbVersionUrl -Finding $lv.Finding -Version $lv.Version) -Text $lv.Version } else { '' })
            [void]$sb.AppendLine("<td class=""mono"">$lvVer</td>")
            [void]$sb.AppendLine("<td>$(& $enc $why)$cvssTag</td>")
            $recoRich = Get-EolKbRecommendationHtml -Finding $lv.Finding
            if (-not $recoRich) { $recoRich = '<span class="rw-l">aucune cible verifiee par les sources</span>' }
            [void]$sb.AppendLine("<td class=""reco"">$recoRich</td>")

            # echeance et tenue de la cible dans le temps
            $projTxt = 'echeance non publiee'
            $projNote = ''
            $projCls = 't-unk'
            if ($lv.Projection) {
                $projTxt = [string]$lv.Projection.DeadlineText
                $projNote = "<span class=""grp"">$(& $enc ([string]$lv.Projection.Verdict))</span>"
                if ($null -eq $lv.Projection.Deadline) { $projCls = 't-unk' }
                else {
                    switch ([string]$lv.Projection.Urgency) {
                        'depassee'    { $projCls = 't-eol' }
                        'immediate'   { $projCls = 't-eol' }
                        'cette annee' { $projCls = 't-soon' }
                        default       { $projCls = 't-ok' }
                    }
                }
            }
            [void]$sb.AppendLine("<td><span class=""tag $projCls"">$(& $enc $projTxt)</span>$projNote</td>")

            # double controle de la cible
            $vTxt = 'non verifiee'; $vCls = 't-unk'
            if ($lv.Verification) {
                switch ([string]$lv.Verification.Status) {
                    'confirme'       { $vTxt = 'confirmee (2 sources)'; $vCls = 't-ok' }
                    'divergence'     { $vTxt = 'divergence a lever'; $vCls = 't-eol' }
                    'source-unique'  { $vTxt = 'source unique'; $vCls = 't-soon' }
                    'non-verifiable' { $vTxt = 'non recoupee'; $vCls = 't-unk' }
                    'sans-objet'     { $vTxt = 'sans cible'; $vCls = 't-unk' }
                }
            }
            $vDetail = ''
            if ($lv.Verification -and $lv.Verification.Detail) { $vDetail = "<span class=""grp"">$(& $enc ([string]$lv.Verification.Detail))</span>" }
            $vendorTxt = ''
            if ($lv.Vendor -and $lv.Vendor.Confidence -ne 'aucune-piste') {
                $ed = [string]$lv.Vendor.Editor
                if (-not $ed) { $ed = 'editeur' }
                $link = [string]$lv.Vendor.SupportUrl
                if ($link) { $vendorTxt = "<span class=""grp"">editeur : <a href=""$(& $enc $link)"">$(& $enc $ed)</a></span>" }
                else { $vendorTxt = "<span class=""grp"">editeur : $(& $enc $ed)</span>" }
                foreach ($fact in @($lv.Vendor.Facts | Select-Object -First 2)) {
                    $vendorTxt += "<span class=""grp"">$(& $enc ([string]$fact))</span>"
                }
            }
            [void]$sb.AppendLine("<td><span class=""tag $vCls"">$(& $enc $vTxt)</span>$vDetail$vendorTxt</td>")
            [void]$sb.AppendLine("<td class=""mono"">$($lv.CoveredCount)$covered</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
        if ($levers.Count -gt [int]$Config.Thresholds.MaxLevers) {
            [void]$sb.AppendLine("<p class=""note"">$($levers.Count - [int]$Config.Thresholds.MaxLevers) levier(s) supplementaire(s) dans les exports.</p>")
        }
        [void]$sb.AppendLine("<p class=""note"">Un levier <b>conditionne</b> la mise a niveau des composants qu'il domine : il n'est pas affirme que sa montee de version les corrige. La verification demande de comparer le SBOM produit apres montee de version. Chaque cible est recoupee sur une source independante de celle qui l'a produite ; une cible non recoupee ou divergente est signalee comme telle et ne doit pas etre planifiee sans controle. L'horizon vise est de $([int]$Config.Thresholds.PlanningHorizonDays / 365) an minimum de support restant apres montee.</p>")
    }

    # ---- tableau principal --------------------------------------
    [void]$sb.AppendLine('<h2>Detail des constats a traiter</h2>')
    [void]$sb.AppendLine('<div class="controls">')
    [void]$sb.AppendLine('<button class="chip" data-filter="all" aria-pressed="true">Tout</button>')
    [void]$sb.AppendLine('<button class="chip" data-filter="eol" aria-pressed="false">Hors support</button>')
    [void]$sb.AppendLine('<button class="chip" data-filter="soon" aria-pressed="false">Fin proche</button>')
    [void]$sb.AppendLine('<button class="chip" data-filter="cve" aria-pressed="false">Avec CVE</button>')
    [void]$sb.AppendLine('<button class="chip" data-filter="direct" aria-pressed="false">Dependances directes</button>')
    [void]$sb.AppendLine('<input type="search" id="q" placeholder="Filtrer par nom, groupe, CVE...">')
    [void]$sb.AppendLine('<span class="rw-l"><b id="count">0</b> ligne(s) affichee(s)</span>')
    [void]$sb.AppendLine('</div>')

    if ($selection.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">Aucun composant en fin de support ni vulnerable dans ce SBOM, selon les sources consultees.</div>')
    } else {
        [void]$sb.AppendLine('<table id="tbl"><thead><tr>')
        foreach ($col in @(
            @{ L = 'Prio'; K = 'prio' }, @{ L = 'Composant'; K = 'name' }, @{ L = 'Version'; K = 'name' },
            @{ L = 'Statut de support'; K = 'days' }, @{ L = 'Horizon'; K = 'days' },
            @{ L = 'Version(s) proposee(s)'; K = 'name' }, @{ L = 'CVE'; K = 'cvss' }, @{ L = 'Levier / source'; K = 'name' })) {
            [void]$sb.AppendLine("<th><button data-sort=""$($col.K)"">$(& $enc $col.L)</button></th>")
        }
        [void]$sb.AppendLine('</tr></thead><tbody>')

        foreach ($f in $selection) {
            $statusCls = 't-unk'
            if ($f.SupportStatus -in @('eol', 'deprecated')) { $statusCls = 't-eol' }
            elseif ($f.SupportStatus -in @('eol_soon', 'dormant', 'outdated_major')) { $statusCls = 't-soon' }
            elseif ($f.SupportStatus -in @('supported', 'maintained')) { $statusCls = 't-ok' }
            $days = 99999
            if ($null -ne $f.DaysToEol) { $days = [int]$f.DaysToEol }
            $rwCls = ''; $rwWidth = 0; $rwLabel = 'pas de calendrier editeur publie'
            $rwBar = $true
            if ($f.SupportStatus -eq 'internal_or_unpublished') { $rwLabel = 'absent des registres publics'; $rwBar = $false }
            elseif ($f.SupportStatus -eq 'collect_failed') { $rwLabel = 'collecte impossible'; $rwBar = $false }
            elseif ($null -eq $f.DaysToEol -and -not $f.LatestPublished) { $rwBar = $false }
            if ($null -eq $f.DaysToEol -and $f.LatestPublished) {
                # pas de calendrier de support : on montre l'activite de publication
                $months = [int]((( Get-Date) - $f.LatestPublished).TotalDays / 30.4)
                $rwLabel = "publie il y a $months mois"
                $rwWidth = [int](100 - (100 * [Math]::Min($months, 36) / 36))
                if ($months -ge $Config.Thresholds.DormantMonths) { $rwCls = ' past' }
                elseif ($months -ge $Config.Thresholds.StaleMonths) { $rwCls = ' soon' }
            }
            if ($null -ne $f.DaysToEol) {
                if ($days -lt 0) { $rwCls = ' past'; $rwWidth = 100; $rwLabel = "depassee depuis $([Math]::Abs($days)) j" }
                else {
                    $rwWidth = [int](100 * [Math]::Min($days, 1095) / 1095)
                    $rwLabel = "$days j restants"
                    if ($days -le $Config.Thresholds.EolSoonDays) { $rwCls = ' soon' }
                }
            }
            $reco = Get-EolKbRecommendationText -Finding $f
            $cvssTxt = '-'
            $cvssCls = ''
            if ($f.VulnCount -gt 0) {
                if ($null -ne $f.MaxCvss) {
                    $cvssTxt = "$($f.MaxCvss)"
                    if ([double]$f.MaxCvss -ge 9) { $cvssCls = 'c-crit' } elseif ([double]$f.MaxCvss -ge 7) { $cvssCls = 'c-high' }
                    elseif ([double]$f.MaxCvss -ge 4) { $cvssCls = 'c-med' } else { $cvssCls = 'c-low' }
                } else { $cvssTxt = 'n/c' }
                $firstVuln = @($f.Vulns | Sort-Object @{ Expression = { if ($null -eq $_.Cvss) { -1 } else { [double]$_.Cvss } } } -Descending)[0]
                $cvssTxt = (Get-EolKbLinkHtml -Url ([string]$firstVuln.Url) -Text $cvssTxt) + " <span class=""rw-l"">($($f.VulnCount))</span>"
                if ($f.KevCount -gt 0) { $cvssTxt += " <span class=""tag t-eol"">EXPLOITEE</span>" }
            }
            $searchKey = (("$($f.Group) $($f.Name) $($f.Version) $($f.Product) " + (($f.Vulns | ForEach-Object { $_.Cve }) -join ' ')).ToLowerInvariant())
            $directFlag = 0
            if ($f.IsDirect) { $directFlag = 1 }
            $occ = ''
            if ($f.Occurrences -gt 1) { $occ = " <span class=""rw-l"">x$($f.Occurrences)</span>" }

            [void]$sb.AppendLine("<tr class=""p$($f.Priority)"" data-status=""$($f.SupportStatus)"" data-cve=""$($f.VulnCount)"" data-direct=""$directFlag"" data-prio=""$($f.Priority)"" data-days=""$days"" data-cvss=""$(if ($null -ne $f.MaxCvss) { $f.MaxCvss } else { 0 })"" data-name=""$(& $enc $f.Name)"" data-search=""$(& $enc $searchKey)"">")
            [void]$sb.AppendLine("<td class=""mono"">$($f.Priority)</td>")
            $grpLine = ''
            if ($f.Group) { $grpLine = "<span class=""grp"">$(& $enc $f.Group)</span>" }
            $nameHtml = Get-EolKbLinkHtml -Url (Get-EolKbComponentUrl -Finding $f) -Text $f.Name -Class 'name'
            [void]$sb.AppendLine("<td>$nameHtml$occ$grpLine<span class=""grp"">$(& $enc $f.PurlType)</span></td>")
            $verTxt = $f.Version
            if (-not $verTxt) { $verTxt = 'non renseignee' }
            $verHtml = $(if ($f.Version) { Get-EolKbLinkHtml -Url (Get-EolKbVersionUrl -Finding $f -Version $f.Version) -Text $verTxt } else { & $enc $verTxt })
            [void]$sb.AppendLine("<td class=""mono"">$verHtml</td>")
            $cycleTxt = ''
            if ($f.Cycle) { $cycleTxt = "<span class=""grp"">cycle $(& $enc $f.Cycle)" + $(if ($f.CycleIsLts) { ' LTS' } else { '' }) + "</span>" }
            [void]$sb.AppendLine("<td><span class=""tag $statusCls"">$(& $enc (Get-EolKbStatusLabel -Status $f.SupportStatus))</span>$cycleTxt</td>")
            $eolTxt = Format-EolKbDate $f.EolDate
            if (-not $eolTxt) { $eolTxt = '' }
            $rwHtml = ''
            if ($rwBar) { $rwHtml = "<div class=""runway$rwCls""><i style=""width:$rwWidth%""></i></div>" }
            [void]$sb.AppendLine("<td><span class=""rw-l"">$eolTxt $(& $enc $rwLabel)</span>$rwHtml</td>")
            $recoHtml = '<span class="rw-l">aucune cible verifiee</span>'
            $recoRich = Get-EolKbRecommendationHtml -Finding $f
            if ($recoRich) { $recoHtml = "<span class=""reco"">$recoRich</span>" }
            [void]$sb.AppendLine("<td>$recoHtml</td>")
            [void]$sb.AppendLine("<td class=""cvss $cvssCls"">$cvssTxt</td>")
            $srcTxt = $f.VerdictSource
            if (-not $srcTxt) { $srcTxt = 'n/c' }
            if ($f.LeverName -and $f.LeverName -ne $f.Name) { $srcTxt = "via $($f.LeverName)" }
            $srcExtra = ''
            if ($f.ProductConfidence) { $srcExtra = "<span class=""grp"">rattachement : $(& $enc $f.ProductConfidence)</span>" }
            elseif ($null -ne $f.VersionsBehind -and $f.VersionsBehind -gt 0) { $srcExtra = "<span class=""grp"">$($f.VersionsBehind) version(s) de retard</span>" }
            [void]$sb.AppendLine("<td class=""rw-l"">$(& $enc $srcTxt)$srcExtra</td>")
            [void]$sb.AppendLine('</tr>')
        }
        [void]$sb.AppendLine('</tbody></table>')
        if (-not $IncludeAll) {
            [void]$sb.AppendLine("<p class=""note"">Seuls les constats materiels sont listes ($($selection.Count) sur $($s.Findings)) : obsolescence averee ou CVE de score >= $($Config.Thresholds.ActionableCvss). Le reste de l'inventaire (a jour, retard mineur, CVE de score inferieur) figure dans les exports CSV et JSON.</p>")
        }
    }

    # ---- projection de planification -----------------------------
    if ($levers.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Projection de planification</h2>')
        [void]$sb.AppendLine("<p class=""sub"">Echeance de traitement de chaque levier et duree de support restante apres montee de version. Une cible est jugee tenable si elle reste supportee au moins $([int]$Config.Thresholds.PlanningHorizonDays) jours ; sinon la seconde montee est annoncee des maintenant.</p>")
        [void]$sb.AppendLine('<table><thead><tr><th>Levier</th><th>A traiter</th><th>Cible</th><th>Support restant apres montee</th><th>Consequence</th></tr></thead><tbody>')
        foreach ($lv in ($levers | Select-Object -First ([int]$Config.Thresholds.MaxLevers))) {
            if (-not $lv.Projection) { continue }
            $pj = $lv.Projection
            $rest = 'non publie'
            $restCls = 't-unk'
            if ($null -ne $pj.TargetSupportDays) {
                $mois = [int]([int]$pj.TargetSupportDays / 30.4)
                $rest = "$mois mois"
                if ([int]$pj.TargetSupportDays -ge [int]$Config.Thresholds.PlanningHorizonLongDays) { $restCls = 't-ok' }
                elseif ([int]$pj.TargetSupportDays -ge [int]$Config.Thresholds.PlanningHorizonDays) { $restCls = 't-ok' }
                else { $restCls = 't-soon' }
            }
            $tv = [string]$pj.TargetVersion
            if (-not $tv) { $tv = 'a arbitrer' }
            [void]$sb.AppendLine("<tr><td><span class=""name"">$(& $enc $lv.Name)</span><span class=""grp"">$(& $enc $lv.Version)</span></td>")
            [void]$sb.AppendLine("<td class=""rw-l"">$(& $enc ([string]$pj.DeadlineText))</td>")
            $tvHtml = $(if ($pj.TargetVersion) { Get-EolKbLinkHtml -Url (Get-EolKbVersionUrl -Finding $lv.Finding -Version ([string]$pj.TargetVersion)) -Text $tv } else { & $enc $tv })
            [void]$sb.AppendLine("<td class=""mono"">$tvHtml</td>")
            [void]$sb.AppendLine("<td><span class=""tag $restCls"">$(& $enc $rest)</span></td>")
            [void]$sb.AppendLine("<td class=""rw-l"">$(& $enc ([string]$pj.Verdict))</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
    }

    # ---- section CVE --------------------------------------------
    [void]$sb.AppendLine('<h2>Vulnerabilites connues et scores CVSS</h2>')
    $vulnFindings = @($Result.Findings | Where-Object { $_.VulnCount -gt 0 } | Sort-Object @{ Expression = { if ($null -eq $_.MaxCvss) { -1 } else { [double]$_.MaxCvss } } } -Descending)
    if ($vulnFindings.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">Aucune vulnerabilite ne concerne les versions presentes dans ce SBOM, d''apres OSV.</div>')
    } else {
        [void]$sb.AppendLine('<p class="sub">Score CVSS v3.x recalcule localement a partir du vecteur publie. Le rapprochement version/plage affectee est effectue sur le poste : OSV est interroge sans version.</p>')
        foreach ($f in $vulnFindings) {
            $head = "$($f.Name) $($f.Version)"
            $maxTxt = 'n/c'
            if ($null -ne $f.MaxCvss) { $maxTxt = [string]$f.MaxCvss }
            $headHtml = (Get-EolKbLinkHtml -Url (Get-EolKbComponentUrl -Finding $f) -Text $f.Name) + ' ' + (& $enc $f.Version)
            [void]$sb.AppendLine("<details><summary><b>$headHtml</b> &mdash; $($f.VulnCount) vulnerabilite(s), CVSS max <span class=""cvss"">$maxTxt</span> ($(& $enc $f.MaxSeverity))</summary><div>")
            [void]$sb.AppendLine('<table><thead><tr><th>CVE</th><th>Identifiant OSV</th><th>CVSS</th><th>Severite</th><th>Corrigee en</th><th>Correspondance</th><th>Resume</th></tr></thead><tbody>')
            foreach ($v in ($f.Vulns | Sort-Object @{ Expression = { if ($null -eq $_.Cvss) { -1 } else { [double]$_.Cvss } } } -Descending)) {
                $cve = $v.Cve
                if (-not $cve) { $cve = '-' }
                $sc = 'n/c'
                if ($null -ne $v.Cvss) { $sc = [string]$v.Cvss }
                $fx = ($v.FixedVersions -join ', ')
                if (-not $fx) { $fx = 'non publiee' }
                $mc = [string]$v.MatchConfidence
                if (-not $mc) { $mc = 'locale' }
                if ($v.PSObject.Properties['Kev'] -and $v.Kev) { $cve = "$cve <span class=""tag t-eol"">EXPLOITEE</span>" }
                $epssTxt = ''
                if ($v.PSObject.Properties['Epss'] -and $null -ne $v.Epss) { $epssTxt = " <span class=""grp"">EPSS $([Math]::Round([double]$v.Epss * 100, 1)) %</span>" }
                [void]$sb.AppendLine("<tr><td class=""mono"">$cve$epssTxt</td><td class=""mono""><a href=""$(& $enc $v.Url)"">$(& $enc $v.Id)</a></td><td class=""cvss"">$sc</td><td class=""mono"">$(& $enc $v.Severity)</td><td class=""mono"">$(& $enc $fx)</td><td class=""rw-l"">$(& $enc $mc)</td><td>$(& $enc $v.Summary)</td></tr>")
            }
            [void]$sb.AppendLine('</tbody></table>')
            if ($f.CvssVector) { [void]$sb.AppendLine("<p class=""note"">Vecteur : <code>$(& $enc $f.CvssVector)</code></p>") }
            [void]$sb.AppendLine('</div></details>')
        }
    }

    # ---- portee hors production ---------------------------------
    $outProd = @($Result.Findings | Where-Object { -not $_.InProduction -and ($_.VulnCount -gt 0 -or $_.SupportStatus -in @('eol', 'deprecated')) })
    if ($outProd.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Ecartes du plan d''action : composants hors execution</h2>')
        [void]$sb.AppendLine("<p class=""sub"">$($outProd.Count) composant(s) de portee test ou fournie par la plateforme presentent un signal, mais ne sont pas embarques dans l'application livree. A traiter dans le cadre de l'hygiene du projet, pas de l'exposition en production.</p>")
        [void]$sb.AppendLine('<table><thead><tr><th>Composant</th><th>Version</th><th>Portee</th><th>Signal</th></tr></thead><tbody>')
        foreach ($f in ($outProd | Select-Object -First 25)) {
            $sig = ($f.ActionReasons -join ' ; ')
            if (-not $sig) { $sig = (Get-EolKbStatusLabel -Status $f.SupportStatus) }
            [void]$sb.AppendLine("<tr><td>$(& $enc $f.Name)</td><td class=""mono"">$(& $enc $f.Version)</td><td class=""mono"">$(& $enc (@($f.Scopes) -join ', '))</td><td class=""rw-l"">$(& $enc $sig)</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
    }

    # ---- constats non concluants --------------------------------
    $pending = @($Result.Findings | Where-Object { $_.SupportStatus -in @('internal_or_unpublished', 'internal_excluded', 'collect_failed', 'version_unknown') })
    [void]$sb.AppendLine('<h2>Composants sans equivalent public</h2>')
    [void]$sb.AppendLine("<p class=""sub"">$($pending.Count) constat(s) : soit le composant est interne (absent des registres publics interroges), soit le SBOM ne porte pas sa version, soit la collecte a echoue. Tous les autres composants ont recu un verdict issu d'une source en ligne.</p>")
    $groups = $pending | Group-Object SupportStatus | Sort-Object Count -Descending
    if ($groups) {
        [void]$sb.AppendLine('<table><thead><tr><th>Motif</th><th>Constats</th><th>Exemples</th></tr></thead><tbody>')
        foreach ($g in $groups) {
            $ex = (@($g.Group | Select-Object -First 6 | ForEach-Object { $_.Name }) -join ', ')
            [void]$sb.AppendLine("<tr><td>$(& $enc (Get-EolKbStatusLabel -Status $g.Name))</td><td class=""mono"">$($g.Count)</td><td class=""mono"">$(& $enc $ex)</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
    }

    # ---- methode -------------------------------------------------
    $stats = Get-EolKbStats
    [void]$sb.AppendLine('<h2>Methode et tracabilite</h2>')
    [void]$sb.AppendLine('<ul class="sub">')
    [void]$sb.AppendLine('<li>Support : endoflife.date, interroge par nom de produit uniquement ; le rattachement version &rarr; cycle est calcule sur le poste.</li>')
    [void]$sb.AppendLine('<li>Vulnerabilites : OSV, interroge par nom de paquet uniquement ; le rapprochement avec la version installee est local.</li>')
    [void]$sb.AppendLine('<li>Publications : deps.dev (Google Open Source Insights), interroge par nom de paquet ; a defaut le registre natif (npm, PyPI, Maven Central, NuGet...). Fournit les versions publiees et leurs dates, d''ou le verdict de maintenance quand l''editeur ne publie pas de calendrier de support.</li>')
    [void]$sb.AppendLine('<li>CVE des composants hors ecosysteme de paquets (runtimes, OS, produits) : NVD, interroge par produit ou identifiant CPE, jamais par version.</li>')
    [void]$sb.AppendLine('<li>Editeur : pour les composants sans calendrier de support publie, le depot source declare par le paquet est interroge (organisation editrice, projet archive, date de derniere publication de la branche majeure). Ces elements sont des faits dates ; <b>aucune date de fin de support n''en est deduite</b>. Le lien editeur est fourni pour qualification.</li>')
    [void]$sb.AppendLine('<li>Priorisation : catalogue CISA des vulnerabilites exploitees en conditions reelles (KEV) et score EPSS (probabilite d''exploitation sous 30 jours). Une CVE du catalogue KEV passe en priorite 1 quelle que soit sa note CVSS.</li>')
    [void]$sb.AppendLine('<li>Double controle : chaque version cible est recoupee sur une source independante de celle qui l''a produite. Statut affiche : confirmee, source unique, non recoupee, ou divergence a lever.</li>')
    [void]$sb.AppendLine("<li>Confidentialite (mode $(& $enc ([string]$Config.Privacy.Mode))) : les requetes sortantes ne portent que des coordonnees publiques. Le nom et la version de l'application, le numero de serie du SBOM et les composants des espaces de noms internes ne sont jamais transmis ; toute requete les contenant est bloquee et tracee dans le journal d'audit.</li>")
    [void]$sb.AppendLine('<li>Versions proposees : uniquement des versions publiees par la source (dernier correctif d''un cycle supporte ou version publiee au registre). Aucune version n''est extrapolee.</li>')
    if (-not $Result.GraphPresent) {
        [void]$sb.AppendLine('<li>Le SBOM ne contient pas de graphe <code>dependencies</code> : aucun lien parent/enfant n''est affirme et la notion de dependance directe est indisponible.</li>')
    }
    $modeTxt = 'en ligne'
    if ($Result.Offline) { $modeTxt = 'hors ligne (cache local)' }
    $divergences = @($Result.Findings | Where-Object { @($_.MatchDivergences).Count -gt 0 })
    [void]$sb.AppendLine("<li>Mode d'execution : <b>$(& $enc $modeTxt)</b> ; recherche de vulnerabilites : $(& $enc ([string]$Result.VulnQueryMode)).</li>")
    if ($Result.VulnQueryMode -eq 'Precise') {
        [void]$sb.AppendLine("<li>Mode precis : la version est transmise a OSV, qui etablit la correspondance ; elle est ensuite recoupee avec l'evaluation locale. $($divergences.Count) constat(s) presentent une divergence entre les deux, tranchee en faveur de la source et signalee dans les remarques.</li>")
    }
    [void]$sb.AppendLine("<li>Cette execution : $($stats.HttpOk) appel(s) externe(s), $($stats.CacheHit) reponse(s) servie(s) par le cache local, $($stats.Blocked) requete(s) bloquee(s) par la garde de confidentialite.</li>")
    [void]$sb.AppendLine('</ul>')
    [void]$sb.AppendLine("<footer>Rapport genere localement. Journal des appels sortants : <code>$(& $enc $Config.Paths.AuditLog)</code>. Base de connaissance : <code>$(& $enc $Config.Paths.CacheRoot)</code>.</footer>")
    [void]$sb.AppendLine("<script>$js</script></div></body></html>")

    $p = Join-Path $OutDir "$Prefix-rapport.html"
    [System.IO.File]::WriteAllText($p, $sb.ToString(), [System.Text.Encoding]::UTF8)
    return $p
}

# ===================================================================
# Synthese console
# ===================================================================
function Write-EolKbConsoleReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Result, [int]$Top = 15)
    $s = $Result.Summary
    $line = '-' * 74
    Write-Host ''
    Write-Host $line -ForegroundColor DarkGray
    $appTxt = $Result.Sbom.AppName
    if (-not $appTxt) { $appTxt = $Result.Sbom.FileName }
    Write-Host " SYNTHESE D'ANALYSE - $appTxt" -ForegroundColor White
    Write-Host $line -ForegroundColor DarkGray
    Write-Host (" SBOM              : {0} (CycloneDX {1}, {2} Mo)" -f $Result.Sbom.FileName, $Result.Sbom.SpecVersion, $Result.Sbom.SizeMB)
    Write-Host (" Composants        : {0} declares -> {1} constats uniques" -f $Result.ComponentCount, $s.Findings)
    $graphTxt = 'absent (posture stricte)'
    if ($Result.GraphPresent) { $graphTxt = 'present' }
    Write-Host (" Graphe            : {0}" -f $graphTxt)
    Write-Host (" Duree             : {0} s" -f $Result.DurationSeconds)
    $modeTxt = 'EN LIGNE'
    if ($Result.Offline) { $modeTxt = 'HORS LIGNE (cache local)' }
    Write-Host (" Mode              : {0} - vulnerabilites : {1}" -f $modeTxt, $Result.VulnQueryMode)
    Write-Host ''
    Write-Host (" Hors support      : {0}" -f $s.Eol) -ForegroundColor Red
    Write-Host (" Fin proche (<{0}j) : {1}" -f $Config.Thresholds.EolSoonDays, $s.EolSoon) -ForegroundColor Yellow
    Write-Host (" Deprecies/dormants: {0}" -f ($s.DeprecatedStatus + $s.Dormant)) -ForegroundColor Yellow
    Write-Host (" Retard majeur     : {0}" -f $s.OutdatedMajor) -ForegroundColor Yellow
    Write-Host (" Retard mineur     : {0}" -f ($s.OutdatedMinor + $s.LowActivity)) -ForegroundColor Gray
    Write-Host (" A jour            : {0}" -f ($s.Supported + $s.Maintained)) -ForegroundColor Green
    Write-Host (" Internes / non publies : {0}" -f $s.Internal) -ForegroundColor DarkGray
    if ($s.CollectFailed -gt 0) { Write-Host (" Collecte impossible: {0}" -f $s.CollectFailed) -ForegroundColor Red }
    Write-Host (" Vulnerables       : {0} constats / {1} CVE (dont {2} critiques, {3} elevees)" -f $s.VulnerableFindings, $s.VulnTotal, $s.CriticalFindings, $s.HighFindings) -ForegroundColor Red
    if ($s.KevFindings -gt 0) { Write-Host (" EXPLOITEES (KEV)  : {0} composants" -f $s.KevFindings) -ForegroundColor Red }
    if ($s.OutOfProduction -gt 0) { Write-Host (" Hors execution    : {0} (test/provided, ecartes du plan)" -f $s.OutOfProduction) -ForegroundColor DarkGray }
    Write-Host ''
    $levers = @($Result.Levers)
    if ($levers.Count -gt 0) {
        Write-Host (" {0} constat(s) materiel(s) sur {1}, regroupes en {2} levier(s) :" -f $s.ActionRequired, $s.Findings, $levers.Count) -ForegroundColor White
        $lrows = foreach ($lv in ($levers | Select-Object -First 12)) {
            $reco = Get-EolKbRecommendationText -Finding $lv.Finding
            if ($reco.Length -gt 40) { $reco = $reco.Substring(0, 37) + '...' }
            $ech = ''
            if ($lv.Projection) { $ech = [string]$lv.Projection.DeadlineText }
            $ver = ''
            if ($lv.Verification) { $ver = [string]$lv.Verification.Status }
            [pscustomobject]@{
                Levier = $lv.Name
                Version = $lv.Version
                Couverts = $lv.CoveredCount
                "CVE>=$($Config.Thresholds.ActionableCvss)" = $lv.HighCveCount
                Cible = $reco
                Echeance = $ech
                Controle = $ver
            }
        }
        Write-Host (($lrows | Format-Table -AutoSize | Out-String -Width 220).Trim())
        Write-Host ''
    }
    $topRows = @($Result.Findings | Where-Object { $_.Priority -le 3 } |
        Sort-Object Priority, @{ Expression = { if ($null -eq $_.DaysToEol) { 99999 } else { $_.DaysToEol } } } |
        Select-Object -First $Top)
    if ($topRows.Count -gt 0 -and $levers.Count -eq 0) {
        Write-Host " A traiter en priorite :" -ForegroundColor White
        $rows = foreach ($f in $topRows) {
            $reco = Get-EolKbRecommendationText -Finding $f
            if ($reco.Length -gt 46) { $reco = $reco.Substring(0, 43) + '...' }
            [pscustomobject]@{
                P = $f.Priority
                Composant = $f.Name
                Version = $f.Version
                Statut = (Get-EolKbStatusLabel -Status $f.SupportStatus)
                Jours = $f.DaysToEol
                CVSS = $f.MaxCvss
                Cible = $reco
            }
        }
        # Out-String -Width explicite : sans cela, la table est vide quand
        # l'hote n'expose pas de largeur de console (tache planifiee, CI).
        Write-Host (($rows | Format-Table -AutoSize | Out-String -Width 200).Trim())
    }
    $stats = Get-EolKbStats
    Write-Host (" Reseau : {0} appels, {1} servis par le cache, {2} bloques (anti-fuite), {3} echecs" -f $stats.HttpOk, $stats.CacheHit, $stats.Blocked, $stats.HttpFail) -ForegroundColor DarkGray
    Write-Host $line -ForegroundColor DarkGray
}

Export-ModuleMember -Function Get-EolKbComponentUrl, Get-EolKbVersionUrl, Get-EolKbRecommendationUrl,
    Get-EolKbLinkHtml, Get-EolKbRecommendationHtml,
    Get-EolKbCveStatusLabel, Write-EolKbCveConsoleReport, Get-EolKbStatusLabel, Get-EolKbHtmlEncode, Format-EolKbDate,
    Get-EolKbRecommendationText, Export-EolKbCsv, Export-EolKbJson, New-EolKbHtmlReport, Write-EolKbConsoleReport
