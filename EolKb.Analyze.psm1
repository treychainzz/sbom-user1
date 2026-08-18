<#
.SYNOPSIS
    Lecture du SBOM CycloneDX, deduplication en constats
    (coordonnee@version), graphe de dependances, puis analyse :
    statut de support, versions cibles proposees, vulnerabilites.
#>

# ===================================================================
# Lecture du SBOM
# ===================================================================
function Read-EolKbSbom {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "SBOM introuvable : $Path" }
    $fi = Get-Item -LiteralPath $Path
    Write-EolKbLog -Message ("Lecture du SBOM : {0} ({1:N1} Mo)" -f $fi.Name, ($fi.Length / 1MB))
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $raw = [System.IO.File]::ReadAllText($fi.FullName)
    $doc = ConvertFrom-JsonCompat -Json $raw
    $raw = $null
    [System.GC]::Collect()
    $sw.Stop()
    if ($null -eq $doc) { throw "SBOM illisible (JSON invalide) : $Path" }

    $fmt = [string](Get-DictValue $doc 'bomFormat' '')
    $spec = [string](Get-DictValue $doc 'specVersion' '')
    if ($fmt -and $fmt -ne 'CycloneDX') { throw "Format non supporte : '$fmt' (CycloneDX attendu)" }
    Write-EolKbLog -Message ("SBOM analyse en {0:N1} s (CycloneDX {1})" -f $sw.Elapsed.TotalSeconds, $spec)

    $meta = Get-DictValue $doc 'metadata'
    $app = Get-DictValue $meta 'component'
    $tools = @()
    $toolsNode = Get-DictValue $meta 'tools'
    $toolList = Get-DictArray -Dict $toolsNode
    if ($toolsNode -is [System.Collections.IDictionary]) { $toolList = Get-DictArray -Dict $toolsNode -Key 'components' }
    foreach ($t in $toolList) {
        if ($t -is [string]) { continue }
        $tn = [string](Get-DictValue $t 'name' '')
        $tv = [string](Get-DictValue $t 'version' '')
        if ($tn) { $tools += ("{0} {1}" -f $tn, $tv).Trim() }
    }

    return [pscustomobject]@{
        Document    = $doc
        Path        = $fi.FullName
        FileName    = $fi.Name
        SizeMB      = [Math]::Round($fi.Length / 1MB, 2)
        SpecVersion = $spec
        SerialNumber = [string](Get-DictValue $doc 'serialNumber' '')
        Timestamp   = [string](Get-DictValue $meta 'timestamp' '')
        Tools       = $tools
        AppName     = [string](Get-DictValue $app 'name' '')
        AppGroup    = [string](Get-DictValue $app 'group' '')
        AppVersion  = [string](Get-DictValue $app 'version' '')
        AppRef      = [string](Get-DictValue $app 'bom-ref' '')
        ParseSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
    }
}

function Get-EolKbSbomComponents {
    <# Aplatit components[] (y compris les imbrications) en objets simples. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Sbom)
    $out = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    foreach ($c in (Get-DictArray -Dict $Sbom.Document -Key 'components')) { $stack.Push($c) }
    while ($stack.Count -gt 0) {
        $c = $stack.Pop()
        if ($c -is [string]) { continue }
        foreach ($child in (Get-DictArray -Dict $c -Key 'components')) { $stack.Push($child) }
        $purl = [string](Get-DictValue $c 'purl' '')
        $p = Resolve-EolKbPurl -Purl $purl
        $group = [string](Get-DictValue $c 'group' '')
        $name = [string](Get-DictValue $c 'name' '')
        $version = [string](Get-DictValue $c 'version' '')
        if (-not $group -and $p.Group) { $group = $p.Group }
        if (-not $name -and $p.Name) { $name = $p.Name }
        if (-not $version -and $p.Version) { $version = $p.Version }
        if (-not $name) { continue }
        # portee reelle : champ 'scope' CycloneDX, ou propriete de l'outil
        # (cyclonedx-maven-plugin publie cdx:maven:package:scope = test/provided)
        $scope = [string](Get-DictValue $c 'scope' '')
        foreach ($prop in (Get-DictArray -Dict $c -Key 'properties')) {
            $pn = [string](Get-DictValue $prop 'name' '')
            if ($pn -imatch 'scope$') {
                $pv = [string](Get-DictValue $prop 'value' '')
                if ($pv) { $scope = $pv }
            }
        }
        [void]$out.Add([pscustomobject]@{
            BomRef   = [string](Get-DictValue $c 'bom-ref' '')
            Name     = $name
            Group    = $group
            Version  = $version
            Purl     = $purl
            PurlType = $p.Type
            Type     = [string](Get-DictValue $c 'type' '')
            Scope    = $scope
        })
    }
    return $out
}

function Get-EolKbDependencyDepth {
    <#
    .SYNOPSIS
        Profondeur minimale de chaque bom-ref depuis le composant racine.
        Sans tableau 'dependencies', renvoie GraphPresent = $false : aucune
        affirmation de lien parent/enfant ne sera faite dans les rapports.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Sbom)
    $deps = Get-DictArray -Dict $Sbom.Document -Key 'dependencies'
    if ($deps.Count -eq 0) { return @{ GraphPresent = $false; Depth = @{}; Parents = @{}; Adjacency = @{}; Root = '' } }

    $adj = @{}
    $parents = @{}
    foreach ($d in $deps) {
        $ref = [string](Get-DictValue $d 'ref' '')
        if (-not $ref) { continue }
        $children = @(Get-DictArray -Dict $d -Key 'dependsOn' | ForEach-Object { [string]$_ })
        $adj[$ref] = $children
        foreach ($c in $children) {
            if (-not $parents.ContainsKey($c)) { $parents[$c] = New-Object System.Collections.ArrayList }
            [void]$parents[$c].Add($ref)
        }
    }
    $rootRef = $Sbom.AppRef
    if (-not $rootRef -or -not $adj.ContainsKey($rootRef)) {
        # racine deduite : reference qui n'est enfant de personne
        foreach ($r in $adj.Keys) { if (-not $parents.ContainsKey($r)) { $rootRef = $r; break } }
    }
    $depth = @{}
    if ($rootRef) {
        $depth[$rootRef] = 0
        $q = New-Object System.Collections.Queue
        $q.Enqueue($rootRef)
        while ($q.Count -gt 0) {
            $cur = $q.Dequeue()
            $d0 = $depth[$cur]
            foreach ($ch in @($adj[$cur])) {
                if (-not $ch) { continue }
                if (-not $depth.ContainsKey($ch) -or $depth[$ch] -gt ($d0 + 1)) {
                    $depth[$ch] = $d0 + 1
                    $q.Enqueue($ch)
                }
            }
        }
    }
    return @{ GraphPresent = $true; Depth = $depth; Parents = $parents; Adjacency = $adj; Root = $rootRef }
}

function Get-EolKbFindings {
    <# Deduplique les composants en constats coordonnee@version. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Components, [Parameter(Mandatory)]$Graph)
    $map = @{}
    foreach ($c in $Components) {
        $eco = Get-EolKbEcosystem -Config $Config -PurlType $c.PurlType
        $coord = Get-EolKbCoordKey -Ecosystem $c.PurlType -Group $c.Group -Name $c.Name
        $key = "$coord@$($c.Version)"
        if (-not $map.ContainsKey($key)) {
            $depth = -1
            if ($Graph.GraphPresent -and $c.BomRef -and $Graph.Depth.ContainsKey($c.BomRef)) { $depth = [int]$Graph.Depth[$c.BomRef] }
            $map[$key] = [pscustomobject]@{
                Key          = $key
                Coordinate   = $coord
                PurlType     = $c.PurlType
                OsvEcosystem = [string]$eco.Osv
                Registry     = [string]$eco.Registry
                DepsDevSystem = [string](Get-DictValue $eco 'DepsDev' '')
                Group        = $c.Group
                Name         = $c.Name
                Version      = $c.Version
                Purl         = $c.Purl
                Type         = $c.Type
                Scopes       = @($c.Scope)
                BomRefs      = @($c.BomRef)
                Occurrences  = 1
                IsInternal   = $false
                Depth        = $depth
                IsDirect     = ($depth -eq 1)
                # champs remplis par l'analyse
                Product      = ''
                ProductConfidence = ''
                ProductUrl   = ''
                Cycle        = ''
                CycleIsLts   = $false
                EolDate      = $null
                DaysToEol    = $null
                SupportStatus = 'pending_enrichment'
                Recommendations = @()
                RegistryLatest = ''
                RegistryUrl   = ''
                RegistryDeprecated = $false
                RegistryNote  = ''
                # cycle de vie observe (publication reelle du paquet)
                MaintenanceStatus = ''
                LatestPublished  = $null
                CurrentPublished = $null
                VersionsBehind   = $null
                MajorBehind      = $null
                LifecycleSource  = ''
                VerdictSource    = ''
                Vulns        = @()
                VulnCount    = 0
                PreciseKey   = ''
                MatchMethod  = ''
                MatchDivergences = @()
                KevCount     = 0
                MaxEpss      = $null
                InProduction = $true
                ScopeNote    = ''
                MaxCvss      = $null
                MaxSeverity  = ''
                Priority     = 5
                Notes        = @()
            }
        } else {
            $f = $map[$key]
            $f.Occurrences++
            if ($c.BomRef -and $f.BomRefs -notcontains $c.BomRef) { $f.BomRefs += $c.BomRef }
            if ($c.Scope -and $f.Scopes -notcontains $c.Scope) { $f.Scopes += $c.Scope }
            if ($Graph.GraphPresent -and $c.BomRef -and $Graph.Depth.ContainsKey($c.BomRef)) {
                $d = [int]$Graph.Depth[$c.BomRef]
                if ($f.Depth -lt 0 -or ($d -ge 0 -and $d -lt $f.Depth)) { $f.Depth = $d; $f.IsDirect = ($d -eq 1) }
            }
        }
    }
    return @($map.Values)
}

# ===================================================================
# Nom de paquet public (transmis) pour chaque ecosysteme
# ===================================================================
function Get-EolKbPackageName {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding)
    switch ($Finding.OsvEcosystem) {
        'Maven'    { if ($Finding.Group) { return "$($Finding.Group):$($Finding.Name)" } else { return $Finding.Name } }
        'PyPI'     { return (($Finding.Name -replace '[-_\.]+', '-').ToLowerInvariant()) }
        'Packagist'{ if ($Finding.Group) { return "$($Finding.Group)/$($Finding.Name)" } else { return $Finding.Name } }
        'Go'       { if ($Finding.Group) { return "$($Finding.Group)/$($Finding.Name)" } else { return $Finding.Name } }
        'npm'      { if ($Finding.Group) { return "$($Finding.Group)/$($Finding.Name)" } else { return $Finding.Name } }
        default    { return $Finding.Name }
    }
}

# ===================================================================
# Statut de support + versions cibles
# ===================================================================
function Set-EolKbSupportStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Finding, [array]$Cycles, [bool]$ProductFound)

    if (-not $ProductFound) {
        if (-not $Finding.Product) { $Finding.SupportStatus = 'product_unmapped' }
        else { $Finding.SupportStatus = 'no_eol_source' }
        return
    }
    if (-not $Finding.Version) {
        $Finding.SupportStatus = 'version_unknown'
        $Finding.Notes += 'Version absente du SBOM : statut de support indeterminable.'
        return
    }
    $match = Get-EolKbCycleMatch -Version $Finding.Version -Cycles $Cycles
    if (-not $match) {
        $Finding.SupportStatus = 'cycle_unknown'
        $Finding.Notes += "Version $($Finding.Version) rattachee a aucun cycle publie pour '$($Finding.Product)'."
    } else {
        $Finding.Cycle = $match.Cycle
        $Finding.CycleIsLts = $match.IsLts
        $Finding.EolDate = $match.EolDate
        $Finding.DaysToEol = $match.DaysToEol
        if ($match.IsEol) { $Finding.SupportStatus = 'eol' }
        elseif ($null -ne $match.DaysToEol -and $match.DaysToEol -le $Config.Thresholds.EolSoonDays) { $Finding.SupportStatus = 'eol_soon' }
        else { $Finding.SupportStatus = 'supported' }
    }

    # ---- versions cibles : uniquement des cycles encore supportes -----
    $alive = @($Cycles | Where-Object { -not $_.IsEol })
    if ($alive.Count -eq 0) {
        $Finding.Notes += "Aucun cycle supporte publie pour '$($Finding.Product)' : produit entierement en fin de vie."
        return
    }
    $sorted = @($alive | Sort-Object -Property @{ Expression = { $_.EolDate } } -Descending)
    $recs = New-Object System.Collections.ArrayList
    $seen = @{}

    $addRec = {
        param($cycle, $kind, $note)
        if (-not $cycle -or $seen.ContainsKey($cycle.Cycle)) { return }
        $seen[$cycle.Cycle] = $true
        $ver = [string]$cycle.Latest
        $n = $note
        if (-not $ver) { $n = ($note + ' | dernier correctif non publie par la source : cibler le cycle ' + $cycle.Cycle).Trim(' |') }
        $activeNote = 'Cycle encore supporte par l''editeur'
        if ($cycle.EolDate) { $activeNote = "Cycle supporte jusqu'au $(([datetime]$cycle.EolDate).ToString('dd/MM/yyyy'))" }
        $link = [string]$cycle.Link
        if (-not $link) { $link = "https://endoflife.date/$($Finding.Product)" }
        [void]$recs.Add([pscustomobject]@{
            Kind      = $kind
            Cycle     = $cycle.Cycle
            Version   = $ver
            IsLts     = $cycle.IsLts
            EolDate   = $cycle.EolDate
            EolRaw    = $cycle.EolRaw
            Source    = 'endoflife.date'
            Link      = $link
            IsActive  = $true
            ActivityNote = $activeNote
            Note      = $n
        })
    }

    # 1) le plus petit cycle supporte superieur au cycle courant (montee minimale)
    if ($Finding.Cycle) {
        $upper = @($alive | Where-Object { (Compare-EolKbVersion -A $_.Cycle -B $Finding.Cycle) -gt 0 })
        if ($upper.Count -gt 0) {
            $minCycle = $upper[0]
            foreach ($u in $upper) { if ((Compare-EolKbVersion -A $u.Cycle -B $minCycle.Cycle) -lt 0) { $minCycle = $u } }
            & $addRec $minCycle 'montee-minimale' 'Plus petit cycle encore supporte au-dessus du cycle actuel.'
        } else {
            $cur = @($alive | Where-Object { $_.Cycle -eq $Finding.Cycle })
            if ($cur.Count -gt 0 -and $Finding.SupportStatus -eq 'eol_soon') {
                & $addRec $cur[0] 'patch-cycle-courant' 'Le cycle actuel est encore supporte : appliquer son dernier correctif.'
            }
        }
    }
    # 2) LTS avec l'horizon de support le plus long
    $lts = @($sorted | Where-Object { $_.IsLts })
    if ($lts.Count -gt 0) { & $addRec $lts[0] 'lts-recommandee' 'Cycle LTS offrant l''horizon de support le plus long.' }
    # 3) cycle supporte le plus recent
    $newest = $alive[0]
    foreach ($a in $alive) { if ((Compare-EolKbVersion -A $a.Cycle -B $newest.Cycle) -gt 0) { $newest = $a } }
    & $addRec $newest 'cycle-le-plus-recent' 'Cycle supporte le plus recent.'

    $max = [int]$Config.Thresholds.MaxRecommendations
    $Finding.Recommendations = @($recs | Select-Object -First $max)
}

# ===================================================================
# Cycle de vie observe : exploitation des dates de publication reelles
# ===================================================================
function ConvertTo-EolKbDate {
    [CmdletBinding()]
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return [datetime]::Parse($Text, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) } catch { }
    try { return [datetime]::ParseExact($Text.Substring(0, 10), 'yyyy-MM-dd', [cultureinfo]::InvariantCulture) } catch { }
    return $null
}

function Set-EolKbLifecycleFacts {
    <#
    .SYNOPSIS
        Renseigne un constat a partir des publications reelles du paquet :
        derniere version, dates, retard, depreciation. Aucune extrapolation,
        uniquement ce que la source publie.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Finding, [Parameter(Mandatory)]$Life)

    if (-not $Life.Found) {
        if ($Life.Attempted) { $Finding.LifecycleSource = 'aucune-source' }
        return
    }
    $Finding.LifecycleSource = $Life.Source
    $Finding.RegistryLatest = $Life.Latest
    if ($Life.Url) { $Finding.RegistryUrl = $Life.Url }
    if ($Life.Deprecated) {
        $Finding.RegistryDeprecated = $true
        $Finding.RegistryNote = $Life.DeprecatedReason
    }
    $Finding.LatestPublished = ConvertTo-EolKbDate -Text $Life.LatestPublished
    if (-not $Finding.LatestPublished -and $Life.Latest -and $Life.PublishedAt.ContainsKey($Life.Latest)) {
        $Finding.LatestPublished = ConvertTo-EolKbDate -Text $Life.PublishedAt[$Life.Latest]
    }
    if ($Finding.Version -and $Life.PublishedAt.ContainsKey($Finding.Version)) {
        $Finding.CurrentPublished = ConvertTo-EolKbDate -Text $Life.PublishedAt[$Finding.Version]
    }
    if (-not $Finding.Version) { return }

    $stable = @($Life.Versions | Where-Object { (ConvertTo-EolKbVersion -Version $_).IsStable })
    $newer = @($stable | Where-Object { (Compare-EolKbVersion -A $_ -B $Finding.Version) -gt 0 })
    $Finding.VersionsBehind = $newer.Count
    $cur = ConvertTo-EolKbVersion -Version $Finding.Version
    $lat = ConvertTo-EolKbVersion -Version $Life.Latest
    if ($cur.Numeric.Count -gt 0 -and $lat.Numeric.Count -gt 0) {
        $Finding.MajorBehind = [int]($lat.Numeric[0] - $cur.Numeric[0])
    }
    $known = @($Life.Versions | Where-Object { $_ -eq $Finding.Version })
    if ($known.Count -eq 0) {
        $Finding.Notes += "Version $($Finding.Version) absente des versions publiees par $($Life.Source) (build interne ou version retiree)."
    }

    $now = Get-Date
    $status = 'a_jour'
    if ($Finding.RegistryDeprecated) { $status = 'deprecie' }
    elseif ($Finding.LatestPublished -and (($now - $Finding.LatestPublished).TotalDays / 30.4) -ge $Config.Thresholds.DormantMonths) { $status = 'dormant' }
    elseif ($null -ne $Finding.MajorBehind -and $Finding.MajorBehind -ge 1) { $status = 'retard_majeur' }
    elseif ($Finding.VersionsBehind -gt 0) {
        $status = 'retard_mineur'
        if ($Finding.CurrentPublished -and (($now - $Finding.CurrentPublished).TotalDays / 30.4) -ge $Config.Thresholds.VersionAgeMonths) { $status = 'version_ancienne' }
    }
    elseif ($Finding.LatestPublished -and (($now - $Finding.LatestPublished).TotalDays / 30.4) -ge $Config.Thresholds.StaleMonths) { $status = 'peu_actif' }
    $Finding.MaintenanceStatus = $status
}

function Get-EolKbVersionActivity {
    <#
    .SYNOPSIS
        Une version proposee doit etre VIVANTE : appartenir a une branche que
        l'editeur alimente encore. On s'appuie sur les dates de publication
        reellement observees, jamais sur une supposition.
    .OUTPUTS
        @{ IsActive; Note }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Finding, [Parameter(Mandatory)]$Life, [string]$Version)

    $now = Get-Date
    $pub = $null
    if ($Version -and $Life.PublishedAt.ContainsKey($Version)) { $pub = ConvertTo-EolKbDate -Text $Life.PublishedAt[$Version] }
    $latestPub = $Finding.LatestPublished
    if (-not $latestPub -and $Life.LatestPublished) { $latestPub = ConvertTo-EolKbDate -Text $Life.LatestPublished }

    if (-not $latestPub) {
        return @{ IsActive = $null; Note = 'Activite du projet non publiee par la source : a confirmer aupres de l''editeur.' }
    }
    $months = [int](($now - $latestPub).TotalDays / 30.4)
    if ($months -ge [int]$Config.Thresholds.DormantMonths) {
        return @{ IsActive = $false
                  Note = "Le projet n'a rien publie depuis $months mois : cette version n'est pas une cible active, envisager un remplacement." }
    }
    $note = "Branche active : derniere publication il y a $months mois"
    if ($pub) { $note += ", cette version publiee le $($pub.ToString('dd/MM/yyyy'))" }
    if ($months -ge [int]$Config.Thresholds.StaleMonths) {
        $note = "Activite faible : derniere publication il y a $months mois"
    }
    return @{ IsActive = $true; Note = $note }
}

function Set-EolKbFinalVerdict {
    <#
    .SYNOPSIS
        Chaque constat recoit une conclusion explicite. Quand l'editeur ne
        publie pas de calendrier de support (cas des bibliotheques), le
        verdict s'appuie sur le cycle de vie observe. Si aucune source
        publique ne connait le composant, il est declare interne / non publie.
        Un echec de collecte est signale comme tel, jamais comme "inconnu".
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Finding)

    if ($Finding.PSObject.Properties['IsInternal'] -and $Finding.IsInternal) {
        $Finding.SupportStatus = 'internal_excluded'
        $Finding.VerdictSource = 'politique interne'
        return
    }
    if ($Finding.SupportStatus -in @('eol', 'eol_soon', 'supported')) {
        $Finding.VerdictSource = 'endoflife.date'
        return
    }
    if (-not $Finding.Version) {
        $Finding.SupportStatus = 'version_unknown'
        $Finding.VerdictSource = 'SBOM'
        return
    }
    if ($Finding.SupportStatus -eq 'cycle_unknown' -and $Finding.Product) {
        $Finding.Notes += "Version non rattachee a un cycle publie de '$($Finding.Product)' : verdict base sur les publications du paquet."
    }
    if ($Finding.MaintenanceStatus) {
        switch ($Finding.MaintenanceStatus) {
            'deprecie'         { $Finding.SupportStatus = 'deprecated' }
            'dormant'          { $Finding.SupportStatus = 'dormant' }
            'retard_majeur'    { $Finding.SupportStatus = 'outdated_major' }
            'version_ancienne' { $Finding.SupportStatus = 'outdated_minor' }
            'retard_mineur'    { $Finding.SupportStatus = 'outdated_minor' }
            'peu_actif'        { $Finding.SupportStatus = 'low_activity' }
            default            { $Finding.SupportStatus = 'maintained' }
        }
        $Finding.VerdictSource = $Finding.LifecycleSource
        return
    }
    if ($Finding.LifecycleSource -eq 'aucune-source') {
        $Finding.SupportStatus = 'internal_or_unpublished'
        $Finding.VerdictSource = 'registres publics'
        $Finding.Notes += 'Coordonnee absente des registres publics interroges : composant interne ou non publie.'
        return
    }
    $Finding.SupportStatus = 'collect_failed'
    $Finding.VerdictSource = 'collecte incomplete'
    $Finding.Notes += 'Aucune source n''a pu etre interrogee pour ce composant (reseau, proxy ou mode hors ligne).'
}

function Set-EolKbPriority {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Finding)
    $p = 5
    $cvss = 0.0
    if ($null -ne $Finding.MaxCvss) { $cvss = [double]$Finding.MaxCvss }
    if ($Finding.KevCount -gt 0) { $p = 1 }
    elseif ($Finding.SupportStatus -eq 'eol' -and $cvss -ge 7.0) { $p = 1 }
    elseif ($Finding.SupportStatus -eq 'eol') { $p = 2 }
    elseif ($cvss -ge 9.0) { $p = 1 }
    elseif ($cvss -ge 7.0) { $p = 2 }
    elseif ($Finding.SupportStatus -eq 'eol_soon') {
        if ($null -ne $Finding.DaysToEol -and $Finding.DaysToEol -le $Config.Thresholds.EolCriticalDays) { $p = 2 } else { $p = 3 }
    }
    elseif ($Finding.SupportStatus -eq 'deprecated') { $p = 2 }
    elseif ($Finding.SupportStatus -in @('dormant', 'outdated_major')) { $p = 3 }
    elseif ($cvss -gt 0) { $p = 3 }
    elseif ($Finding.SupportStatus -in @('outdated_minor', 'low_activity')) { $p = 4 }
    elseif ($Finding.SupportStatus -in @('version_unknown', 'internal_or_unpublished', 'collect_failed')) { $p = 4 }
    if ($Finding.IsDirect -and $p -gt 1) { $p = $p - 1 }   # dependance directe : action plus accessible
    $Finding.Priority = $p
}

# ===================================================================
# Pipeline d'analyse
# ===================================================================
function Invoke-EolKbAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$Sbom,
        [ValidateSet('None', 'Needed', 'All')][string]$RegistryLookup = 'Needed',
        [switch]$Offline,
        [switch]$NoVulns
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $components = Get-EolKbSbomComponents -Sbom $Sbom
    Write-EolKbLog -Message "Composants declares : $($components.Count)"
    $graph = Get-EolKbDependencyDepth -Sbom $Sbom
    if (-not $graph.GraphPresent) {
        Write-EolKbLog -Level WARN -Message "Aucun graphe 'dependencies' : profondeur et liens parent/enfant non exploitables (posture stricte)."
    }
    $findings = Get-EolKbFindings -Config $Config -Components $components -Graph $graph
    Write-EolKbLog -Message "Constats uniques (coordonnee@version) : $($findings.Count)"

    # --- 0a. Portee : ce qui est reellement embarque en production ----
    $ignored = @($Config.Thresholds.IgnoredScopes | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $outOfProd = 0
    foreach ($f in $findings) {
        foreach ($sc in @($f.Scopes)) {
            $sl = ([string]$sc).ToLowerInvariant()
            if ($sl -and ($ignored -contains $sl)) {
                $f.InProduction = $false
                $f.ScopeNote = "Portee '$sl' : composant non embarque a l'execution."
            }
        }
        if (-not $f.InProduction) { $outOfProd++ }
    }
    if ($outOfProd -gt 0) {
        Write-EolKbLog -Message "Composants hors production (test, provided...) ecartes du plan d'action : $outOfProd"
    }

    # --- 0. Confidentialite : ce qui ne sortira pas du poste ----------
    $secrets = @($Sbom.AppName, $Sbom.AppVersion, $Sbom.SerialNumber, $Sbom.FileName,
                 [System.IO.Path]::GetFileNameWithoutExtension($Sbom.FileName), $env:COMPUTERNAME, $env:USERNAME)
    $internalPrefixes = @($Config.Privacy.InternalNamespaces)
    if ($Config.Privacy.DetectInternalFromSbom -and $Sbom.AppGroup) { $internalPrefixes += $Sbom.AppGroup }
    Set-EolKbPrivacyContext -Secrets $secrets -InternalPrefixes $internalPrefixes
    $nbInternal = 0
    foreach ($f in $findings) {
        if (Test-EolKbInternalCoordinate -Group $f.Group -Name $f.Name -Prefixes $internalPrefixes) {
            $f.IsInternal = $true
            $f.SupportStatus = 'internal_excluded'
            $f.VerdictSource = 'politique interne'
            $f.Notes += 'Espace de noms interne : aucune requete externe n''a ete emise pour ce composant.'
            $nbInternal++
        }
    }
    if ($nbInternal -gt 0) {
        Write-EolKbLog -Message "Composants internes exclus de toute requete externe : $nbInternal"
    }

    # --- 1. Support (endoflife.date) --------------------------------
    $index = Get-EolKbProductIndex -Config $Config -Offline:$Offline
    $identifiers = Get-EolKbIdentifierIndex -Config $Config -Offline:$Offline
    $coords = @{}
    foreach ($f in $findings) { if (-not $coords.ContainsKey($f.Coordinate)) { $coords[$f.Coordinate] = $f } }
    Write-EolKbLog -Message "Coordonnees uniques a enrichir : $($coords.Count)"

    $cycleCache = @{}
    $i = 0; $lastTick = [datetime]::UtcNow
    foreach ($f in $findings) {
        $i++
        if (([datetime]::UtcNow - $lastTick).TotalMilliseconds -ge 400) {
            Write-Progress -Id 1 -Activity 'Analyse du support' -Status "$i / $($findings.Count)" -PercentComplete ([int](100 * $i / [Math]::Max(1, $findings.Count)))
            $lastTick = [datetime]::UtcNow
        }
        if ($f.IsInternal) { continue }
        $res = Get-EolKbCachedProductResolution -Config $Config -Ecosystem $f.PurlType -Group $f.Group -Name $f.Name `
            -Purl $f.Purl -Index $index -IdentifierIndex $identifiers -Offline:$Offline
        if (-not $res) { $f.SupportStatus = 'product_unmapped'; continue }
        $f.Product = $res.Slug
        $f.ProductConfidence = $res.Confidence
        $f.ProductUrl = "https://endoflife.date/$($res.Slug)"
        if (-not $cycleCache.ContainsKey($res.Slug)) {
            $cycleCache[$res.Slug] = Get-EolKbProductCycles -Config $Config -Slug $res.Slug -Offline:$Offline
        }
        $pc = $cycleCache[$res.Slug]
        Set-EolKbSupportStatus -Config $Config -Finding $f -Cycles $pc.Cycles -ProductFound ([bool]$pc.Found)
    }
    Write-Progress -Id 1 -Activity 'Analyse du support' -Completed

    # --- 2. Vulnerabilites (OSV) ------------------------------------
    $vulnMode = Get-EolKbVulnQueryMode -Config $Config
    $preciseIndex = @{}
    if (-not $NoVulns) {
        $items = @()
        $byKey = @{}
        $preciseItems = @()
        foreach ($f in $findings) {
            if ($f.IsInternal -or -not $f.OsvEcosystem) { continue }
            $pkg = Get-EolKbPackageName -Finding $f
            $k = "$($f.OsvEcosystem)|$pkg"
            if (-not $byKey.ContainsKey($k)) {
                $byKey[$k] = New-Object System.Collections.ArrayList
                $items += [pscustomobject]@{ Key = $k; OsvEcosystem = $f.OsvEcosystem; PackageName = $pkg }
            }
            [void]$byKey[$k].Add($f)
            if ($vulnMode -eq 'Precise' -and $f.Version) {
                $pk = "$k@$($f.Version)"
                $f.PreciseKey = $pk
                if (-not ($preciseItems | Where-Object { $_.Key -eq $pk })) {
                    $preciseItems += [pscustomobject]@{ Key = $pk; OsvEcosystem = $f.OsvEcosystem; PackageName = $pkg; Version = $f.Version }
                }
            }
        }
        if ($vulnMode -eq 'Precise') {
            Write-EolKbLog -Message "Interrogation OSV en mode precis : $($preciseItems.Count) couples paquet@version (correspondance etablie par la source, puis recoupee localement)"
            $preciseIndex = Get-EolKbVulnIndexPrecise -Config $Config -Items $preciseItems -Offline:$Offline
        } else {
            Write-EolKbLog -Message "Interrogation OSV sans version : $($items.Count) paquets (correspondance locale)"
        }
        $index2 = Get-EolKbVulnIndex -Config $Config -Items $items -Offline:$Offline

        $ids = @{}
        foreach ($src in @($index2, $preciseIndex)) {
            foreach ($k in $src.Keys) {
                foreach ($v in $src[$k]) {
                    $id = [string](Get-DictValue $v 'id' '')
                    if ($id) { $ids[$id] = [string](Get-DictValue $v 'modified' '') }
                }
            }
        }
        Write-EolKbLog -Message "Fiches de vulnerabilite a resoudre : $($ids.Count)"
        $records = @{}
        $j = 0; $lastTick = [datetime]::UtcNow
        foreach ($id in $ids.Keys) {
            $j++
            if (([datetime]::UtcNow - $lastTick).TotalMilliseconds -ge 400) {
                Write-Progress -Id 2 -Activity 'Fiches de vulnerabilites' -Status "$j / $($ids.Count)" -PercentComplete ([int](100 * $j / [Math]::Max(1, $ids.Count)))
                $lastTick = [datetime]::UtcNow
            }
            $rec = Get-EolKbVulnRecord -Config $Config -Id $id -Modified $ids[$id] -Offline:$Offline
            if ($rec) { $records[$id] = $rec }
        }
        Write-Progress -Id 2 -Activity 'Fiches de vulnerabilites' -Completed

        foreach ($k in $byKey.Keys) {
            $pkgVulns = @($index2[$k])
            if ($pkgVulns.Count -eq 0) { continue }
            $parts = $k -split '\|', 2
            $eco = $parts[0]; $pkg = $parts[1]
            foreach ($f in $byKey[$k]) {
                if (-not $f.Version) { $f.Notes += 'Vulnerabilites non evaluees : version absente.'; continue }
                # identifiants confirmes par la source pour CETTE version
                $confirmed = @{}
                $hasPrecise = $false
                if ($f.PreciseKey -and $preciseIndex.ContainsKey($f.PreciseKey)) {
                    $hasPrecise = $true
                    foreach ($pv in $preciseIndex[$f.PreciseKey]) {
                        $pid = [string](Get-DictValue $pv 'id' '')
                        if ($pid) { $confirmed[$pid] = $true }
                    }
                }
                foreach ($v in $pkgVulns) {
                    $id = [string](Get-DictValue $v 'id' '')
                    if (-not $records.ContainsKey($id)) { continue }
                    $rec = $records[$id]
                    $hit = Test-EolKbVulnAgainstFinding -Record $rec -Finding $f -Ecosystem $eco -PackageName $pkg
                    if ($hasPrecise) {
                        $srv = $confirmed.ContainsKey($id)
                        if ($srv -and $hit) { $hit.MatchConfidence = 'confirmee-osv+locale' }
                        elseif ($srv -and -not $hit) {
                            # la source affirme, l'evaluation locale non : on retient la source
                            $hit = Test-EolKbVulnAgainstFinding -Record $rec -Finding $f -Ecosystem $eco -PackageName $pkg -Force
                            if ($hit) {
                                $hit.MatchConfidence = 'confirmee-osv (divergence locale)'
                                $f.MatchDivergences += $id
                            }
                        } elseif (-not $srv -and $hit) {
                            # l'evaluation locale affirme, la source non : on ne retient pas
                            $f.MatchDivergences += $id
                            $f.Notes += "Divergence de correspondance sur $id : ecartee car non confirmee par OSV pour la version $($f.Version)."
                            $hit = $null
                        }
                    }
                    if ($hit) { $f.Vulns += $hit }
                }
                if ($hasPrecise) { $f.MatchMethod = 'osv-serveur' } else { $f.MatchMethod = 'locale' }
                $f.VulnCount = $f.Vulns.Count
                if ($f.VulnCount -gt 0) {
                    $scores = @($f.Vulns | Where-Object { $null -ne $_.Cvss } | ForEach-Object { [double]$_.Cvss })
                    if ($scores.Count -gt 0) {
                        $f.MaxCvss = ($scores | Measure-Object -Maximum).Maximum
                        $f.MaxSeverity = Get-EolKbSeverityLabel -Score $f.MaxCvss
                    } else {
                        $f.MaxSeverity = 'INCONNUE'
                    }
                }
            }
        }
    }

    # --- 2b. Exploitation reelle : catalogue CISA KEV et score EPSS ---
    if (-not $NoVulns) {
        $allCves = @()
        foreach ($f in $findings) {
            foreach ($v in $f.Vulns) { if ($v.Cve) { $allCves += [string]$v.Cve } }
        }
        $allCves = @($allCves | Select-Object -Unique)
        if ($allCves.Count -gt 0) {
            $kev = Get-EolKbKevCatalog -Config $Config -Offline:$Offline
            $epss = Get-EolKbEpssScores -Config $Config -CveIds $allCves -Offline:$Offline
            foreach ($f in $findings) {
                foreach ($v in $f.Vulns) {
                    $cve = [string]$v.Cve
                    $isKev = ($cve -and $kev.ContainsKey($cve))
                    $score = $null
                    if ($cve -and $epss.ContainsKey($cve)) { $score = [double]$epss[$cve] }
                    $v | Add-Member -NotePropertyName Kev -NotePropertyValue $isKev -Force
                    $v | Add-Member -NotePropertyName KevSince -NotePropertyValue $(if ($isKev) { [string]$kev[$cve].dateAdded } else { '' }) -Force
                    $v | Add-Member -NotePropertyName Epss -NotePropertyValue $score -Force
                    if ($isKev) { $f.KevCount++ }
                    if ($null -ne $score -and ($null -eq $f.MaxEpss -or $score -gt $f.MaxEpss)) { $f.MaxEpss = $score }
                }
            }
            $nbKev = @($findings | Where-Object { $_.KevCount -gt 0 }).Count
            if ($nbKev -gt 0) { Write-EolKbLog -Level WARN -Message "$nbKev composant(s) portent une vulnerabilite EXPLOITEE en conditions reelles (catalogue CISA)." }
        }
    }

    # --- 3. Cycle de vie publie (deps.dev, sinon registre natif) -----
    if ($RegistryLookup -ne 'None') {
        $targets = @($findings | Where-Object { (-not $_.IsInternal) -and ($_.Registry -or $_.DepsDevSystem) })
        if ($RegistryLookup -eq 'Needed') {
            $targets = @($targets | Where-Object {
                $_.VulnCount -gt 0 -or $_.SupportStatus -in @('eol', 'eol_soon') -or -not $_.Product -or $_.IsDirect
            })
        }
        Write-EolKbLog -Message "Cycle de vie publie : $($targets.Count) paquets interroges"
        $k = 0; $lastTick = [datetime]::UtcNow
        foreach ($f in $targets) {
            $k++
            if (([datetime]::UtcNow - $lastTick).TotalMilliseconds -ge 400) {
                Write-Progress -Id 3 -Activity 'Versions publiees' -Status "$k / $($targets.Count)" -PercentComplete ([int](100 * $k / [Math]::Max(1, $targets.Count)))
                $lastTick = [datetime]::UtcNow
            }
            $life = Get-EolKbPackageLifecycle -Config $Config -DepsDevSystem $f.DepsDevSystem -Registry $f.Registry `
                -Group $f.Group -Name $f.Name -PackageName (Get-EolKbPackageName -Finding $f) `
                -Offline:$Offline -Vulnerable:($f.VulnCount -gt 0)
            Set-EolKbLifecycleFacts -Config $Config -Finding $f -Life $life
            if (-not $life.Found) { continue }

            if ($f.VulnCount -gt 0 -and $f.Version) {
                $blocks = @()
                foreach ($v in $f.Vulns) { foreach ($b in $v.AffectedBlocks) { $blocks += $b } }
                $safe = $null
                if ($blocks.Count -gt 0) {
                    $safe = Get-EolKbSafeVersion -CurrentVersion $f.Version -AvailableVersions $life.Versions -AffectedBlocks $blocks
                }
                if ($safe) {
                    $act = Get-EolKbVersionActivity -Config $Config -Finding $f -Life $life -Version $safe
                    $secRec = [pscustomobject]@{
                        Kind = 'correctif-securite'; Cycle = ''; Version = $safe; IsLts = $false
                        EolDate = $null; EolRaw = ''; Source = $life.Source; Link = $f.RegistryUrl
                        IsActive = $act.IsActive; ActivityNote = $act.Note
                        Note = 'Plus petite version publiee, superieure a la version actuelle, non concernee par les vulnerabilites detectees.'
                    }
                    $merged = @($secRec) + @($f.Recommendations)
                    $f.Recommendations = @($merged | Select-Object -First ([int]$Config.Thresholds.MaxRecommendations))
                } elseif ($blocks.Count -gt 0) {
                    $f.Notes += 'Aucune version publiee connue ne corrige toutes les vulnerabilites detectees.'
                }
            }
            if ($f.Recommendations.Count -eq 0 -and $life.Latest -and $f.Version -and
                (Compare-EolKbVersion -A $life.Latest -B $f.Version) -gt 0) {
                $note = 'Derniere version publiee (information de publication, pas un engagement de support).'
                if ($f.LatestPublished) { $note = "Derniere version publiee le $($f.LatestPublished.ToString('dd/MM/yyyy')) (publication, pas un engagement de support)." }
                $act = Get-EolKbVersionActivity -Config $Config -Finding $f -Life $life -Version $life.Latest
                $f.Recommendations = @([pscustomobject]@{
                    Kind = 'derniere-version-publiee'; Cycle = ''; Version = $life.Latest; IsLts = $false
                    EolDate = $null; EolRaw = ''; Source = $life.Source; Link = $f.RegistryUrl
                    IsActive = $act.IsActive; ActivityNote = $act.Note; Note = $note
                })
                if (-not $act.IsActive) {
                    $f.Notes += "Aucune version active : $($act.Note)"
                }
            }
        }
        Write-Progress -Id 3 -Activity 'Versions publiees' -Completed
    }

    # --- 4. CVE des composants hors ecosysteme OSV (NVD) -------------
    if (-not $NoVulns) {
        $nvdTargets = @($findings | Where-Object { (-not $_.IsInternal) -and (-not $_.OsvEcosystem) -and $_.Version })
        if ($nvdTargets.Count -gt 0) {
            Write-EolKbLog -Message "Repli NVD (composants hors ecosysteme OSV) : $($nvdTargets.Count)"
            $n = 0
            foreach ($f in $nvdTargets) {
                $n++
                Write-Progress -Id 4 -Activity 'CVE (NVD)' -Status "$n / $($nvdTargets.Count)" -PercentComplete ([int](100 * $n / [Math]::Max(1, $nvdTargets.Count)))
                $cpes = @()
                if ($f.Product) { $cpes = @((Get-EolKbProductIdentifiers -Config $Config -Slug $f.Product).Cpe) }
                $records = @()
                $strict = $false
                foreach ($c in @($cpes | Where-Object { $_ -like 'cpe:2.3:*' } | Select-Object -First 2)) {
                    $records += @(Get-EolKbNvdVulns -Config $Config -CpeMatch $c -Offline:$Offline)
                    $strict = $true
                }
                if ($records.Count -eq 0 -and -not $strict) {
                    $records = @(Get-EolKbNvdVulns -Config $Config -Keyword $f.Name -Offline:$Offline)
                }
                foreach ($rec in $records) {
                    $hit = Test-EolKbNvdAgainstFinding -Record $rec -Finding $f -StrictCpe:$strict
                    if ($hit -and -not ($f.Vulns | Where-Object { $_.Id -eq $hit.Id })) { $f.Vulns += $hit }
                }
                $f.VulnCount = $f.Vulns.Count
                if ($f.VulnCount -gt 0) {
                    $scores = @($f.Vulns | Where-Object { $null -ne $_.Cvss } | ForEach-Object { [double]$_.Cvss })
                    if ($scores.Count -gt 0) {
                        $f.MaxCvss = ($scores | Measure-Object -Maximum).Maximum
                        $f.MaxSeverity = Get-EolKbSeverityLabel -Score $f.MaxCvss
                    } else { $f.MaxSeverity = 'INCONNUE' }
                }
            }
            Write-Progress -Id 4 -Activity 'CVE (NVD)' -Completed
        }
    }

    # --- 5. Verdict final : aucun constat ne reste sans conclusion ----
    foreach ($f in $findings) {
        Set-EolKbFinalVerdict -Config $Config -Finding $f
        Set-EolKbPriority -Config $Config -Finding $f
        Set-EolKbActionability -Config $Config -Finding $f
    }

    # --- 6. Consolidation : composants majeurs a traiter --------------
    $levers = Get-EolKbLevers -Config $Config -Findings $findings -Graph $graph
    # verification multi-sources + piste editeur + projection, sur les seuls leviers
    $levers = @(Add-EolKbLeverIntelligence -Config $Config -Levers $levers -Offline:$Offline)
    $act = @($findings | Where-Object { $_.ActionRequired }).Count
    Write-EolKbLog -Message "Materialite : $act constat(s) a traiter sur $($findings.Count), regroupes en $($levers.Count) levier(s)"
    $sw.Stop()

    return [pscustomobject]@{
        Sbom            = $Sbom
        Findings        = @($findings)
        Graph           = $graph
        Levers          = $levers
        ComponentCount  = $components.Count
        GraphPresent    = $graph.GraphPresent
        DurationSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        Offline         = [bool]$Offline
        Online          = (-not [bool]$Offline)
        VulnQueryMode   = $vulnMode
        PrivacyMode     = [string]$Config.Privacy.Mode
        RegistryLookup  = $RegistryLookup
        Summary         = (Get-EolKbSummary -Config $Config -Findings $findings)
        GeneratedAt     = (Get-Date)
    }
}

function Test-EolKbVulnAgainstFinding {
    <# Rapprochement LOCAL d'une fiche OSV avec un constat. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)]$Finding, [string]$Ecosystem, [string]$PackageName, [switch]$Force)

    $blocks = @()
    $affected = Get-DictArray -Dict $Record -Key 'affected'
    foreach ($a in $affected) {
        $pkg = Get-DictValue $a 'package'
        $nm = [string](Get-DictValue $pkg 'name' '')
        $ec = [string](Get-DictValue $pkg 'ecosystem' '')
        if ($nm -and $nm -ne $PackageName) { continue }
        if ($ec -and $Ecosystem -and ($ec -split ':')[0] -ne $Ecosystem) { continue }
        $blocks += $a
    }
    if ($blocks.Count -eq 0) { return $null }

    $affectedNow = $false; $conf = 'unknown'; $fixed = @()
    foreach ($b in $blocks) {
        $r = Test-EolKbVersionAffected -Version $Finding.Version -Affected $b
        if ($r.Fixed) { $fixed += $r.Fixed }
        if ($r.Affected) { $affectedNow = $true; $conf = $r.Confidence }
    }
    if (-not $affectedNow -and -not $Force) { return $null }

    # severite : vecteur CVSS v3 calcule localement, sinon libelle de la source
    $cvss = $null; $vector = ''; $cvssVersion = ''
    foreach ($sev in (Get-DictArray -Dict $Record -Key 'severity')) {
        $t = [string](Get-DictValue $sev 'type' '')
        $s = [string](Get-DictValue $sev 'score' '')
        if ($t -like 'CVSS_V3*' -or $s -like 'CVSS:3*') {
            $vector = $s; $cvssVersion = 'v3'
            $calc = Get-EolKbCvss3Score -Vector $s
            if ($null -ne $calc) { $cvss = $calc }
        } elseif (($t -like 'CVSS_V4*' -or $s -like 'CVSS:4*') -and -not $vector) {
            $vector = $s; $cvssVersion = 'v4'
        }
    }
    $label = ''
    if ($null -ne $cvss) { $label = Get-EolKbSeverityLabel -Score $cvss }
    else {
        $ds = Get-DictValue $Record 'database_specific'
        $sevTxt = [string](Get-DictValue $ds 'severity' '')
        if ($sevTxt) { $label = $sevTxt.ToUpperInvariant() } else { $label = 'INCONNUE' }
    }
    $aliases = @(Get-DictArray -Dict $Record -Key 'aliases' | ForEach-Object { [string]$_ })
    $id = [string](Get-DictValue $Record 'id' '')
    $cve = @($aliases | Where-Object { $_ -like 'CVE-*' })
    $cveId = ''
    if ($cve.Count -gt 0) { $cveId = $cve[0] }
    elseif ($id -like 'CVE-*') { $cveId = $id }

    return [pscustomobject]@{
        Id            = $id
        Cve           = $cveId
        Aliases       = $aliases
        Summary       = [string](Get-DictValue $Record 'summary' '')
        Published     = [string](Get-DictValue $Record 'published' '')
        Modified      = [string](Get-DictValue $Record 'modified' '')
        Cvss          = $cvss
        CvssVector    = $vector
        CvssVersion   = $cvssVersion
        Severity      = $label
        FixedVersions = @($fixed | Sort-Object -Unique)
        MatchConfidence = $conf
        VulnSource    = 'OSV'
        Url           = "https://osv.dev/vulnerability/$id"
        AffectedBlocks = $blocks
    }
}

function Test-EolKbNvdAgainstFinding {
    <#
    .SYNOPSIS
        Rapprochement LOCAL d'une fiche NVD avec un constat : la version
        installee est comparee aux plages CPE renvoyees par NVD. Aucune
        version n'a ete transmise pour obtenir ces fiches.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)]$Finding, [switch]$StrictCpe)

    $ver = [string]$Finding.Version
    if (-not $ver) { return $null }
    $tokens = @()
    foreach ($t in @($Finding.Name, $Finding.Product)) {
        if ($t) { $tokens += ([string]$t).ToLowerInvariant(); $tokens += (([string]$t).ToLowerInvariant() -replace '-', '_') }
    }
    $hit = $false
    foreach ($m in (Get-DictArray -Dict $Record -Key 'matches')) {
        $criteria = [string](Get-DictValue $m 'criteria' '')
        $parts = $criteria -split ':'
        if ($parts.Count -lt 6) { continue }
        $product = $parts[4].ToLowerInvariant()
        if (-not $StrictCpe -and $tokens.Count -gt 0 -and ($tokens -notcontains $product)) { continue }
        $cpeVer = $parts[5]

        if ($cpeVer -and $cpeVer -ne '*' -and $cpeVer -ne '-') {
            if ((Compare-EolKbVersion -A $ver -B $cpeVer) -eq 0) { $hit = $true; break }
            continue
        }
        $vsi = [string](Get-DictValue $m 'vsi' ''); $vse = [string](Get-DictValue $m 'vse' '')
        $vei = [string](Get-DictValue $m 'vei' ''); $vee = [string](Get-DictValue $m 'vee' '')
        if (-not ($vsi -or $vse -or $vei -or $vee)) { continue }   # "toutes versions" : trop large, on n'affirme pas
        $ok = $true
        if ($vsi -and (Compare-EolKbVersion -A $ver -B $vsi) -lt 0) { $ok = $false }
        if ($ok -and $vse -and (Compare-EolKbVersion -A $ver -B $vse) -le 0) { $ok = $false }
        if ($ok -and $vei -and (Compare-EolKbVersion -A $ver -B $vei) -gt 0) { $ok = $false }
        if ($ok -and $vee -and (Compare-EolKbVersion -A $ver -B $vee) -ge 0) { $ok = $false }
        if ($ok) { $hit = $true; break }
    }
    if (-not $hit) { return $null }

    $score = Get-DictValue $Record 'score'
    $label = 'INCONNUE'
    if ($null -ne $score) { $label = Get-EolKbSeverityLabel -Score ([double]$score) }
    $id = [string](Get-DictValue $Record 'id' '')
    return [pscustomobject]@{
        Id            = $id
        Cve           = $id
        Aliases       = @()
        Summary       = [string](Get-DictValue $Record 'summary' '')
        Published     = [string](Get-DictValue $Record 'published' '')
        Modified      = ''
        Cvss          = $score
        CvssVector    = [string](Get-DictValue $Record 'vector' '')
        CvssVersion   = 'v3'
        Severity      = $label
        FixedVersions = @()
        MatchConfidence = 'cpe-range'
        VulnSource    = 'NVD'
        Url           = "https://nvd.nist.gov/vuln/detail/$id"
        AffectedBlocks = @()
    }
}

function Test-EolKbSbomAgainstCve {
    <#
    .SYNOPSIS
        Repond a la question : "cette application est-elle concernee par
        cette CVE ?" en confrontant la fiche de vulnerabilite aux composants
        du SBOM. Le rapprochement de version est fait localement.
    .OUTPUTS
        @{ Id; Status; Matches; Present; Cvss; Severity; Summary; Source; Note }
        Status :
          'affecte'         au moins un composant du SBOM est dans une plage vulnerable
          'non-affecte'     les paquets vises sont presents mais dans une version hors plage
          'absent'          aucun des paquets vises n'est present dans le SBOM
          'indetermine'     paquet present mais version absente du SBOM, ou plages non exploitables
          'cve-inconnue'    aucune source publique ne connait cet identifiant
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Findings, [Parameter(Mandatory)][string]$Id, [switch]$Offline)

    $res = [ordered]@{
        Id = $Id.ToUpperInvariant(); Status = 'cve-inconnue'; Matches = @(); Present = @()
        Cvss = $null; Severity = ''; Summary = ''; Source = ''; Aliases = @(); FixedVersions = @()
        Note = ''; Url = ''
    }
    $vuln = Get-EolKbVulnById -Config $Config -Id $Id -Offline:$Offline
    if (-not $vuln.Found) {
        $res.Note = 'Identifiant inconnu des sources interrogees (OSV, NVD) ou sources injoignables : aucune conclusion ne peut etre tiree.'
        if ($Offline) { $res.Note = 'Mode hors ligne : fiche de vulnerabilite absente du cache local, aucune conclusion possible.' }
        return [pscustomobject]$res
    }
    $res.Source = $vuln.Source
    $rec = $vuln.Record

    if ($vuln.Kind -eq 'osv') {
        $res.Url = "https://osv.dev/vulnerability/$($res.Id)"
        $res.Summary = [string](Get-DictValue $rec 'summary' '')
        $res.Aliases = @(Get-DictArray -Dict $rec -Key 'aliases' | ForEach-Object { [string]$_ })
        foreach ($sev in (Get-DictArray -Dict $rec -Key 'severity')) {
            $sc = [string](Get-DictValue $sev 'score' '')
            if ($sc -like 'CVSS:3*') {
                $calc = Get-EolKbCvss3Score -Vector $sc
                if ($null -ne $calc) { $res.Cvss = $calc }
            }
        }
        # paquets vises par la fiche
        $targets = @()
        foreach ($a in (Get-DictArray -Dict $rec -Key 'affected')) {
            $pkg = Get-DictValue $a 'package'
            $targets += @{ Eco = [string](Get-DictValue $pkg 'ecosystem' ''); Name = [string](Get-DictValue $pkg 'name' ''); Block = $a }
        }
        foreach ($f in $Findings) {
            if (-not $f.OsvEcosystem) { continue }
            $pkgName = Get-EolKbPackageName -Finding $f
            foreach ($t in $targets) {
                $ecoOk = (-not $t.Eco -or ($t.Eco -split ':')[0] -ieq $f.OsvEcosystem)
                if (-not $ecoOk -or ($t.Name -and $t.Name -ine $pkgName)) { continue }
                if (-not $f.Version) {
                    $res.Present += [pscustomobject]@{ Finding = $f; Reason = 'version absente du SBOM' }
                    continue
                }
                $hit = Test-EolKbVersionAffected -Version $f.Version -Affected $t.Block
                if ($hit.Fixed) { $res.FixedVersions += $hit.Fixed }
                if ($hit.Affected) {
                    $res.Matches += [pscustomobject]@{ Finding = $f; Fixed = @($hit.Fixed); Confidence = $hit.Confidence }
                } else {
                    $res.Present += [pscustomobject]@{ Finding = $f; Reason = 'version hors des plages vulnerables publiees' }
                }
            }
        }
    } else {
        $res.Url = "https://nvd.nist.gov/vuln/detail/$($res.Id)"
        $res.Summary = [string](Get-DictValue $rec 'summary' '')
        $res.Cvss = Get-DictValue $rec 'score'
        # produits vises par les CPE
        $products = @()
        foreach ($m in (Get-DictArray -Dict $rec -Key 'matches')) {
            $parts = ([string](Get-DictValue $m 'criteria' '')) -split ':'
            if ($parts.Count -ge 5) { $products += $parts[4].ToLowerInvariant() }
        }
        $products = @($products | Select-Object -Unique)
        foreach ($f in $Findings) {
            $tokens = @()
            foreach ($t in @($f.Name, $f.Product)) { if ($t) { $tokens += ([string]$t).ToLowerInvariant(); $tokens += (([string]$t).ToLowerInvariant() -replace '-', '_') } }
            $concerned = @($tokens | Where-Object { $products -contains $_ })
            if ($concerned.Count -eq 0) { continue }
            if (-not $f.Version) { $res.Present += [pscustomobject]@{ Finding = $f; Reason = 'version absente du SBOM' }; continue }
            $hit = Test-EolKbNvdAgainstFinding -Record $rec -Finding $f
            if ($hit) { $res.Matches += [pscustomobject]@{ Finding = $f; Fixed = @(); Confidence = 'cpe-range' } }
            else { $res.Present += [pscustomobject]@{ Finding = $f; Reason = 'version hors des plages CPE publiees' } }
        }
    }

    $res.FixedVersions = @($res.FixedVersions | Sort-Object -Unique)
    if ($null -ne $res.Cvss) { $res.Severity = Get-EolKbSeverityLabel -Score $res.Cvss }
    if (@($res.Matches).Count -gt 0) {
        $res.Status = 'affecte'
        $res.Note = "$(@($res.Matches).Count) composant(s) du SBOM se trouvent dans une plage de versions declaree vulnerable."
    } elseif (@($res.Present | Where-Object { $_.Reason -like 'version absente*' }).Count -gt 0) {
        $res.Status = 'indetermine'
        $res.Note = 'Le paquet vise est present mais le SBOM ne porte pas sa version : conclusion impossible sans cette information.'
    } elseif (@($res.Present).Count -gt 0) {
        $res.Status = 'non-affecte'
        $res.Note = 'Le paquet vise est present, dans une version situee hors des plages vulnerables publiees.'
    } else {
        $res.Status = 'absent'
        $res.Note = 'Aucun composant du SBOM ne correspond aux paquets ou produits vises par cette vulnerabilite.'
    }
    # les composants internes n'ont pas ete confrontes aux sources externes
    $internal = @($Findings | Where-Object { $_.PSObject.Properties['IsInternal'] -and $_.IsInternal }).Count
    if ($internal -gt 0 -and $res.Status -ne 'affecte') {
        $res.Note += " $internal composant(s) interne(s) n'ont pas ete confrontes aux sources externes (politique de confidentialite)."
    }
    return [pscustomobject]$res
}

function Invoke-EolKbCveCheck {
    <# Verifie une liste d'identifiants de vulnerabilites contre un SBOM. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Sbom, [Parameter(Mandatory)][string[]]$CveIds,
          $Findings, [switch]$Offline)
    if (-not $Findings) {
        $components = Get-EolKbSbomComponents -Sbom $Sbom
        $graph = Get-EolKbDependencyDepth -Sbom $Sbom
        $Findings = Get-EolKbFindings -Config $Config -Components $components -Graph $graph
        $internalPrefixes = @($Config.Privacy.InternalNamespaces)
        if ($Config.Privacy.DetectInternalFromSbom -and $Sbom.AppGroup) { $internalPrefixes += $Sbom.AppGroup }
        Set-EolKbPrivacyContext -Secrets @($Sbom.AppName, $Sbom.AppVersion, $Sbom.SerialNumber, $Sbom.FileName) -InternalPrefixes $internalPrefixes
        foreach ($f in $Findings) {
            if (Test-EolKbInternalCoordinate -Group $f.Group -Name $f.Name -Prefixes $internalPrefixes) { $f.IsInternal = $true }
        }
    }
    $out = @()
    foreach ($id in $CveIds) {
        if (-not $id) { continue }
        Write-EolKbLog -Message "Verification ciblee : $id"
        $out += Test-EolKbSbomAgainstCve -Config $Config -Findings $Findings -Id $id -Offline:$Offline
    }
    return @($out)
}

function Get-EolKbSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Findings)
    $byStatus = @{}
    foreach ($s in @('eol', 'eol_soon', 'supported', 'deprecated', 'dormant', 'outdated_major',
                     'outdated_minor', 'low_activity', 'maintained', 'version_unknown',
                     'internal_or_unpublished', 'internal_excluded', 'collect_failed')) { $byStatus[$s] = 0 }
    $vulnerable = 0; $critical = 0; $high = 0; $cveTotal = 0; $deprecated = 0
    $action = 0; $highCve = 0
    foreach ($f in $Findings) {
        if ($f.PSObject.Properties['ActionRequired'] -and $f.ActionRequired) { $action++ }
        $highCve += @($f.Vulns | Where-Object { $null -ne $_.Cvss -and [double]$_.Cvss -ge $Config.Thresholds.ActionableCvss }).Count
        if ($byStatus.ContainsKey($f.SupportStatus)) { $byStatus[$f.SupportStatus]++ } else { $byStatus[$f.SupportStatus] = 1 }
        if ($f.VulnCount -gt 0) { $vulnerable++; $cveTotal += $f.VulnCount }
        if ($null -ne $f.MaxCvss) {
            if ([double]$f.MaxCvss -ge 9.0) { $critical++ }
            elseif ([double]$f.MaxCvss -ge 7.0) { $high++ }
        }
        if ($f.RegistryDeprecated) { $deprecated++ }
    }
    return [pscustomobject]@{
        Findings         = $Findings.Count
        Eol              = $byStatus['eol']
        EolSoon          = $byStatus['eol_soon']
        Supported        = $byStatus['supported']
        DeprecatedStatus = $byStatus['deprecated']
        Dormant          = $byStatus['dormant']
        OutdatedMajor    = $byStatus['outdated_major']
        OutdatedMinor    = $byStatus['outdated_minor']
        LowActivity      = $byStatus['low_activity']
        Maintained       = $byStatus['maintained']
        VersionUnknown   = $byStatus['version_unknown']
        Internal         = $byStatus['internal_or_unpublished'] + $byStatus['internal_excluded']
        CollectFailed    = $byStatus['collect_failed']
        Deprecated       = $deprecated
        VulnerableFindings = $vulnerable
        VulnTotal        = $cveTotal
        CriticalFindings = $critical
        HighFindings     = $high
        Priority1        = @($Findings | Where-Object { $_.Priority -eq 1 }).Count
        Priority2        = @($Findings | Where-Object { $_.Priority -eq 2 }).Count
        ActionRequired   = $action
        HighCveTotal     = $highCve
        KevFindings      = @($Findings | Where-Object { $_.KevCount -gt 0 }).Count
        OutOfProduction  = @($Findings | Where-Object { -not $_.InProduction }).Count
    }
}

Export-ModuleMember -Function Read-EolKbSbom, Get-EolKbSbomComponents, Get-EolKbDependencyDepth, Get-EolKbFindings,
    Get-EolKbPackageName, Set-EolKbSupportStatus, Set-EolKbPriority, Invoke-EolKbAnalysis,
    Test-EolKbVulnAgainstFinding, Get-EolKbSummary, ConvertTo-EolKbDate, Set-EolKbLifecycleFacts,
    Set-EolKbFinalVerdict, Get-EolKbVersionActivity, Test-EolKbNvdAgainstFinding, Test-EolKbSbomAgainstCve, Invoke-EolKbCveCheck
