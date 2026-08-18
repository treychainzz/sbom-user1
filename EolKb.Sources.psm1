<#
.SYNOPSIS
    Fournisseurs de donnees externes derriere une couche d'abstraction :
    endoflife.date (support), registres de paquets (versions publiees),
    OSV (vulnerabilites). Chaque appel passe par le cache local.
    Aucune version applicative n'est transmise.
#>

# ===================================================================
# purl
# ===================================================================
function Resolve-EolKbPurl {
    [CmdletBinding()]
    param([string]$Purl)
    $out = [pscustomobject]@{ Type = ''; Group = ''; Name = ''; Version = ''; Valid = $false }
    if ([string]::IsNullOrWhiteSpace($Purl)) { return $out }
    if ($Purl -notmatch '^pkg:([^/]+)/(.+)$') { return $out }
    $out.Type = $Matches[1].ToLowerInvariant()
    $rest = $Matches[2]
    $rest = ($rest -split '\?')[0]
    $rest = ($rest -split '#')[0]
    if ($rest -match '^(.*)@([^@]+)$') { $rest = $Matches[1]; $out.Version = [uri]::UnescapeDataString($Matches[2]) }
    $parts = $rest -split '/'
    $out.Name = [uri]::UnescapeDataString($parts[-1])
    if ($parts.Count -gt 1) { $out.Group = [uri]::UnescapeDataString(($parts[0..($parts.Count - 2)] -join '/')) }
    $out.Valid = $true
    return $out
}

function Get-EolKbEcosystem {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [string]$PurlType)
    $t = ([string]$PurlType).ToLowerInvariant()
    if ($Config.Ecosystems.ContainsKey($t)) { return $Config.Ecosystems[$t] }
    return @{ Osv = ''; Registry = '' }
}

function Get-EolKbCoordKey {
    [CmdletBinding()]
    param([string]$Ecosystem, [string]$Group, [string]$Name)
    $g = if ($Group) { "$Group`:" } else { '' }
    return ("{0}|{1}{2}" -f $Ecosystem.ToLowerInvariant(), $g, $Name).ToLowerInvariant()
}

# ===================================================================
# endoflife.date : index des produits
# ===================================================================
function Get-EolKbProductIndex {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [switch]$Offline)
    $root = $Config.Paths.CacheRoot
    $entry = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'eol-index' -Key 'products'
    if ($entry -and ($entry.Fresh -or $Offline)) { return @(Get-DictArray -Dict $entry.Payload) }
    if ($Offline) { return @() }

    $slugs = @()
    try {
        $r = Invoke-EolKbRequest -Config $Config -Uri ($Config.Sources.EolApiV1 + '/') -Purpose 'eol-index'
        foreach ($p in (Get-DictArray -Dict $r -Key 'result')) {
            $n = Get-DictValue $p 'name'
            if (-not $n) { $n = Get-DictValue $p 'permalink' }
            if (-not $n -and $p -is [string]) { $n = $p }
            if ($n) { $slugs += [string]$n }
        }
    } catch {
        Write-EolKbLog -Level WARN -Message "API v1 indisponible ($($_.Exception.Message)), repli sur /api/all.json"
    }
    if ($slugs.Count -eq 0) {
        try {
            $r = Invoke-EolKbRequest -Config $Config -Uri ($Config.Sources.EolApiLegacy + '/all.json') -Purpose 'eol-index-legacy'
            $slugs = @(Get-DictArray -Dict $r | ForEach-Object { [string]$_ })
        } catch {
            Write-EolKbLog -Level ERROR -Message "Index endoflife.date inaccessible : $($_.Exception.Message)"
            if ($entry) { return @(Get-DictArray -Dict $entry.Payload) }
            return @()
        }
    }
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'eol-index' -Key 'products' -Payload $slugs `
        -TtlDays $Config.Ttl.EolProductIndex -Source 'endoflife.date' | Out-Null
    Write-EolKbLog -Level INFO -Message "Index endoflife.date : $($slugs.Count) produits"
    return $slugs
}

# ===================================================================
# endoflife.date : fiche produit -> cycles normalises
# Gere le format v1 (result.releases[]) et l'ancien format (tableau).
# ===================================================================
function ConvertTo-EolKbCycles {
    [CmdletBinding()]
    param($Raw)
    $releases = @()
    $res = Get-DictValue $Raw 'result'
    if ($res) {
        $releases = Get-DictArray -Dict $res -Key 'releases'
        if ($releases.Count -eq 0) { $releases = Get-DictArray -Dict $res -Key 'cycles' }
    }
    if ($releases.Count -eq 0) { $releases = Get-DictArray -Dict $Raw }

    $now = (Get-Date).Date
    $out = @()
    foreach ($r in $releases) {
        if ($r -is [string]) { continue }
        $cycle = Get-DictValue $r 'name'
        if (-not $cycle) { $cycle = Get-DictValue $r 'cycle' }
        if (-not $cycle) { continue }

        $eolRaw = Get-DictValue $r 'eolFrom'
        if ($null -eq $eolRaw) { $eolRaw = Get-DictValue $r 'eol' }
        $eolDate = $null
        try { if ($eolRaw -and ([string]$eolRaw) -match '^\d{4}-\d{2}-\d{2}') { $eolDate = [datetime]::ParseExact(([string]$eolRaw).Substring(0, 10), 'yyyy-MM-dd', [cultureinfo]::InvariantCulture) } } catch { }

        $isEol = Get-DictValue $r 'isEol'
        if ($null -eq $isEol) {
            if ($eolDate) { $isEol = ($eolDate -le $now) }
            elseif ($eolRaw -is [bool]) { $isEol = [bool]$eolRaw }
            elseif (([string]$eolRaw) -in @('true', 'True')) { $isEol = $true }
            else { $isEol = $false }
        } else { $isEol = [bool]$isEol }

        $ltsRaw = Get-DictValue $r 'isLts'
        if ($null -eq $ltsRaw) { $ltsRaw = Get-DictValue $r 'lts' }
        $isLts = $false
        if ($ltsRaw -is [bool]) { $isLts = [bool]$ltsRaw }
        elseif ($ltsRaw) { $isLts = $true }   # date de passage en LTS

        $supportRaw = Get-DictValue $r 'eoasFrom'
        if ($null -eq $supportRaw) { $supportRaw = Get-DictValue $r 'support' }

        $latestObj = Get-DictValue $r 'latest'
        $latest = ''; $latestDate = ''; $link = ''
        if ($latestObj -is [string]) { $latest = [string]$latestObj }
        elseif ($latestObj) {
            $latest = [string](Get-DictValue $latestObj 'name' '')
            $latestDate = [string](Get-DictValue $latestObj 'date' '')
            $link = [string](Get-DictValue $latestObj 'link' '')
        }
        if (-not $latestDate) { $latestDate = [string](Get-DictValue $r 'latestReleaseDate' '') }
        if (-not $link) { $link = [string](Get-DictValue $r 'link' '') }

        $days = $null
        if ($eolDate) { $days = [int]($eolDate - $now).TotalDays }
        $eolRawText = ''
        if ($null -ne $eolRaw) { $eolRawText = [string]$eolRaw }
        $supportText = ''
        if ($null -ne $supportRaw) { $supportText = [string]$supportRaw }

        $out += [pscustomobject]@{
            Cycle       = [string]$cycle
            Label       = [string](Get-DictValue $r 'label' ([string]$cycle))
            ReleaseDate = [string](Get-DictValue $r 'releaseDate' ([string](Get-DictValue $r 'date' '')))
            EolRaw      = $eolRawText
            EolDate     = $eolDate
            DaysToEol   = $days
            IsEol       = $isEol
            IsLts       = $isLts
            SupportEnd  = $supportText
            Latest      = $latest
            LatestDate  = $latestDate
            Link        = $link
        }
    }
    return $out
}

function Get-EolKbTtlForCycles {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [array]$Cycles)
    if ($Cycles.Count -eq 0) { return $Config.Ttl.EolNegative }
    $alive = @($Cycles | Where-Object { -not $_.IsEol })
    if ($alive.Count -eq 0) { return $Config.Ttl.EolProductDead }
    $near = @($alive | Where-Object { $null -ne $_.DaysToEol -and $_.DaysToEol -le $Config.Thresholds.EolSoonDays })
    if ($near.Count -gt 0) { return $Config.Ttl.EolProductNearEol }
    return $Config.Ttl.EolProductDefault
}

function Get-EolKbProductCycles {
    <# Retourne @{ Found; Cycles; Source; Url; FromCache; AgeDays } #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Slug, [switch]$Offline, [switch]$Force)
    $root = $Config.Paths.CacheRoot
    $entry = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'eol-product' -Key $Slug
    if ($entry -and -not $Force -and ($entry.Fresh -or $Offline)) {
        $found = [bool](Get-DictValue $entry.Payload 'found' $false)
        $cycles = @()
        if ($found) { $cycles = ConvertTo-EolKbCycles -Raw (Get-DictValue $entry.Payload 'raw') }
        return @{ Found = $found; Cycles = $cycles; Source = $entry.Source; Url = "https://endoflife.date/$Slug"
                  FromCache = $true; AgeDays = $entry.AgeDays }
    }
    if ($Offline) { return @{ Found = $false; Cycles = @(); Source = 'offline'; Url = ''; FromCache = $false; AgeDays = -1 } }

    $raw = $null; $source = 'endoflife.date/api/v1'
    try {
        $raw = Invoke-EolKbRequest -Config $Config -Uri "$($Config.Sources.EolApiV1)/$Slug" -Purpose 'eol-product' -TolerateNotFound
    } catch {
        Write-EolKbLog -Level DEBUG -Message "v1 en echec pour '$Slug' : $($_.Exception.Message)"
    }
    if ($null -eq $raw) {
        try {
            $raw = Invoke-EolKbRequest -Config $Config -Uri "$($Config.Sources.EolApiLegacy)/$Slug.json" -Purpose 'eol-product-legacy' -TolerateNotFound
            $source = 'endoflife.date/api'
        } catch { $raw = $null }
    }
    if ($null -eq $raw) {
        Set-EolKbCacheEntry -CacheRoot $root -Namespace 'eol-product' -Key $Slug `
            -Payload @{ found = $false } -TtlDays $Config.Ttl.EolNegative -Source 'endoflife.date' | Out-Null
        return @{ Found = $false; Cycles = @(); Source = 'endoflife.date'; Url = ''; FromCache = $false; AgeDays = 0 }
    }
    $cycles = ConvertTo-EolKbCycles -Raw $raw
    $ttl = Get-EolKbTtlForCycles -Config $Config -Cycles $cycles
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'eol-product' -Key $Slug `
        -Payload @{ found = $true; raw = $raw } -TtlDays $ttl -Source $source `
        -Meta @{ cycles = $cycles.Count } | Out-Null
    return @{ Found = $true; Cycles = $cycles; Source = $source; Url = "https://endoflife.date/$Slug"; FromCache = $false; AgeDays = 0 }
}

# ===================================================================
# Resolution coordonnee -> produit endoflife.date
# Hierarchie de confiance : table interne > correspondance exacte de
# l'index > prefixe connu. Aucun rapprochement approximatif.
# ===================================================================
function Get-EolKbProductMap {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config)
    if ($script:ProductMap) { return $script:ProductMap }
    $p = Join-Path $Config.RootPath 'data\ProductMap.psd1'
    if (-not (Test-Path -LiteralPath $p)) { $p = Join-Path $Config.RootPath 'data/ProductMap.psd1' }
    if (Test-Path -LiteralPath $p) { $script:ProductMap = Import-PowerShellDataFile -LiteralPath $p }
    else { $script:ProductMap = @{ Exact = @{}; Prefix = @{} } }
    return $script:ProductMap
}

function Get-EolKbIdentifierIndex {
    <#
    .SYNOPSIS
        Table des identifiants publics (purl) declares par endoflife.date,
        soit la correspondance officielle "coordonnee de paquet -> produit".
        Un seul appel, mis en cache 30 jours ; c'est ce qui permet de
        rattacher automatiquement un composant sans table manuelle.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [switch]$Offline)
    $root = $Config.Paths.CacheRoot
    $entry = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'eol-index' -Key 'identifiers-purl' -OverrideTtlDays $Config.Ttl.EolIdentifiers
    if ($entry -and ($entry.Fresh -or $Offline)) {
        $map = @{}
        $pl = $entry.Payload
        if ($pl -is [System.Collections.IDictionary]) {
            foreach ($k in $pl.Keys) { $map[[string]$k] = [string]$pl[$k] }
        }
        return $map
    }
    if ($Offline) { return @{} }

    $map = @{}
    foreach ($uri in @("$($Config.Sources.EolIdentifiers)/purl/", "$($Config.Sources.EolIdentifiers)/purl")) {
        try {
            $r = Invoke-EolKbRequest -Config $Config -Uri $uri -Purpose 'eol-identifiers' -TolerateNotFound
        } catch { $r = $null }
        if ($null -eq $r) { continue }
        # Le schema peut evoluer : on accepte plusieurs formes
        # ({identifier, product}, {purl, product:{name}}, dictionnaire plat).
        $items = Get-DictArray -Dict $r -Key 'result'
        if ($items.Count -eq 0) { $items = Get-DictArray -Dict $r -Key 'identifiers' }
        if ($items.Count -eq 0 -and $r -is [System.Collections.IDictionary]) {
            foreach ($k in $r.Keys) {
                if ([string]$k -like 'pkg:*') { $map[([string]$k).ToLowerInvariant()] = [string]$r[$k] }
            }
        }
        foreach ($it in $items) {
            if ($it -is [string]) { continue }
            $id = [string](Get-DictValue $it 'identifier' '')
            if (-not $id) { $id = [string](Get-DictValue $it 'purl' '') }
            if (-not $id) { $id = [string](Get-DictValue $it 'id' '') }
            if (-not $id) { continue }
            $prod = Get-DictValue $it 'product'
            $slug = ''
            if ($prod -is [string]) { $slug = [string]$prod }
            elseif ($prod) { $slug = [string](Get-DictValue $prod 'name' '') }
            if (-not $slug) {
                foreach ($p in (Get-DictArray -Dict $it -Key 'products')) {
                    if ($p -is [string]) { $slug = [string]$p } else { $slug = [string](Get-DictValue $p 'name' '') }
                    if ($slug) { break }
                }
            }
            if ($slug) { $map[$id.ToLowerInvariant()] = $slug }
        }
        if ($map.Count -gt 0) { break }
    }
    if ($map.Count -eq 0) {
        Write-EolKbLog -Level WARN -Message "Table des identifiants purl indisponible : rattachement limite a la table interne et aux noms de produits."
    } else {
        Write-EolKbLog -Message "Identifiants purl endoflife.date : $($map.Count) correspondances"
    }
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'eol-index' -Key 'identifiers-purl' -Payload $map `
        -TtlDays $Config.Ttl.EolIdentifiers -Source 'endoflife.date' | Out-Null
    return $map
}

function Get-EolKbPurlCandidates {
    <# purl plausibles (sans version) pour une coordonnee de composant. #>
    [CmdletBinding()]
    param([string]$Ecosystem, [string]$Group, [string]$Name)
    $eco = ([string]$Ecosystem).ToLowerInvariant()
    $nm = ([string]$Name)
    $gr = ([string]$Group)
    $out = @()
    if ($eco -and $gr) { $out += "pkg:$eco/$gr/$nm" }
    if ($eco) { $out += "pkg:$eco/$nm" }
    if ($gr) {
        $out += "pkg:github/$gr/$nm"
        $out += "pkg:golang/$gr/$nm"
    }
    $out += "pkg:generic/$nm"
    $out += "pkg:docker/library/$nm"
    $out += "pkg:os/$nm"
    $out += "pkg:github/$nm/$nm"
    return @($out | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
}

function Get-EolKbNameVariants {
    <# Variantes normalisees d'un nom de composant, pour rapprochement exact. #>
    [CmdletBinding()]
    param([string]$Name, [string]$Group)
    $nm = ([string]$Name).ToLowerInvariant()
    $v = New-Object System.Collections.ArrayList
    [void]$v.Add($nm)
    [void]$v.Add(($nm -replace '[_\s\.]+', '-'))
    [void]$v.Add(($nm -replace '\.js$', '' -replace '-js$', ''))
    foreach ($suffix in @('-core', '-api', '-server', '-client', '-common', '-runtime', '-jdk', '-bin', '-lib', '-embed')) {
        if ($nm.EndsWith($suffix)) { [void]$v.Add($nm.Substring(0, $nm.Length - $suffix.Length)) }
    }
    if ($nm -match '^@([^/]+)/') { [void]$v.Add($Matches[1]) }   # scope npm : @angular/core -> angular
    if ($Group -match '^@(.+)$') { [void]$v.Add($Matches[1].ToLowerInvariant()) }
    return @($v | Where-Object { $_ } | Select-Object -Unique)
}

function Resolve-EolKbProduct {
    <#
    .SYNOPSIS
        Rattache une coordonnee a un produit endoflife.date, en cascade :
        table interne > identifiants purl publies par endoflife.date >
        nom exact d'un produit > variantes normalisees du nom >
        segment du groupe Maven > prefixe connu.
        Retourne @{ Slug; Confidence } ou $null (aucun rapprochement approximatif).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [string]$Ecosystem, [string]$Group, [string]$Name, [string]$Purl,
        [Parameter(Mandatory)][array]$Index,
        [hashtable]$IdentifierIndex = @{}
    )
    $map = Get-EolKbProductMap -Config $Config
    $eco = ([string]$Ecosystem).ToLowerInvariant()
    $nm = ([string]$Name).ToLowerInvariant()
    $gr = ([string]$Group).ToLowerInvariant()
    $idx = @{}
    foreach ($s in $Index) { $idx[([string]$s).ToLowerInvariant()] = [string]$s }

    $accept = {
        param($slug, $confidence)
        if (-not $slug) { return $null }
        if ($idx.Count -eq 0 -or $idx.ContainsKey(([string]$slug).ToLowerInvariant())) {
            return @{ Slug = [string]$slug; Confidence = $confidence }
        }
        return $null
    }

    # 1) table interne (prioritaire : corrige les cas ambigus)
    $candidates = @()
    if ($gr) { $candidates += "$eco`:$gr`:$nm"; $candidates += "$eco`:$gr`:*" }
    $candidates += "$eco`:$nm"; $candidates += $nm
    foreach ($k in $candidates) {
        if ($map.Exact.ContainsKey($k)) {
            $r = & $accept $map.Exact[$k] 'table-interne'
            if ($r) { return $r }
        }
    }

    # 2) identifiants purl publies par endoflife.date (source officielle)
    if ($IdentifierIndex.Count -gt 0) {
        $purls = @()
        if ($Purl) {
            $clean = (($Purl -split '\?')[0] -split '#')[0]
            $clean = ($clean -replace '@[^@/]+$', '')
            $purls += $clean.ToLowerInvariant()
        }
        $purls += Get-EolKbPurlCandidates -Ecosystem $eco -Group $gr -Name $nm
        foreach ($pl in $purls) {
            if ($IdentifierIndex.ContainsKey($pl)) {
                $r = & $accept $IdentifierIndex[$pl] 'identifiant-purl'
                if ($r) { return $r }
            }
        }
    }

    # 3) nom exact d'un produit publie
    if ($idx.ContainsKey($nm)) { return @{ Slug = $idx[$nm]; Confidence = 'nom-produit' } }

    # 4) variantes normalisees du nom
    foreach ($v in (Get-EolKbNameVariants -Name $nm -Group $gr)) {
        if ($idx.ContainsKey($v)) { return @{ Slug = $idx[$v]; Confidence = 'nom-normalise' } }
    }

    # 5) segments du groupe Maven / namespace (org.eclipse.jetty -> jetty)
    if ($gr) {
        $stop = @('org', 'com', 'net', 'io', 'fr', 'de', 'eu', 'co', 'me', 'dev', 'software', 'group', 'project')
        $segments = @($gr -split '[\./]' | Where-Object { $_ -and ($stop -notcontains $_) })
        [array]::Reverse($segments)
        foreach ($seg in $segments) {
            if ($idx.ContainsKey($seg)) { return @{ Slug = $idx[$seg]; Confidence = 'segment-groupe' } }
        }
    }

    # 6) prefixes connus
    foreach ($k in $map.Prefix.Keys) {
        if ($nm.StartsWith([string]$k)) {
            $r = & $accept $map.Prefix[$k] 'prefixe'
            if ($r) { return $r }
        }
    }
    return $null
}

function Get-EolKbCachedProductResolution {
    <# Memorise la resolution (y compris les echecs) pour ne pas la refaire. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [string]$Ecosystem, [string]$Group, [string]$Name, [string]$Purl,
          [array]$Index, [hashtable]$IdentifierIndex = @{}, [switch]$Offline)
    $key = Get-EolKbCoordKey -Ecosystem $Ecosystem -Group $Group -Name $Name
    $root = $Config.Paths.CacheRoot
    $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'mapping' -Key $key
    if ($e -and ($e.Fresh -or $Offline)) {
        $slug = [string](Get-DictValue $e.Payload 'slug' '')
        if (-not $slug) { return $null }
        return @{ Slug = $slug; Confidence = [string](Get-DictValue $e.Payload 'confidence' 'cache') }
    }
    $r = Resolve-EolKbProduct -Config $Config -Ecosystem $Ecosystem -Group $Group -Name $Name -Purl $Purl `
        -Index $Index -IdentifierIndex $IdentifierIndex
    $payload = if ($r) { @{ slug = $r.Slug; confidence = $r.Confidence } } else { @{ slug = '' } }
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'mapping' -Key $key -Payload $payload `
        -TtlDays $Config.Ttl.ProductMapping -Source 'local' | Out-Null
    return $r
}

# ===================================================================
# Registres de paquets : liste des versions publiees
# (le nom du paquet seul est transmis, jamais la version installee)
# ===================================================================
function Get-EolKbRegistryInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][string]$Registry,
        [string]$Group, [Parameter(Mandatory)][string]$Name,
        [switch]$Offline, [switch]$Vulnerable
    )
    $key = Get-EolKbCoordKey -Ecosystem $Registry -Group $Group -Name $Name
    $root = $Config.Paths.CacheRoot
    $ttl = if ($Vulnerable) { $Config.Ttl.RegistryVulnerable } else { $Config.Ttl.Registry }
    $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'registry' -Key $key -OverrideTtlDays $ttl
    if ($e -and ($e.Fresh -or $Offline)) {
        return @{
            Found = [bool](Get-DictValue $e.Payload 'found' $false)
            Versions = @(Get-DictArray -Dict $e.Payload -Key 'versions' | ForEach-Object { [string]$_ })
            Latest = [string](Get-DictValue $e.Payload 'latest' '')
            Deprecated = [bool](Get-DictValue $e.Payload 'deprecated' $false)
            DeprecationNote = [string](Get-DictValue $e.Payload 'note' '')
            Url = [string](Get-DictValue $e.Payload 'url' '')
            Source = $Registry; FromCache = $true; AgeDays = $e.AgeDays
        }
    }
    if ($Offline) { return @{ Found = $false; Versions = @(); Latest = ''; Deprecated = $false; DeprecationNote = ''; Url = ''; Source = $Registry; FromCache = $false; AgeDays = -1 } }

    $base = $Config.Sources.Registries[$Registry]
    if (-not $base) { return @{ Found = $false; Versions = @(); Latest = ''; Deprecated = $false; DeprecationNote = ''; Url = ''; Source = $Registry; FromCache = $false; AgeDays = -1 } }

    $full = if ($Group) { "$Group/$Name" } else { $Name }
    $versions = @(); $latest = ''; $deprecated = $false; $note = ''; $url = ''; $raw = $null
    $exempt = @($Name, $Group, $full)

    try {
        switch ($Registry) {
            'npm' {
                $enc = [uri]::EscapeDataString($full)
                $url = "$base/$enc"
                $raw = Invoke-EolKbRequest -Config $Config -Uri $url -Purpose 'registry-npm' -ExemptTokens $exempt `
                    -Headers @{ 'Accept' = 'application/vnd.npm.install-v1+json' } -TolerateNotFound
                if ($raw) {
                    $vs = Get-DictValue $raw 'versions'
                    if ($vs -is [System.Collections.IDictionary]) {
                        $versions = @($vs.Keys | ForEach-Object { [string]$_ })
                        $tags = Get-DictValue $raw 'dist-tags'
                        $latest = [string](Get-DictValue $tags 'latest' '')
                        if ($latest -and $vs.Contains($latest)) {
                            $d = Get-DictValue $vs[$latest] 'deprecated'
                            if ($d) { $deprecated = $true; $note = [string]$d }
                        }
                    }
                    $url = "https://www.npmjs.com/package/$full"
                }
            }
            'PyPI' {
                $url = "$base/$Name/json"
                $raw = Invoke-EolKbRequest -Config $Config -Uri $url -Purpose 'registry-pypi' -ExemptTokens $exempt -TolerateNotFound
                if ($raw) {
                    $rel = Get-DictValue $raw 'releases'
                    if ($rel -is [System.Collections.IDictionary]) { $versions = @($rel.Keys | ForEach-Object { [string]$_ }) }
                    $info = Get-DictValue $raw 'info'
                    $latest = [string](Get-DictValue $info 'version' '')
                    $cls = @(Get-DictArray -Dict $info -Key 'classifiers' | ForEach-Object { [string]$_ })
                    if ($cls -contains 'Development Status :: 7 - Inactive') { $deprecated = $true; $note = 'Classifie inactif sur PyPI' }
                    $url = "https://pypi.org/project/$Name/"
                }
            }
            'Maven' {
                $gp = ($Group -replace '\.', '/')
                $url = "$base/$gp/$Name/maven-metadata.xml"
                $txt = Invoke-EolKbRequest -Config $Config -Uri $url -Purpose 'registry-maven' -ExemptTokens $exempt -Raw -TolerateNotFound
                if ($txt) {
                    try {
                        $xml = [xml]$txt
                        $versions = @($xml.metadata.versioning.versions.version | ForEach-Object { [string]$_ })
                        $latest = [string]$xml.metadata.versioning.release
                        if (-not $latest) { $latest = [string]$xml.metadata.versioning.latest }
                    } catch { Write-EolKbLog -Level DEBUG -Message "maven-metadata.xml illisible pour $Group`:$Name" }
                    $url = "https://central.sonatype.com/artifact/$Group/$Name"
                }
            }
            'NuGet' {
                $id = $Name.ToLowerInvariant()
                $url = "$base/$id/index.json"
                $raw = Invoke-EolKbRequest -Config $Config -Uri $url -Purpose 'registry-nuget' -ExemptTokens $exempt -TolerateNotFound
                if ($raw) {
                    $versions = @(Get-DictArray -Dict $raw -Key 'versions' | ForEach-Object { [string]$_ })
                    $url = "https://www.nuget.org/packages/$Name"
                }
            }
            'RubyGems' {
                $url = "$base/$Name.json"
                $raw = Invoke-EolKbRequest -Config $Config -Uri $url -Purpose 'registry-gem' -ExemptTokens $exempt -TolerateNotFound
                if ($raw) {
                    foreach ($v in (Get-DictArray -Dict $raw)) {
                        if (-not [bool](Get-DictValue $v 'yanked' $false)) { $versions += [string](Get-DictValue $v 'number' '') }
                    }
                    $url = "https://rubygems.org/gems/$Name"
                }
            }
            'Go' {
                $mod = $full.ToLowerInvariant()
                $url = "$base/$mod/@v/list"
                $txt = Invoke-EolKbRequest -Config $Config -Uri $url -Purpose 'registry-go' -ExemptTokens $exempt -Raw -TolerateNotFound
                if ($txt) { $versions = @($txt -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }) }
                $url = "https://pkg.go.dev/$full"
            }
            'crates' {
                $url = "$base/$Name"
                $raw = Invoke-EolKbRequest -Config $Config -Uri $url -Purpose 'registry-crates' -ExemptTokens $exempt -TolerateNotFound
                if ($raw) {
                    foreach ($v in (Get-DictArray -Dict $raw -Key 'versions')) {
                        if (-not [bool](Get-DictValue $v 'yanked' $false)) { $versions += [string](Get-DictValue $v 'num' '') }
                    }
                    $url = "https://crates.io/crates/$Name"
                }
            }
            'Packagist' {
                $url = "$base/$full.json"
                $raw = Invoke-EolKbRequest -Config $Config -Uri $url -Purpose 'registry-packagist' -ExemptTokens $exempt -TolerateNotFound
                if ($raw) {
                    $pk = Get-DictValue $raw 'packages'
                    if ($pk -is [System.Collections.IDictionary]) {
                        foreach ($k in $pk.Keys) {
                            foreach ($v in (Get-DictArray -Dict $pk[$k])) { $versions += [string](Get-DictValue $v 'version' '') }
                        }
                    }
                    $url = "https://packagist.org/packages/$full"
                }
            }
        }
    } catch {
        Write-EolKbLog -Level WARN -Message "Registre $Registry indisponible pour '$full' : $($_.Exception.Message)"
        return @{ Found = $false; Versions = @(); Latest = ''; Deprecated = $false; DeprecationNote = ''; Url = $url; Source = $Registry; FromCache = $false; AgeDays = -1 }
    }

    $versions = @($versions | Where-Object { $_ } | Sort-Object -Unique)
    $found = ($versions.Count -gt 0)
    $storeTtl = $ttl
    if (-not $found) { $storeTtl = $Config.Ttl.RegistryNegative }
    if (-not $latest -and $found) {
        $stable = @($versions | Where-Object { (ConvertTo-EolKbVersion -Version $_).IsStable })
        if ($stable.Count -eq 0) { $stable = $versions }
        $latest = (Sort-EolKbVersionList -Versions $stable -Descending)[0]
    }
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'registry' -Key $key -Source $Registry `
        -TtlDays $storeTtl -Payload @{ found = $found; versions = $versions; latest = $latest; deprecated = $deprecated; note = $note; url = $url } | Out-Null
    return @{ Found = $found; Versions = $versions; Latest = $latest; Deprecated = $deprecated
              DeprecationNote = $note; Url = $url; Source = $Registry; FromCache = $false; AgeDays = 0 }
}

# ===================================================================
# OSV : index paquet -> vulnerabilites (SANS version, cf. Privacy)
# ===================================================================
function Get-EolKbVulnIndex {
    <#
    .SYNOPSIS
        Pour une liste de coordonnees, retourne une table
        cle -> @( @{id; modified} ). Interrogation par lots de 100,
        uniquement avec ecosysteme + nom de paquet.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][array]$Items,     # @{ Key; OsvEcosystem; PackageName }
        [switch]$Offline
    )
    $root = $Config.Paths.CacheRoot
    $result = @{}
    $todo = @()
    foreach ($it in $Items) {
        $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'osv-pkg' -Key $it.Key -OverrideTtlDays $Config.Ttl.OsvPackageIndex
        if ($e -and ($e.Fresh -or $Offline)) {
            $result[$it.Key] = @(Get-DictArray -Dict $e.Payload -Key 'vulns')
        } elseif (-not $Offline) {
            $todo += $it
        } else {
            $result[$it.Key] = @()
        }
    }
    if ($todo.Count -eq 0) { return $result }

    $size = [int]$Config.Sources.OsvBatchSize
    for ($i = 0; $i -lt $todo.Count; $i += $size) {
        $batch = @($todo[$i..([Math]::Min($i + $size - 1, $todo.Count - 1))])
        $queries = @()
        foreach ($b in $batch) { $queries += @{ package = @{ ecosystem = $b.OsvEcosystem; name = $b.PackageName } } }
        $body = ConvertTo-JsonCompat -InputObject @{ queries = $queries } -Depth 6 -Compress
        $exempt = @($batch | ForEach-Object { $_.PackageName })
        try {
            $resp = Invoke-EolKbRequest -Config $Config -Uri $Config.Sources.OsvQueryBatch -Method POST -Body $body `
                -Purpose 'osv-querybatch' -ExemptTokens $exempt
        } catch {
            $msg = $_.Exception.Message
            if ($msg -like '*CONFIDENTIALITE*') {
                # une seule coordonnee du lot est en cause : on rejoue le lot
                # element par element pour ne pas perdre les autres.
                Write-EolKbLog -Level WARN -Message "Lot OSV bloque par la garde de confidentialite, reprise coordonnee par coordonnee."
                foreach ($b in $batch) {
                    $single = ConvertTo-JsonCompat -InputObject @{ queries = @(@{ package = @{ ecosystem = $b.OsvEcosystem; name = $b.PackageName } }) } -Depth 6 -Compress
                    try {
                        $r1 = Invoke-EolKbRequest -Config $Config -Uri $Config.Sources.OsvQueryBatch -Method POST -Body $single `
                            -Purpose 'osv-querybatch' -ExemptTokens @($b.PackageName)
                        $v1 = @()
                        foreach ($rr in (Get-DictArray -Dict $r1 -Key 'results')) {
                            foreach ($v in (Get-DictArray -Dict $rr -Key 'vulns')) {
                                $v1 += @{ id = [string](Get-DictValue $v 'id' ''); modified = [string](Get-DictValue $v 'modified' '') }
                            }
                        }
                        $result[$b.Key] = $v1
                        Set-EolKbCacheEntry -CacheRoot $root -Namespace 'osv-pkg' -Key $b.Key -Payload @{ vulns = $v1 } `
                            -TtlDays $Config.Ttl.OsvPackageIndex -Source 'osv.dev' | Out-Null
                    } catch {
                        Write-EolKbLog -Level WARN -Message "Coordonnee ecartee de l'interrogation OSV : $($b.PackageName) ($($_.Exception.Message))"
                    }
                }
                continue
            }
            Write-EolKbLog -Level WARN -Message "OSV querybatch en echec sur un lot de $($batch.Count) : $msg"
            continue
        }
        $results = @(Get-DictArray -Dict $resp -Key 'results')
        for ($k = 0; $k -lt $batch.Count; $k++) {
            $item = $batch[$k]
            $vulns = @()
            if ($k -lt $results.Count) {
                foreach ($v in (Get-DictArray -Dict $results[$k] -Key 'vulns')) {
                    $vulns += @{ id = [string](Get-DictValue $v 'id' ''); modified = [string](Get-DictValue $v 'modified' '') }
                }
            }
            $result[$item.Key] = $vulns
            Set-EolKbCacheEntry -CacheRoot $root -Namespace 'osv-pkg' -Key $item.Key `
                -Payload @{ vulns = $vulns } -TtlDays $Config.Ttl.OsvPackageIndex -Source 'osv.dev' | Out-Null
        }
        Write-EolKbLog -Level DEBUG -Message "OSV : lot de $($batch.Count) coordonnees interroge"
    }
    return $result
}

function Get-EolKbVulnQueryMode {
    <# Resout 'Auto' selon le mode de confidentialite en vigueur. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config)
    $m = [string]$Config.Privacy.VulnQueryMode
    if (-not $m -or $m -eq 'Auto') {
        if ([string]$Config.Privacy.Mode -eq 'Strict') { return 'PackageOnly' }
        return 'Precise'
    }
    if ($m -eq 'Precise' -and [string]$Config.Privacy.Mode -eq 'Strict') {
        Write-EolKbLog -Level WARN -Message "Mode de confidentialite Strict : la recherche precise (version transmise) est desactivee, repli sur PackageOnly."
        return 'PackageOnly'
    }
    return $m
}

function Get-EolKbVulnIndexPrecise {
    <#
    .SYNOPSIS
        Interrogation OSV AVEC la version installee : c'est OSV qui etablit
        la correspondance, ce qui elimine le risque d'interpreter a tort une
        plage de versions. Utilise en mode de confidentialite 'Balanced'
        uniquement (une version de paquet public y est consideree comme non
        sensible, l'identite applicative n'etant jamais transmise).
    .OUTPUTS
        Table cle "eco|paquet@version" -> @( @{id; modified} )
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][array]$Items,     # @{ Key; OsvEcosystem; PackageName; Version }
        [switch]$Offline
    )
    $root = $Config.Paths.CacheRoot
    $result = @{}
    $todo = @()
    foreach ($it in $Items) {
        $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'osv-pkg-v' -Key $it.Key -OverrideTtlDays $Config.Ttl.OsvPackageIndex
        if ($e -and ($e.Fresh -or $Offline)) { $result[$it.Key] = @(Get-DictArray -Dict $e.Payload -Key 'vulns') }
        elseif (-not $Offline) { $todo += $it }
        # hors ligne sans entree en cache : la cle reste ABSENTE, afin que
        # l'analyse retombe sur l'evaluation locale plutot que de conclure
        # a tort que la source n'a rien signale.
    }
    if ($todo.Count -eq 0) { return $result }

    $size = [int]$Config.Sources.OsvBatchSize
    for ($i = 0; $i -lt $todo.Count; $i += $size) {
        $batch = @($todo[$i..([Math]::Min($i + $size - 1, $todo.Count - 1))])
        $queries = @()
        foreach ($b in $batch) {
            $queries += @{ package = @{ ecosystem = $b.OsvEcosystem; name = $b.PackageName }; version = [string]$b.Version }
        }
        $body = ConvertTo-JsonCompat -InputObject @{ queries = $queries } -Depth 6 -Compress
        try {
            $resp = Invoke-EolKbRequest -Config $Config -Uri $Config.Sources.OsvQueryBatch -Method POST -Body $body `
                -Purpose 'osv-querybatch-precis'
        } catch {
            $msg = $_.Exception.Message
            if ($msg -like '*CONFIDENTIALITE*') {
                Write-EolKbLog -Level WARN -Message "Lot OSV precis bloque par la garde de confidentialite, reprise coordonnee par coordonnee."
                foreach ($b in $batch) {
                    $single = ConvertTo-JsonCompat -InputObject @{ queries = @(@{ package = @{ ecosystem = $b.OsvEcosystem; name = $b.PackageName }; version = [string]$b.Version }) } -Depth 6 -Compress
                    try {
                        $r1 = Invoke-EolKbRequest -Config $Config -Uri $Config.Sources.OsvQueryBatch -Method POST -Body $single -Purpose 'osv-querybatch-precis'
                        $v1 = @()
                        foreach ($rr in (Get-DictArray -Dict $r1 -Key 'results')) {
                            foreach ($v in (Get-DictArray -Dict $rr -Key 'vulns')) {
                                $v1 += @{ id = [string](Get-DictValue $v 'id' ''); modified = [string](Get-DictValue $v 'modified' '') }
                            }
                        }
                        $result[$b.Key] = $v1
                        Set-EolKbCacheEntry -CacheRoot $root -Namespace 'osv-pkg-v' -Key $b.Key -Payload @{ vulns = $v1 } `
                            -TtlDays $Config.Ttl.OsvPackageIndex -Source 'osv.dev/precis' | Out-Null
                    } catch {
                        Write-EolKbLog -Level WARN -Message "Coordonnee ecartee de l'interrogation OSV precise : $($b.PackageName) ($($_.Exception.Message))"
                    }
                }
                continue
            }
            Write-EolKbLog -Level WARN -Message "OSV (mode precis) en echec sur un lot de $($batch.Count) : $msg"
            # aucune cle ajoutee : repli sur l'evaluation locale
            continue
        }
        $results = @(Get-DictArray -Dict $resp -Key 'results')
        for ($k = 0; $k -lt $batch.Count; $k++) {
            $item = $batch[$k]
            $vulns = @()
            if ($k -lt $results.Count) {
                foreach ($v in (Get-DictArray -Dict $results[$k] -Key 'vulns')) {
                    $vulns += @{ id = [string](Get-DictValue $v 'id' ''); modified = [string](Get-DictValue $v 'modified' '') }
                }
            }
            $result[$item.Key] = $vulns
            Set-EolKbCacheEntry -CacheRoot $root -Namespace 'osv-pkg-v' -Key $item.Key `
                -Payload @{ vulns = $vulns } -TtlDays $Config.Ttl.OsvPackageIndex -Source 'osv.dev/precis' | Out-Null
        }
        Write-EolKbLog -Level DEBUG -Message "OSV precis : lot de $($batch.Count) couples paquet@version interroge"
    }
    return $result
}

function Get-EolKbKevCatalog {
    <#
    .SYNOPSIS
        Catalogue CISA des vulnerabilites EXPLOITEES en conditions reelles.
        Un fichier unique, sans parametre : aucune information sur
        l'entreprise n'est transmise. C'est le signal de priorisation le
        plus solide : une CVE de ce catalogue est activement utilisee.
    .OUTPUTS
        Table cveId -> @{ dateAdded; ransomware }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [switch]$Offline)
    $root = $Config.Paths.CacheRoot
    $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'nvd' -Key 'kev-catalog' -OverrideTtlDays $Config.Ttl.Kev
    $build = {
        param($p)
        $map = @{}
        $node = Get-DictValue $p 'cves'
        if ($node -is [System.Collections.IDictionary]) {
            foreach ($k in $node.Keys) {
                $v = $node[$k]
                $map[[string]$k] = @{ dateAdded = [string](Get-DictValue $v 'dateAdded' ''); ransomware = [string](Get-DictValue $v 'ransomware' '') }
            }
        }
        return $map
    }
    if ($e -and ($e.Fresh -or $Offline)) { return (& $build $e.Payload) }
    if ($Offline) { return @{} }
    try {
        $raw = Invoke-EolKbRequest -Config $Config -Uri $Config.Sources.KevFeed -Purpose 'cisa-kev' -TolerateNotFound
    } catch {
        Write-EolKbLog -Level WARN -Message "Catalogue CISA KEV inaccessible : $($_.Exception.Message)"
        if ($e) { return (& $build $e.Payload) }
        return @{}
    }
    $cves = @{}
    foreach ($v in (Get-DictArray -Dict $raw -Key 'vulnerabilities')) {
        $id = [string](Get-DictValue $v 'cveID' '')
        if (-not $id) { continue }
        $cves[$id] = @{ dateAdded = [string](Get-DictValue $v 'dateAdded' '')
                        ransomware = [string](Get-DictValue $v 'knownRansomwareCampaignUse' '') }
    }
    Write-EolKbLog -Message "Catalogue CISA KEV : $($cves.Count) vulnerabilites exploitees connues"
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'nvd' -Key 'kev-catalog' -Payload @{ cves = $cves } `
        -TtlDays $Config.Ttl.Kev -Source 'cisa.gov' | Out-Null
    return $cves
}

function Get-EolKbEpssScores {
    <#
    .SYNOPSIS
        Probabilite d'exploitation sous 30 jours (EPSS), par identifiant CVE.
        Seuls des identifiants publics de vulnerabilites sont transmis.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string[]]$CveIds, [switch]$Offline)
    $root = $Config.Paths.CacheRoot
    $out = @{}
    $todo = @()
    foreach ($id in ($CveIds | Where-Object { $_ -like 'CVE-*' } | Select-Object -Unique)) {
        $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'nvd' -Key "epss|$id" -OverrideTtlDays $Config.Ttl.Epss
        if ($e -and ($e.Fresh -or $Offline)) { $out[$id] = [double](Get-DictValue $e.Payload 'score' 0) }
        elseif (-not $Offline) { $todo += $id }
    }
    if ($todo.Count -eq 0) { return $out }
    for ($i = 0; $i -lt $todo.Count; $i += 100) {
        $batch = @($todo[$i..([Math]::Min($i + 99, $todo.Count - 1))])
        $uri = "$($Config.Sources.EpssApi)?cve=$($batch -join ',')"
        try {
            $raw = Invoke-EolKbRequest -Config $Config -Uri $uri -Purpose 'epss' -ExemptTokens $batch -TolerateNotFound
        } catch {
            Write-EolKbLog -Level DEBUG -Message "EPSS indisponible : $($_.Exception.Message)"
            continue
        }
        foreach ($d in (Get-DictArray -Dict $raw -Key 'data')) {
            $id = [string](Get-DictValue $d 'cve' '')
            if (-not $id) { continue }
            $score = 0.0
            try { $score = [double](Get-DictValue $d 'epss' 0) } catch { }
            $out[$id] = $score
            Set-EolKbCacheEntry -CacheRoot $root -Namespace 'nvd' -Key "epss|$id" -Payload @{ score = $score } `
                -TtlDays $Config.Ttl.Epss -Source 'first.org' | Out-Null
        }
    }
    return $out
}

Export-ModuleMember -Function Get-EolKbKevCatalog, Get-EolKbEpssScores

function Get-EolKbVulnRecord {
    <#
    .SYNOPSIS
        Fiche complete d'une vulnerabilite. Le cache n'est invalide que si
        le champ 'modified' renvoye par querybatch differe : une fiche non
        modifiee n'est jamais retelechargee.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Id, [string]$Modified = '', [switch]$Offline)
    $root = $Config.Paths.CacheRoot
    $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'osv-vuln' -Key $Id -OverrideTtlDays $Config.Ttl.OsvVulnRecord
    if ($e) {
        $cachedMod = [string](Get-DictValue $e.Meta 'modified' '')
        if ($Offline -or -not $Modified -or $cachedMod -eq $Modified) { return $e.Payload }
    }
    if ($Offline) { return $null }
    try {
        $raw = Invoke-EolKbRequest -Config $Config -Uri "$($Config.Sources.OsvVuln)/$Id" -Purpose 'osv-vuln' -TolerateNotFound
    } catch {
        Write-EolKbLog -Level WARN -Message "Fiche OSV $Id inaccessible : $($_.Exception.Message)"
        if ($e) { return $e.Payload }
        return $null
    }
    if ($null -eq $raw) { return $null }
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'osv-vuln' -Key $Id -Payload $raw `
        -TtlDays $Config.Ttl.OsvVulnRecord -Source 'osv.dev' -Meta @{ modified = [string](Get-DictValue $raw 'modified' $Modified) } | Out-Null
    return $raw
}

# ===================================================================
# Cycle de vie observe : versions publiees AVEC leur date
# Source principale : deps.dev (un appel, nom du paquet seul).
# Repli : registre natif (npm, PyPI, Maven, NuGet...).
# C'est ce qui permet de conclure sur un composant que endoflife.date
# ne suit pas : activite de publication, depreciation, retard de version.
# ===================================================================
function Get-EolKbDepsDevPackage {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$System, [Parameter(Mandatory)][string]$Name)
    $uri = "$($Config.Sources.DepsDev)/$System/packages/$([uri]::EscapeDataString($Name))"
    $raw = Invoke-EolKbRequest -Config $Config -Uri $uri -Purpose 'deps.dev' -ExemptTokens @($Name) -TolerateNotFound
    if ($null -eq $raw) { return $null }
    $versions = @(); $latest = ''; $deprecated = $false; $reason = ''; $latestPub = ''
    foreach ($v in (Get-DictArray -Dict $raw -Key 'versions')) {
        $vk = Get-DictValue $v 'versionKey'
        $num = [string](Get-DictValue $vk 'version' '')
        if (-not $num) { continue }
        $pub = [string](Get-DictValue $v 'publishedAt' '')
        $isDef = [bool](Get-DictValue $v 'isDefault' $false)
        $isDep = [bool](Get-DictValue $v 'isDeprecated' $false)
        $versions += @{ v = $num; p = $pub; d = $isDep }
        if ($isDef) {
            $latest = $num; $latestPub = $pub
            if ($isDep) { $deprecated = $true; $reason = [string](Get-DictValue $v 'deprecatedReason' '') }
        }
    }
    if ($versions.Count -eq 0) { return $null }
    return @{ versions = $versions; latest = $latest; latestPublished = $latestPub
              deprecated = $deprecated; reason = $reason; source = 'deps.dev' }
}

function Get-EolKbPackageLifecycle {
    <#
    .SYNOPSIS
        Retourne l'etat de publication reel d'un paquet :
        versions connues, date de publication de chacune (si la source la
        fournit), derniere version, depreciation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [string]$DepsDevSystem, [string]$Registry,
        [string]$Group, [Parameter(Mandatory)][string]$Name, [string]$PackageName,
        [switch]$Offline, [switch]$Vulnerable
    )
    $key = Get-EolKbCoordKey -Ecosystem ("$DepsDevSystem$Registry") -Group $Group -Name $Name
    $root = $Config.Paths.CacheRoot
    $ttl = $Config.Ttl.DepsDev
    if ($Vulnerable) { $ttl = $Config.Ttl.RegistryVulnerable }
    $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'lifecycle' -Key $key -OverrideTtlDays $ttl

    $build = {
        param($payload, $fromCache, $age)
        $vers = @(); $pub = @{}
        foreach ($v in (Get-DictArray -Dict $payload -Key 'versions')) {
            $num = [string](Get-DictValue $v 'v' '')
            if (-not $num) { continue }
            $vers += $num
            $d = [string](Get-DictValue $v 'p' '')
            if ($d) { $pub[$num] = $d }
        }
        return @{
            Found           = [bool](Get-DictValue $payload 'found' $false)
            Versions        = $vers
            PublishedAt     = $pub
            Latest          = [string](Get-DictValue $payload 'latest' '')
            LatestPublished = [string](Get-DictValue $payload 'latestPublished' '')
            Deprecated      = [bool](Get-DictValue $payload 'deprecated' $false)
            DeprecatedReason = [string](Get-DictValue $payload 'reason' '')
            Source          = [string](Get-DictValue $payload 'source' '')
            Url             = [string](Get-DictValue $payload 'url' '')
            Attempted       = $true
            FromCache       = $fromCache
            AgeDays         = $age
        }
    }

    if ($e -and ($e.Fresh -or $Offline)) { return (& $build $e.Payload $true $e.AgeDays) }
    if ($Offline) {
        return @{ Found = $false; Versions = @(); PublishedAt = @{}; Latest = ''; LatestPublished = ''
                  Deprecated = $false; DeprecatedReason = ''; Source = 'hors-ligne'; Url = ''
                  Attempted = $false; FromCache = $false; AgeDays = -1 }
    }

    $pkg = $PackageName
    if (-not $pkg) { $pkg = $Name }
    $payload = $null
    $failed = $false
    if ($DepsDevSystem) {
        try { $payload = Get-EolKbDepsDevPackage -Config $Config -System $DepsDevSystem -Name $pkg }
        catch { $failed = $true; Write-EolKbLog -Level DEBUG -Message "deps.dev indisponible pour '$pkg' : $($_.Exception.Message)" }
    }
    # repli : registre natif (donne les versions, pas toujours les dates)
    if ($null -eq $payload -and $Registry) {
        $ri = Get-EolKbRegistryInfo -Config $Config -Registry $Registry -Group $Group -Name $Name -Vulnerable:$Vulnerable
        if ($ri.Found) {
            $payload = @{ versions = @($ri.Versions | ForEach-Object { @{ v = $_; p = ''; d = $false } })
                          latest = $ri.Latest; latestPublished = ''; deprecated = $ri.Deprecated
                          reason = $ri.DeprecationNote; source = $ri.Source; url = $ri.Url }
        }
    }
    if ($null -eq $payload) {
        $store = @{ found = $false; versions = @(); source = 'aucune-source' }
        Set-EolKbCacheEntry -CacheRoot $root -Namespace 'lifecycle' -Key $key -Payload $store `
            -TtlDays $Config.Ttl.RegistryNegative -Source 'lifecycle' `
            -Meta @{ system = $DepsDevSystem; registry = $Registry; group = $Group; name = $Name; pkg = $pkg } | Out-Null
        $res = & $build $store $false 0
        $res.Attempted = (-not $failed)
        return $res
    }
    $payload['found'] = $true
    if (-not $payload.ContainsKey('url') -or -not $payload['url']) {
        $payload['url'] = "https://deps.dev/$DepsDevSystem/$([uri]::EscapeDataString($pkg))"
    }
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'lifecycle' -Key $key -Payload $payload `
        -TtlDays $ttl -Source ([string]$payload['source']) `
        -Meta @{ system = $DepsDevSystem; registry = $Registry; group = $Group; name = $Name; pkg = $pkg } | Out-Null
    return (& $build $payload $false 0)
}

# ===================================================================
# NVD : repli CVE pour les composants hors ecosysteme OSV
# (runtimes, OS, produits d'editeur). Interroge par produit / CPE,
# jamais par version : le rapprochement de version reste local.
# ===================================================================
function Get-EolKbProductIdentifiers {
    <# Identifiants (purl, cpe) declares par endoflife.date pour un produit. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Slug)
    $e = Get-EolKbCacheEntry -CacheRoot $Config.Paths.CacheRoot -Namespace 'eol-product' -Key $Slug -OverrideTtlDays 3650
    if (-not $e) { return @{ Purl = @(); Cpe = @() } }
    $res = Get-DictValue $e.Payload 'raw'
    $node = Get-DictValue $res 'result'
    if (-not $node) { $node = $res }
    $purls = @(); $cpes = @()
    $ident = Get-DictValue $node 'identifiers'
    foreach ($i in (Get-DictArray -Dict $ident)) {
        if ($i -is [string]) { continue }
        $p = [string](Get-DictValue $i 'purl' '')
        $c = [string](Get-DictValue $i 'cpe' '')
        if (-not $p -and -not $c) {
            $t = [string](Get-DictValue $i 'type' '')
            $v = [string](Get-DictValue $i 'id' (Get-DictValue $i 'identifier' ''))
            if ($t -eq 'purl') { $p = $v } elseif ($t -eq 'cpe') { $c = $v }
        }
        if ($p) { $purls += $p }
        if ($c) { $cpes += $c }
    }
    return @{ Purl = @($purls | Select-Object -Unique); Cpe = @($cpes | Select-Object -Unique) }
}

function ConvertTo-EolKbNvdRecord {
    [CmdletBinding()]
    param($Cve)
    $id = [string](Get-DictValue $Cve 'id' '')
    $desc = ''
    foreach ($d in (Get-DictArray -Dict $Cve -Key 'descriptions')) {
        if ([string](Get-DictValue $d 'lang' '') -eq 'en') { $desc = [string](Get-DictValue $d 'value' ''); break }
    }
    $vector = ''; $score = $null
    $metrics = Get-DictValue $Cve 'metrics'
    foreach ($k in @('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40')) {
        foreach ($m in (Get-DictArray -Dict $metrics -Key $k)) {
            $data = Get-DictValue $m 'cvssData'
            $v = [string](Get-DictValue $data 'vectorString' '')
            if ($v -and -not $vector) {
                $vector = $v
                $calc = Get-EolKbCvss3Score -Vector $v
                if ($null -ne $calc) { $score = $calc }
                elseif ($null -ne (Get-DictValue $data 'baseScore')) { $score = [double](Get-DictValue $data 'baseScore') }
            }
        }
        if ($vector) { break }
    }
    $matches = @()
    foreach ($cfg in (Get-DictArray -Dict $Cve -Key 'configurations')) {
        foreach ($node in (Get-DictArray -Dict $cfg -Key 'nodes')) {
            foreach ($cm in (Get-DictArray -Dict $node -Key 'cpeMatch')) {
                if (-not [bool](Get-DictValue $cm 'vulnerable' $true)) { continue }
                $matches += @{
                    criteria = [string](Get-DictValue $cm 'criteria' '')
                    vsi = [string](Get-DictValue $cm 'versionStartIncluding' '')
                    vse = [string](Get-DictValue $cm 'versionStartExcluding' '')
                    vei = [string](Get-DictValue $cm 'versionEndIncluding' '')
                    vee = [string](Get-DictValue $cm 'versionEndExcluding' '')
                }
            }
        }
    }
    return @{ id = $id; summary = $desc; vector = $vector; score = $score
              published = [string](Get-DictValue $Cve 'published' ''); matches = $matches }
}

function Get-EolKbNvdVulns {
    <#
    .SYNOPSIS
        CVE NVD pour un produit, par correspondance CPE ou mot-cle.
        Aucune version n'est envoyee : les plages de versions renvoyees
        sont evaluees localement.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [string]$CpeMatch, [string]$Keyword, [switch]$Offline)
    $key = "nvd|$CpeMatch|$Keyword".ToLowerInvariant()
    $root = $Config.Paths.CacheRoot
    $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'nvd' -Key $key -OverrideTtlDays $Config.Ttl.NvdIndex
    if ($e -and ($e.Fresh -or $Offline)) { return @(Get-DictArray -Dict $e.Payload -Key 'vulns') }
    if ($Offline) { return @() }

    $uri = ''
    if ($CpeMatch) {
        $uri = "$($Config.Sources.NvdApi)?virtualMatchString=$([uri]::EscapeDataString($CpeMatch))&resultsPerPage=2000"
    } elseif ($Keyword) {
        $uri = "$($Config.Sources.NvdApi)?keywordSearch=$([uri]::EscapeDataString($Keyword))&keywordExactMatch&resultsPerPage=2000"
    } else { return @() }

    $headers = @{}
    if ($Config.Sources.NvdApiKey) { $headers['apiKey'] = [string]$Config.Sources.NvdApiKey }
    # 'cpe:2.3' et le nom public du produit sont des jetons d'identification,
    # pas des versions : ils sont declares exempts pour la garde anti-fuite.
    # Jetons d'identification, pas des versions : le numero d'API NVD present
    # dans le chemin (/rest/json/cves/2.0) et les prefixes CPE.
    $exempt = @(([uri]$Config.Sources.NvdApi).AbsolutePath, 'cpe:2.3', 'cpe:/a', 'cpe:/o', $CpeMatch, $Keyword)
    try {
        $raw = Invoke-EolKbRequest -Config $Config -Uri $uri -Purpose 'nvd' -Headers $headers -ExemptTokens $exempt -TolerateNotFound
    } catch {
        Write-EolKbLog -Level WARN -Message "NVD indisponible ($CpeMatch$Keyword) : $($_.Exception.Message)"
        if ($e) { return @(Get-DictArray -Dict $e.Payload -Key 'vulns') }
        return @()
    }
    if ($null -eq $raw) { $raw = @{} }
    $vulns = @()
    foreach ($item in (Get-DictArray -Dict $raw -Key 'vulnerabilities')) {
        $cve = Get-DictValue $item 'cve'
        if ($cve) { $vulns += (ConvertTo-EolKbNvdRecord -Cve $cve) }
    }
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'nvd' -Key $key -Payload @{ vulns = $vulns } `
        -TtlDays $Config.Ttl.NvdIndex -Source 'nvd.nist.gov' | Out-Null
    return $vulns
}

function Get-EolKbVulnById {
    <#
    .SYNOPSIS
        Fiche d'une vulnerabilite designee par son identifiant (CVE-..., GHSA-...).
        OSV en premier (couvre les ecosystemes de paquets), repli NVD pour les
        CVE que OSV ne connait pas (produits, runtimes, OS).
    .OUTPUTS
        @{ Found; Kind = 'osv'|'nvd'; Record; Source }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Id, [switch]$Offline)

    $id = $Id.Trim().ToUpperInvariant()
    $rec = Get-EolKbVulnRecord -Config $Config -Id $id -Offline:$Offline
    if ($rec) { return @{ Found = $true; Kind = 'osv'; Record = $rec; Source = 'osv.dev' } }

    if ($id -notlike 'CVE-*') { return @{ Found = $false; Kind = ''; Record = $null; Source = '' } }

    $key = "nvd-id|$id".ToLowerInvariant()
    $root = $Config.Paths.CacheRoot
    $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'nvd' -Key $key -OverrideTtlDays $Config.Ttl.NvdIndex
    if ($e -and ($e.Fresh -or $Offline)) {
        $p = Get-DictValue $e.Payload 'record'
        if ($p) { return @{ Found = $true; Kind = 'nvd'; Record = $p; Source = 'nvd.nist.gov' } }
        return @{ Found = $false; Kind = ''; Record = $null; Source = 'nvd.nist.gov' }
    }
    if ($Offline) { return @{ Found = $false; Kind = ''; Record = $null; Source = 'hors-ligne' } }

    $headers = @{}
    if ($Config.Sources.NvdApiKey) { $headers['apiKey'] = [string]$Config.Sources.NvdApiKey }
    $exempt = @(([uri]$Config.Sources.NvdApi).AbsolutePath, $id)
    try {
        $raw = Invoke-EolKbRequest -Config $Config -Uri "$($Config.Sources.NvdApi)?cveId=$id" -Purpose 'nvd-cve' `
            -Headers $headers -ExemptTokens $exempt -TolerateNotFound
    } catch {
        Write-EolKbLog -Level WARN -Message "NVD inaccessible pour $id : $($_.Exception.Message)"
        return @{ Found = $false; Kind = ''; Record = $null; Source = 'nvd.nist.gov' }
    }
    $record = $null
    foreach ($item in (Get-DictArray -Dict $raw -Key 'vulnerabilities')) {
        $cve = Get-DictValue $item 'cve'
        if ($cve) { $record = ConvertTo-EolKbNvdRecord -Cve $cve; break }
    }
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'nvd' -Key $key -Payload @{ record = $record } `
        -TtlDays $Config.Ttl.NvdIndex -Source 'nvd.nist.gov' | Out-Null
    if ($record) { return @{ Found = $true; Kind = 'nvd'; Record = $record; Source = 'nvd.nist.gov' } }
    return @{ Found = $false; Kind = ''; Record = $null; Source = 'nvd.nist.gov' }
}

Export-ModuleMember -Function Get-EolKbVulnById

Export-ModuleMember -Function Get-EolKbIdentifierIndex, Get-EolKbPurlCandidates, Get-EolKbNameVariants,
    Get-EolKbDepsDevPackage, Get-EolKbPackageLifecycle, Get-EolKbProductIdentifiers, Get-EolKbNvdVulns,
    ConvertTo-EolKbNvdRecord

Export-ModuleMember -Function Resolve-EolKbPurl, Get-EolKbEcosystem, Get-EolKbCoordKey, Get-EolKbProductIndex,
    ConvertTo-EolKbCycles, Get-EolKbTtlForCycles, Get-EolKbProductCycles, Get-EolKbProductMap,
    Resolve-EolKbProduct, Get-EolKbCachedProductResolution, Get-EolKbRegistryInfo,
    Get-EolKbVulnIndex, Get-EolKbVulnRecord, Get-EolKbVulnIndexPrecise, Get-EolKbVulnQueryMode
