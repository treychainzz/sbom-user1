<#
.SYNOPSIS
    Comparaison de versions, evaluation locale des plages OSV, rattachement
    d'une version a un cycle de support, calcul du score CVSS v3.x.
    Tout est LOCAL : aucune version n'est transmise a l'exterieur.
#>

function ConvertTo-EolKbVersion {
    <#
    .SYNOPSIS
        Normalise une version en objet comparable.
        Gere : semver, Maven (1.2.3.RELEASE, 1.2-SNAPSHOT), Java (1.8.0_452),
        dates (2023.10.1), prefixes v/V, epoch Debian (1:2.3-4).
    #>
    [CmdletBinding()]
    param([AllowNull()][string]$Version)

    $result = [pscustomobject]@{
        Original   = $Version
        Numeric    = @()
        Prerelease = ''
        Qualifier  = ''
        IsStable   = $true
        Parsable   = $false
    }
    if ([string]::IsNullOrWhiteSpace($Version)) { return $result }

    $v = $Version.Trim()
    $v = $v -replace '^[vV](?=\d)', ''
    if ($v -match '^\d+:(.+)$') { $v = $Matches[1] }          # epoch deb/rpm
    $v = $v -replace '\+.*$', ''                              # metadonnees build
    $v = $v -replace '_', '.'                                 # 1.8.0_452 -> 1.8.0.452

    $pre = ''
    if ($v -match '^([0-9][0-9\.]*)[-\.]?([A-Za-z].*)$') {
        $core = $Matches[1]; $pre = $Matches[2]
    } elseif ($v -match '^([0-9][0-9\.]*)$') {
        $core = $Matches[1]
    } else {
        $result.Prerelease = $v
        $result.IsStable = $false
        return $result
    }

    $nums = @()
    foreach ($p in ($core.Trim('.') -split '\.')) {
        if ($p -match '^\d+$') { $nums += [int64]$p }
    }
    $result.Numeric = $nums
    $result.Prerelease = $pre
    $result.Qualifier = $pre
    $result.Parsable = ($nums.Count -gt 0)
    # RELEASE / FINAL / GA sont des marqueurs de stabilite, pas des preversions
    $result.IsStable = ($pre -eq '' -or $pre -imatch '^(release|final|ga|sp\d*|jre\d*)$')
    return $result
}

function Compare-EolKbVersion {
    <# -1 si A < B, 0 si egal, 1 si A > B. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()]$A, [Parameter(Mandatory)][AllowEmptyString()]$B)

    $va = if ($A -is [string] -or $null -eq $A) { ConvertTo-EolKbVersion -Version ([string]$A) } else { $A }
    $vb = if ($B -is [string] -or $null -eq $B) { ConvertTo-EolKbVersion -Version ([string]$B) } else { $B }

    $max = [Math]::Max($va.Numeric.Count, $vb.Numeric.Count)
    for ($i = 0; $i -lt $max; $i++) {
        $x = if ($i -lt $va.Numeric.Count) { $va.Numeric[$i] } else { 0 }
        $y = if ($i -lt $vb.Numeric.Count) { $vb.Numeric[$i] } else { 0 }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    # Partie numerique identique : une version stable est superieure a une preversion
    if ($va.IsStable -and -not $vb.IsStable) { return 1 }
    if (-not $va.IsStable -and $vb.IsStable) { return -1 }
    if ($va.IsStable -and $vb.IsStable) { return 0 }   # 5.3.31.RELEASE == 5.3.31
    if ($va.Prerelease -eq $vb.Prerelease) { return 0 }
    return [string]::Compare($va.Prerelease, $vb.Prerelease, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-EolKbVersionAffected {
    <#
    .SYNOPSIS
        Evalue localement si $Version est concernee par un bloc 'affected' OSV.
    .OUTPUTS
        Hashtable @{ Affected = $true/$false; Confidence = 'exact'|'range'|'unknown'; Fixed = @() }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)]$Affected      # element du tableau affected[] (dictionnaire)
    )
    $fixed = @()
    $out = @{ Affected = $false; Confidence = 'unknown'; Fixed = @() }
    if ([string]::IsNullOrWhiteSpace($Version)) { return $out }

    # 1) liste explicite de versions -> comparaison exacte
    $versions = Get-DictArray -Dict $Affected -Key 'versions'
    if ($versions.Count -gt 0) {
        foreach ($v in $versions) {
            if ([string]$v -eq $Version) { $out.Affected = $true; $out.Confidence = 'exact'; break }
        }
        if ($out.Affected) {
            # on complete les versions correctives si presentes
            foreach ($r in (Get-DictArray -Dict $Affected -Key 'ranges')) {
                foreach ($ev in (Get-DictArray -Dict $r -Key 'events')) {
                    $f = Get-DictValue $ev 'fixed'
                    if ($f) { $fixed += [string]$f }
                }
            }
            $out.Fixed = @($fixed | Sort-Object -Unique)
            return $out
        }
        # Version absente de la liste explicite : on continue avec les plages
    }

    # 2) plages introduced/fixed/last_affected
    # Une plage OSV est une suite d'intervalles : [introduced, fixed[ ou
    # [introduced, last_affected]. La version est concernee si elle tombe
    # dans AU MOINS un intervalle (les intervalles sont donc reconstruits
    # avant evaluation, et non evalues au fil des evenements).
    foreach ($r in (Get-DictArray -Dict $Affected -Key 'ranges')) {
        $type = [string](Get-DictValue $r 'type' 'ECOSYSTEM')
        if ($type -eq 'GIT') { continue }        # non exploitable sur une version de paquet
        $intervals = New-Object System.Collections.ArrayList
        $cur = $null
        foreach ($ev in (Get-DictArray -Dict $r -Key 'events')) {
            $i = Get-DictValue $ev 'introduced'
            $f = Get-DictValue $ev 'fixed'
            $la = Get-DictValue $ev 'last_affected'
            if ($i) {
                if ($cur) { [void]$intervals.Add($cur) }
                $cur = @{ From = [string]$i; To = $null; Inclusive = $false }
            } elseif ($f) {
                $fixed += [string]$f
                if ($cur) { $cur.To = [string]$f; $cur.Inclusive = $false; [void]$intervals.Add($cur); $cur = $null }
            } elseif ($la) {
                if ($cur) { $cur.To = [string]$la; $cur.Inclusive = $true; [void]$intervals.Add($cur); $cur = $null }
            }
        }
        if ($cur) { [void]$intervals.Add($cur) }

        foreach ($iv in $intervals) {
            $afterStart = ($iv.From -eq '0' -or (Compare-EolKbVersion -A $Version -B $iv.From) -ge 0)
            if (-not $afterStart) { continue }
            $beforeEnd = $true
            if ($iv.To) {
                $cmp = Compare-EolKbVersion -A $Version -B $iv.To
                if ($iv.Inclusive) { $beforeEnd = ($cmp -le 0) } else { $beforeEnd = ($cmp -lt 0) }
            }
            if ($beforeEnd) { $out.Affected = $true; $out.Confidence = 'range'; break }
        }
    }
    $out.Fixed = @($fixed | Sort-Object -Unique)
    return $out
}

function Get-EolKbSafeVersion {
    <#
    .SYNOPSIS
        Plus petite version >= version courante, stable, presente au registre
        et non concernee par les vulnerabilites fournies. Retourne $null si
        aucune version connue ne convient (jamais de version inventee).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CurrentVersion,
        [string[]]$AvailableVersions = @(),
        [array]$AffectedBlocks = @()
    )
    if ($AvailableVersions.Count -eq 0) { return $null }
    $cands = @($AvailableVersions |
        Where-Object { (ConvertTo-EolKbVersion -Version $_).IsStable } |
        Where-Object { (Compare-EolKbVersion -A $_ -B $CurrentVersion) -gt 0 })
    if ($cands.Count -eq 0) { return $null }
    $sorted = Sort-EolKbVersionList -Versions $cands
    foreach ($c in $sorted) {
        $bad = $false
        foreach ($a in $AffectedBlocks) {
            $r = Test-EolKbVersionAffected -Version $c -Affected $a
            if ($r.Affected) { $bad = $true; break }
        }
        if (-not $bad) { return $c }
    }
    return $null
}

function Sort-EolKbVersionList {
    [CmdletBinding()]
    param([string[]]$Versions, [switch]$Descending)
    $arr = @($Versions)
    for ($i = 1; $i -lt $arr.Count; $i++) {
        for ($j = $i; $j -gt 0 -and (Compare-EolKbVersion -A $arr[$j] -B $arr[$j - 1]) -lt 0; $j--) {
            $tmp = $arr[$j]; $arr[$j] = $arr[$j - 1]; $arr[$j - 1] = $tmp
        }
    }
    if ($Descending) { [array]::Reverse($arr) }
    return $arr
}

function Get-EolKbCycleMatch {
    <#
    .SYNOPSIS
        Rattache une version au cycle de support le plus specifique.
        Ex : 17.0.9 -> cycle '17' ; 3.11.2 -> '3.11' ; 1.8.0.452 -> '1.8'.
        Aucun rattachement approximatif : le prefixe doit correspondre exactement.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][array]$Cycles)

    $v = ConvertTo-EolKbVersion -Version $Version
    if (-not $v.Parsable) { return $null }
    $best = $null; $bestLen = -1
    foreach ($c in $Cycles) {
        $cn = [string]$c.Cycle
        if ([string]::IsNullOrWhiteSpace($cn)) { continue }
        $cv = ConvertTo-EolKbVersion -Version ($cn -replace '\.x$', '' -replace '-lts$', '')
        if (-not $cv.Parsable) { continue }
        if ($cv.Numeric.Count -gt $v.Numeric.Count) { continue }
        $ok = $true
        for ($i = 0; $i -lt $cv.Numeric.Count; $i++) {
            if ($cv.Numeric[$i] -ne $v.Numeric[$i]) { $ok = $false; break }
        }
        if ($ok -and $cv.Numeric.Count -gt $bestLen) { $best = $c; $bestLen = $cv.Numeric.Count }
    }
    return $best
}

# ===================================================================
# CVSS v3.0 / v3.1 : calcul du score de base a partir du vecteur.
# Aucune valeur n'est inventee : si le vecteur est absent ou en v4/v2,
# on remonte le vecteur brut et le libelle fourni par la source.
# ===================================================================
function Get-EolKbCvss3Score {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Vector)

    if ($Vector -notmatch '^CVSS:3\.[01]/') { return $null }
    $m = @{}
    foreach ($part in ($Vector -split '/')) {
        if ($part -match '^([A-Z]+):([A-Z]+)$') { $m[$Matches[1]] = $Matches[2] }
    }
    $wAV = @{ N = 0.85; A = 0.62; L = 0.55; P = 0.2 }
    $wAC = @{ L = 0.77; H = 0.44 }
    $wUI = @{ N = 0.85; R = 0.62 }
    $wCIA = @{ H = 0.56; L = 0.22; N = 0.0 }
    $wPRu = @{ N = 0.85; L = 0.62; H = 0.27 }
    $wPRc = @{ N = 0.85; L = 0.68; H = 0.5 }

    foreach ($k in @('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A')) {
        if (-not $m.ContainsKey($k)) { return $null }
    }
    foreach ($k in @('C', 'I', 'A')) {
        if (-not $wCIA.ContainsKey($m[$k])) { return $null }
    }
    if ($m['S'] -notin @('U', 'C')) { return $null }
    $scopeChanged = ($m['S'] -eq 'C')
    $pr = if ($scopeChanged) { $wPRc[$m['PR']] } else { $wPRu[$m['PR']] }
    if ($null -eq $wAV[$m['AV']] -or $null -eq $wAC[$m['AC']] -or $null -eq $pr -or $null -eq $wUI[$m['UI']]) { return $null }

    $iss = 1 - ((1 - $wCIA[$m['C']]) * (1 - $wCIA[$m['I']]) * (1 - $wCIA[$m['A']]))
    if ($scopeChanged) {
        $impact = 7.52 * ($iss - 0.029) - 3.25 * [Math]::Pow($iss - 0.02, 15)
    } else {
        $impact = 6.42 * $iss
    }
    if ($impact -le 0) { return 0.0 }
    $expl = 8.22 * $wAV[$m['AV']] * $wAC[$m['AC']] * $pr * $wUI[$m['UI']]
    $base = if ($scopeChanged) { 1.08 * ($impact + $expl) } else { $impact + $expl }
    if ($base -gt 10) { $base = 10 }
    # roundup officiel CVSS v3.1 (arrondi superieur au dixieme)
    $i = [int][Math]::Round($base * 100000, 0)
    if (($i % 10000) -eq 0) { $score = $i / 100000.0 }
    else { $score = ([Math]::Floor($i / 10000) + 1) / 10.0 }
    return [Math]::Round($score, 1)
}

function Get-EolKbSeverityLabel {
    [CmdletBinding()]
    param([AllowNull()]$Score)
    if ($null -eq $Score) { return 'INCONNUE' }
    $s = [double]$Score
    if ($s -ge 9.0) { return 'CRITIQUE' }
    if ($s -ge 7.0) { return 'ELEVEE' }
    if ($s -ge 4.0) { return 'MOYENNE' }
    if ($s -gt 0.0) { return 'FAIBLE' }
    return 'AUCUNE'
}

Export-ModuleMember -Function ConvertTo-EolKbVersion, Compare-EolKbVersion, Test-EolKbVersionAffected,
    Get-EolKbSafeVersion, Sort-EolKbVersionList, Get-EolKbCycleMatch, Get-EolKbCvss3Score, Get-EolKbSeverityLabel
