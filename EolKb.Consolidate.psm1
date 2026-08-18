<#
.SYNOPSIS
    Reduction du bruit sur les gros SBOM : selection des constats
    materiels (obsolescence averee ou CVE elevee/critique), puis
    regroupement sous les COMPOSANTS LEVIERS, c'est-a-dire les
    dependances de premier niveau qui commandent la montee de version.

    L'identification des leviers repose sur une analyse de dominance
    (algorithme iteratif de Cooper-Harvey-Kennedy) du graphe
    'dependencies' du SBOM : le levier d'un composant transitif est
    son ancetre dominant situe directement sous l'application.

    Prudence assumee : un levier CONDITIONNE la mise a niveau des
    composants qu'il domine ; il ne prouve pas leur correction. La
    verification demande de comparer avec le SBOM de la version cible.
#>

function Set-EolKbActionability {
    <#
    .SYNOPSIS
        Tri du bruit sur un SBOM d'entreprise. Deux niveaux de signal :

        SIGNAUX FORTS (un seul suffit) - ce sont des faits publies :
          - vulnerabilite EXPLOITEE en conditions reelles (catalogue CISA KEV),
            quelle que soit sa note ;
          - vulnerabilite de score >= seuil (7.0 par defaut) ;
          - fin de support publiee par l'editeur (eol, eol_soon) ;
          - paquet deprecie par l'editeur ou depot archive.

        SIGNAUX FAIBLES (il en faut au moins deux) - ce sont des indices,
        pas des verdicts. Sur un SBOM Maven, "aucune publication depuis
        deux ans" ou "une majeure de retard" decrivent le plus souvent une
        bibliotheque stable et terminee : les remonter une par une noierait
        le rapport et ferait manquer l'essentiel.

        PORTEE : un composant de test ou 'provided' n'est pas embarque a
        l'execution ; il n'entre jamais dans le plan d'action et est
        comptabilise a part.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Finding)

    $strongReasons = @()
    $weakReasons = @()
    $minCvss = [double]$Config.Thresholds.ActionableCvss
    $strongStatuses = @($Config.Thresholds.StrongSignalStatuses)
    $weakStatuses = @($Config.Thresholds.WeakSignalStatuses)

    # --- signaux forts ------------------------------------------------
    if ($Finding.KevCount -gt 0) {
        $strongReasons += "$($Finding.KevCount) vulnerabilite(s) exploitee(s) en conditions reelles (CISA KEV)"
    }
    if ($null -ne $Finding.MaxCvss -and [double]$Finding.MaxCvss -ge $minCvss) {
        $n = @($Finding.Vulns | Where-Object { $null -ne $_.Cvss -and [double]$_.Cvss -ge $minCvss }).Count
        $strongReasons += "$n CVE de score >= $minCvss (max $($Finding.MaxCvss))"
    }
    if ($strongStatuses -contains $Finding.SupportStatus) {
        $strongReasons += (Get-EolKbStatusLabel -Status $Finding.SupportStatus)
    }

    # --- signaux faibles ----------------------------------------------
    if ($weakStatuses -contains $Finding.SupportStatus) {
        $weakReasons += (Get-EolKbStatusLabel -Status $Finding.SupportStatus)
    }
    if ($null -ne $Finding.MaxCvss -and [double]$Finding.MaxCvss -lt $minCvss -and $Finding.VulnCount -gt 0) {
        $weakReasons += "$($Finding.VulnCount) CVE de score inferieur au seuil (max $($Finding.MaxCvss))"
    }
    if ($null -ne $Finding.MajorBehind -and [int]$Finding.MajorBehind -ge 2) {
        $weakReasons += "$($Finding.MajorBehind) versions majeures de retard"
    }
    $weakReasons = @($weakReasons | Select-Object -Unique)

    # --- decision -----------------------------------------------------
    $required = $false
    $reasons = @()
    if ($strongReasons.Count -gt 0) {
        $required = $true
        $reasons = @($strongReasons) + @($weakReasons)
    } elseif ($weakReasons.Count -ge [int]$Config.Thresholds.WeakSignalsRequired) {
        $required = $true
        $reasons = @("faisceau d'indices : " + ($weakReasons -join ', '))
    } else {
        $reasons = $weakReasons
    }

    # la portee prime sur tout : hors production, pas de plan d'action
    if ($required -and -not $Finding.InProduction) {
        $required = $false
        $reasons = @($Finding.ScopeNote) + $reasons
    }

    $Finding | Add-Member -NotePropertyName ActionRequired -NotePropertyValue ([bool]$required) -Force
    $Finding | Add-Member -NotePropertyName ActionReasons -NotePropertyValue @($reasons) -Force
    $Finding | Add-Member -NotePropertyName SignalStrength -NotePropertyValue $(if ($strongReasons.Count -gt 0) { 'fort' } elseif ($weakReasons.Count -gt 0) { 'faible' } else { 'aucun' }) -Force
    $Finding | Add-Member -NotePropertyName LeverRef -NotePropertyValue '' -Force
    $Finding | Add-Member -NotePropertyName LeverName -NotePropertyValue '' -Force
}

function Get-EolKbFamilyKey {
    <# Famille de coordonnees : groupId Maven, portee npm, vendeur composer. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding)
    $g = [string]$Finding.Group
    if ($g) { return ("$($Finding.PurlType):$g").ToLowerInvariant() }
    $n = [string]$Finding.Name
    if ($n -match '^@([^/]+)/') { return ("$($Finding.PurlType):@$($Matches[1])").ToLowerInvariant() }
    return ''
}

function Get-EolKbDominators {
    <#
    .SYNOPSIS
        Arbre de dominance du graphe de dependances (Cooper-Harvey-Kennedy).
        Retourne @{ Idom = ref -> ref dominant immediat; Rpo = ref -> rang }.
        Choix de cet algorithme : correct sur les graphes cycliques, simple
        a implementer et a auditer, performances suffisantes a cette echelle.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Graph)

    $idom = @{}
    if (-not $Graph.GraphPresent -or -not $Graph.Root) { return @{ Idom = $idom; Rpo = @{} } }
    $adj = $Graph.Adjacency
    $root = [string]$Graph.Root

    # --- parcours en profondeur iteratif -> ordre postfixe inverse ----
    $post = New-Object System.Collections.ArrayList
    $seen = @{}
    $stack = New-Object System.Collections.Stack
    $stack.Push(@{ Node = $root; Index = 0 })
    $seen[$root] = $true
    while ($stack.Count -gt 0) {
        $frame = $stack.Peek()
        $children = @()
        if ($adj.ContainsKey($frame.Node)) { $children = @($adj[$frame.Node]) }
        if ($frame.Index -lt $children.Count) {
            $child = [string]$children[$frame.Index]
            $frame.Index++
            if ($child -and -not $seen.ContainsKey($child)) {
                $seen[$child] = $true
                $stack.Push(@{ Node = $child; Index = 0 })
            }
        } else {
            [void]$post.Add($frame.Node)
            [void]$stack.Pop()
        }
    }
    $order = @($post)
    [array]::Reverse($order)          # ordre postfixe inverse
    $rpo = @{}
    for ($i = 0; $i -lt $order.Count; $i++) { $rpo[$order[$i]] = $i }

    # --- iteration jusqu'a stabilisation ------------------------------
    $idom[$root] = $root
    $preds = $Graph.Parents
    $changed = $true
    $guard = 0
    while ($changed -and $guard -lt 50) {
        $changed = $false
        $guard++
        foreach ($n in $order) {
            if ($n -eq $root) { continue }
            $new = $null
            $plist = @()
            if ($preds.ContainsKey($n)) { $plist = @($preds[$n]) }
            foreach ($p in $plist) {
                $p = [string]$p
                if (-not $idom.ContainsKey($p)) { continue }
                if ($null -eq $new) { $new = $p; continue }
                # intersection des chaines de dominance
                $a = $p; $b = $new
                $safety = 0
                while ($a -ne $b -and $safety -lt 1000) {
                    $safety++
                    while ($rpo.ContainsKey($a) -and $rpo.ContainsKey($b) -and $rpo[$a] -gt $rpo[$b]) {
                        if (-not $idom.ContainsKey($a) -or $idom[$a] -eq $a) { break }
                        $a = $idom[$a]
                    }
                    while ($rpo.ContainsKey($a) -and $rpo.ContainsKey($b) -and $rpo[$b] -gt $rpo[$a]) {
                        if (-not $idom.ContainsKey($b) -or $idom[$b] -eq $b) { break }
                        $b = $idom[$b]
                    }
                    if ($rpo[$a] -eq $rpo[$b]) { break }
                }
                $new = $a
            }
            if ($null -ne $new -and (-not $idom.ContainsKey($n) -or $idom[$n] -ne $new)) {
                $idom[$n] = $new
                $changed = $true
            }
        }
    }
    return @{ Idom = $idom; Rpo = $rpo }
}

function Get-EolKbLeverRef {
    <# Ancetre dominant situe directement sous l'application. #>
    [CmdletBinding()]
    param([string]$Ref, [hashtable]$Idom, [string]$Root)
    if (-not $Ref -or -not $Idom.ContainsKey($Ref)) { return '' }
    $cur = $Ref
    $guard = 0
    while ($guard -lt 200) {
        $guard++
        if (-not $Idom.ContainsKey($cur)) { return '' }
        $parent = [string]$Idom[$cur]
        if ($parent -eq $Root -or $parent -eq $cur) { return $cur }
        $cur = $parent
    }
    return ''
}

function Get-EolKbLevers {
    <#
    .SYNOPSIS
        Regroupe les constats materiels sous les composants leviers.
        Sans graphe de dependances, aucun regroupement n'est affirme :
        chaque constat materiel constitue son propre levier.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Findings, [Parameter(Mandatory)]$Graph)

    $actionable = @($Findings | Where-Object { $_.ActionRequired })
    if ($actionable.Count -eq 0) { return @() }

    $refIndex = @{}
    foreach ($f in $Findings) {
        foreach ($r in $f.BomRefs) { if ($r -and -not $refIndex.ContainsKey($r)) { $refIndex[$r] = $f } }
    }
    $dom = Get-EolKbDominators -Graph $Graph
    $root = ''
    if ($Graph.GraphPresent) { $root = [string]$Graph.Root }

    $groups = @{}
    foreach ($f in $actionable) {
        $leverFinding = $f
        $leverRef = ''
        if ($Graph.GraphPresent) {
            $best = $null; $bestDepth = 99999
            foreach ($r in $f.BomRefs) {
                $lr = Get-EolKbLeverRef -Ref ([string]$r) -Idom $dom.Idom -Root $root
                if (-not $lr -or -not $refIndex.ContainsKey($lr)) { continue }
                $d = 1
                if ($Graph.Depth.ContainsKey($lr)) { $d = [int]$Graph.Depth[$lr] }
                if ($d -lt $bestDepth) { $bestDepth = $d; $best = $lr }
            }
            if ($best) { $leverRef = $best; $leverFinding = $refIndex[$best] }
        }
        if (-not $leverRef -and -not $Graph.GraphPresent) {
            # Sans graphe de dependances, aucun lien parent/enfant n'est
            # affirme. On regroupe alors par FAMILLE de coordonnees
            # (groupId Maven, portee npm) : ce n'est pas une affirmation
            # de dependance, mais cela evite de presenter des centaines de
            # lignes issues du meme ensemble a mettre a niveau ensemble.
            $family = Get-EolKbFamilyKey -Finding $f
            if ($family) {
                $leverRef = "famille:$family"
                $leverFinding = $f
            }
        }
        if (-not $leverRef) { $leverRef = "self:$($f.Key)" }
        $f.LeverRef = $leverRef
        $f.LeverName = $leverFinding.Name

        if (-not $groups.ContainsKey($leverRef)) {
            $groups[$leverRef] = [pscustomobject]@{
                Ref            = $leverRef
                Finding        = $leverFinding
                Name           = $leverFinding.Name
                Group          = $leverFinding.Group
                Version        = $leverFinding.Version
                PurlType       = $leverFinding.PurlType
                IsDirect       = $leverFinding.IsDirect
                Consolidated   = ($leverFinding.Key -ne $f.Key)
                LeverKind      = 'dependance'
                Covered        = @()
                CoveredCount   = 0
                DirectHit      = $false
                HighCveCount   = 0
                MaxCvss        = $null
                WorstPriority  = 9
                Statuses       = @()
                Recommendations = $leverFinding.Recommendations
                Reasons        = @()
                Vendor         = $null
                Verification   = $null
                Projection     = $null
            }
        }
        $g = $groups[$leverRef]
        # famille : le representant est le composant au signal le plus fort
        if ($leverRef -like 'famille:*') {
            if ($f.Priority -lt $g.Finding.Priority) {
                $g.Finding = $f; $g.Name = $f.Name; $g.Group = $f.Group; $g.Version = $f.Version
                $g.Recommendations = $f.Recommendations
            }
            $g.LeverKind = 'famille'
        }
        $g.Covered += $f
        if ($f.Key -eq $leverFinding.Key) { $g.DirectHit = $true } else { $g.Consolidated = $true }
        if ($null -ne $f.MaxCvss) {
            $high = @($f.Vulns | Where-Object { $null -ne $_.Cvss -and [double]$_.Cvss -ge $Config.Thresholds.ActionableCvss })
            $g.HighCveCount += $high.Count
            if ($null -eq $g.MaxCvss -or [double]$f.MaxCvss -gt [double]$g.MaxCvss) { $g.MaxCvss = $f.MaxCvss }
        }
        if ($f.Priority -lt $g.WorstPriority) { $g.WorstPriority = $f.Priority }
        if ($g.Statuses -notcontains $f.SupportStatus) { $g.Statuses += $f.SupportStatus }
    }

    foreach ($g in $groups.Values) {
        $g.CoveredCount = @($g.Covered).Count
        $reasons = @()
        $kev = 0
        foreach ($cf in $g.Covered) { $kev += [int]$cf.KevCount }
        if ($kev -gt 0) { $reasons += "$kev CVE EXPLOITEE(S) (CISA KEV)" }
        if ($g.HighCveCount -gt 0) { $reasons += "$($g.HighCveCount) CVE >= $($Config.Thresholds.ActionableCvss)" }
        $obs = @($g.Covered | Where-Object { $_.SupportStatus -in @($Config.Thresholds.StrongSignalStatuses) })
        if ($obs.Count -gt 0) { $reasons += "$($obs.Count) en obsolescence averee" }
        $faisceau = @($g.Covered | Where-Object { $_.SignalStrength -eq 'faible' })
        if ($obs.Count -eq 0 -and $g.HighCveCount -eq 0 -and $faisceau.Count -gt 0) {
            $reasons += "$($faisceau.Count) au faisceau d'indices (retard cumule)"
        }
        $g.Reasons = $reasons
    }

    $levers = @($groups.Values | Sort-Object `
        @{ Expression = { $_.WorstPriority } }, `
        @{ Expression = { $_.HighCveCount }; Descending = $true }, `
        @{ Expression = { $_.CoveredCount }; Descending = $true }, `
        @{ Expression = { $_.Name } })
    return $levers
}

function Confirm-EolKbTarget {
    <#
    .SYNOPSIS
        DOUBLE CONTROLE avant publication du rapport : la version cible
        proposee est reverifiee aupres d'une source INDEPENDANTE de celle
        qui l'a produite (deps.dev <-> registre natif de l'ecosysteme).
    .OUTPUTS
        @{ Status; Detail; Sources }
        Status : 'confirme'   la cible existe dans au moins deux sources
                 'source-unique'  une seule source disponible, cible non recoupee
                 'divergence' les sources ne concordent pas -> la cible est
                              signalee comme a confirmer, jamais presentee
                              comme certaine
                 'non-verifiable' hors ligne ou aucune seconde source
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Finding, [switch]$Offline)

    $target = ''
    foreach ($r in $Finding.Recommendations) { if ($r.Version) { $target = [string]$r.Version; break } }
    $sources = @()
    if ($Finding.LifecycleSource) { $sources += $Finding.LifecycleSource }
    if ($Finding.VerdictSource -and $sources -notcontains $Finding.VerdictSource) { $sources += $Finding.VerdictSource }

    if (-not $target) { return @{ Status = 'sans-objet'; Detail = 'Aucune version cible a verifier.'; Sources = $sources } }
    if (-not $Finding.Registry) { return @{ Status = 'non-verifiable'; Detail = 'Pas de registre de reference pour ce type de composant.'; Sources = $sources } }

    # source de controle : le registre natif si la cible vient de deps.dev
    # ou d'endoflife.date, deps.dev dans le cas inverse.
    $control = $null
    if ($Finding.LifecycleSource -eq 'deps.dev' -or $Finding.VerdictSource -eq 'endoflife.date') {
        $control = Get-EolKbRegistryInfo -Config $Config -Registry $Finding.Registry -Group $Finding.Group `
            -Name $Finding.Name -Offline:$Offline
        if ($control.Found) { $sources += "registre $($Finding.Registry)" }
    } elseif ($Finding.DepsDevSystem) {
        $dd = $null
        if (-not $Offline) {
            try { $dd = Get-EolKbDepsDevPackage -Config $Config -System $Finding.DepsDevSystem -Name (Get-EolKbPackageName -Finding $Finding) } catch { }
        }
        if ($dd) {
            $control = @{ Found = $true; Versions = @($dd.versions | ForEach-Object { [string]$_.v }); Latest = [string]$dd.latest }
            $sources += 'deps.dev'
        }
    }
    if ($null -eq $control -or -not $control.Found) {
        return @{ Status = 'non-verifiable'; Detail = 'Seconde source indisponible (hors ligne, proxy ou paquet absent).'; Sources = $sources }
    }

    $present = @($control.Versions | Where-Object { $_ -eq $target })
    if ($present.Count -gt 0) {
        return @{ Status = 'confirme'; Detail = "Version $target publiee et confirmee par $($sources.Count) sources independantes."; Sources = $sources }
    }
    # tolerance : la cible peut etre un cycle (ex. '3.2') et non un numero exact
    $sameCycle = @($control.Versions | Where-Object { $_ -like "$target*" })
    if ($sameCycle.Count -gt 0) {
        $latestOfCycle = (Sort-EolKbVersionList -Versions $sameCycle -Descending)[0]
        return @{ Status = 'confirme'; Detail = "Cycle $target confirme au registre (dernier correctif publie : $latestOfCycle)."; Sources = $sources }
    }
    return @{ Status = 'divergence'
              Detail = "Version $target annoncee par $($Finding.VerdictSource) mais absente du registre $($Finding.Registry) : cible a confirmer avant planification."
              Sources = $sources }
}

function Get-EolKbLeverProjection {
    <#
    .SYNOPSIS
        Projection de planification : echeance a laquelle le levier doit
        etre traite, et duree de support restante de la cible proposee.
        Une cible n'est jugee tenable que si elle reste supportee au moins
        PlanningHorizonDays (365 j par defaut) : sinon la montee devra etre
        replanifiee, ce qui est dit explicitement.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Lever)

    $now = (Get-Date).Date
    $horizon = [int]$Config.Thresholds.PlanningHorizonDays
    $deadline = $null
    foreach ($f in $Lever.Covered) {
        if ($null -eq $f.EolDate) { continue }
        if ($null -eq $deadline -or [datetime]$f.EolDate -lt $deadline) { $deadline = [datetime]$f.EolDate }
    }
    $target = $null; $targetDays = $null; $fallback = $null
    foreach ($r in $Lever.Recommendations) {
        if (-not $r.Version -and -not $r.Cycle) { continue }
        if ($r.EolDate) {
            $days = [int](([datetime]$r.EolDate - $now).TotalDays)
            if ($days -ge $horizon -and $null -eq $target) { $target = $r; $targetDays = $days }
            if ($null -eq $fallback -or ($fallback.EolDate -and $days -gt [int](([datetime]$fallback.EolDate - $now).TotalDays))) { $fallback = $r }
        } elseif ($null -eq $fallback) { $fallback = $r }
    }
    $verdict = ''
    if ($target) {
        $verdict = "Cible tenable : support publie encore $([int]($targetDays / 30.4)) mois."
    } elseif ($fallback -and $fallback.EolDate) {
        $d = [int](([datetime]$fallback.EolDate - $now).TotalDays)
        $target = $fallback; $targetDays = $d
        $verdict = "Attention : la meilleure cible publiee n'est supportee que $([Math]::Max(0, [int]($d / 30.4))) mois - prevoir une seconde montee avant le $(([datetime]$fallback.EolDate).ToString('dd/MM/yyyy'))."
    } elseif ($fallback) {
        $target = $fallback
        $verdict = "Horizon de support non publie pour la cible : a confirmer aupres de l'editeur avant de planifier."
    } else {
        $verdict = "Aucune cible publiee : arbitrage a faire avec l'editeur."
    }

    $urgency = 'a planifier'
    $deadlineText = 'echeance non publiee'
    if ($deadline) {
        $left = [int](($deadline - $now).TotalDays)
        $q = "T{0} {1}" -f ([Math]::Floor(($deadline.Month - 1) / 3) + 1), $deadline.Year
        if ($left -lt 0) { $urgency = 'depassee'; $deadlineText = "echeance depassee depuis $([Math]::Abs($left)) j" }
        elseif ($left -le 90) { $urgency = 'immediate'; $deadlineText = "avant le $($deadline.ToString('dd/MM/yyyy')) ($q, $left j)" }
        elseif ($left -le $horizon) { $urgency = 'cette annee'; $deadlineText = "avant le $($deadline.ToString('dd/MM/yyyy')) ($q, $left j)" }
        else { $urgency = 'a planifier'; $deadlineText = "avant le $($deadline.ToString('dd/MM/yyyy')) ($q)" }
    }
    $targetVersion = ''
    if ($target) {
        $targetVersion = [string]$target.Version
        if (-not $targetVersion) { $targetVersion = "cycle $($target.Cycle)" }
    }
    return @{
        Deadline        = $deadline
        DeadlineText    = $deadlineText
        Urgency         = $urgency
        TargetVersion   = $targetVersion
        TargetSupportDays = $targetDays
        TargetEol       = $(if ($target) { $target.EolDate } else { $null })
        Verdict         = $verdict
        Sustainable     = ($null -ne $targetDays -and $targetDays -ge $horizon)
    }
}

function Add-EolKbLeverIntelligence {
    <#
    .SYNOPSIS
        Enrichissement final des composants leviers, avant redaction du
        rapport : piste editeur (pour ceux que endoflife.date ne suit pas),
        double controle de la cible sur une source independante, et
        projection de planification.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Levers, [switch]$Offline)

    $max = [int]$Config.Thresholds.DeepCheckMaxLevers
    $i = 0
    foreach ($lv in $Levers) {
        $i++
        if ($i -gt $max) { break }
        Write-Progress -Id 5 -Activity 'Verification des composants leviers' -Status "$i / $([Math]::Min($max, @($Levers).Count))" `
            -PercentComplete ([int](100 * $i / [Math]::Max(1, [Math]::Min($max, @($Levers).Count))))

        # 1) piste editeur si aucun calendrier de support publie
        if (-not $lv.Finding.Product) {
            $vendor = Get-EolKbVendorLifecycle -Config $Config -Finding $lv.Finding -Offline:$Offline
            $lv.Vendor = $vendor
            if ($vendor.Archived) {
                $lv.Finding.Notes += $vendor.ArchivedNote
                if ($lv.Finding.SupportStatus -notin @('eol', 'deprecated')) { $lv.Finding.SupportStatus = 'deprecated' }
            }
        }
        # 2) double controle de la cible
        $lv.Verification = Confirm-EolKbTarget -Config $Config -Finding $lv.Finding -Offline:$Offline
        # 3) projection
        $lv.Projection = Get-EolKbLeverProjection -Config $Config -Lever $lv
    }
    Write-Progress -Id 5 -Activity 'Verification des composants leviers' -Completed
    return $Levers
}

function Get-EolKbLeverSummaryText {
    [CmdletBinding()]
    param($Lever)
    $parts = @()
    if ($Lever.CoveredCount -gt 1) { $parts += "$($Lever.CoveredCount) composants concernes" }
    foreach ($r in $Lever.Reasons) { $parts += $r }
    return ($parts -join ', ')
}

Export-ModuleMember -Function Set-EolKbActionability, Get-EolKbFamilyKey, Get-EolKbDominators, Get-EolKbLeverRef,
    Get-EolKbLevers, Get-EolKbLeverSummaryText, Confirm-EolKbTarget, Get-EolKbLeverProjection,
    Add-EolKbLeverIntelligence
