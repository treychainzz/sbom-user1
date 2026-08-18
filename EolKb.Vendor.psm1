<#
.SYNOPSIS
    Recherche des informations d'EDITEUR pour les composants que
    endoflife.date ne suit pas : depot source, organisation editrice,
    page de support, etat du projet (archive, derniere publication par
    branche majeure).

.NOTES
    REGLE ABSOLUE : aucune date de fin de support n'est deduite ici.
    Une date de fin de support n'est affichee que si une source la
    PUBLIE explicitement (endoflife.date). Les elements collectes ici
    sont des FAITS verifiables (depot archive, date de derniere
    publication) et un LIEN vers l'editeur a qualifier. Une piste
    non confirmee est presentee comme telle, jamais comme une date.
#>

function Get-EolKbGitHubSlug {
    <# Extrait owner/repo d'une URL de depot, sinon $null. #>
    [CmdletBinding()]
    param([string]$Url)
    if (-not $Url) { return $null }
    $u = $Url -replace '^git\+', '' -replace '\.git$', ''
    $u = $u -replace '^scm:git:', '' -replace '^git@github\.com:', 'https://github.com/'
    $u = $u -replace '^git://', 'https://' -replace '^ssh://git@', 'https://'
    if ($u -match 'github\.com[/:]([^/]+)/([^/#?]+)') {
        return @{ Owner = $Matches[1]; Repo = ($Matches[2] -replace '\.git$', '') }
    }
    return $null
}

function Get-EolKbRepositoryInfo {
    <#
    .SYNOPSIS
        Depot source, page d'accueil et signal d'abandon declares par
        l'editeur dans les metadonnees publiques du paquet.
        Seul le nom du paquet est transmis (sauf Maven, cf. note).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [string]$Registry, [string]$Group, [Parameter(Mandatory)][string]$Name,
        [string]$LatestVersion, [switch]$Offline
    )
    $key = Get-EolKbCoordKey -Ecosystem "repo-$Registry" -Group $Group -Name $Name
    $root = $Config.Paths.CacheRoot
    $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'vendor' -Key $key -OverrideTtlDays $Config.Ttl.Vendor
    if ($e -and ($e.Fresh -or $Offline)) {
        return @{
            Found = [bool](Get-DictValue $e.Payload 'found' $false)
            RepoUrl = [string](Get-DictValue $e.Payload 'repo' '')
            Homepage = [string](Get-DictValue $e.Payload 'homepage' '')
            Abandoned = [bool](Get-DictValue $e.Payload 'abandoned' $false)
            Replacement = [string](Get-DictValue $e.Payload 'replacement' '')
            Source = [string](Get-DictValue $e.Payload 'source' '')
        }
    }
    if ($Offline) { return @{ Found = $false; RepoUrl = ''; Homepage = ''; Abandoned = $false; Replacement = ''; Source = 'hors-ligne' } }

    $base = $Config.Sources.Registries[$Registry]
    $repo = ''; $home = ''; $abandoned = $false; $replacement = ''; $src = $Registry
    $full = $Name
    if ($Group) { $full = "$Group/$Name" }
    $exempt = @($Name, $Group, $full)
    try {
        switch ($Registry) {
            'npm' {
                # /latest est une etiquette de distribution, pas un numero de version :
                # aucune version applicative n'est transmise.
                $raw = Invoke-EolKbRequest -Config $Config -Uri "$base/$([uri]::EscapeDataString($full))/latest" `
                    -Purpose 'vendor-npm' -ExemptTokens $exempt -TolerateNotFound
                if ($raw) {
                    $r = Get-DictValue $raw 'repository'
                    if ($r -is [string]) { $repo = [string]$r } elseif ($r) { $repo = [string](Get-DictValue $r 'url' '') }
                    $home = [string](Get-DictValue $raw 'homepage' '')
                    if (Get-DictValue $raw 'deprecated') { $abandoned = $true }
                }
            }
            'PyPI' {
                $raw = Invoke-EolKbRequest -Config $Config -Uri "$base/$Name/json" -Purpose 'vendor-pypi' -ExemptTokens $exempt -TolerateNotFound
                if ($raw) {
                    $info = Get-DictValue $raw 'info'
                    $home = [string](Get-DictValue $info 'home_page' '')
                    $urls = Get-DictValue $info 'project_urls'
                    if ($urls -is [System.Collections.IDictionary]) {
                        foreach ($k in $urls.Keys) {
                            $v = [string]$urls[$k]
                            if ($v -match 'github\.com' -and -not $repo) { $repo = $v }
                            if ([string]$k -imatch 'home|documentation' -and -not $home) { $home = $v }
                        }
                    }
                }
            }
            'Packagist' {
                $raw = Invoke-EolKbRequest -Config $Config -Uri "https://repo.packagist.org/packages/$full.json" `
                    -Purpose 'vendor-packagist' -ExemptTokens $exempt -TolerateNotFound
                if ($raw) {
                    $pkg = Get-DictValue $raw 'package'
                    $repo = [string](Get-DictValue $pkg 'repository' '')
                    $ab = Get-DictValue $pkg 'abandoned'
                    if ($null -ne $ab -and "$ab" -ne 'False') { $abandoned = $true; if ($ab -is [string]) { $replacement = [string]$ab } }
                }
            }
            'Maven' {
                # Le POM n'est adressable que par version : on utilise la DERNIERE
                # version PUBLIQUE renvoyee par le registre, jamais celle de
                # l'application. Desactivable via Privacy.AllowPublicLatestInPath.
                if ($LatestVersion -and $Config.Privacy.AllowPublicLatestInPath) {
                    $gp = ($Group -replace '\.', '/')
                    $uri = "$base/$gp/$Name/$LatestVersion/$Name-$LatestVersion.pom"
                    $txt = Invoke-EolKbRequest -Config $Config -Uri $uri -Purpose 'vendor-maven-pom' `
                        -ExemptTokens (@($exempt) + @($LatestVersion)) -Raw -TolerateNotFound
                    if ($txt) {
                        try {
                            $xml = [xml]$txt
                            $repo = [string]$xml.project.scm.url
                            $home = [string]$xml.project.url
                            if (-not $repo) { $repo = [string]$xml.project.scm.connection }
                        } catch { }
                    }
                }
            }
            'NuGet' {
                $raw = Invoke-EolKbRequest -Config $Config -Uri "https://azuresearch-usnc.nuget.org/query?q=packageid:$([uri]::EscapeDataString($Name))&take=1" `
                    -Purpose 'vendor-nuget' -ExemptTokens $exempt -TolerateNotFound
                if ($raw) {
                    foreach ($d in (Get-DictArray -Dict $raw -Key 'data')) {
                        $repo = [string](Get-DictValue $d 'projectUrl' '')
                        $home = $repo
                        break
                    }
                }
            }
        }
    } catch {
        Write-EolKbLog -Level DEBUG -Message "Metadonnees editeur indisponibles pour '$full' : $($_.Exception.Message)"
    }

    $found = [bool]($repo -or $home -or $abandoned)
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'vendor' -Key $key -TtlDays $Config.Ttl.Vendor -Source $src `
        -Payload @{ found = $found; repo = $repo; homepage = $home; abandoned = $abandoned; replacement = $replacement; source = $src } | Out-Null
    return @{ Found = $found; RepoUrl = $repo; Homepage = $home; Abandoned = $abandoned; Replacement = $replacement; Source = $src }
}

function Get-EolKbGitHubFacts {
    <#
    .SYNOPSIS
        Faits publies par le depot editeur : projet archive, date de
        derniere activite, publications par branche majeure.
        Ce sont des faits dates, pas une date de fin de support.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Owner, [Parameter(Mandatory)][string]$Repo, [switch]$Offline)
    $key = "github|$Owner/$Repo".ToLowerInvariant()
    $root = $Config.Paths.CacheRoot
    $e = Get-EolKbCacheEntry -CacheRoot $root -Namespace 'vendor' -Key $key -OverrideTtlDays $Config.Ttl.Vendor
    $build = {
        param($p)
        $rel = @{}
        $node = Get-DictValue $p 'releasesByMajor'
        if ($node -is [System.Collections.IDictionary]) { foreach ($k in $node.Keys) { $rel[[string]$k] = [string]$node[$k] } }
        return @{
            Found = [bool](Get-DictValue $p 'found' $false)
            Archived = [bool](Get-DictValue $p 'archived' $false)
            PushedAt = [string](Get-DictValue $p 'pushedAt' '')
            Homepage = [string](Get-DictValue $p 'homepage' '')
            HtmlUrl = [string](Get-DictValue $p 'htmlUrl' '')
            Owner = [string](Get-DictValue $p 'owner' '')
            LastRelease = [string](Get-DictValue $p 'lastRelease' '')
            LastReleaseDate = [string](Get-DictValue $p 'lastReleaseDate' '')
            ReleasesByMajor = $rel
            Source = 'github'
        }
    }
    if ($e -and ($e.Fresh -or $Offline)) { return (& $build $e.Payload) }
    if ($Offline) { return @{ Found = $false; Archived = $false; PushedAt = ''; Homepage = ''; HtmlUrl = ''; Owner = ''; LastRelease = ''; LastReleaseDate = ''; ReleasesByMajor = @{}; Source = 'hors-ligne' } }

    $headers = @{ 'Accept' = 'application/vnd.github+json' }
    if ($Config.Sources.GitHubToken) { $headers['Authorization'] = "Bearer $($Config.Sources.GitHubToken)" }
    $payload = @{ found = $false }
    try {
        $repoRaw = Invoke-EolKbRequest -Config $Config -Uri "$($Config.Sources.GitHubApi)/repos/$Owner/$Repo" `
            -Purpose 'vendor-github' -Headers $headers -ExemptTokens @($Owner, $Repo) -TolerateNotFound
        if ($repoRaw) {
            $payload['found'] = $true
            $payload['archived'] = [bool](Get-DictValue $repoRaw 'archived' $false)
            $payload['pushedAt'] = [string](Get-DictValue $repoRaw 'pushed_at' '')
            $payload['homepage'] = [string](Get-DictValue $repoRaw 'homepage' '')
            $payload['htmlUrl'] = [string](Get-DictValue $repoRaw 'html_url' '')
            $ow = Get-DictValue $repoRaw 'owner'
            $payload['owner'] = [string](Get-DictValue $ow 'login' $Owner)
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match '\(403\)|\(429\)') {
            Write-EolKbLog -Level WARN -Message "Quota GitHub atteint (60 appels/heure sans jeton). Renseignez Sources.GitHubToken dans la configuration pour interroger les depots editeurs."
        } else {
            Write-EolKbLog -Level DEBUG -Message "Depot GitHub $Owner/$Repo inaccessible : $msg"
        }
    }
    if ($payload['found']) {
        try {
            $rels = Invoke-EolKbRequest -Config $Config -Uri "$($Config.Sources.GitHubApi)/repos/$Owner/$Repo/releases?per_page=100" `
                -Purpose 'vendor-github-releases' -Headers $headers -ExemptTokens @($Owner, $Repo) -TolerateNotFound
            $byMajor = @{}
            $lastTag = ''; $lastDate = ''
            foreach ($r in (Get-DictArray -Dict $rels)) {
                if ([bool](Get-DictValue $r 'draft' $false) -or [bool](Get-DictValue $r 'prerelease' $false)) { continue }
                $tag = [string](Get-DictValue $r 'tag_name' '')
                $date = [string](Get-DictValue $r 'published_at' '')
                if (-not $tag -or -not $date) { continue }
                if (-not $lastDate -or $date -gt $lastDate) { $lastDate = $date; $lastTag = $tag }
                $v = ConvertTo-EolKbVersion -Version $tag
                if ($v.Numeric.Count -gt 0) {
                    $maj = [string]$v.Numeric[0]
                    if (-not $byMajor.ContainsKey($maj) -or $date -gt $byMajor[$maj]) { $byMajor[$maj] = $date }
                }
            }
            $payload['releasesByMajor'] = $byMajor
            $payload['lastRelease'] = $lastTag
            $payload['lastReleaseDate'] = $lastDate
        } catch {
            Write-EolKbLog -Level DEBUG -Message "Publications GitHub $Owner/$Repo inaccessibles : $($_.Exception.Message)"
        }
    }
    Set-EolKbCacheEntry -CacheRoot $root -Namespace 'vendor' -Key $key -Payload $payload `
        -TtlDays $Config.Ttl.Vendor -Source 'github' | Out-Null
    return (& $build $payload)
}

function Get-EolKbVendorLifecycle {
    <#
    .SYNOPSIS
        Piste editeur pour un composant non suivi par endoflife.date.
    .OUTPUTS
        @{ Editor; SupportUrl; RepoUrl; Archived; ArchivedNote; MajorBranchLastRelease;
           Facts = @(); Confidence } - AUCUNE date de fin de support inventee.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Finding, [switch]$Offline)

    $out = @{ Editor = ''; SupportUrl = ''; RepoUrl = ''; Archived = $false; ArchivedNote = ''
              MajorBranchLastRelease = ''; Facts = @(); Confidence = 'aucune-piste'; Probed = $true }
    if (-not $Finding.Registry -and -not $Finding.DepsDevSystem) { $out.Probed = $false; return $out }

    $repoInfo = Get-EolKbRepositoryInfo -Config $Config -Registry $Finding.Registry -Group $Finding.Group `
        -Name $Finding.Name -LatestVersion $Finding.RegistryLatest -Offline:$Offline
    if ($repoInfo.Abandoned) {
        $out.Facts += 'Paquet declare abandonne par l''editeur sur le registre.'
        if ($repoInfo.Replacement) { $out.Facts += "Remplacement indique par l'editeur : $($repoInfo.Replacement)." }
    }
    $out.RepoUrl = $repoInfo.RepoUrl
    if ($repoInfo.Homepage) { $out.SupportUrl = $repoInfo.Homepage }

    $slug = Get-EolKbGitHubSlug -Url $repoInfo.RepoUrl
    if (-not $slug -and $repoInfo.Homepage) { $slug = Get-EolKbGitHubSlug -Url $repoInfo.Homepage }
    if ($slug) {
        $gh = Get-EolKbGitHubFacts -Config $Config -Owner $slug.Owner -Repo $slug.Repo -Offline:$Offline
        if ($gh.Found) {
            $out.Editor = $gh.Owner
            if (-not $out.SupportUrl -and $gh.Homepage) { $out.SupportUrl = $gh.Homepage }
            if (-not $out.RepoUrl) { $out.RepoUrl = $gh.HtmlUrl }
            if ($gh.Archived) {
                $out.Archived = $true
                $out.ArchivedNote = 'Depot archive par l''editeur : plus aucune correction attendue.'
                $out.Facts += $out.ArchivedNote
            }
            if ($gh.LastReleaseDate) {
                $out.Facts += "Derniere publication de l'editeur : $($gh.LastRelease) le $(([datetime]$gh.LastReleaseDate).ToString('dd/MM/yyyy'))."
            }
            # activite de la branche majeure utilisee par l'application
            $cur = ConvertTo-EolKbVersion -Version $Finding.Version
            if ($cur.Numeric.Count -gt 0) {
                $maj = [string]$cur.Numeric[0]
                if ($gh.ReleasesByMajor.ContainsKey($maj)) {
                    $d = [datetime]$gh.ReleasesByMajor[$maj]
                    $out.MajorBranchLastRelease = $d.ToString('yyyy-MM-dd')
                    $months = [int](((Get-Date) - $d).TotalDays / 30.4)
                    $out.Facts += "Branche majeure $maj : derniere correction publiee le $($d.ToString('dd/MM/yyyy')) (il y a $months mois)."
                } else {
                    $out.Facts += "Aucune publication trouvee pour la branche majeure $maj chez l'editeur."
                }
            }
            $out.Confidence = 'observe-depot-editeur'
        }
    }
    if (-not $out.SupportUrl -and $out.RepoUrl) { $out.SupportUrl = $out.RepoUrl }
    if ($out.Confidence -eq 'aucune-piste' -and $out.SupportUrl) { $out.Confidence = 'lien-editeur-a-qualifier' }
    return $out
}

Export-ModuleMember -Function Get-EolKbGitHubSlug, Get-EolKbRepositoryInfo, Get-EolKbGitHubFacts, Get-EolKbVendorLifecycle
