<#
.SYNOPSIS
    Entretien de la base de connaissance locale : etat, prechauffage,
    rafraichissement des entrees perimees, purge.

.DESCRIPTION
    A planifier (tache planifiee Windows, une fois par jour ou par semaine)
    pour que les analyses interactives tournent presque entierement sur le
    cache : les appels reseau lents sont alors sortis du chemin critique.

    Rythme conseille :
      - quotidien  : -Refresh (met a jour l'index OSV des paquets deja vus,
                     TTL 1 j, et les fiches produit proches de l'EOL)
      - hebdomadaire : -Refresh -IncludeRegistries
      - mensuel    : -Purge -OlderThanDays 180 (elimine les coordonnees
                     qui ne sont plus rencontrees)

.PARAMETER Status
    Affiche l'etat du cache (volumetrie, age, entrees perimees).

.PARAMETER Warm
    Prechauffe le cache a partir d'un ou plusieurs SBOM, sans produire de
    rapport : utile avant une campagne d'analyse.

.PARAMETER Refresh
    Reinterroge les entrees perimees (TTL depasse) deja presentes en cache.

.PARAMETER IncludeRegistries
    Inclut les entrees de registre de paquets dans le rafraichissement.

.PARAMETER Purge
    Supprime les entrees plus anciennes que -OlderThanDays.

.EXAMPLE
    .\Update-EolKbCache.ps1 -Status

.EXAMPLE
    .\Update-EolKbCache.ps1 -Warm -SbomPath C:\sboms\*.json

.EXAMPLE
    .\Update-EolKbCache.ps1 -Refresh -IncludeRegistries
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [Parameter(ParameterSetName = 'Warm')][switch]$Warm,
    [Parameter(ParameterSetName = 'Warm')][string[]]$SbomPath,
    [Parameter(ParameterSetName = 'Refresh')][switch]$Refresh,
    [Parameter(ParameterSetName = 'Refresh')][switch]$IncludeRegistries,
    [Parameter(ParameterSetName = 'Purge')][switch]$Purge,
    [Parameter(ParameterSetName = 'Purge')][int]$OlderThanDays = 180,
    [string]$ConfigPath,
    [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')][string]$LogLevel = 'INFO'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
foreach ($m in @('Common', 'Version', 'Sources', 'Vendor', 'Analyze', 'Consolidate', 'Report')) {
    Import-Module (Join-Path $root "lib\EolKb.$m.psm1") -Force -DisableNameChecking
}
if (-not $ConfigPath) { $ConfigPath = Join-Path $root 'EolKb.Config.psd1' }
$cfg = Get-EolKbConfig -Path $ConfigPath -Force
Set-EolKbLogging -Level $LogLevel
Initialize-EolKbCache -CacheRoot $cfg.Paths.CacheRoot | Out-Null
Initialize-EolKbNetwork -Config $cfg

# ---------------------------------------------------------------------
function Get-EolKbStaleEntries {
    param($Config, [string[]]$Namespaces)
    $out = @()
    foreach ($ns in $Namespaces) {
        $dir = Join-Path $Config.Paths.CacheRoot $ns
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter '*.json' -Recurse -File)) {
            try {
                $o = ConvertFrom-JsonCompat -Json ([System.IO.File]::ReadAllText($f.FullName))
                $fetched = [datetime]::Parse([string](Get-DictValue $o 'fetchedAt'), [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
                $ttl = [double](Get-DictValue $o 'ttlDays' 7)
                $age = ([datetime]::UtcNow - $fetched.ToUniversalTime()).TotalDays
                if ($age -gt $ttl) {
                    $out += [pscustomobject]@{ Namespace = $ns; Key = [string](Get-DictValue $o 'key')
                                               Meta = (Get-DictValue $o 'meta'); AgeDays = [Math]::Round($age, 1); TtlDays = $ttl }
                }
            } catch { }
        }
    }
    return $out
}

switch ($PSCmdlet.ParameterSetName) {

    'Status' {
        Write-Host ''
        Write-Host " Base de connaissance : $($cfg.Paths.CacheRoot)" -ForegroundColor White
        Write-Host ((Get-EolKbCacheSummary -CacheRoot $cfg.Paths.CacheRoot | Format-Table -AutoSize | Out-String -Width 200).Trim())
        $stale = Get-EolKbStaleEntries -Config $cfg -Namespaces @('eol-index', 'eol-product', 'registry', 'lifecycle', 'vendor', 'osv-pkg', 'osv-pkg-v', 'nvd', 'mapping')
        Write-Host " Entrees perimees : $($stale.Count)" -ForegroundColor Yellow
        if ($stale.Count -gt 0) {
            $stale | Group-Object Namespace | ForEach-Object {
                Write-Host ("   {0,-14} {1,5}  (age max {2} j)" -f $_.Name, $_.Count, (($_.Group | Measure-Object AgeDays -Maximum).Maximum))
            }
        }
        Write-Host ''
        Write-Host ' TTL en vigueur (jours) :' -ForegroundColor White
        $cfg.Ttl.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("   {0,-20} {1}" -f $_.Name, $_.Value) }
        Write-Host ''
        Write-Host " Journal des appels sortants : $($cfg.Paths.AuditLog)"
        if (Test-Path -LiteralPath $cfg.Paths.AuditLog) {
            $lines = @(Get-Content -LiteralPath $cfg.Paths.AuditLog -Tail 2000)
            $blocked = @($lines | Where-Object { $_ -match '"status":-1' })
            Write-Host ("   $($lines.Count) appel(s) recent(s), $($blocked.Count) bloque(s) par la garde anti-fuite")
        }
        Write-Host ''
    }

    'Warm' {
        if (-not $SbomPath) { throw 'Indiquez -SbomPath (un ou plusieurs fichiers, jokers acceptes).' }
        $files = @()
        foreach ($p in $SbomPath) { $files += @(Get-ChildItem -Path $p -File) }
        if ($files.Count -eq 0) { throw 'Aucun SBOM trouve.' }
        Write-Host " Prechauffage a partir de $($files.Count) SBOM" -ForegroundColor White
        foreach ($f in $files) {
            Write-EolKbLog -Message "Prechauffage : $($f.Name)"
            try {
                $sbom = Read-EolKbSbom -Path $f.FullName
                $null = Invoke-EolKbAnalysis -Config $cfg -Sbom $sbom -RegistryLookup 'All'
            } catch {
                Write-EolKbLog -Level ERROR -Message "Echec sur $($f.Name) : $($_.Exception.Message)"
            }
        }
        $st = Get-EolKbStats
        Write-Host (" Termine : {0} appels externes, {1} servis par le cache" -f $st.HttpOk, $st.CacheHit) -ForegroundColor Green
    }

    'Refresh' {
        $ns = @('eol-index', 'eol-product', 'osv-pkg', 'osv-pkg-v', 'nvd', 'mapping')
        if ($IncludeRegistries) { $ns += @('registry', 'lifecycle') }
        $stale = Get-EolKbStaleEntries -Config $cfg -Namespaces $ns
        Write-Host " $($stale.Count) entree(s) perimee(s) a rafraichir" -ForegroundColor White
        $i = 0
        foreach ($e in $stale) {
            $i++
            Write-Progress -Activity 'Rafraichissement du cache' -Status "$i / $($stale.Count)" -PercentComplete ([int](100 * $i / [Math]::Max(1, $stale.Count)))
            try {
                switch ($e.Namespace) {
                    'eol-index'   { Get-EolKbProductIndex -Config $cfg | Out-Null }
                    'eol-product' { Get-EolKbProductCycles -Config $cfg -Slug $e.Key -Force | Out-Null }
                    'osv-pkg-v'   {
                        $parts = $e.Key -split '\|', 2
                        if ($parts.Count -eq 2 -and $parts[1] -match '^(.*)@([^@]+)$') {
                            Get-EolKbVulnIndexPrecise -Config $cfg -Items @([pscustomobject]@{ Key = $e.Key; OsvEcosystem = $parts[0]; PackageName = $Matches[1]; Version = $Matches[2] }) | Out-Null
                        }
                    }
                    'osv-pkg'     {
                        $parts = $e.Key -split '\|', 2
                        if ($parts.Count -eq 2) {
                            Get-EolKbVulnIndex -Config $cfg -Items @([pscustomobject]@{ Key = $e.Key; OsvEcosystem = $parts[0]; PackageName = $parts[1] }) | Out-Null
                        }
                    }
                    'registry'    {
                        $parts = $e.Key -split '\|', 2
                        if ($parts.Count -eq 2) {
                            $coord = $parts[1] -split ':', 2
                            $grp = ''
                            $nm = $coord[0]
                            if ($coord.Count -eq 2) { $grp = $coord[0]; $nm = $coord[1] }
                            Get-EolKbRegistryInfo -Config $cfg -Registry $parts[0] -Group $grp -Name $nm | Out-Null
                        }
                    }
                    'lifecycle'   {
                        # les metadonnees de l'entree portent de quoi rejouer l'appel
                        $mt = $e.Meta
                        if ($mt) {
                            Get-EolKbPackageLifecycle -Config $cfg -DepsDevSystem ([string](Get-DictValue $mt 'system' '')) `
                                -Registry ([string](Get-DictValue $mt 'registry' '')) -Group ([string](Get-DictValue $mt 'group' '')) `
                                -Name ([string](Get-DictValue $mt 'name' '')) -PackageName ([string](Get-DictValue $mt 'pkg' '')) | Out-Null
                        }
                    }
                    'nvd'         {
                        $parts = $e.Key -split '\|'
                        if ($parts.Count -ge 3) { Get-EolKbNvdVulns -Config $cfg -CpeMatch $parts[1] -Keyword $parts[2] | Out-Null }
                    }
                    'mapping'     { }   # resolution locale, se recalcule seule
                }
            } catch {
                Write-EolKbLog -Level WARN -Message "Rafraichissement impossible ($($e.Namespace) / $($e.Key)) : $($_.Exception.Message)"
            }
        }
        Write-Progress -Activity 'Rafraichissement du cache' -Completed
        $st = Get-EolKbStats
        Write-Host (" Termine : {0} appels externes, {1} echecs" -f $st.HttpOk, $st.HttpFail) -ForegroundColor Green
    }

    'Purge' {
        $n = Clear-EolKbCache -CacheRoot $cfg.Paths.CacheRoot -OlderThanDays $OlderThanDays
        Write-Host " $n entree(s) supprimee(s) (plus anciennes que $OlderThanDays j)" -ForegroundColor Green
    }
}
