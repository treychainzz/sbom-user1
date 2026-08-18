<#
.SYNOPSIS
    Analyse d'obsolescence d'une application a partir d'un SBOM CycloneDX.

.DESCRIPTION
    Lit un SBOM CycloneDX (JSON), identifie les composants hors support ou
    proches de la fin de support, propose des versions cibles encore
    supportees, remonte les CVE avec leur score CVSS, et produit un rapport
    HTML autonome + des exports CSV/JSON.

    Confidentialite : aucune version ni identite applicative ne sort du
    poste. Les sources externes ne recoivent que des coordonnees publiques
    (nom de produit, nom de paquet). Tout le rapprochement de versions est
    effectue localement. Une garde bloque toute requete contenant un motif
    de version.

    Base de connaissance locale : les reponses externes sont mises en cache
    (un fichier JSON par entree, TTL adapte au rythme de changement de
    chaque source), ce qui evite de reinterroger les memes composants.

.PARAMETER SbomPath
    Chemin du fichier SBOM CycloneDX (.json). Demande interactivement si absent.

.PARAMETER OutputDir
    Dossier de sortie des rapports. Par defaut celui de la configuration.

.PARAMETER RegistryLookup
    Etendue de la collecte des versions publiees : All (defaut, tous les
    composants sont interroges en ligne), Needed (seulement quand une cible
    est necessaire, plus rapide), None (aucune consultation).

.PARAMETER Mode
    'Online' (defaut) : les sources sont interrogees, le rapport est etabli
    sur des donnees fraiches. 'Offline' : aucun appel reseau, analyse menee
    uniquement sur la base de connaissance locale - le rapport indique alors
    explicitement l'anciennete des donnees utilisees.

.PARAMETER Offline
    Raccourci equivalent a -Mode Offline.

.PARAMETER VulnQueryMode
    Fiabilite du rapprochement des vulnerabilites :
      Precise     la version est transmise a OSV, qui etablit lui-meme la
                  correspondance ; le resultat est recoupe avec l'evaluation
                  locale et toute divergence est signalee. Rapport le plus fiable.
      PackageOnly seul le nom du paquet sort, la correspondance de version est
                  faite sur le poste.
      Auto        (defaut) Precise en confidentialite Balanced, PackageOnly en Strict.

.PARAMETER NoVulns
    N'interroge pas OSV (analyse de support uniquement).

.PARAMETER RefreshOlderThanDays
    Force le rafraichissement des entrees de cache plus anciennes que N jours.

.PARAMETER Cve
    Un ou plusieurs identifiants de vulnerabilite (CVE-2021-44228, GHSA-...).
    Le script indique si l'application est concernee, en confrontant la fiche
    publiee aux composants du SBOM (rapprochement de version local).

.PARAMETER CveOnly
    Ne fait que la verification -Cve : pas d'analyse d'obsolescence, reponse
    en quelques secondes.

.PARAMETER PrivacyMode
    'Balanced' (defaut) ou 'Strict'. En mode Strict, aucune version ne figure
    dans une requete sortante. Dans les deux modes, l'identite applicative,
    les identifiants du SBOM et les composants internes ne sortent jamais.

.PARAMETER InternalNamespace
    Prefixes de coordonnees internes (ex : 'com.masociete', '@masociete').
    Aucune requete externe n'est emise pour ces composants.

.PARAMETER MinCvss
    Score CVSS a partir duquel une vulnerabilite rend un composant
    "a traiter" (defaut 7.0, soit ELEVEE et CRITIQUE).

.PARAMETER IncludeAllInHtml
    Inclut tous les constats dans le tableau HTML (par defaut, seuls ceux
    necessitant une action ; l'inventaire complet reste dans les exports).

.EXAMPLE
    .\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json

.EXAMPLE
    .\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -RegistryLookup All -Verbose

.EXAMPLE
    .\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -Offline

.EXAMPLE
    # Suis-je concerne par Log4Shell ?
    .\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -Cve CVE-2021-44228 -CveOnly

.EXAMPLE
    .\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -Cve CVE-2021-44228,CVE-2022-22965 -PrivacyMode Strict
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$SbomPath,
    [string]$OutputDir,
    [ValidateSet('None', 'Needed', 'All')][string]$RegistryLookup = 'All',
    [ValidateSet('Online', 'Offline')][string]$Mode = 'Online',
    [switch]$Offline,
    [ValidateSet('Auto', 'Precise', 'PackageOnly')][string]$VulnQueryMode,
    [switch]$NoVulns,
    [int]$RefreshOlderThanDays = -1,
    [string[]]$Cve,
    [switch]$CveOnly,
    [double]$MinCvss = -1,
    [ValidateSet('Balanced', 'Strict')][string]$PrivacyMode,
    [string[]]$InternalNamespace,
    [switch]$IncludeAllInHtml,
    [switch]$OpenReport,
    [string]$ConfigPath,
    [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')][string]$LogLevel = 'INFO'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

foreach ($m in @('Common', 'Version', 'Sources', 'Vendor', 'Analyze', 'Consolidate', 'Report')) {
    Import-Module (Join-Path $root "lib\EolKb.$m.psm1") -Force -DisableNameChecking
}

# --- fichier d'entree -------------------------------------------------
if (-not $SbomPath) {
    $SbomPath = Read-Host 'Chemin du fichier SBOM CycloneDX (.json)'
}
$SbomPath = $SbomPath.Trim('"').Trim("'")
if (-not (Test-Path -LiteralPath $SbomPath)) { throw "Fichier SBOM introuvable : $SbomPath" }

# --- configuration ----------------------------------------------------
if (-not $ConfigPath) { $ConfigPath = Join-Path $root 'EolKb.Config.psd1' }
$cfg = Get-EolKbConfig -Path $ConfigPath -Force
if ($OutputDir) { $cfg.Paths.ReportRoot = $OutputDir }
if ($MinCvss -ge 0) { $cfg.Thresholds.ActionableCvss = $MinCvss }
if ($PrivacyMode) { $cfg.Privacy.Mode = $PrivacyMode }
if ($InternalNamespace) { $cfg.Privacy.InternalNamespaces = @($cfg.Privacy.InternalNamespaces) + @($InternalNamespace) }
foreach ($d in @($cfg.Paths.CacheRoot, $cfg.Paths.ReportRoot, $cfg.Paths.RunLog)) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
if ($Offline) { $Mode = 'Offline' }
$isOffline = ($Mode -eq 'Offline')
if ($VulnQueryMode) { $cfg.Privacy.VulnQueryMode = $VulnQueryMode }
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
Set-EolKbLogging -Level $LogLevel -LogFile (Join-Path $cfg.Paths.RunLog "scan-$stamp.log")
Initialize-EolKbCache -CacheRoot $cfg.Paths.CacheRoot | Out-Null
Initialize-EolKbNetwork -Config $cfg

Write-EolKbLog -Message "eol-scan demarre (PowerShell $($PSVersionTable.PSVersion))"
if ($isOffline) {
    Write-EolKbLog -Level WARN -Message 'MODE HORS LIGNE : aucune source ne sera interrogee, le rapport reposera sur le cache local et son anciennete sera indiquee.'
} else {
    Write-EolKbLog -Message 'MODE EN LIGNE : les sources publiques sont interrogees pour un rapport a jour.'
}
if ($cfg.Privacy.Mode -eq 'Strict') {
    Write-EolKbLog -Message 'Confidentialite Strict : aucune version ne figurera dans une requete sortante.'
} else {
    Write-EolKbLog -Message 'Confidentialite Balanced : coordonnees publiques autorisees, identite applicative et composants internes proteges.'
}
if ($RefreshOlderThanDays -ge 0 -and -not $isOffline) {
    $n = Clear-EolKbCache -CacheRoot $cfg.Paths.CacheRoot -OlderThanDays $RefreshOlderThanDays
    Write-EolKbLog -Message "Rafraichissement force : $n entree(s) de cache supprimee(s) (> $RefreshOlderThanDays j)"
}

# --- analyse ----------------------------------------------------------
$sbom = Read-EolKbSbom -Path $SbomPath

# --- verification ciblee d'une ou plusieurs CVE -----------------------
$cveChecks = @()
if ($Cve) {
    # tolere -Cve "CVE-1,CVE-2" (chaine unique) comme -Cve CVE-1,CVE-2 (tableau)
    $cveIds = @($Cve | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ } | ForEach-Object { $_.Trim() })
    $cveChecks = @(Invoke-EolKbCveCheck -Config $cfg -Sbom $sbom -CveIds $cveIds -Offline:$isOffline)
    Write-EolKbCveConsoleReport -Checks $cveChecks -Sbom $sbom
    if ($CveOnly) {
        Write-Host ''
        [pscustomobject]@{ CveChecks = $cveChecks; Sbom = $sbom.FileName }
        return
    }
}

$result = Invoke-EolKbAnalysis -Config $cfg -Sbom $sbom -RegistryLookup $RegistryLookup -Offline:$isOffline -NoVulns:$NoVulns
$result | Add-Member -NotePropertyName CveChecks -NotePropertyValue $cveChecks -Force

# --- restitution ------------------------------------------------------
$safeName = $sbom.AppName
if (-not $safeName) { $safeName = [System.IO.Path]::GetFileNameWithoutExtension($sbom.FileName) }
$safeName = ($safeName -replace '[^\w\.-]', '_')
$prefix = "$safeName-$stamp"

$html = New-EolKbHtmlReport -Config $cfg -Result $result -OutDir $cfg.Paths.ReportRoot -Prefix $prefix -IncludeAll:$IncludeAllInHtml
$csv = Export-EolKbCsv -Result $result -OutDir $cfg.Paths.ReportRoot -Prefix $prefix
$json = Export-EolKbJson -Result $result -OutDir $cfg.Paths.ReportRoot -Prefix $prefix

Write-EolKbConsoleReport -Config $cfg -Result $result

Write-Host ''
Write-Host ' Rapports produits :' -ForegroundColor White
Write-Host "   HTML : $html"
foreach ($c in $csv) { Write-Host "   CSV  : $c" }
Write-Host "   JSON : $json"
Write-Host ''

if ($OpenReport -and -not $env:CI) {
    try { Start-Process $html } catch { Write-EolKbLog -Level WARN -Message "Ouverture automatique impossible : $($_.Exception.Message)" }
}

# objet exploitable en sortie de pipeline
[pscustomobject]@{
    CveChecks  = $cveChecks
    Summary    = $result.Summary
    HtmlReport = $html
    CsvReports = $csv
    JsonReport = $json
    Findings   = $result.Findings
}
