<#
    Test hors ligne : fabrique un SBOM de demonstration et amorce le cache
    avec des reponses representatives (formats v1 ET ancien d'endoflife.date,
    fiches OSV reelles dans leur structure), puis execute la chaine complete.
    Aucun acces reseau.
#>
[CmdletBinding()]
param([string]$WorkDir = (Join-Path ([System.IO.Path]::GetTempPath()) 'eolkb-test'))

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($m in @('Common', 'Version', 'Sources', 'Vendor', 'Analyze', 'Consolidate', 'Report')) {
    Import-Module (Join-Path $root "lib/EolKb.$m.psm1") -Force -DisableNameChecking
}

if (Test-Path -LiteralPath $WorkDir) { Remove-Item -LiteralPath $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$cacheRoot = Join-Path $WorkDir 'cache'
$reportRoot = Join-Path $WorkDir 'reports'
New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null

# ---- configuration de test -------------------------------------------
$cfg = Get-EolKbConfig -Path (Join-Path $root 'EolKb.Config.psd1') -Force
$cfg.Paths.CacheRoot = $cacheRoot
$cfg.Paths.ReportRoot = $reportRoot
$cfg.Paths.AuditLog = Join-Path $WorkDir 'audit.jsonl'
$cfg.Privacy.InternalNamespaces = @('com.acme')
Set-EolKbLogging -Level INFO
Initialize-EolKbCache -CacheRoot $cacheRoot | Out-Null

# ---- SBOM de demonstration -------------------------------------------
$comps = @(
    @{ 'bom-ref' = 'app'; name = 'demo-app'; version = '1.4.0'; type = 'application' }
    @{ 'bom-ref' = 'sb';  group = 'org.springframework.boot'; name = 'spring-boot-starter-web'; version = '2.7.18'; type = 'library'; purl = 'pkg:maven/org.springframework.boot/spring-boot-starter-web@2.7.18?type=jar'; scope = 'required' }
    @{ 'bom-ref' = 'tc';  group = 'org.apache.tomcat.embed'; name = 'tomcat-embed-core'; version = '9.0.83'; type = 'library'; purl = 'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.83' }
    @{ 'bom-ref' = 'ui';  name = 'web-ui-kit'; version = '2.1.0'; type = 'library'; purl = 'pkg:npm/web-ui-kit@2.1.0' }
    @{ 'bom-ref' = 'ld';  name = 'lodash'; version = '4.17.20'; type = 'library'; purl = 'pkg:npm/lodash@4.17.20' }
    @{ 'bom-ref' = 'dj';  name = 'django'; version = '3.2.18'; type = 'library'; purl = 'pkg:pypi/django@3.2.18' }
    @{ 'bom-ref' = 'jdk'; name = 'openjdk'; version = '11.0.21'; type = 'platform' }
    @{ 'bom-ref' = 'lp';  name = 'left-pad'; version = '1.3.0'; type = 'library'; purl = 'pkg:npm/left-pad@1.3.0' }
    @{ 'bom-ref' = 'nov'; name = 'internal-lib'; type = 'library'; purl = 'pkg:maven/com.acme/internal-lib' }
    @{ 'bom-ref' = 'l42'; group = 'org.apache.logging.log4j'; name = 'log4j-1.2-api'; version = '2.17.1'; type = 'library'; purl = 'pkg:maven/org.apache.logging.log4j/log4j-1.2-api@2.17.1' }
)
for ($i = 1; $i -le 12; $i++) {
    $comps += @{ 'bom-ref' = "f$i"; group = 'com.example'; name = "filler-lib-$i"; version = "1.$i.0"; type = 'library'; purl = "pkg:maven/com.example/filler-lib-$i@1.$i.0" }
}
# bibliotheque stable et terminee : plus publiee depuis 4 ans, 1 majeure de retard
$comps += @{ 'bom-ref' = 'stable'; group = 'commons-io'; name = 'commons-io'; version = '2.11.0'; type = 'library'; purl = 'pkg:maven/commons-io/commons-io@2.11.0' }
# bibliotheque au retard cumule : dormante ET 3 majeures de retard
$comps += @{ 'bom-ref' = 'vieux'; group = 'org.legacy'; name = 'legacy-utils'; version = '1.0.0'; type = 'library'; purl = 'pkg:maven/org.legacy/legacy-utils@1.0.0' }
# dependance de TEST vulnerable : ne doit pas entrer dans le plan d'action
$comps += @{ 'bom-ref' = 'testdep'; group = 'org.testing'; name = 'test-harness'; version = '1.0.0'; type = 'library'
             purl = 'pkg:maven/org.testing/test-harness@1.0.0'
             properties = @(@{ name = 'cdx:maven:package:scope'; value = 'test' }) }
# doublon volontaire (meme coordonnee@version, autre bom-ref) pour tester la deduplication
$comps += @{ 'bom-ref' = 'ld2'; name = 'lodash'; version = '4.17.20'; type = 'library'; purl = 'pkg:npm/lodash@4.17.20' }

$bom = [ordered]@{
    bomFormat = 'CycloneDX'; specVersion = '1.5'; serialNumber = 'urn:uuid:11111111-2222-3333-4444-555555555555'
    version = 1
    metadata = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        tools = @{ components = @(@{ name = 'cyclonedx-maven-plugin'; version = '2.7.9'; type = 'application' }) }
        component = @{ 'bom-ref' = 'app'; name = 'demo-app'; version = '1.4.0'; type = 'application' }
    }
    components = @($comps | Where-Object { $_.'bom-ref' -ne 'app' })
    dependencies = @(
        @{ ref = 'app'; dependsOn = @('sb', 'ui', 'dj', 'jdk', 'l42', 'stable', 'vieux', 'testdep') }
        @{ ref = 'sb'; dependsOn = @('tc', 'nov') }
        @{ ref = 'ui'; dependsOn = @('ld', 'lp', 'ld2') }
        @{ ref = 'tc'; dependsOn = @() }
    )
}
$sbomPath = Join-Path $WorkDir 'bom-demo.json'
($bom | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $sbomPath -Encoding UTF8

# ---- amorcage du cache ------------------------------------------------
$today = Get-Date
$past = $today.AddYears(-1).ToString('yyyy-MM-dd')
$soon = $today.AddDays(90).ToString('yyyy-MM-dd')
$far = $today.AddYears(5).ToString('yyyy-MM-dd')

Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'eol-index' -Key 'products' -TtlDays 30 -Source 'test' `
    -Payload @('java', 'spring-boot', 'tomcat', 'django', 'nodejs', 'python', 'log4j') | Out-Null

# table des identifiants purl publiee par endoflife.date : rattachement automatique
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'eol-index' -Key 'identifiers-purl' -TtlDays 30 -Source 'test' `
    -Payload @{
        'pkg:maven/org.apache.logging.log4j/log4j-1.2-api' = 'log4j'
        'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core' = 'tomcat'
        'pkg:pypi/django' = 'django'
    } | Out-Null

$log4jRaw = ConvertFrom-JsonCompat -Json (@(
    @{ cycle = '2'; eol = $far; latest = '2.24.3'; lts = $false }
    @{ cycle = '1'; eol = $past; latest = '1.2.17'; lts = $false }
) | ConvertTo-Json -Depth 8)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'eol-product' -Key 'log4j' -TtlDays 45 -Source 'test-legacy' `
    -Payload @{ found = $true; raw = $log4jRaw } | Out-Null

# format API v1 (result.releases, isEol/eolFrom)
$javaRaw = ConvertFrom-JsonCompat -Json (@{
    schema_version = '1.0.0'
    result = @{
        name = 'java'; label = 'Java'
        identifiers = @(@{ purl = 'pkg:generic/java' }, @{ cpe = 'cpe:2.3:a:oracle:jdk' })
        releases = @(
            @{ name = '21'; label = 'Java 21 LTS'; releaseDate = '2023-09-19'; isLts = $true; isEol = $false; eolFrom = $far; latest = @{ name = '21.0.5'; date = '2024-10-15'; link = 'https://example.invalid/21' } }
            @{ name = '17'; label = 'Java 17 LTS'; releaseDate = '2021-09-14'; isLts = $true; isEol = $false; eolFrom = $far; latest = @{ name = '17.0.13'; date = '2024-10-15' } }
            @{ name = '11'; label = 'Java 11 LTS'; releaseDate = '2018-09-25'; isLts = $true; isEol = $false; eolFrom = $soon; latest = @{ name = '11.0.25'; date = '2024-10-15' } }
            @{ name = '8';  label = 'Java 8';     releaseDate = '2014-03-18'; isLts = $true; isEol = $true;  eolFrom = $past; latest = @{ name = '8u432'; date = '2024-10-15' } }
        )
    }
} | ConvertTo-Json -Depth 12)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'eol-product' -Key 'java' -TtlDays 45 -Source 'test-v1' `
    -Payload @{ found = $true; raw = $javaRaw } | Out-Null

# ancien format (tableau de cycles, eol = date ou booleen)
$sbRaw = ConvertFrom-JsonCompat -Json (@(
    @{ cycle = '3.3'; releaseDate = '2024-11-21'; eol = $far; latest = '3.3.5'; lts = $false; support = $far }
    @{ cycle = '3.2'; releaseDate = '2023-11-23'; eol = $soon; latest = '3.2.11'; lts = $false; support = $past }
    @{ cycle = '2.7'; releaseDate = '2022-05-19'; eol = $past; latest = '2.7.18'; lts = $false; support = $past }
) | ConvertTo-Json -Depth 8)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'eol-product' -Key 'spring-boot' -TtlDays 10 -Source 'test-legacy' `
    -Payload @{ found = $true; raw = $sbRaw } | Out-Null

$tcRaw = ConvertFrom-JsonCompat -Json (@(
    @{ cycle = '11.0'; eol = $far; latest = '11.0.2'; lts = $false }
    @{ cycle = '10.1'; eol = $far; latest = '10.1.34'; lts = $false }
    @{ cycle = '9.0';  eol = $soon; latest = '9.0.97'; lts = $false }
    @{ cycle = '8.5';  eol = $past; latest = '8.5.100'; lts = $false }
) | ConvertTo-Json -Depth 8)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'eol-product' -Key 'tomcat' -TtlDays 10 -Source 'test-legacy' `
    -Payload @{ found = $true; raw = $tcRaw } | Out-Null

$djRaw = ConvertFrom-JsonCompat -Json (@(
    @{ cycle = '5.1'; eol = $far; latest = '5.1.3'; lts = $false }
    @{ cycle = '4.2'; eol = $soon; latest = '4.2.17'; lts = $true }
    @{ cycle = '3.2'; eol = $past; latest = '3.2.25'; lts = $true }
) | ConvertTo-Json -Depth 8)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'eol-product' -Key 'django' -TtlDays 10 -Source 'test-legacy' `
    -Payload @{ found = $true; raw = $djRaw } | Out-Null

# OSV : index paquet -> vulnerabilites
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-pkg' -Key 'npm|lodash' -TtlDays 1 -Source 'test' `
    -Payload @{ vulns = @(@{ id = 'GHSA-29mw-wpgm-hmr9'; modified = '2024-01-01T00:00:00Z' }) } | Out-Null
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-pkg' -Key 'PyPI|django' -TtlDays 1 -Source 'test' `
    -Payload @{ vulns = @(@{ id = 'GHSA-test-django'; modified = '2024-02-01T00:00:00Z' }) } | Out-Null

$v1 = ConvertFrom-JsonCompat -Json (@{
    id = 'GHSA-29mw-wpgm-hmr9'; modified = '2024-01-01T00:00:00Z'; published = '2020-04-28T00:00:00Z'
    aliases = @('CVE-2020-8203'); summary = 'Prototype pollution dans lodash'
    severity = @(@{ type = 'CVSS_V3'; score = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N' })
    affected = @(@{
        package = @{ ecosystem = 'npm'; name = 'lodash' }
        ranges = @(@{ type = 'SEMVER'; events = @(@{ introduced = '0' }, @{ fixed = '4.17.21' }) })
    })
    database_specific = @{ severity = 'HIGH' }
} | ConvertTo-Json -Depth 12)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-vuln' -Key 'GHSA-29mw-wpgm-hmr9' -TtlDays 3650 -Source 'test' `
    -Meta @{ modified = '2024-01-01T00:00:00Z' } -Payload $v1 | Out-Null

$v2 = ConvertFrom-JsonCompat -Json (@{
    id = 'GHSA-test-django'; modified = '2024-02-01T00:00:00Z'; published = '2023-05-03T00:00:00Z'
    aliases = @('CVE-2023-99999'); summary = 'Deni de service dans Django'
    severity = @(@{ type = 'CVSS_V3'; score = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' })
    affected = @(@{
        package = @{ ecosystem = 'PyPI'; name = 'django' }
        ranges = @(@{ type = 'ECOSYSTEM'; events = @(@{ introduced = '3.2' }, @{ fixed = '3.2.19' }, @{ introduced = '4.2' }, @{ fixed = '4.2.1' }) })
    })
} | ConvertTo-Json -Depth 12)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-vuln' -Key 'GHSA-test-django' -TtlDays 3650 -Source 'test' `
    -Meta @{ modified = '2024-02-01T00:00:00Z' } -Payload $v2 | Out-Null

# Cycle de vie publie (format deps.dev : versions + dates + depreciation)
function Set-Life([string]$System, [string]$Registry, [string]$Group, [string]$Name, $Payload) {
    $k = Get-EolKbCoordKey -Ecosystem "$System$Registry" -Group $Group -Name $Name
    Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'lifecycle' -Key $k -TtlDays 7 -Source 'test' -Payload $Payload | Out-Null
}
$old = $today.AddYears(-4).ToString('o')
$recent = $today.AddDays(-40).ToString('o')

Set-Life 'npm' 'npm' '' 'web-ui-kit' @{
    found = $true; source = 'deps.dev'; latest = '4.0.0'; latestPublished = $recent; deprecated = $false; reason = ''
    url = 'https://deps.dev/npm/web-ui-kit'
    versions = @(@{ v = '2.1.0'; p = $old; d = $false }, @{ v = '3.5.0'; p = $recent; d = $false }, @{ v = '4.0.0'; p = $recent; d = $false })
}
Set-Life 'npm' 'npm' '' 'lodash' @{
    found = $true; source = 'deps.dev'; latest = '4.17.21'; latestPublished = $old; deprecated = $false; reason = ''
    url = 'https://deps.dev/npm/lodash'
    versions = @(@{ v = '4.17.19'; p = $old; d = $false }, @{ v = '4.17.20'; p = $old; d = $false }, @{ v = '4.17.21'; p = $old; d = $false })
}
Set-Life 'npm' 'npm' '' 'left-pad' @{
    found = $true; source = 'deps.dev'; latest = '1.3.0'; latestPublished = $old; deprecated = $true
    reason = 'use String.prototype.padStart()'; url = 'https://deps.dev/npm/left-pad'
    versions = @(@{ v = '1.2.0'; p = $old; d = $true }, @{ v = '1.3.0'; p = $old; d = $true })
}
Set-Life 'pypi' 'PyPI' '' 'django' @{
    found = $true; source = 'deps.dev'; latest = '5.1.3'; latestPublished = $recent; deprecated = $false; reason = ''
    url = 'https://deps.dev/pypi/django'
    versions = @(@{ v = '3.2.18'; p = $old; d = $false }, @{ v = '3.2.19'; p = $old; d = $false },
                 @{ v = '3.2.25'; p = $old; d = $false }, @{ v = '4.2.1'; p = $recent; d = $false },
                 @{ v = '4.2.17'; p = $recent; d = $false }, @{ v = '5.1.3'; p = $recent; d = $false })
}
Set-Life 'maven' 'Maven' 'org.springframework.boot' 'spring-boot-starter-web' @{
    found = $true; source = 'deps.dev'; latest = '3.3.5'; latestPublished = $recent; deprecated = $false; reason = ''
    url = 'https://deps.dev/maven/org.springframework.boot%3Aspring-boot-starter-web'
    versions = @(@{ v = '2.7.18'; p = $old; d = $false }, @{ v = '3.2.11'; p = $recent; d = $false }, @{ v = '3.3.5'; p = $recent; d = $false })
}
Set-Life 'maven' 'Maven' 'org.apache.logging.log4j' 'log4j-1.2-api' @{
    found = $true; source = 'deps.dev'; latest = '2.24.3'; latestPublished = $recent; deprecated = $false; reason = ''
    url = 'https://deps.dev/maven/org.apache.logging.log4j%3Alog4j-1.2-api'
    versions = @(@{ v = '2.17.1'; p = $old; d = $false }, @{ v = '2.24.3'; p = $recent; d = $false })
}
Set-Life 'maven' 'Maven' 'commons-io' 'commons-io' @{
    found = $true; source = 'deps.dev'; latest = '2.20.0'; latestPublished = $old; deprecated = $false; reason = ''
    versions = @(@{ v = '2.11.0'; p = $old; d = $false }, @{ v = '2.20.0'; p = $old; d = $false })
}
Set-Life 'maven' 'Maven' 'org.legacy' 'legacy-utils' @{
    found = $true; source = 'deps.dev'; latest = '4.2.0'; latestPublished = $old; deprecated = $false; reason = ''
    versions = @(@{ v = '1.0.0'; p = $old; d = $false }, @{ v = '4.2.0'; p = $old; d = $false })
}
Set-Life 'maven' 'Maven' 'org.testing' 'test-harness' @{
    found = $true; source = 'deps.dev'; latest = '1.0.0'; latestPublished = $old; deprecated = $false; reason = ''
    versions = @(@{ v = '1.0.0'; p = $old; d = $false })
}
# CVE critique sur la dependance de test
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-pkg' -Key 'Maven|org.testing:test-harness' -TtlDays 1 -Source 'test' `
    -Payload @{ vulns = @(@{ id = 'GHSA-test-scope'; modified = '2024-03-01T00:00:00Z' }) } | Out-Null
$vTest = ConvertFrom-JsonCompat -Json (@{
    id = 'GHSA-test-scope'; modified = '2024-03-01T00:00:00Z'; aliases = @('CVE-2024-00001')
    summary = 'Execution de code dans un utilitaire de test'
    severity = @(@{ type = 'CVSS_V3'; score = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' })
    affected = @(@{ package = @{ ecosystem = 'Maven'; name = 'org.testing:test-harness' }
                    ranges = @(@{ type = 'ECOSYSTEM'; events = @(@{ introduced = '0' }) }) })
} | ConvertTo-Json -Depth 12)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-vuln' -Key 'GHSA-test-scope' -TtlDays 3650 -Source 'test' `
    -Meta @{ modified = '2024-03-01T00:00:00Z' } -Payload $vTest | Out-Null

# catalogue CISA KEV : la CVE de django y figure
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'nvd' -Key 'kev-catalog' -TtlDays 1 -Source 'test' `
    -Payload @{ cves = @{ 'CVE-2023-99999' = @{ dateAdded = '2024-02-15'; ransomware = 'Known' } } } | Out-Null

# composants absents des registres publics (internes) : reponse negative, pas "inconnu"
foreach ($n in @('internal-lib')) { Set-Life 'maven' 'Maven' 'com.acme' $n @{ found = $false; versions = @(); source = 'aucune-source' } }
for ($i = 1; $i -le 12; $i++) { Set-Life 'maven' 'Maven' 'com.example' "filler-lib-$i" @{ found = $false; versions = @(); source = 'aucune-source' } }
Set-Life 'maven' 'Maven' 'org.apache.tomcat.embed' 'tomcat-embed-core' @{
    found = $true; source = 'deps.dev'; latest = '11.0.2'; latestPublished = $recent; deprecated = $false; reason = ''
    url = 'https://deps.dev/maven/org.apache.tomcat.embed%3Atomcat-embed-core'
    versions = @(@{ v = '9.0.83'; p = $old; d = $false }, @{ v = '10.1.34'; p = $recent; d = $false }, @{ v = '11.0.2'; p = $recent; d = $false })
}

# Metadonnees editeur : depot declare par le paquet + faits GitHub
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'vendor' -Key (Get-EolKbCoordKey -Ecosystem 'repo-npm' -Group '' -Name 'web-ui-kit') `
    -TtlDays 14 -Source 'npm' -Payload @{ found = $true; repo = 'git+https://github.com/acme-corp/web-ui-kit.git'
        homepage = 'https://acme-corp.example/support/web-ui-kit'; abandoned = $false; replacement = ''; source = 'npm' } | Out-Null
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'vendor' -Key 'github|acme-corp/web-ui-kit' -TtlDays 14 -Source 'github' `
    -Payload @{ found = $true; archived = $false; pushedAt = $recent; homepage = 'https://acme-corp.example/support/web-ui-kit'
        htmlUrl = 'https://github.com/acme-corp/web-ui-kit'; owner = 'acme-corp'
        lastRelease = 'v4.0.0'; lastReleaseDate = $recent
        releasesByMajor = @{ '2' = $old; '3' = $recent; '4' = $recent } } | Out-Null
# paquet abandonne declare par l'editeur (left-pad)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'vendor' -Key (Get-EolKbCoordKey -Ecosystem 'repo-npm' -Group '' -Name 'left-pad') `
    -TtlDays 14 -Source 'npm' -Payload @{ found = $true; repo = 'https://github.com/left-pad-org/left-pad'
        homepage = ''; abandoned = $true; replacement = 'String.prototype.padStart'; source = 'npm' } | Out-Null
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'vendor' -Key 'github|left-pad-org/left-pad' -TtlDays 14 -Source 'github' `
    -Payload @{ found = $true; archived = $true; pushedAt = $old; homepage = ''
        htmlUrl = 'https://github.com/left-pad-org/left-pad'; owner = 'left-pad-org'
        lastRelease = 'v1.3.0'; lastReleaseDate = $old; releasesByMajor = @{ '1' = $old } } | Out-Null

# OSV mode precis : correspondance etablie par la source pour paquet@version
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-pkg-v' -Key 'npm|lodash@4.17.20' -TtlDays 1 -Source 'test' `
    -Payload @{ vulns = @(@{ id = 'GHSA-29mw-wpgm-hmr9'; modified = '2024-01-01T00:00:00Z' }) } | Out-Null
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-pkg-v' -Key 'PyPI|django@3.2.18' -TtlDays 1 -Source 'test' `
    -Payload @{ vulns = @(@{ id = 'GHSA-test-django'; modified = '2024-02-01T00:00:00Z' }) } | Out-Null

# Fiches pour la verification ciblee (-Cve)
$cveLog4j = ConvertFrom-JsonCompat -Json (@{
    id = 'CVE-2021-44228'; modified = '2024-01-01T00:00:00Z'; published = '2021-12-10T00:00:00Z'
    summary = 'Execution de code a distance via JNDI dans log4j-core'
    severity = @(@{ type = 'CVSS_V3'; score = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' })
    affected = @(@{
        package = @{ ecosystem = 'Maven'; name = 'org.apache.logging.log4j:log4j-1.2-api' }
        ranges = @(@{ type = 'ECOSYSTEM'; events = @(@{ introduced = '2.0' }, @{ fixed = '2.17.1' }) })
    })
} | ConvertTo-Json -Depth 12)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-vuln' -Key 'CVE-2021-44228' -TtlDays 3650 -Source 'test' `
    -Meta @{ modified = '2024-01-01T00:00:00Z' } -Payload $cveLog4j | Out-Null

$cveDjango = ConvertFrom-JsonCompat -Json (@{
    id = 'CVE-2023-41164'; modified = '2024-01-01T00:00:00Z'; published = '2023-09-04T00:00:00Z'
    summary = 'Deni de service par URI trop long dans Django'
    severity = @(@{ type = 'CVSS_V3'; score = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' })
    affected = @(@{
        package = @{ ecosystem = 'PyPI'; name = 'django' }
        ranges = @(@{ type = 'ECOSYSTEM'; events = @(@{ introduced = '3.2' }, @{ fixed = '3.2.21' }) })
    })
} | ConvertTo-Json -Depth 12)
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'osv-vuln' -Key 'CVE-2023-41164' -TtlDays 3650 -Source 'test' `
    -Meta @{ modified = '2024-01-01T00:00:00Z' } -Payload $cveDjango | Out-Null

# NVD : repli CVE pour openjdk (hors ecosysteme OSV), interroge par CPE
Set-EolKbCacheEntry -CacheRoot $cacheRoot -Namespace 'nvd' -Key 'nvd|cpe:2.3:a:oracle:jdk|' -TtlDays 2 -Source 'test' `
    -Payload @{ vulns = @(@{
        id = 'CVE-2024-21147'; summary = 'Vulnerabilite Oracle Java SE (Hotspot)'
        vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'; score = 7.4; published = '2024-07-16T00:00:00Z'
        matches = @(@{ criteria = 'cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*'; vsi = '11.0.0'; vse = ''; vei = '11.0.23'; vee = '' })
    }) } | Out-Null

# ---- execution --------------------------------------------------------
$sbom = Read-EolKbSbom -Path $sbomPath
$result = Invoke-EolKbAnalysis -Config $cfg -Sbom $sbom -RegistryLookup 'All' -Offline
$html = New-EolKbHtmlReport -Config $cfg -Result $result -OutDir $reportRoot -Prefix 'demo'
$csv = Export-EolKbCsv -Result $result -OutDir $reportRoot -Prefix 'demo'
$json = Export-EolKbJson -Result $result -OutDir $reportRoot -Prefix 'demo'
Write-EolKbConsoleReport -Config $cfg -Result $result

# ---- verifications ----------------------------------------------------
$fail = 0
function Check($label, $cond) {
    if ($cond) { Write-Host "  OK   $label" -ForegroundColor Green }
    else { Write-Host "  FAIL $label" -ForegroundColor Red; $script:fail++ }
}
Write-Host ''
Write-Host ' Verifications :' -ForegroundColor White
$byName = @{}
foreach ($f in $result.Findings) { $byName[$f.Name] = $f }

Check 'graphe detecte' ($result.GraphPresent)
Check 'deduplication lodash (2 occurrences)' ($byName['lodash'].Occurrences -eq 2)
Check 'spring-boot 2.7.18 -> hors support' ($byName['spring-boot-starter-web'].SupportStatus -eq 'eol')
Check 'spring-boot rattache au cycle 2.7' ($byName['spring-boot-starter-web'].Cycle -eq '2.7')
Check 'spring-boot : montee minimale proposee = 3.2.11' (@($byName['spring-boot-starter-web'].Recommendations | Where-Object { $_.Kind -eq 'montee-minimale' }).Version -eq '3.2.11')
Check 'openjdk 11.0.21 -> fin proche' ($byName['openjdk'].SupportStatus -eq 'eol_soon')
Check 'openjdk cible LTS proposee' (@($byName['openjdk'].Recommendations | Where-Object { $_.IsLts }).Count -gt 0)
Check 'tomcat 9.0.83 -> fin proche' ($byName['tomcat-embed-core'].SupportStatus -eq 'eol_soon')
Check 'django 3.2.18 -> hors support' ($byName['django'].SupportStatus -eq 'eol')
Check 'lodash : CVE detectee' ($byName['lodash'].VulnCount -eq 1)
Check 'lodash : CVE-2020-8203 identifiee' ($byName['lodash'].Vulns[0].Cve -eq 'CVE-2020-8203')
Check 'lodash : CVSS 5.9 calcule localement' ($byName['lodash'].MaxCvss -eq 5.9)
Check 'lodash : correctif propose 4.17.21' (@($byName['lodash'].Recommendations | Where-Object { $_.Kind -eq 'correctif-securite' }).Version -eq '4.17.21')
Check 'django : CVE detectee sur la plage 3.2-3.2.19' ($byName['django'].VulnCount -eq 1)
Check 'left-pad : depreciation remontee' ($byName['left-pad'].RegistryDeprecated)
Check 'left-pad : verdict = deprecie' ($byName['left-pad'].SupportStatus -eq 'deprecated')
Check 'composant interne exclu de toute requete externe' ($byName['internal-lib'].IsInternal -and $byName['internal-lib'].SupportStatus -eq 'internal_excluded')

# --- verdicts issus des sources en ligne, aucun "inconnu" ---------------
$known = @('eol', 'eol_soon', 'supported', 'deprecated', 'dormant', 'outdated_major',
           'outdated_minor', 'low_activity', 'maintained', 'version_unknown',
           'internal_or_unpublished', 'internal_excluded', 'collect_failed')
$orphelins = @($result.Findings | Where-Object { $_.SupportStatus -notin $known })
Check 'aucun constat sans verdict qualifie' ($orphelins.Count -eq 0)
Check 'aucun constat en attente d''enrichissement' (@($result.Findings | Where-Object { $_.SupportStatus -eq 'pending_enrichment' }).Count -eq 0)
Check 'chaque constat porte une source de verdict' (@($result.Findings | Where-Object { -not $_.VerdictSource }).Count -eq 0)
Check 'log4j-1.2-api rattache via identifiant purl' ($byName['log4j-1.2-api'].Product -eq 'log4j' -and $byName['log4j-1.2-api'].ProductConfidence -eq 'identifiant-purl')
Check 'lodash : dormant (derniere publication > 24 mois)' ($byName['lodash'].SupportStatus -eq 'dormant')
Check 'lodash : retard de version mesure' ($byName['lodash'].VersionsBehind -eq 1)
Check 'filler-lib-1 : declare interne / non publie' ($byName['filler-lib-1'].SupportStatus -eq 'internal_or_unpublished')
Check 'filler-lib-1 : verdict trace' ($byName['filler-lib-1'].VerdictSource -eq 'registres publics')
Check 'openjdk : CVE NVD detectee par plage CPE' (@($byName['openjdk'].Vulns | Where-Object { $_.Id -eq 'CVE-2024-21147' }).Count -eq 1)
Check 'openjdk : CVSS 7.4 calcule depuis le vecteur' ($byName['openjdk'].MaxCvss -eq 7.4)
Check 'tomcat : cible publiee proposee' (@($byName['tomcat-embed-core'].Recommendations).Count -gt 0)
Check 'dates de publication exploitees' ($null -ne $byName['django'].LatestPublished)
Check 'dependance directe identifiee (spring-boot)' ($byName['spring-boot-starter-web'].IsDirect)
Check 'transitif identifie (tomcat, profondeur 2)' ($byName['tomcat-embed-core'].Depth -eq 2)
Check 'log4j-1.2-api : nom avec chiffres accepte' ($byName['log4j-1.2-api'].SupportStatus -ne $null)
Check 'priorite 1 ou 2 sur spring-boot' ($byName['spring-boot-starter-web'].Priority -le 2)
Check 'rapport HTML produit' (Test-Path -LiteralPath $html)
Check 'CSV plan d''action produit' (Test-Path -LiteralPath $csv[0])
Check 'CSV obsolescence produit' (Test-Path -LiteralPath $csv[1])
Check 'CSV CVE produit' (Test-Path -LiteralPath $csv[2])
Check 'CSV plan d''action : colonnes de planification' ((Get-Content -LiteralPath $csv[0] -Raw) -match 'CibleTenable1An')
Check 'JSON produit' (Test-Path -LiteralPath $json)
$htmlTxt = Get-Content -LiteralPath $html -Raw
# autonome = aucune RESSOURCE chargee depuis le reseau (script, style, image) ;
# les liens hypertexte vers les sources restent evidemment autorises.
Check 'HTML autonome (aucune ressource externe chargee)' (($htmlTxt -notmatch '(?i)src\s*=\s*"https?://') -and ($htmlTxt -notmatch '(?i)<link[^>]+href\s*=\s*"https?://'))
Check 'HTML contient la vague d''obsolescence' ($htmlTxt -match 'Vague d')
Check 'aucun appel reseau en mode hors ligne' ((Get-EolKbStats).HttpOk -eq 0)

# --- consolidation : composants majeurs a piloter ----------------------
$levers = @($result.Levers)
$leverByName = @{}
foreach ($l in $levers) { $leverByName[$l.Name] = $l }
Check 'des leviers sont identifies' ($levers.Count -gt 0)
Check 'moins de leviers que de constats' ($levers.Count -lt $result.Findings.Count)
Check 'bruit d''inventaire ecarte (filler-lib non materiel)' (-not $byName['filler-lib-1'].ActionRequired)
Check 'CVE moyenne seule non materielle (lodash CVSS 5.9 mais dormant)' ($byName['lodash'].ActionRequired)
Check 'tomcat transitif consolide sous spring-boot' ($byName['tomcat-embed-core'].LeverName -eq 'spring-boot-starter-web')
Check 'lodash consolide sous web-ui-kit' ($byName['lodash'].LeverName -eq 'web-ui-kit')
Check 'left-pad consolide sous web-ui-kit' ($byName['left-pad'].LeverName -eq 'web-ui-kit')
Check 'levier web-ui-kit couvre 2 composants ou plus' ($leverByName['web-ui-kit'].CoveredCount -ge 2)
Check 'levier spring-boot porte une cible de montee' (@($leverByName['spring-boot-starter-web'].Recommendations).Count -gt 0)
Check 'CVE elevees comptees sur le levier' ($leverByName['openjdk'].HighCveCount -ge 1)
Check 'dependance directe = son propre levier' ($byName['django'].LeverName -eq 'django')

# --- editeur, double controle et projection ----------------------------
$ui = $leverByName['web-ui-kit']
Check 'editeur identifie pour un composant hors endoflife.date' ($ui.Vendor -and $ui.Vendor.Editor -eq 'acme-corp')
Check 'lien de support editeur remonte' ($ui.Vendor.SupportUrl -like 'https://acme-corp.example/*')
Check 'faits editeur dates (publications par branche majeure)' (@($ui.Vendor.Facts | Where-Object { $_ -like '*branche majeure 2*' }).Count -eq 1)
Check 'aucune date d''EOL inventee pour l''editeur' ($null -eq $ui.Finding.EolDate)
$lpVendor = Get-EolKbVendorLifecycle -Config $cfg -Finding $byName['left-pad'] -Offline
Check 'depot archive detecte comme fait editeur' ($lpVendor.Archived -and $lpVendor.Facts -match 'archive')
Check 'paquet declare abandonne par l''editeur' (@($lpVendor.Facts | Where-Object { $_ -like '*abandonne*' }).Count -eq 1)
Check 'double controle : cible confirmee sur 2 sources' ($leverByName['django'].Verification.Status -in @('confirme', 'non-verifiable'))
Check 'double controle renseigne sur chaque levier' (@($levers | Select-Object -First 5 | Where-Object { $null -eq $_.Verification }).Count -eq 0)
Check 'projection : echeance calculee' ($null -ne $leverByName['spring-boot-starter-web'].Projection.Deadline)
Check 'projection : cible tenable >= 1 an' ($leverByName['spring-boot-starter-web'].Projection.Sustainable)
Check 'projection : verdict de planification redige' ($leverByName['openjdk'].Projection.Verdict -like '*mois*')
Check 'projection presente dans le rapport HTML' ((Get-Content -LiteralPath $html -Raw) -match 'Projection de planification')

# --- tri du bruit sur un SBOM d'entreprise ------------------------------
Check 'bibliotheque stable et dormante : ecartee du plan (1 seul indice)' (-not $byName['commons-io'].ActionRequired)
Check 'retard cumule : retenu par faisceau d''indices' ($byName['legacy-utils'].ActionRequired -and $byName['legacy-utils'].SignalStrength -eq 'faible')
Check 'CVE critique de portee test : hors production' (-not $byName['test-harness'].InProduction)
Check 'CVE critique de portee test : ecartee du plan d''action' (-not $byName['test-harness'].ActionRequired)
Check 'portee test tracee dans les motifs' (@($byName['test-harness'].ActionReasons) -match 'test')
Check 'CVE exploitee (KEV) detectee' ($byName['django'].KevCount -ge 1)
Check 'CVE exploitee : priorite maximale' ($byName['django'].Priority -eq 1)
Check 'CVE exploitee : motif explicite' (@($byName['django'].ActionReasons) -match 'CISA KEV')
Check 'signal fort correctement qualifie' ($byName['django'].SignalStrength -eq 'fort')
Check 'plan d''action plus court que l''inventaire' (@($result.Levers).Count -lt ($result.Summary.Findings / 2))

# --- mode d'execution et fiabilite du rapprochement ---------------------
Check 'mode d''execution trace dans le resultat' ($result.Offline -and -not $result.Online)
Check 'mode de recherche de vulnerabilites resolu' ($result.VulnQueryMode -in @('Precise', 'PackageOnly'))
Check 'correspondance confirmee par la source (mode precis)' ($byName['lodash'].MatchMethod -eq 'osv-serveur')
Check 'CVE marquee confirmee par OSV et localement' ($byName['lodash'].Vulns[0].MatchConfidence -like 'confirmee-osv*')
Check 'repli local quand la source n''a pas repondu' ($byName['log4j-1.2-api'].MatchMethod -in @('', 'locale'))
Check 'bandeau de mode present dans le rapport' ((Get-Content -LiteralPath $html -Raw) -match 'Analyse hors ligne')

# --- verification ciblee d'une CVE (-Cve) -------------------------------
$checks = @(Invoke-EolKbCveCheck -Config $cfg -Sbom $sbom -CveIds @('CVE-2023-41164', 'CVE-2021-44228', 'CVE-1999-0001') -Findings $result.Findings -Offline)
$byCve = @{}
foreach ($c in $checks) { $byCve[$c.Id] = $c }
Check 'CVE ciblee : version vulnerable detectee' ($byCve['CVE-2023-41164'].Status -eq 'affecte')
Check 'CVE ciblee : composant nomme' (@($byCve['CVE-2023-41164'].Matches | Where-Object { $_.Finding.Name -eq 'django' }).Count -eq 1)
Check 'CVE ciblee : version corrective remontee' ($byCve['CVE-2023-41164'].FixedVersions -contains '3.2.21')
Check 'CVE ciblee : CVSS recalcule localement' ($byCve['CVE-2021-44228'].Cvss -eq 10.0)
Check 'CVE ciblee : paquet deja corrige declare non concerne' ($byCve['CVE-2021-44228'].Status -eq 'non-affecte')
Check 'CVE ciblee : identifiant inconnu signale sans conclusion' ($byCve['CVE-1999-0001'].Status -eq 'cve-inconnue')
Check 'CVE ciblee : reponse HTML generee' ((New-EolKbHtmlReport -Config $cfg -Result ($result | Add-Member -NotePropertyName CveChecks -NotePropertyValue $checks -Force -PassThru) -OutDir $reportRoot -Prefix 'demo-cve') -and ((Get-Content -LiteralPath (Join-Path $reportRoot 'demo-cve-rapport.html') -Raw) -match 'APPLICATION CONCERNEE'))

# --- versions proposees actives + liens de sources ----------------------
$djReco = @($byName['django'].Recommendations | Where-Object { $_.Source -eq 'endoflife.date' })[0]
Check 'version proposee qualifiee active' ($djReco.IsActive -eq $true)
Check 'activite justifiee par une date publiee' ($djReco.ActivityNote -match 'jusqu''au|publication')
Check 'projet actif : cible recente marquee active' (@($byName['web-ui-kit'].Recommendations)[0].IsActive -eq $true)
$dormantReco = @($byName['legacy-utils'].Recommendations)[0]
Check 'projet dormant : version proposee marquee non active' ($dormantReco.IsActive -eq $false)
Check 'projet dormant : remplacement suggere explicitement' ($dormantReco.ActivityNote -match 'remplacement')
Check 'aucune version active tracee dans les remarques' (@($byName['legacy-utils'].Notes) -match 'Aucune version active')
Check 'correctif de securite sur projet dormant : signale non actif' (@($byName['lodash'].Recommendations)[0].IsActive -eq $false)
Check 'lien composant construit' ((Get-EolKbComponentUrl -Finding $byName['lodash']) -like 'https://*')
Check 'lien version npm precise' ((Get-EolKbVersionUrl -Finding $byName['lodash'] -Version '4.17.21') -eq 'https://www.npmjs.com/package/lodash/v/4.17.21')
Check 'lien version maven precise' ((Get-EolKbVersionUrl -Finding $byName['spring-boot-starter-web'] -Version '3.2.11') -like 'https://central.sonatype.com/artifact/org.springframework.boot/spring-boot-starter-web/3.2.11')
$djEol = @($byName['django'].Recommendations | Where-Object { $_.Source -eq 'endoflife.date' })[0]
Check 'lien de la cible pointe vers l''editeur pour un produit suivi' ((Get-EolKbRecommendationUrl -Finding $byName['django'] -Recommendation $djEol) -like '*endoflife.date*')
Check 'lien de la cible pointe vers le registre pour un correctif' ((Get-EolKbRecommendationUrl -Finding $byName['lodash'] -Recommendation @($byName['lodash'].Recommendations)[0]) -like 'https://www.npmjs.com/package/lodash/v/*')
$htmlNow = Get-Content -LiteralPath $html -Raw
Check 'HTML : composants cliquables' ($htmlNow -match '<a href="https://[^"]+"[^>]*class="name"')
Check 'HTML : CVE cliquable depuis le tableau' ($htmlNow -match 'href="https://osv\.dev/vulnerability/')
Check 'HTML : marqueur de version active' ($htmlNow -match 'ACTIVE</span>')
Check 'HTML : liens ouverts dans un nouvel onglet' ($htmlNow -match 'rel="noopener"')

# --- SBOM plat (sans graphe) : regroupement par famille -----------------
$flat = [ordered]@{
    bomFormat = 'CycloneDX'; specVersion = '1.5'
    metadata = @{ component = @{ 'bom-ref' = 'flat'; name = 'flat-app'; version = '1.0.0'; type = 'application' } }
    components = @(
        @{ 'bom-ref' = 'f1'; group = 'org.springframework.boot'; name = 'spring-boot-starter-web'; version = '2.7.18'; purl = 'pkg:maven/org.springframework.boot/spring-boot-starter-web@2.7.18' }
        @{ 'bom-ref' = 'f2'; group = 'org.springframework.boot'; name = 'spring-boot-starter-json'; version = '2.7.18'; purl = 'pkg:maven/org.springframework.boot/spring-boot-starter-json@2.7.18' }
        @{ 'bom-ref' = 'f3'; group = 'org.springframework.boot'; name = 'spring-boot-autoconfigure'; version = '2.7.18'; purl = 'pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.7.18' }
    )
}
$flatPath = Join-Path $WorkDir 'bom-plat.json'
($flat | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $flatPath -Encoding UTF8
$flatSbom = Read-EolKbSbom -Path $flatPath
$flatResult = Invoke-EolKbAnalysis -Config $cfg -Sbom $flatSbom -RegistryLookup All -Offline
Check 'SBOM plat : absence de graphe detectee' (-not $flatResult.GraphPresent)
Check 'SBOM plat : les modules du meme groupe forment un seul levier' (@($flatResult.Levers).Count -eq 1)
Check 'SBOM plat : regroupement annonce comme famille de coordonnees' (@($flatResult.Levers)[0].LeverKind -eq 'famille')
Check 'SBOM plat : les 3 composants sont couverts' (@($flatResult.Levers)[0].CoveredCount -eq 3)

# --- confidentialite : ce qui sort et ce qui ne sort jamais -------------
# le contexte de confidentialite appartient au SBOM analyse : on retablit
# celui du SBOM principal apres l'analyse du SBOM plat.
Set-EolKbPrivacyContext -Secrets @($sbom.AppName, $sbom.AppVersion, $sbom.SerialNumber, $sbom.FileName) -InternalPrefixes @('com.acme')
$nvdUri = "$($cfg.Sources.NvdApi)?virtualMatchString=$([uri]::EscapeDataString('cpe:2.3:a:oracle:jdk'))&resultsPerPage=2000"
$nvdExempt = @(([uri]$cfg.Sources.NvdApi).AbsolutePath, 'cpe:2.3', 'cpe:2.3:a:oracle:jdk')
Check 'requete NVD autorisee' ((Get-EolKbLeakSuspects -Uri $nvdUri -ExemptTokens $nvdExempt).Count -eq 0)
Check 'requete deps.dev autorisee' ((Get-EolKbLeakSuspects -Uri "$($cfg.Sources.DepsDev)/maven/packages/$([uri]::EscapeDataString('org.apache.logging.log4j:log4j-1.2-api'))" -ExemptTokens @('org.apache.logging.log4j:log4j-1.2-api')).Count -eq 0)
Check 'requete OSV sans version autorisee' ((Get-EolKbLeakSuspects -Uri $cfg.Sources.OsvQueryBatch -Body '{"queries":[{"package":{"ecosystem":"npm","name":"lodash"}}]}' -ExemptTokens @('lodash')).Count -eq 0)
Check 'mode Balanced : version publique autorisee' ((Get-EolKbLeakSuspects -Uri 'https://api.deps.dev/v3/systems/npm/packages/lodash/versions/4.17.20' -Mode 'Balanced').Count -eq 0)
Check 'mode Strict : version bloquee' ((Get-EolKbLeakSuspects -Uri 'https://api.deps.dev/v3/systems/npm/packages/lodash/versions/4.17.20' -Mode 'Strict').Count -gt 0)
Check 'identite applicative toujours bloquee' ((Get-EolKbLeakSuspects -Uri 'https://api.deps.dev/v3/systems/npm/packages/demo-app' -Mode 'Balanced').Count -gt 0)
Check 'version applicative seule : pas de blocage a tort' ((Get-EolKbLeakSuspects -Uri "https://api.deps.dev/v3/systems/maven/packages/com.example%3Afiller-lib-4/versions/$($sbom.AppVersion)" -Mode 'Balanced').Count -eq 0)
Check 'fragment de nom : pas de blocage a tort' ((Get-EolKbLeakSuspects -Uri 'https://api.deps.dev/v3/systems/npm/packages/demo-application-utils' -Mode 'Balanced').Count -eq 0)
Check 'numero de serie du SBOM toujours bloque' ((Get-EolKbLeakSuspects -Uri 'https://x.example/q' -Body "{'bom':'$($sbom.SerialNumber)'}" -Mode 'Balanced').Count -gt 0)
Check 'coordonnee interne bloquee' ((Get-EolKbLeakSuspects -Uri "https://api.deps.dev/v3/systems/maven/packages/$([uri]::EscapeDataString('com.acme:internal-lib'))" -Mode 'Balanced').Count -gt 0)

Write-Host ''
if ($fail -eq 0) { Write-Host " Tous les tests passent. Rapport : $html" -ForegroundColor Green }
else { Write-Host " $fail test(s) en echec." -ForegroundColor Red; exit 1 }
