<#
.SYNOPSIS
    Socle commun : configuration, journalisation, JSON compatible 5.1/7.x,
    magasin de cache local, couche HTTP avec garde anti-fuite de version.
#>

$script:LogLevel   = 'INFO'
$script:LogFile    = $null
$script:MemCache   = @{}
$script:HostClock  = @{}
$script:Stats      = [ordered]@{ CacheHit = 0; CacheMiss = 0; CacheStale = 0; HttpOk = 0; HttpFail = 0; HttpBytes = 0; Blocked = 0 }
$script:Config     = $null

# ===================================================================
# Configuration
# ===================================================================
function Get-EolKbConfig {
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$Force
    )
    if ($script:Config -and -not $Force) { return $script:Config }
    if (-not $Path) { $Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'EolKb.Config.psd1' }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Fichier de configuration introuvable : $Path" }

    $cfg = Import-PowerShellDataFile -LiteralPath $Path
    $userHome = [Environment]::GetFolderPath('UserProfile')
    if (-not $userHome) { $userHome = $env:HOME }
    foreach ($k in @($cfg.Paths.Keys)) {
        $v = [Environment]::ExpandEnvironmentVariables([string]$cfg.Paths[$k])
        if ($v -match '%') {
            # Variable non resolue (poste verrouille, contexte de service) : repli sur le profil
            $v = Join-Path $userHome ($v -replace '%[^%]+%\\?', '')
        }
        $cfg.Paths[$k] = $v
    }
    $cfg['ConfigPath'] = (Resolve-Path -LiteralPath $Path).Path
    $cfg['RootPath']   = Split-Path -Parent $cfg['ConfigPath']
    $script:Config = $cfg
    return $cfg
}

function Set-EolKbLogging {
    [CmdletBinding()]
    param(
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [string]$LogFile
    )
    $script:LogLevel = $Level
    if ($LogFile) {
        $dir = Split-Path -Parent $LogFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $script:LogFile = $LogFile
    }
}

function Write-EolKbLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [switch]$NoConsole
    )
    $order = @{ DEBUG = 0; INFO = 1; WARN = 2; ERROR = 3 }
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$stamp [$Level] $Message"
    if ($script:LogFile) {
        try { [System.IO.File]::AppendAllText($script:LogFile, $line + [Environment]::NewLine) } catch { }
    }
    if ($NoConsole -or $order[$Level] -lt $order[$script:LogLevel]) { return }
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'DEBUG' { Write-Host $line -ForegroundColor DarkGray }
        default { Write-Host $line -ForegroundColor Gray }
    }
}

function Get-EolKbStats { return $script:Stats }

# ===================================================================
# JSON compatible PowerShell 5.1 / 7.x
#   5.1 : System.Web.Extensions (rapide, MaxJsonLength leve) -> Dictionary
#   7.x : ConvertFrom-Json -AsHashtable (System.Text.Json)   -> Hashtable
# Dans les deux cas l'acces se fait via Get-DictValue.
# ===================================================================
$script:Jss = $null
function ConvertFrom-JsonCompat {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Json)
    process {
        if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            return ($Json | ConvertFrom-Json -AsHashtable -Depth 64)
        }
        if (-not $script:Jss) {
            Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
            $script:Jss = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $script:Jss.MaxJsonLength = [int]::MaxValue
            $script:Jss.RecursionLimit = 256
        }
        return $script:Jss.DeserializeObject($Json)
    }
}

function ConvertTo-JsonCompat {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject, [int]$Depth = 24, [switch]$Compress)
    return ($InputObject | ConvertTo-Json -Depth $Depth -Compress:$Compress)
}

function Get-DictValue {
    <# Acces tolerant (Hashtable, Dictionary, PSCustomObject), insensible a la casse en second recours. #>
    [CmdletBinding()]
    param($Dict, [Parameter(Mandatory)][string]$Key, $Default = $null)
    if ($null -eq $Dict) { return $Default }
    if ($Dict -is [System.Collections.IDictionary]) {
        if ($Dict.Contains($Key)) {
            $v = $Dict[$Key]
            if ($null -eq $v) { return $Default }
            return $v
        }
        foreach ($k in $Dict.Keys) {
            if ([string]$k -ieq $Key) {
                $v = $Dict[$k]
                if ($null -eq $v) { return $Default }
                return $v
            }
        }
        return $Default
    }
    if ($Dict -is [System.Collections.Generic.IDictionary[string, object]]) {
        $out = $null
        if ($Dict.TryGetValue($Key, [ref]$out)) { return $out }
        return $Default
    }
    $p = $Dict.PSObject.Properties[$Key]
    if ($p) {
        if ($null -eq $p.Value) { return $Default }
        return $p.Value
    }
    return $Default
}

function Get-DictArray {
    <# Retourne toujours un tableau (jamais $null), utile pour les listes JSON. #>
    [CmdletBinding()]
    param($Dict, [string]$Key)
    $v = if ($Key) { Get-DictValue -Dict $Dict -Key $Key } else { $Dict }
    if ($null -eq $v) { return @() }
    if ($v -is [string]) { return @($v) }
    if ($v -is [System.Collections.IEnumerable]) { return @($v) }
    return @($v)
}

function Get-EolKbHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text, [int]$Length = 20)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant()))
        $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
        return $hex.Substring(0, [Math]::Min($Length, $hex.Length))
    } finally { $sha.Dispose() }
}

# ===================================================================
# Magasin de cache (base de connaissance locale)
#
# Choix de stockage : un fichier JSON par entree, reparti dans 256
# sous-dossiers (2 premiers caracteres du hash de la cle).
# Pourquoi pas un seul gros JSON : il faudrait le reserialiser en
# entier a chaque ecriture (des dizaines de Mo, risque de corruption
# en cas d'arret). Pourquoi pas SQLite : necessite un assembly non
# present par defaut et donc des droits d'installation.
# Ce format donne : ecriture atomique, TTL par entree, lecture O(1),
# purge selective, et diff/versionnement possible.
# ===================================================================
function Initialize-EolKbCache {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CacheRoot)
    foreach ($ns in @('eol-index', 'eol-product', 'registry', 'lifecycle', 'vendor', 'osv-pkg', 'osv-pkg-v', 'osv-vuln', 'nvd', 'mapping')) {
        $p = Join-Path $CacheRoot $ns
        if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
    $script:MemCache = @{}
    return $CacheRoot
}

function Get-EolKbCachePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CacheRoot, [Parameter(Mandatory)][string]$Namespace, [Parameter(Mandatory)][string]$Key)
    $h = Get-EolKbHash -Text $Key
    $shard = $h.Substring(0, 2)
    $dir = Join-Path (Join-Path $CacheRoot $Namespace) $shard
    return (Join-Path $dir "$h.json")
}

function Get-EolKbCacheEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CacheRoot,
        [Parameter(Mandatory)][string]$Namespace,
        [Parameter(Mandatory)][string]$Key,
        [double]$OverrideTtlDays = -1
    )
    $memKey = "$Namespace|$Key"
    if ($script:MemCache.ContainsKey($memKey)) { return $script:MemCache[$memKey] }

    $path = Get-EolKbCachePath -CacheRoot $CacheRoot -Namespace $Namespace -Key $Key
    if (-not (Test-Path -LiteralPath $path)) { $script:Stats.CacheMiss++; return $null }
    try {
        $raw = [System.IO.File]::ReadAllText($path)
        $obj = ConvertFrom-JsonCompat -Json $raw
    } catch {
        Write-EolKbLog -Level WARN -Message "Entree de cache illisible, suppression : $path"
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        $script:Stats.CacheMiss++
        return $null
    }
    $fetchedAt = [datetime]::MinValue
    try { $fetchedAt = [datetime]::Parse([string](Get-DictValue $obj 'fetchedAt'), [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) } catch { }
    $ttl = [double](Get-DictValue $obj 'ttlDays' 7)
    if ($OverrideTtlDays -ge 0) { $ttl = $OverrideTtlDays }
    $age = ([datetime]::UtcNow - $fetchedAt.ToUniversalTime()).TotalDays

    $entry = [pscustomobject]@{
        Namespace = $Namespace
        Key       = $Key
        Payload   = (Get-DictValue $obj 'payload')
        Meta      = (Get-DictValue $obj 'meta')
        Source    = [string](Get-DictValue $obj 'source')
        FetchedAt = $fetchedAt
        TtlDays   = $ttl
        AgeDays   = [Math]::Round($age, 3)
        Fresh     = ($age -le $ttl)
        Path      = $path
    }
    if ($entry.Fresh) { $script:Stats.CacheHit++ } else { $script:Stats.CacheStale++ }
    $script:MemCache[$memKey] = $entry
    return $entry
}

function Set-EolKbCacheEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CacheRoot,
        [Parameter(Mandatory)][string]$Namespace,
        [Parameter(Mandatory)][string]$Key,
        $Payload,
        [double]$TtlDays = 7,
        [string]$Source = '',
        $Meta = $null
    )
    $path = Get-EolKbCachePath -CacheRoot $CacheRoot -Namespace $Namespace -Key $Key
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $doc = [ordered]@{
        schema    = 1
        namespace = $Namespace
        key       = $Key
        source    = $Source
        fetchedAt = [datetime]::UtcNow.ToString('o')
        ttlDays   = $TtlDays
        meta      = $Meta
        payload   = $Payload
    }
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, (ConvertTo-JsonCompat -InputObject $doc -Depth 32 -Compress))
    Move-Item -LiteralPath $tmp -Destination $path -Force

    $script:MemCache["$Namespace|$Key"] = [pscustomobject]@{
        Namespace = $Namespace; Key = $Key; Payload = $Payload; Meta = $Meta; Source = $Source
        FetchedAt = [datetime]::UtcNow; TtlDays = $TtlDays; AgeDays = 0; Fresh = $true; Path = $path
    }
    return $path
}

function Get-EolKbCacheSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CacheRoot)
    $rows = @()
    foreach ($ns in (Get-ChildItem -LiteralPath $CacheRoot -Directory -ErrorAction SilentlyContinue)) {
        $files = @(Get-ChildItem -LiteralPath $ns.FullName -Filter '*.json' -Recurse -File -ErrorAction SilentlyContinue)
        $size = 0
        $oldest = $null
        if ($files.Count -gt 0) {
            $size = ($files | Measure-Object -Property Length -Sum).Sum
            $oldest = ($files | Sort-Object LastWriteTimeUtc | Select-Object -First 1).LastWriteTimeUtc
        }
        $rows += [pscustomobject]@{
            Namespace = $ns.Name
            Entries   = $files.Count
            SizeKB    = [Math]::Round($size / 1KB, 1)
            OldestUtc = $oldest
        }
    }
    return $rows
}

function Clear-EolKbCache {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CacheRoot, [string]$Namespace = '*', [int]$OlderThanDays = -1)
    $target = Join-Path $CacheRoot $Namespace
    $files = @(Get-ChildItem -Path $target -Filter '*.json' -Recurse -File -ErrorAction SilentlyContinue)
    if ($OlderThanDays -ge 0) {
        $limit = (Get-Date).AddDays(-$OlderThanDays)
        $files = @($files | Where-Object { $_.LastWriteTime -lt $limit })
    }
    $n = $files.Count
    $files | Remove-Item -Force -ErrorAction SilentlyContinue
    $script:MemCache = @{}
    return $n
}

# ===================================================================
# Anti-fuite : aucune version ne doit sortir
# ===================================================================
function Test-EolKbVersionLeak {
    <# Retourne les motifs ressemblant a une version dans une chaine sortante. #>
    [CmdletBinding()]
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $m = [regex]::Matches($Text, '\d+\.\d+(\.\d+)*')
    return @($m | ForEach-Object { $_.Value })
}

$script:Secrets = @()
$script:InternalPrefixes = @()

function Set-EolKbPrivacyContext {
    <#
    .SYNOPSIS
        Declare ce qui ne doit JAMAIS sortir du poste : identite de
        l'application, identifiants du SBOM, chemins, et prefixes de
        coordonnees internes. Toute requete contenant l'un de ces jetons
        est bloquee et tracee, quel que soit le mode de confidentialite.
    #>
    [CmdletBinding()]
    param([string[]]$Secrets = @(), [string[]]$InternalPrefixes = @())
    # Un simple numero de version n'identifie personne et se retrouve
    # legitimement dans les coordonnees publiques : le proteger provoquerait
    # des blocages a tort. Ce qui identifie, c'est le NOM de l'application,
    # le numero de serie du SBOM, la machine, le compte.
    $script:Secrets = @($Secrets |
        Where-Object { $_ -and ([string]$_).Length -ge 5 } |
        Where-Object { ([string]$_) -notmatch '^[vV]?\d+(\.\d+)*[-\w.]*$' } |
        ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)
    $script:InternalPrefixes = @($InternalPrefixes | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)
    Write-EolKbLog -Level DEBUG -Message "Confidentialite : $($script:Secrets.Count) jeton(s) proteges, $($script:InternalPrefixes.Count) espace(s) de noms interne(s)"
}

function Get-EolKbPrivacyContext {
    return @{ Secrets = $script:Secrets; InternalPrefixes = $script:InternalPrefixes }
}

function Test-EolKbInternalCoordinate {
    <# Vrai si la coordonnee appartient a un espace de noms interne. #>
    [CmdletBinding()]
    param([string]$Group, [string]$Name, [string[]]$Prefixes)
    $list = $Prefixes
    if (-not $list -or $list.Count -eq 0) { $list = $script:InternalPrefixes }
    if (-not $list -or $list.Count -eq 0) { return $false }
    $g = ([string]$Group).ToLowerInvariant()
    $n = ([string]$Name).ToLowerInvariant()
    foreach ($p in $list) {
        $pp = ([string]$p).ToLowerInvariant()
        if (-not $pp) { continue }
        if ($g -and ($g -eq $pp -or $g.StartsWith($pp))) { return $true }
        if ($n -and $n.StartsWith($pp)) { return $true }
    }
    return $false
}

function Get-EolKbLeakSuspects {
    <#
    .SYNOPSIS
        Motifs de version presents dans une requete sortante, apres retrait
        des jetons d'identification publics declares exempts (nom de paquet
        contenant des chiffres, prefixe CPE, numero d'API dans le chemin).
        Un resultat non vide = requete a bloquer.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri, [string]$Body, [string[]]$ExemptTokens = @(), [string]$Mode = 'Balanced')
    $scanUri = ([uri]$Uri).PathAndQuery
    $scanBody = [string]$Body
    foreach ($t in $ExemptTokens) {
        if ([string]::IsNullOrEmpty($t)) { continue }
        foreach ($form in @($t, [uri]::EscapeDataString($t))) {
            $scanUri = $scanUri.Replace($form, '')
            $scanBody = $scanBody.Replace($form, '')
        }
    }
    $out = @()
    # 1) donnees sensibles : bloquees dans TOUS les modes
    $hay = ($scanUri + ' ' + $scanBody).ToLowerInvariant()
    foreach ($sec in $script:Secrets) {
        # correspondance sur jeton entier : evite qu'un fragment commun
        # declenche un blocage sans raison
        if ($hay -match ('(?<![\w.-])' + [regex]::Escape($sec) + '(?![\w.-])')) { $out += "identite:$sec" }
    }
    foreach ($pfx in $script:InternalPrefixes) {
        if ($hay.Contains($pfx)) { $out += "interne:$pfx" }
    }
    # 2) versions : bloquees uniquement en mode Strict
    if ($Mode -eq 'Strict') {
        $out += Test-EolKbVersionLeak -Text $scanUri
        if ($scanBody) { $out += Test-EolKbVersionLeak -Text $scanBody }
    }
    return @($out)
}

function Write-EolKbAudit {
    <# Journal des appels sortants : trace uniquement l'URI et la coordonnee
       publique, jamais la version ni l'identite applicative. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AuditLog,
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [string]$Purpose = '',
        [int]$Status = 0,
        [int]$Bytes = 0,
        [string[]]$LeakSuspects = @()
    )
    $dir = Split-Path -Parent $AuditLog
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $rec = [ordered]@{
        ts = [datetime]::UtcNow.ToString('o'); method = $Method; uri = $Uri
        purpose = $Purpose; status = $Status; bytes = $Bytes
        leakSuspects = @($LeakSuspects)
    }
    try { [System.IO.File]::AppendAllText($AuditLog, (ConvertTo-JsonCompat -InputObject $rec -Depth 5 -Compress) + [Environment]::NewLine) } catch { }
}

# ===================================================================
# Couche HTTP
# ===================================================================
function Initialize-EolKbNetwork {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config)
    if ($Config.Network.ForceTls12) {
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
        } catch { }
    }
    try { [System.Net.ServicePointManager]::DefaultConnectionLimit = 16 } catch { }
}

function Get-EolKbProxyArgs {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Config)
    $pArgs = @{}
    $proxy = [string]$Config.Network.Proxy
    if (-not $proxy) {
        foreach ($v in @('HTTPS_PROXY', 'HTTP_PROXY', 'https_proxy', 'http_proxy')) {
            $e = [Environment]::GetEnvironmentVariable($v)
            if ($e) { $proxy = $e; break }
        }
    }
    if ($proxy) {
        $pArgs['Proxy'] = $proxy
        if ($Config.Network.ProxyUseDefaultCredentials) { $pArgs['ProxyUseDefaultCredentials'] = $true }
    }
    return $pArgs
}

function Invoke-EolKbRequest {
    <#
    .SYNOPSIS
        Appel HTTP unique et controle : garde anti-fuite, throttling par hote,
        reprise sur erreur, journal d'audit. Retourne un objet JSON deserialise
        (ou le texte brut avec -Raw).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [string]$Body,
        [hashtable]$Headers,
        [string]$Purpose = '',
        [string[]]$ExemptTokens = @(),
        [switch]$AllowVersion,
        [switch]$Raw,
        [switch]$TolerateNotFound
    )
    # --- Garde de confidentialite -----------------------------------
    $mode = [string]$Config.Privacy.Mode
    if (-not $mode) { $mode = 'Balanced' }
    $suspects = Get-EolKbLeakSuspects -Uri $Uri -Body $Body -ExemptTokens $ExemptTokens -Mode $mode
    if ($suspects.Count -gt 0) {
        $script:Stats.Blocked++
        Write-EolKbAudit -AuditLog $Config.Paths.AuditLog -Uri $Uri -Method $Method -Purpose $Purpose -Status -1 -LeakSuspects $suspects
        $motif = 'donnee sensible'
        if ($mode -eq 'Strict' -and @($suspects | Where-Object { $_ -notlike 'identite:*' -and $_ -notlike 'interne:*' }).Count -gt 0) { $motif = 'version (mode Strict)' }
        throw "CONFIDENTIALITE : requete bloquee, $motif detecte dans la charge sortante ($($suspects -join ', ')). URI=$Uri"
    }

    # --- Throttling par hote ----------------------------------------
    $h = ([uri]$Uri).Host
    $minGap = [int]$Config.Network.ThrottleMsPerHost
    if ($script:HostClock.ContainsKey($h)) {
        $elapsed = ([datetime]::UtcNow - $script:HostClock[$h]).TotalMilliseconds
        if ($elapsed -lt $minGap) { Start-Sleep -Milliseconds ([int]($minGap - $elapsed)) }
    }
    $script:HostClock[$h] = [datetime]::UtcNow

    $hdr = @{ 'User-Agent' = [string]$Config.Network.UserAgent; 'Accept' = 'application/json' }
    if ($Headers) { foreach ($k in $Headers.Keys) { $hdr[$k] = $Headers[$k] } }

    $params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $hdr
        TimeoutSec      = [int]$Config.Network.TimeoutSec
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if ($Method -eq 'POST') { $params['Body'] = $Body; $params['ContentType'] = 'application/json' }
    foreach ($kv in (Get-EolKbProxyArgs -Config $Config).GetEnumerator()) { $params[$kv.Key] = $kv.Value }

    $delay = [int]$Config.Network.RetryDelayMs
    $maxTry = [int]$Config.Network.MaxRetry
    for ($try = 1; $try -le $maxTry; $try++) {
        try {
            $resp = Invoke-WebRequest @params
            $content = [string]$resp.Content
            $script:Stats.HttpOk++
            $script:Stats.HttpBytes += $content.Length
            Write-EolKbAudit -AuditLog $Config.Paths.AuditLog -Uri $Uri -Method $Method -Purpose $Purpose -Status 200 -Bytes $content.Length
            if ($Raw) { return $content }
            return (ConvertFrom-JsonCompat -Json $content)
        } catch {
            $status = 0
            try { $status = [int]$_.Exception.Response.StatusCode.value__ } catch { }
            if ($status -eq 404 -or $status -eq 410) {
                Write-EolKbAudit -AuditLog $Config.Paths.AuditLog -Uri $Uri -Method $Method -Purpose $Purpose -Status $status
                if ($TolerateNotFound) { return $null }
                throw "HTTP $status sur $Uri"
            }
            $retryable = ($status -eq 0 -or $status -eq 408 -or $status -eq 429 -or $status -ge 500)
            if (-not $retryable -or $try -eq $maxTry) {
                $script:Stats.HttpFail++
                Write-EolKbAudit -AuditLog $Config.Paths.AuditLog -Uri $Uri -Method $Method -Purpose $Purpose -Status $status
                throw "Echec HTTP ($status) sur $Uri : $($_.Exception.Message)"
            }
            Write-EolKbLog -Level DEBUG -Message "Nouvel essai ($try/$maxTry) apres $delay ms sur $Uri (statut $status)"
            Start-Sleep -Milliseconds $delay
            $delay = $delay * 2
        }
    }
}

Export-ModuleMember -Function Get-EolKbConfig, Set-EolKbLogging, Write-EolKbLog, Get-EolKbStats,
    ConvertFrom-JsonCompat, ConvertTo-JsonCompat, Get-DictValue, Get-DictArray, Get-EolKbHash,
    Initialize-EolKbCache, Get-EolKbCachePath, Get-EolKbCacheEntry, Set-EolKbCacheEntry,
    Get-EolKbCacheSummary, Clear-EolKbCache, Test-EolKbVersionLeak, Get-EolKbLeakSuspects, Write-EolKbAudit,
    Set-EolKbPrivacyContext, Get-EolKbPrivacyContext, Test-EolKbInternalCoordinate,
    Initialize-EolKbNetwork, Get-EolKbProxyArgs, Invoke-EolKbRequest
