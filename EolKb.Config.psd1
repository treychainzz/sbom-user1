@{
    # ------------------------------------------------------------------
    # Chemins (les variables %VAR% sont resolues au chargement)
    # ------------------------------------------------------------------
    Paths = @{
        CacheRoot  = '%LOCALAPPDATA%\EolKb\cache'
        ReportRoot = '%USERPROFILE%\Documents\EolKb\reports'
        AuditLog   = '%LOCALAPPDATA%\EolKb\audit\outbound.jsonl'
        RunLog     = '%LOCALAPPDATA%\EolKb\logs'
    }

    # ------------------------------------------------------------------
    # Reseau / proxy d'entreprise
    # ------------------------------------------------------------------
    Network = @{
        UserAgent              = 'eol-kb-scanner/1.0 (+internal inventory tool)'
        TimeoutSec             = 30
        MaxRetry               = 3
        RetryDelayMs           = 1200      # delai initial, double a chaque essai
        ThrottleMsPerHost      = 250       # 4 req/s max par hote
        Proxy                  = ''        # vide = variables d'env HTTP(S)_PROXY puis proxy systeme
        ProxyUseDefaultCredentials = $true # NTLM/Kerberos du poste
        ForceTls12             = $true     # requis sur PowerShell 5.1
    }

    # ------------------------------------------------------------------
    # POLITIQUE DE FRAICHEUR (TTL en jours)
    #
    # Justification du calibrage (mesure du rythme reel de changement
    # de chaque source, cf. README section "Calibrage des TTL") :
    #  - endoflife.date : une fiche produit change quand un nouveau cycle
    #    sort ou quand une date d'EOL est annoncee => rythme mensuel a
    #    trimestriel. 45 j suffit pour un cycle confortable, mais on
    #    resserre a 10 j quand l'EOL approche (la decision devient
    #    sensible), et on relache a 180 j pour un cycle deja mort
    #    (une date d'EOL passee ne redevient jamais supportee).
    #  - registres (npm/PyPI/Maven/NuGet...) : publication de patchs
    #    quotidienne a hebdomadaire => 7 j (3 j si le composant est
    #    vulnerable, on a besoin du dernier patch).
    #  - OSV : nouvelles CVE tous les jours => index paquet->CVE a 1 j.
    #    En revanche la FICHE d'une CVE est immuable : on l'invalide non
    #    par TTL mais par comparaison du champ 'modified' renvoye par
    #    querybatch (cout : 0 requete supplementaire).
    # ------------------------------------------------------------------
    Ttl = @{
        EolProductIndex     = 30    # liste des produits endoflife.date
        EolProductDefault   = 45    # fiche produit, EOL lointain
        EolProductNearEol   = 10    # fiche produit, EOL dans < 180 j
        EolProductDead      = 180   # fiche produit, cycle deja EOL
        EolNegative         = 21    # produit inconnu (cache negatif)
        Registry            = 7     # metadonnees paquet
        RegistryVulnerable  = 3     # idem si CVE presente
        RegistryNegative    = 14
        OsvPackageIndex     = 1     # paquet -> liste d'IDs de vulns
        OsvVulnRecord       = 3650  # fiche vuln : invalidee par 'modified'
        ProductMapping      = 14    # resolution coordonnee -> produit EOL
        EolIdentifiers      = 30    # table purl/cpe -> produit endoflife.date
        DepsDev             = 7     # versions publiees + dates (deps.dev)
        NvdIndex            = 2     # CVE NVD par produit (composants hors ecosysteme OSV)
        Vendor              = 14    # depot / metadonnees editeur (change lentement)
        Kev                 = 1     # catalogue CISA des vulnerabilites exploitees
        Epss                = 7     # probabilite d'exploitation (EPSS)
    }

    # ------------------------------------------------------------------
    # Seuils d'analyse
    # ------------------------------------------------------------------
    Thresholds = @{
        EolSoonDays      = 180   # "bientot en fin de support"
        EolCriticalDays  = 90    # passe en priorite haute
        # Cycle de vie OBSERVE, utilise quand l'editeur ne publie pas de
        # calendrier de support (cas de la majorite des bibliotheques) :
        # ces seuils qualifient l'activite reelle de publication du paquet.
        StaleMonths      = 12    # aucune publication depuis N mois -> "peu actif"
        DormantMonths    = 24    # aucune publication depuis N mois -> "dormant"
        VersionAgeMonths = 36    # version installee plus ancienne que N mois -> alerte
        # --- Materialite : ce qui est porte a l'action -----------------
        # Sur un SBOM de plusieurs milliers de composants, seuls sont
        # remontes les constats repondant a l'un de ces deux criteres.
        ActionableCvss     = 7.0   # CVE ELEVEE (>=7) ou CRITIQUE (>=9)

        # SIGNAUX FORTS : un seul suffit a porter le composant a l'action.
        # Ce sont des faits publies par un editeur ou une source d'autorite.
        StrongSignalStatuses = @('eol', 'eol_soon', 'deprecated')

        # SIGNAUX FAIBLES : sur un SBOM Maven de plusieurs milliers de
        # composants, "plus publie depuis 2 ans" ou "une majeure de retard"
        # decrivent souvent une bibliotheque stable et terminee, pas une
        # obsolescence. Il en faut donc PLUSIEURS pour porter a l'action.
        WeakSignalStatuses  = @('dormant', 'outdated_major', 'outdated_minor', 'low_activity')
        WeakSignalsRequired = 2

        # Portees reellement embarquees en production. Une CVE sur une
        # dependance de test n'expose pas l'application : elle est listee
        # a part, jamais dans le plan d'action.
        ActionableScopes = @('required', 'runtime', 'compile', 'implementation', '')
        IgnoredScopes    = @('test', 'provided', 'optional', 'excluded', 'system', 'dev', 'development', 'testimplementation')

        # Conserve pour compatibilite : union des signaux forts
        ActionableStatuses = @('eol', 'eol_soon', 'deprecated')
        MaxLevers          = 15    # nb de composants leviers presentes en tete de rapport
        # --- Projection / planification -------------------------------
        # Une montee de version n'est jugee tenable que si la cible reste
        # supportee au moins ce delai : sinon il faudra replanifier.
        PlanningHorizonDays     = 365
        PlanningHorizonLongDays = 730
        # Nb max de composants leviers pour lesquels on interroge l'editeur
        # et on croise les sources (limite les appels sortants).
        DeepCheckMaxLevers      = 25
        CvssReportMin    = 0.0   # score minimal remonte dans le rapport CVE
        MaxRecommendations = 3   # nb max de versions proposees par composant
    }

    # ------------------------------------------------------------------
    # Confidentialite / anti-fuite
    # ------------------------------------------------------------------
    Privacy = @{
        # ------------------------------------------------------------------
        # Ce qui est protege : ce dont la divulgation renseignerait un
        # attaquant sur l'entreprise. Ce qui ne l'est pas : les coordonnees
        # publiques des composants, deja connues de tous.
        #
        #  Mode = 'Balanced' (defaut)
        #     Sortent : nom de produit, nom de paquet public, et si besoin
        #     leur numero de version (deja publique cote registre).
        #     Ne sortent JAMAIS : nom et version de l'application, numero de
        #     serie du SBOM, chemins, noms de machines, et toute coordonnee
        #     appartenant a un espace de noms interne.
        #
        #  Mode = 'Strict'
        #     Idem, plus aucune version dans une requete sortante : la
        #     correspondance de version est alors integralement locale.
        #     A utiliser si la politique interne interdit de reveler
        #     qu'un couple (paquet, version) est recherche.
        # ------------------------------------------------------------------
        Mode = 'Balanced'

        # Espaces de noms internes : aucune requete externe n'est emise pour
        # ces composants (leur nom revelerait l'architecture interne).
        # Ex : 'com.masociete', '@masociete', 'MaSociete.'
        InternalNamespaces = @()

        # Ajoute automatiquement le groupe du composant applicatif du SBOM
        # a la liste ci-dessus.
        DetectInternalFromSbom = $true

        # Mode de recherche de vulnerabilites :
        #  'Auto'        (defaut) Precise si Mode=Balanced, PackageOnly si Strict
        #  'Precise'     la version est transmise a OSV : c'est la SOURCE qui
        #                etablit la correspondance, ce qui supprime tout risque
        #                d'interpretation locale d'une plage de versions.
        #                Le resultat est en plus recoupe avec l'evaluation
        #                locale : toute divergence est signalee dans le rapport.
        #  'PackageOnly' seul le nom du paquet est transmis, la correspondance
        #                de version est faite sur le poste.
        VulnQueryMode = 'Auto'

        # Ne jamais journaliser l'identite applicative dans l'audit sortant
        AuditIncludeAppIdentity = $false

        # Le POM Maven n'est adressable que par version : la recherche du
        # depot editeur utilise la DERNIERE version PUBLIQUE du registre,
        # jamais celle de l'application.
        AllowPublicLatestInPath = $true
    }

    # ------------------------------------------------------------------
    # Sources externes
    # ------------------------------------------------------------------
    Sources = @{
        EolApiV1        = 'https://endoflife.date/api/v1/products'
        EolApiLegacy    = 'https://endoflife.date/api'
        EolIdentifiers  = 'https://endoflife.date/api/v1/identifiers'
        # deps.dev (Google Open Source Insights) : liste des versions publiees
        # AVEC leur date de publication et leur statut de depreciation, en un
        # seul appel ne portant que le nom public du paquet.
        DepsDev         = 'https://api.deps.dev/v3/systems'
        # NVD : repli CVE pour les composants hors ecosysteme OSV (runtimes,
        # OS, produits). Interroge par produit/CPE, jamais par version.
        NvdApi          = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        NvdApiKey       = ''     # optionnel : leve la limite a 50 req/30 s
        # Depot editeur : faits publies (projet archive, publications par
        # branche majeure). Sert a qualifier les composants que
        # endoflife.date ne suit pas, SANS jamais deduire de date d'EOL.
        GitHubApi       = 'https://api.github.com'
        GitHubToken     = ''     # optionnel : passe de 60 a 5000 appels/heure
        # Catalogue CISA des vulnerabilites EXPLOITEES en conditions reelles :
        # le signal le plus fort pour prioriser. Fichier unique, aucun
        # parametre, donc aucune information sur l'entreprise n'en ressort.
        KevFeed         = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        # EPSS : probabilite d'exploitation sous 30 jours, par identifiant CVE.
        EpssApi         = 'https://api.first.org/data/v1/epss'
        OsvQueryBatch   = 'https://api.osv.dev/v1/querybatch'
        OsvVuln         = 'https://api.osv.dev/v1/vulns'
        OsvBatchSize    = 100
        Registries = @{
            npm      = 'https://registry.npmjs.org'
            PyPI     = 'https://pypi.org/pypi'
            Maven    = 'https://repo1.maven.org/maven2'
            NuGet    = 'https://api.nuget.org/v3-flatcontainer'
            RubyGems = 'https://rubygems.org/api/v1/versions'
            Go       = 'https://proxy.golang.org'
            crates   = 'https://crates.io/api/v1/crates'
            Packagist= 'https://repo.packagist.org/p2'
        }
    }

    # purl type -> ecosysteme OSV + registre interne
    Ecosystems = @{
        maven    = @{ Osv = 'Maven';     Registry = 'Maven';     DepsDev = 'maven' }
        npm      = @{ Osv = 'npm';       Registry = 'npm';       DepsDev = 'npm' }
        pypi     = @{ Osv = 'PyPI';      Registry = 'PyPI';      DepsDev = 'pypi' }
        nuget    = @{ Osv = 'NuGet';     Registry = 'NuGet';     DepsDev = 'nuget' }
        gem      = @{ Osv = 'RubyGems';  Registry = 'RubyGems';  DepsDev = 'rubygems' }
        golang   = @{ Osv = 'Go';        Registry = 'Go';        DepsDev = 'go' }
        cargo    = @{ Osv = 'crates.io'; Registry = 'crates';    DepsDev = 'cargo' }
        composer = @{ Osv = 'Packagist'; Registry = 'Packagist'; DepsDev = '' }
        deb      = @{ Osv = 'Debian';    Registry = '';          DepsDev = '' }
        rpm      = @{ Osv = '';          Registry = '';          DepsDev = '' }
        apk      = @{ Osv = 'Alpine';    Registry = '';          DepsDev = '' }
        generic  = @{ Osv = '';          Registry = '';          DepsDev = '' }
    }
}
