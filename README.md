# eol-scan — analyse d'obsolescence d'un SBOM CycloneDX

Détecte les composants **hors support** ou **bientôt en fin de support** à partir d'un SBOM CycloneDX,
propose des **versions cibles encore supportées**, remonte les **CVE et scores CVSS**, et produit un
rapport HTML autonome + exports CSV/JSON.

Conçu pour un poste Windows verrouillé : PowerShell 5.1 ou 7.x, aucun droit admin, proxy d'entreprise,
**aucune version ni identité applicative transmise à l'extérieur**.

---

## 1. Prérequis

| Élément | Détail |
|---|---|
| PowerShell | 5.1 (intégré à Windows) ou 7.x |
| Droits | aucun (tout s'écrit dans `%LOCALAPPDATA%` et `Documents`) |
| Réseau | HTTPS vers `endoflife.date`, `api.osv.dev` et les registres de paquets, via le proxy du poste |

Débloquer les fichiers après copie (fichiers téléchargés = marqués « bloqués » par Windows) :

```powershell
Get-ChildItem -Recurse .\eol-scan | Unblock-File
```

Si l'exécution de scripts est refusée, lancer sans modifier la politique machine :

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json
```

---

## 2. Utilisation

```powershell
# analyse simple (le chemin est demandé s'il n'est pas fourni)
.\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json

# suis-je concerné par cette vulnérabilité ? (réponse en quelques secondes)
.\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -Cve CVE-2021-44228 -CveOnly

# plusieurs CVE, en même temps que l'analyse complète
.\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -Cve CVE-2021-44228,CVE-2022-22965

# consulter les registres pour tous les composants (première passe plus longue)
.\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -RegistryLookup All

# hors ligne : uniquement la base de connaissance locale (mode dégradé, signalé dans le rapport)
.\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -Mode Offline

# forcer le rafraîchissement des données de plus de 7 jours
.\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -RefreshOlderThanDays 7
```

Principaux paramètres : `-Mode Online|Offline`, `-VulnQueryMode Auto|Precise|PackageOnly`,
`-Cve`, `-CveOnly`, `-PrivacyMode Balanced|Strict`, `-InternalNamespace`,
`-OutputDir`, `-RegistryLookup None|Needed|All`, `-Offline`, `-NoVulns`, `-MinCvss 8.0`,
`-IncludeAllInHtml`, `-OpenReport`, `-LogLevel DEBUG`.

### Mode en ligne (défaut) et mode hors ligne

| | `-Mode Online` (défaut) | `-Mode Offline` |
|---|---|---|
| Sources | interrogées à chaque analyse | aucune, cache local uniquement |
| Fiabilité | données du jour | dépend de l'ancienneté du cache |
| Données manquantes | collectées | signalées « collecte impossible », jamais supposées |
| Rapport | bandeau « Analyse en ligne » | bandeau « Analyse hors ligne » bien visible |

Une analyse est **en ligne par défaut** : le mode hors ligne doit être demandé explicitement, et il
est alors annoncé en tête du rapport pour que personne ne prenne un rapport daté pour un rapport frais.

### Fiabilité du rapprochement des vulnérabilités

`-VulnQueryMode` choisit qui établit la correspondance entre une version et une plage vulnérable :

| Mode | Ce qui sort | Fiabilité |
|---|---|---|
| `Precise` | nom du paquet **+ version** | **la source (OSV) tranche**, puis le résultat est recoupé avec l'évaluation locale ; toute divergence est signalée dans le rapport |
| `PackageOnly` | nom du paquet seul | toutes les plages sont rapatriées et évaluées sur le poste |
| `Auto` (défaut) | — | `Precise` en confidentialité `Balanced`, `PackageOnly` en `Strict` |

Le mode `Precise` supprime le risque d'interpréter à tort une plage de versions (pré-versions,
versions Maven qualifiées, écosystèmes aux règles particulières). Chaque CVE du rapport porte sa
méthode de correspondance : `confirmee-osv+locale`, `confirmee-osv (divergence locale)` ou `locale`.

Si un lot de requêtes est bloqué par la garde de confidentialité (collision entre une coordonnée
publique et un jeton protégé), il est **rejoué coordonnée par coordonnée** : seule la coordonnée en
cause est écartée, et elle est nommée dans le journal.

### Vérifier une vulnérabilité précise

`-Cve` répond à la question « cette application est-elle concernée ? ». La fiche est récupérée
auprès d'OSV, avec repli sur NVD pour les CVE que OSV ne couvre pas, puis **confrontée localement**
aux composants du SBOM. Cinq réponses possibles, jamais d'approximation :

| Réponse | Signification |
|---|---|
| `APPLICATION CONCERNEE` | un composant est dans une plage de versions déclarée vulnérable — la liste et les versions correctives sont données |
| `NON CONCERNEE` | le paquet visé est présent, dans une version hors des plages publiées |
| `COMPOSANT ABSENT DU SBOM` | aucun composant ne correspond au paquet ou produit visé |
| `INDETERMINE` | le paquet est présent mais le SBOM ne porte pas sa version : la question reste ouverte |
| `VULNERABILITE INCONNUE DES SOURCES` | l'identifiant n'est connu ni d'OSV ni de NVD — aucune conclusion n'est tirée |

```
==========================================================================
 CVE-2023-41164 : APPLICATION CONCERNEE
==========================================================================
 CVSS   : 7.5 (ELEVEE)
 1 composant(s) du SBOM se trouvent dans une plage de versions declaree vulnerable.

Composant Version Corrigee
django    3.2.18  3.2.21
```

Avec `-CveOnly`, seule cette vérification est faite. Sans ce commutateur, la réponse s'ajoute en
tête du rapport HTML, avant l'analyse d'obsolescence.

Sorties (dans `%USERPROFILE%\Documents\EolKb\reports`) :

- `<app>-<horodatage>-rapport.html` — rapport autonome (aucune ressource externe, ouvrable hors ligne)
- `<app>-<horodatage>-obsolescence.csv` — inventaire complet, séparateur `;` pour Excel FR
- `<app>-<horodatage>-cve.csv` — une ligne par CVE
- `<app>-<horodatage>-analyse.json` — résultat structuré pour outillage

---

## 3. Chaîne de sources : chaque composant reçoit un verdict

Les sources sont interrogées **en cascade**, jusqu'à obtenir une conclusion.
Aucun composant ne ressort en « inconnu » : soit une source répond, soit il est déclaré
interne, soit l'échec de collecte est nommé.

**Rattachement à un produit suivi (calendrier de support éditeur)**

1. table interne `data\ProductMap.psd1` ;
2. **identifiants purl publiés par endoflife.date** (`/api/v1/identifiers/purl/`) — rattachement
   automatique, sans intervention manuelle ;
3. nom exact d'un produit suivi ;
4. variantes normalisées du nom (`-core`, `.js`, `_`, scope npm `@angular/core` → `angular`) ;
5. segments du groupe Maven (`org.eclipse.jetty` → `jetty`) ;
6. préfixes connus.

**Cycle de vie publié** (pour tout le reste, soit la majorité des bibliothèques)

- **deps.dev** (Google Open Source Insights) : toutes les versions publiées **avec leur date**
  et leur état de dépréciation, en un appel ne portant que le nom public du paquet ;
- repli automatique sur le registre natif (npm, PyPI, Maven Central, NuGet, RubyGems, Go, crates, Packagist).

**Vulnérabilités**

- **OSV** pour les écosystèmes de paquets (interrogé sans version) ;
- **NVD** en repli pour les composants hors écosystème (runtimes, OS, produits) : interrogé par
  identifiant CPE du produit — repris de la fiche endoflife.date — ou par nom, jamais par version ;
  les plages CPE sont comparées localement à la version installée.

**Statuts possibles**

| Statut | Signification | Source du verdict |
|---|---|---|
| `eol` / `eol_soon` / `supported` | calendrier de support de l'éditeur | endoflife.date |
| `deprecated` | paquet marqué déprécié | deps.dev / registre |
| `dormant` | plus aucune publication depuis > 24 mois | deps.dev / registre |
| `outdated_major` | au moins une version majeure de retard | deps.dev / registre |
| `outdated_minor` | retard mineur ou version installée ancienne | deps.dev / registre |
| `low_activity` | à jour, mais plus de publication depuis > 12 mois | deps.dev / registre |
| `maintained` | dernière version, projet actif | deps.dev / registre |
| `version_unknown` | le SBOM ne porte pas la version du composant | SBOM |
| `internal_or_unpublished` | absent de tous les registres publics interrogés → composant interne | registres publics |
| `collect_failed` | aucune source n'a pu être jointe (réseau, proxy, mode hors ligne) | collecte |

Les trois axes restent **séparés**, jamais fusionnés en un verdict unique : support / maintenance,
sécurité (CVE + CVSS), publication (dernière version, dates).

**Règle qui prime sur toutes les autres : ne jamais afficher une information non vérifiée.**
Une date de fin de support provient d'une source qui la publie, jamais d'une extrapolation ;
une version cible non recoupée est signalée comme telle ; un composant inconnu des sources est
déclaré interne plutôt que supposé.

Règles appliquées :

- **Aucune donnée inventée.** Une version n'est proposée que si elle est publiée par la source
  (dernier correctif d'un cycle supporté, ou version présente au registre).
- **La version proposée doit être vivante.** Chaque cible porte un marqueur `ACTIVE` / `NON ACTIVE`
  justifié par une date : « Cycle supporté jusqu'au 15/11/2026 » (calendrier éditeur) ou
  « Branche active : dernière publication il y a 2 mois » (publications observées). Si le projet
  n'a plus rien publié depuis `DormantMonths`, la cible est marquée **NON ACTIVE** et le rapport
  écrit qu'il faut envisager un remplacement plutôt que de faire croire à une montée utile.
- **Toutes les sources sont cliquables.** Nom du composant, version installée, version cible et
  identifiant de CVE renvoient vers la page qui publie l'information : registre
  (npmjs.com, PyPI, Maven Central, NuGet, RubyGems, crates.io, Packagist, pkg.go.dev),
  fiche produit endoflife.date, dépôt éditeur, fiche OSV ou NVD. Les exports CSV portent les
  colonnes `LienComposant`, `LienVersionCible` et `CibleActive`, le JSON porte `url` et `active`
  sur chaque recommandation.
- **Aucune revendication sans preuve.** Sans graphe `dependencies` dans le SBOM, aucun lien
  parent/enfant n'est affirmé et la notion de dépendance directe est signalée comme indisponible.
- Les constats non concluants sont listés en clair dans une section dédiée plutôt que comblés.

---

## 4. Trier le bruit d'un SBOM d'entreprise

Sur un SBOM Maven de plusieurs milliers de composants, la difficulté n'est pas de trouver des
anomalies : c'est de ne pas en trouver trop. Le tri se fait en trois passes.

### 4.1 La portée d'abord

Un composant de portée `test`, `provided`, `optional` ou `excluded` n'est pas embarqué à
l'exécution : **une CVE critique dessus n'expose pas l'application**. Ces composants sont exclus du
plan d'action et listés dans une section séparée (« Écartés du plan d'action : composants hors
exécution »). La portée est lue dans le champ `scope` CycloneDX **et** dans les propriétés de
l'outil (`cdx:maven:package:scope`, que pose le plugin CycloneDX Maven).

### 4.2 Signaux forts contre faisceau d'indices

| Niveau | Signal | Effet |
|---|---|---|
| **Fort** | vulnérabilité **exploitée en conditions réelles** (catalogue CISA KEV) | priorité 1, quelle que soit la note CVSS |
| **Fort** | CVE de score ≥ 7.0 (réglable par `-MinCvss`) | porté à l'action |
| **Fort** | fin de support publiée par l'éditeur (`eol`, `eol_soon`) | porté à l'action |
| **Fort** | paquet déprécié par l'éditeur, dépôt archivé | porté à l'action |
| Faible | plus aucune publication depuis 24 mois (`dormant`) | 1 indice |
| Faible | retard de version (majeur ou mineur), faible activité | 1 indice |
| Faible | CVE de score inférieur au seuil | 1 indice |
| Faible | ≥ 2 versions majeures de retard | 1 indice |

**Un signal fort suffit. Il faut au moins deux indices faibles** (`WeakSignalsRequired`).

C'est le réglage qui fait la différence sur un SBOM réel : `commons-io` qui n'a rien publié depuis
quatre ans n'est pas obsolète, c'est une bibliothèque terminée — un seul indice, elle ne remonte
pas. En revanche `legacy-utils`, dormante **et** trois majeures en retard, remonte avec la mention
« faisceau d'indices ». Le score EPSS (probabilité d'exploitation à 30 jours) est affiché à côté de
chaque CVE pour arbitrer.

### 4.3 Regroupement sous les composants à piloter

Les constats retenus sont rattachés à la dépendance de premier niveau qui les commande, par
**analyse de dominance** (algorithme itératif de Cooper-Harvey-Kennedy) sur le graphe
`dependencies`. Monter ce composant est l'action qui conditionne la mise à niveau de tous ceux
qu'il domine.

**Si le SBOM n'a pas de graphe** (scanner de système de fichiers, SBOM plat), aucun lien
parent/enfant n'est affirmé : le regroupement se fait alors par **famille de coordonnées**
(groupId Maven, portée npm) et il est annoncé comme tel dans le rapport. Trois modules
`org.springframework.boot:*` deviennent une seule ligne à traiter, sans prétendre qu'il existe
entre eux une relation de dépendance.

Résultat typique : quelques milliers de composants → quelques dizaines de constats matériels →
une dizaine de composants à piloter, chacun avec sa version cible.

```
8 constat(s) materiel(s) sur 24, regroupes en 5 levier(s) :

Levier                  Version Couverts CVE>=7 Cible                                 Echeance
django                  3.2.18         1      1 3.2.19 (corrige les CVE detectees)    echeance depassee
spring-boot-starter-web 2.7.18         2      0 3.2.11 (support jusqu'au 15/11/2026)  T4 2026
```

Deux garde-fous :

- un levier **conditionne** la mise à niveau des composants qu'il domine ; il n'est **pas** affirmé
  que sa montée de version les corrige — la vérification demande de comparer le SBOM produit après
  montée de version ;
- rien n'est jamais supprimé de l'inventaire : les composants écartés du plan d'action restent
  intégralement dans les exports CSV et JSON, avec la raison de leur mise à l'écart
  (`AActionner`, `MotifAction`, `ForceDuSignal`, `EnProduction`).

---

## 5. Éditeur, double contrôle et projection

### 5.1 Chercher l'éditeur quand endoflife.date ne couvre pas le composant

Pour les composants sans calendrier de support publié (cas d'un produit éditeur type Ibexa, ou
d'une bibliothèque), le script remonte jusqu'à l'éditeur, **automatiquement** :

1. métadonnées publiques du paquet → dépôt source et page d'accueil déclarés par l'éditeur
   (npm `/latest`, PyPI `project_urls`, Packagist, POM Maven, NuGet) ;
2. si le dépôt est sur GitHub → faits publiés par l'éditeur : **projet archivé**, date de la
   **dernière publication**, et **dernière correction publiée sur la branche majeure utilisée par
   l'application** ;
3. signal d'abandon déclaré au registre (`deprecated` npm, `abandoned` Packagist) et son
   remplacement recommandé.

**Ce qui n'est jamais fait** : déduire une date de fin de support à partir de ces éléments.
Une date d'EOL n'est affichée que si une source la **publie** (endoflife.date). Sinon le rapport
donne les faits datés, le nom de l'organisation éditrice et le **lien vers sa page de support**,
étiquetés « à qualifier ». Un composant dont le dépôt est archivé est en revanche déclaré
`deprecated` : c'est un fait publié par l'éditeur, pas une déduction.

Jeton facultatif : `Sources.GitHubToken` dans la configuration (60 → 5000 appels/heure).

### 5.2 Double contrôle avant publication du rapport

Chaque version cible est **recoupée sur une source indépendante de celle qui l'a produite** :
une cible issue de deps.dev ou d'endoflife.date est vérifiée contre le registre natif, et
inversement. Quatre résultats possibles, affichés en clair dans le plan d'action :

| Statut | Signification |
|---|---|
| `confirmée (2 sources)` | la version cible est publiée d'après deux sources indépendantes |
| `source unique` / `non recoupée` | une seule source disponible — à contrôler avant planification |
| `divergence à lever` | la cible annoncée est absente du registre — **elle n'est pas présentée comme sûre** |
| `sans cible` | aucune version cible n'a pu être établie |

Les CVE portent également leur source (`OSV` ou `NVD`), ce qui permet de tracer chaque score CVSS.

### 5.3 Projection de planification à un an

Pour chaque composant levier, le rapport calcule :

- **l'échéance de traitement** : la plus proche fin de support parmi les composants qu'il couvre,
  avec son trimestre (`T4 2026`), et un niveau d'urgence (dépassée / immédiate / cette année / à planifier) ;
- **la durée de support restante après montée** pour la version cible ;
- la **conséquence** : une cible n'est jugée tenable que si elle reste supportée au moins
  `PlanningHorizonDays` (365 j). Sinon le rapport annonce dès maintenant la seconde montée :
  *« la meilleure cible publiée n'est supportée que 7 mois — prévoir une seconde montée avant le 15/11/2026 »*.

Si l'horizon n'est pas publié par la source, c'est écrit tel quel (« à confirmer auprès de
l'éditeur »), jamais estimé.

---

## 6. Autonomie : aucune base interne à maintenir

Le script n'a **pas besoin qu'un administrateur alimente une base de composants** :

- le rattachement composant → produit suivi utilise la **table d'identifiants purl publiée par
  endoflife.date**, rafraîchie automatiquement (TTL 30 j) ;
- les versions publiées et leurs dates viennent de **deps.dev / registres**, interrogés à la volée ;
- les CVE viennent d'**OSV** et de **NVD** ;
- l'éditeur est découvert via les **métadonnées du paquet** puis son **dépôt source** ;
- les composants majeurs sont déterminés par **analyse du graphe de dépendances du SBOM**,
  sans liste maintenue à la main ;
- le cache local se met à jour tout seul à l'expiration des TTL, pendant les analyses ordinaires.

`data\ProductMap.psd1` n'est donc **pas** une base à tenir à jour : c'est un fichier de
**correction ponctuelle**, utile seulement pour arbitrer un cas particulier (composant interne
assimilé à un produit public, groupe Maven maison). Le script fonctionne sans y toucher.

---

## 7. Confidentialité : ce qui sort, ce qui ne sort jamais

Les appels sortants sont assumés : ils portent des **coordonnées publiques**, déjà connues de tous
(nom de produit, nom de paquet publié, et selon le mode son numéro de version). Ce qui est protégé,
c'est ce dont la divulgation renseignerait un attaquant sur l'entreprise.

**Ne sort jamais, quel que soit le mode :**

| Donnée | Pourquoi |
|---|---|
| nom et version de l'application | associer une application à ses vulnérabilités est l'information la plus sensible du SBOM |
| numéro de série et nom de fichier du SBOM | corrèle plusieurs requêtes à une même application |
| nom de machine et de compte | expose l'environnement interne |
| composants des espaces de noms internes | révèle l'architecture et le nommage internes |

Toute requête contenant l'un de ces jetons est **bloquée avant émission**, comptée et tracée dans le
journal d'audit — la garde s'applique quel que soit le code appelant.

**Deux modes :**

| Mode | Coordonnées publiques | Versions publiques dans une requête |
|---|---|---|
| `Balanced` (défaut) | oui | oui (permet le POM Maven, les fiches de version, les vérifications précises) |
| `Strict` | oui | non — toute la correspondance de version reste locale |

```powershell
.\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -PrivacyMode Strict
.\Invoke-SbomEolScan.ps1 -SbomPath .\bom.json -InternalNamespace 'com.masociete','@masociete'
```

Les composants internes sont **exclus de toute requête externe** et reçoivent le statut
« Interne : non transmis à l'extérieur ». Le groupe du composant applicatif du SBOM est ajouté
automatiquement à cette liste (`Privacy.DetectInternalFromSbom`).

Traçabilité : `%LOCALAPPDATA%\EolKb\audit\outbound.jsonl` contient un enregistrement JSON par
appel (horodatage, méthode, URI, statut, octets, motif de blocage éventuel) — vérifiable par
l'équipe sécurité.

---

## 8. Base de connaissance locale

`%LOCALAPPDATA%\EolKb\cache\<espace>\<xx>\<hash>.json`

**Un fichier JSON par entrée**, réparti dans 256 sous-dossiers (2 premiers caractères du hash SHA1
de la clé). Écriture atomique (`.tmp` + `Move`), TTL embarqué dans l'entrée, mémo en RAM pendant
l'exécution.

Pourquoi ce format : un JSON monolithique devrait être réécrit intégralement à chaque mise à jour
(dizaines de Mo, risque de corruption sur interruption) ; SQLite exige un assembly absent du poste
par défaut. Ici : lecture O(1), purge sélective, aucune dépendance.

Espaces de noms : `eol-index`, `eol-product`, `registry`, `lifecycle`, `vendor`, `osv-pkg`,
`osv-pkg-v`, `osv-vuln`, `nvd`, `mapping`.

### Calibrage des TTL

| Donnée | TTL | Justification |
|---|---|---|
| Index des produits endoflife.date | 30 j | la liste des produits bouge de façon marginale |
| Fiche produit (EOL lointain) | 45 j | un cycle ou une date d'EOL n'apparaît qu'au rythme mensuel/trimestriel |
| Fiche produit (EOL < 180 j) | 10 j | la décision devient sensible : on resserre |
| Fiche produit (tous cycles morts) | 180 j | une date d'EOL passée ne redevient jamais supportée |
| Produit inconnu (cache négatif) | 21 j | évite de re-tester en boucle des coordonnées non rattachables |
| Registre de paquets | 7 j | publication de correctifs hebdomadaire |
| Registre, composant vulnérable | 3 j | il faut le dernier correctif disponible |
| Index OSV paquet → CVE | 1 j | de nouvelles CVE sortent quotidiennement |
| Index OSV paquet@version → CVE | 1 j | même rythme, mode `Precise` |
| CVE NVD par produit | 2 j | même rythme, volume par requête plus lourd |
| Dépôt / métadonnées éditeur | 14 j | archivage et page de support changent rarement |
| Catalogue CISA KEV | 1 j | mis à jour au fil des exploitations constatées |
| Score EPSS | 7 j | recalculé quotidiennement, évolution lente hors pic |
| Versions publiées (deps.dev) | 7 j | publication de correctifs hebdomadaire (3 j si CVE) |
| Identifiants purl endoflife.date | 30 j | table de correspondance stable |
| Fiche d'une CVE | invalidation par `modified` | la fiche est immuable : `querybatch` renvoie déjà son horodatage, une fiche inchangée n'est jamais retéléchargée (coût : 0 requête) |

### Entretien / phase de préchauffage

```powershell
.\Update-EolKbCache.ps1 -Status                          # volumétrie, entrées périmées, TTL, audit
.\Update-EolKbCache.ps1 -Warm -SbomPath C:\sboms\*.json  # préchauffage avant une campagne
.\Update-EolKbCache.ps1 -Refresh                         # réinterroge uniquement le périmé
.\Update-EolKbCache.ps1 -Refresh -IncludeRegistries
.\Update-EolKbCache.ps1 -Purge -OlderThanDays 180
```

Cadence conseillée (tâche planifiée, session utilisateur) :

| Fréquence | Commande | Effet |
|---|---|---|
| quotidienne | `-Refresh` | index OSV (TTL 1 j) et fiches proches de l'EOL à jour |
| hebdomadaire | `-Refresh -IncludeRegistries` | dernières versions publiées |
| mensuelle | `-Purge -OlderThanDays 180` | élimine les coordonnées disparues du parc |

Création de la tâche :

```powershell
$a = New-ScheduledTaskAction -Execute 'powershell.exe' `
     -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\outils\eol-scan\Update-EolKbCache.ps1" -Refresh'
Register-ScheduledTask -TaskName 'EolKb-Refresh' -Action $a `
     -Trigger (New-ScheduledTaskTrigger -Daily -At 7am)
```

Avec un cache chaud, une analyse de SBOM de ~55 000 lignes se termine sans appel réseau notable :
les composants déjà vus ne sont plus jamais réinterrogés avant expiration de leur TTL.

---

## 9. Performance sur gros SBOM

- Parsing : `ConvertFrom-Json -AsHashtable` (PowerShell 7) ou `JavaScriptSerializer` avec
  `MaxJsonLength` relevé (PowerShell 5.1) — les deux renvoient des dictionnaires, l'accès est unifié.
- Déduplication en **constats** `coordonnée@version` : plusieurs milliers de composants se réduisent
  typiquement à quelques centaines de coordonnées à enrichir.
- OSV interrogé **par lots de 100** coordonnées.
- Collecte des versions publiées selon `-RegistryLookup` : `All` (défaut) interroge tous les
  composants pour qu'aucun ne reste sans verdict ; `Needed` limite aux composants à enjeu
  (CVE, EOL, non rattaché, dépendance directe) et va plus vite sur un premier passage.
- Barres de progression limitées à un événement toutes les 400 ms (évite le figement de la console).

---

## 10. Ajuster un rattachement

Le rattachement est automatique via les identifiants purl publiés par endoflife.date. La table
interne ne sert qu'à **corriger ou compléter** les cas particuliers (produit interne assimilé à un
produit public, groupe Maven maison, etc.) — ajouter une entrée dans
`data\ProductMap.psd1` :

```powershell
'maven:org.acme.framework:*'   = 'spring-boot'   # tout le groupe
'npm:@acme/ui'                 = 'angular'
'monruntime'                   = 'java'          # tous écosystèmes
```

Tout slug est **validé contre l'index endoflife.date** au moment de l'analyse : un slug inexistant
est ignoré (aucune donnée inventée), le composant reste simplement non rattaché.

---

## 11. Arborescence

```
eol-scan\
  Invoke-SbomEolScan.ps1     point d'entrée : analyse + rapports
  Update-EolKbCache.ps1      état / préchauffage / rafraîchissement / purge du cache
  EolKb.Config.psd1          chemins, proxy, TTL, seuils, confidentialité, sources
  data\ProductMap.psd1       correspondances coordonnée -> produit endoflife.date
  lib\
    EolKb.Common.psm1        config, log, JSON 5.1/7.x, cache, HTTP + garde anti-fuite
    EolKb.Version.psm1       comparaison de versions, plages OSV, cycles, calcul CVSS v3.x
    EolKb.Sources.psm1       endoflife.date, registres (npm/PyPI/Maven/NuGet/…), OSV
    EolKb.Analyze.psm1       lecture SBOM, graphe, statuts, versions cibles, priorités
    EolKb.Vendor.psm1        dépôt source, faits éditeur (archivage, publications)
    EolKb.Consolidate.psm1   matérialité, leviers (dominance), double contrôle, projection
    EolKb.Report.psm1        HTML autonome, CSV, JSON, synthèse console
  tests\Test-Offline.ps1     jeu de tests hors ligne (118 vérifications)
```

Vérifier l'installation :

```powershell
.\tests\Test-Offline.ps1
```
