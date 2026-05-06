Documentation Technique : script.js (OSBOM)
Ce document décrit l'architecture logicielle et les fonctionnalités embarquées dans le fichier JavaScript principal de l'application OSBOM (Obsolescence SBOM).

1. Architecture Globale
L'application est construite en Vanilla JavaScript (sans framework comme React ou Vue). Elle repose sur une architecture orientée événements et s'exécute entièrement côté client (Frontend).

Asynchronisme : Utilisation intensive de async/await pour gérer les multiples requêtes HTTP (APIs externes).

Stockage : Utilisation exclusive du localStorage du navigateur pour la persistance des données (profils, historique, règles d'apprentissage).

Performances : Implémentation d'un cache local (cache) pour éviter de requêter plusieurs fois la même dépendance lors du traitement d'un SBOM, et traitement par lots (Batch) pour ne pas figer l'interface.

2. Variables d'État Globales
Le script maintient l'état de l'application via plusieurs variables globales critiques :

appProfiles / currentProfileId : Gère les espaces de travail isolés.

activeWorkspace : Contient les composants (BOM) et dépendances actuellement affichés.

customEolDb : Dictionnaire local contenant les règles EOL manuelles créées par l'utilisateur.

pendingOrphans : Map agissant comme un "sas d'attente" pour les composants non reconnus.

validEolSlugs : Set contenant la liste officielle de tous les produits supportés par l'API endoflife.date.

3. Les Modules Principaux
3.1. Import et Traitement du SBOM (processSbom)
C'est le cœur du réacteur. Lorsqu'un fichier JSON est importé :

Le script extrait les composants et les relations de dépendances (arborescence).

Il déduplique les composants pour éviter les requêtes API inutiles.

Il lance les vérifications de sécurité par lots (Batch processing de 15 composants) pour interroger les API sans bloquer le thread principal.

Il génère le code HTML dynamique du tableau de bord (lignes accordéon, badges, menus déroulants).

3.2. Moteur de Détection EOL & Fallback (getSecurityData)
Cette fonction évalue l'obsolescence d'un composant en suivant 4 scénarios stricts :

Scénario 1 (Base Locale) : Vérifie si l'utilisateur a créé une règle manuelle pour ce composant dans customEolDb.

Scénario 2 (API Officielle) : Interroge endoflife.date/api pour récupérer les cycles de vie officiels.

Scénario 3 (Fallback Registres) : Si aucune date EOL officielle n'existe, interroge NPM, PyPI ou Maven via getRegistryInfo() pour trouver la date de publication de la version. L'âge du composant détermine sa priorité (ex: > 3 ans = P2 "Vieux").

Scénario 4 (Orphelin) : Si toutes les étapes précédentes échouent, le composant est envoyé dans pendingOrphans (le Sas d'Apprentissage).

3.3. Analyse des Vulnérabilités CVE (OSV API)
Le script interroge la base de données open-source OSV (api.osv.dev).

Extraction des failles (CVE, GHSA).

Utilisation de la fonction calculateUniversalCVSS() pour recalculer et normaliser les scores CVSS v3.x et v4.0.

Extraction de la version de correction (fixed) pour afficher une solution de remédiation à l'utilisateur.

3.4. Apprentissage Autonome & Règles Manuelles
Permet de surcharger les résultats de l'API ou d'intégrer des composants internes/privés.

renderApprobationTab() : Affiche les composants du sas d'attente.

saveCustomOverride() : Enregistre une nouvelle règle. L'utilisateur définit un "Cycle / Version Majeure" (qui regroupe les sous-versions) et une "Version Cible". Cette donnée est sauvegardée dans le localStorage sous la clé titan_custom_eol et devient prioritaire pour les futurs imports.

4. Dictionnaire des Fonctions Clés
Utilitaires & Sécurité
escapeHTML(str) : Nettoie les chaînes de caractères pour prévenir les failles XSS avant l'injection dans le DOM.

doFetch(url, opts) : Wrapper pour la fonction native fetch. Gère dynamiquement le routage via le proxy CORS si nécessaire (sauf pour les API qui supportent nativement le CORS comme OSV).

Algorithmique EOL
getEolSlug(name) : Nettoie et formate le nom d'un composant (ex: supprime les préfixes @ ou les suffixes -core) et utilise un dictionnaire de synonymes (EOL_ALIAS_MAP) pour faire correspondre le nom SBOM avec l'identifiant de l'API (ex: spring-boot-starter-web -> spring-boot).

isVersionInCycle(version, cycle) : Détermine si une version exacte (ex: 4.17.15) appartient à une version majeure définie (ex: 4).

evaluateSupportPhase(c, isCustom) : Calcule le statut textuel et visuel (Standard, Sécurité, Obsolète) en comparant les dates EOL avec la date du jour. Gère l'affichage en jours/mois/années écoulés.

Interface & Interactions (UI)
openCVE(event, name, version) : Ouvre la modale affichant les détails des vulnérabilités associées à un composant.

filterDashboard() / filterCVEs() : Moteurs de recherche textuelle en temps réel (barre de recherche globale).

exportToCSV() : Construit un fichier .csv à la volée à partir des données lastProcessedVulns et déclenche son téléchargement.

Gestion du Proxy CORS
testProxyConnection() : Effectue un ping vers une API connue via le proxy configuré pour valider son accessibilité.

saveProxyConfig() : Sauvegarde l'URL du proxy (utile pour les environnements d'entreprise stricts).
