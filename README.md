# OSBOM (Obsolescence SBOM) - Control Tower

![Version](https://img.shields.io/badge/version-1.0-blue.svg)
![Vanilla JS](https://img.shields.io/badge/JavaScript-Vanilla-yellow.svg)
![HTML/CSS](https://img.shields.io/badge/Frontend-HTML%2FCSS-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**OSBOM** est un tableau de bord interactif, 100% côté client (Frontend-only), conçu pour analyser les nomenclatures logicielles (SBOM), suivre le cycle de vie des dépendances (End of Life) et auditer les vulnérabilités de sécurité (CVE).

Contrairement aux outils classiques, OSBOM embarque un moteur de "Fallback" intelligent via les registres publics et un sas d'apprentissage autonome pour mémoriser vos composants internes.

---

## Fonctionnalités Principales

*   **Import SBOM Intelligent :** Lecture instantanée des fichiers SBOM (JSON) sans besoin de backend.
*   **Suivi EOL (End Of Life) :** Interrogation en temps réel de l'API `endoflife.date` pour connaître les dates de fin de support.
*   **Scan de Vulnérabilités (CVE) :** Détection des failles via l'API officielle OSV avec calcul dynamique des scores CVSS (v3 & v4) et recommandations de patchs.
*   **Apprentissage Autonome :** Un sas qui capture les composants inconnus ou propriétaires pour vous permettre de définir manuellement leurs cycles de vie et versions cibles (sauvegardé localement).
*   **Fallback Registre (Plan B) :** Si un composant n'a pas de date de fin de vie officielle, OSBOM interroge discrètement NPM, Maven ou PyPI pour deviner son âge et estimer son obsolescence (ex: *Vieillissant > 2 ans*).
*   **Scoring P0 à P4 :** Tri automatique des urgences (P0 = Failles critiques ou obsolètes, P4 = À jour et sécurisé).
*   **Privacy First :** Aucune base de données externe, aucune télémétrie. Tout le traitement se fait dans le navigateur de l'utilisateur (`localStorage`).

---

## Installation & Lancement

OSBOM est un projet purement statique (Vanilla JS, HTML, CSS). Il n'y a aucune dépendance, aucun `npm install` ou étape de build complexe.

1. **Cloner le dépôt :**
   ```bash
   git clone [https://github.com/VOTRE_NOM/osbom.git](https://github.com/VOTRE_NOM/osbom.git)

Lancer l'application :
Ouvrez simplement le fichier index.html dans n'importe quel navigateur web moderne (Chrome, Edge, Firefox, Safari).

Comment utiliser OSBOM ?
1. Importer un SBOM
Cliquez sur le bouton "Importer JSON" et sélectionnez votre fichier SBOM. L'analyse se lance automatiquement. Vous pouvez importer plusieurs fichiers, ils seront regroupés dans l'Espace de travail actuel.

2. Le Sas d'Apprentissage (Composants orphelins)
Si un composant n'est reconnu ni par les API officielles, ni par les registres (ex: dépendances internes), il atterrit dans l'onglet "Apprentissage Autonome".

Cliquez sur "Définir le cycle EOL".

Renseignez le Cycle / Version Majeure (ex: 4 pour la version 4.17.15).

Définissez la Version Cible recommandée.

Validez : le composant disparaîtra du sas et l'inventaire se mettra à jour. Cette règle est mémorisée à vie dans votre navigateur.

3. Gestion de l'historique et Profils
Vous pouvez créer des Profils (ex: "Projet Alpha", "Projet Beta") pour isoler vos tableaux de bord.
L'historique conserve vos imports récents pour vous permettre de les rajouter ou de les remplacer d'un simple clic.

Stack Technique & Architecture
HTML5 / CSS3 : Design moderne, mode sombre natif, structure full CSS Grid (Responsive).

JavaScript (ES6+) : Architecture orientée événements, asynchrone (Promises/Async-Await).

Stockage : localStorage (pour la configuration, l'historique et la base de connaissances personnalisée).

API externes utilisées :

endoflife.date/api (Statuts officiels)

api.osv.dev (Base de données open-source de vulnérabilités)

registry.npmjs.org / pypi.org / packagist.org (Analyse d'âge "Fallback")

corsproxy.io (Contournement optionnel du CORS pour certaines API restrictives)

Dépannage (Reset)
Si vous souhaitez remettre votre base de connaissances et votre tableau de bord à l'état d'usine :

Ouvrez la console de développement de votre navigateur (F12).

Tapez la commande suivante et appuyez sur Entrée :

JavaScript
localStorage.clear();
Rafraîchissez la page (F5).

Contribution
Les contributions (Pull Requests) sont les bienvenues. N'hésitez pas à ouvrir une Issue si vous remarquez un bug ou si vous avez une idée de fonctionnalité (ex: Export PDF, intégration de nouveaux registres, etc.).
