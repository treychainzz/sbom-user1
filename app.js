/** * RA-Pilot v7.5 - ÉDITION TITAN ABSOLUE
 * Optimisations : OSV Batching, Cache 2 Niveaux, Lazy Loading SBOM
 */

// --- DICTIONNAIRE DE TRADUCTION POUR LES API (ENDOFLIFE SLUGS) ---
// Transforme les noms de packages NPM/Maven/Docker en slugs stricts pour l'API.
const eolSlugMap = {
    // 🌍 Langages & Runtimes
    "python3": "python",
    "python2": "python",
    "python-core": "python",
    "node": "nodejs",
    "node.js": "nodejs",
    "java": "java",
    "openjdk": "java", // EOL.date a "java" ou "oracle-jdk" ou "corretto"
    "golang": "go",
    "csharp": "dotnet", // C# suit le cycle de vie de .NET
    "dotnet-core": "dotnet",

    // 🗄️ Bases de données
    "postgresql-client": "postgresql",
    "postgres": "postgresql",
    "mysql-server": "mysql",
    "mariadb-server": "mariadb",
    "mongodb-org": "mongodb",
    "redis-server": "redis",
    "elastic": "elasticsearch",
    "sqlite3": "sqlite",
    "cassandra-client": "cassandra",

    // ⚙️ Serveurs & Infra
    "nginx-core": "nginx",
    "apache2": "httpd", // EOL date utilise "httpd" pour Apache Web Server
    "apache": "httpd",
    "tomcat-embed-core": "tomcat",
    "tomcat-embed": "tomcat",
    "haproxy-systemd": "haproxy",
    "rabbitmq-server": "rabbitmq",

    // 🛡️ OS & Système
    "alpine-base": "alpine",
    "ubuntu-minimal": "ubuntu",
    "debian-sys": "debian",
    "redhat-enterprise-linux": "rhel",
    "redhat": "rhel",
    "centos-release": "centos",
    "amazon-linux-extras": "amazon-linux",
    "amazonlinux": "amazon-linux",
    "windows-server-core": "windows-server",

    // ☕ Frameworks Java (Maven)
    "spring-boot-starter-web": "spring-boot",
    "spring-boot-starter": "spring-boot",
    "spring-boot-autoconfigure": "spring-boot",
    "spring-core": "spring-framework",
    "spring-context": "spring-framework",
    "spring-web": "spring-framework",
    "spring-security-core": "spring-security",
    "hibernate-core": "hibernate",
    "hibernate-entitymanager": "hibernate",
    
    // (Note : Log4j, Jackson ou Guava ne sont pas toujours tracés par EOL.date, 
    // l'API renverra proprement 404 et le script affichera "---")
    "log4j-core": "log4j", 
    "log4j-api": "log4j",

    // ⚛️ Frameworks Frontend & Node (NPM)
    "react-dom": "react",
    "react-router": "react",
    "react-native": "react-native",
    "vue-router": "vue",
    "vuex": "vue",
    "vue3": "vue",
    "@angular/core": "angular",
    "angularjs": "angular", // Angular 1.x vs moderne
    "next": "nextjs", // NPM c'est "next", EOL.date c'est "nextjs"
    "nuxt3": "nuxtjs",

    // 🐳 DevOps & Outils
    "docker-ce": "docker",
    "docker-cli": "docker",
    "kubernetes-client": "kubernetes",
    "kubelet": "kubernetes",
    "kubectl": "kubernetes",
    "terraform-provider-aws": "terraform"
};

// Fonction de nettoyage pour l'API (Infaillible)
const getEolSlug = (rawName) => {
    let n = (rawName || "").toLowerCase().trim();
    
    // 1. Traduction prioritaire via notre dictionnaire
    if (eolSlugMap[n]) return eolSlugMap[n];
    
    // 2. Nettoyage des scopes NPM (ex: "@babel/core" -> "core")
    if (n.startsWith('@') && n.includes('/')) {
        n = n.split('/')[1];
    }

    // 3. Nettoyage des suffixes techniques courants
    n = n.replace(/-(core|api|starter|web|client|server|module|impl|engine|cli|ce|release|base)$/i, '');
    
    // 4. On s'assure qu'il ne reste pas de chiffres collés à la fin (ex: vue3 -> vue)
    n = n.replace(/[0-9]+$/, '');

    return n.trim();
};

// --- MOTEUR DE RECONNAISSANCE DES NOMS (Fuzzy Matching Étendu) ---
// Règle d'or : Les termes les plus longs/spécifiques doivent être AVANT les termes courts.
const keywordRules = [
    // 🐳 DevOps, Cloud & CI/CD
    { key: "ansible", name: "Ansible" },
    { key: "terraform", name: "Terraform" },
    { key: "docker", name: "Docker" },
    { key: "kube", name: "Kubernetes" }, // Capte kubernetes, kubectl, kubelet
    { key: "helm", name: "Helm" },
    { key: "jenkins", name: "Jenkins" },
    { key: "gitlab", name: "GitLab" },
    { key: "prometheus", name: "Prometheus" },
    { key: "grafana", name: "Grafana" },
    { key: "vault", name: "HashiCorp Vault" },
    { key: "consul", name: "HashiCorp Consul" },

    // 🌍 Langages & Runtimes
    { key: "python", name: "Python" }, // Capte python3, python-core, etc.
    { key: "node", name: "Node.js" },
    { key: "openjdk", name: "OpenJDK" },
    { key: "java", name: "Java" },
    { key: "golang", name: "Go" },
    { key: "ruby", name: "Ruby" },
    { key: "php", name: "PHP" },
    { key: "typescript", name: "TypeScript" },
    { key: "rust", name: "Rust" },
    { key: "scala", name: "Scala" },
    { key: "kotlin", name: "Kotlin" },
    { key: "dotnet", name: ".NET" },
    { key: "csharp", name: "C#" },

    // 🗄️ Bases de données & Caches
    { key: "postgres", name: "PostgreSQL" }, // Capte postgresql, postgres-client
    { key: "mysql", name: "MySQL" },
    { key: "maria", name: "MariaDB" },
    { key: "mongo", name: "MongoDB" },
    { key: "redis", name: "Redis" },
    { key: "elastic", name: "Elasticsearch" },
    { key: "cassandra", name: "Apache Cassandra" },
    { key: "sqlite", name: "SQLite" },
    { key: "memcached", name: "Memcached" },
    { key: "oracle", name: "Oracle DB" },
    { key: "couchbase", name: "Couchbase" },

    // ⚙️ Serveurs & Infra
    { key: "nginx", name: "NGINX" },
    { key: "apache2", name: "Apache HTTP Server" },
    { key: "httpd", name: "Apache HTTP Server" },
    { key: "tomcat", name: "Apache Tomcat" },
    { key: "jetty", name: "Eclipse Jetty" },
    { key: "haproxy", name: "HAProxy" },
    { key: "traefik", name: "Traefik" },
    { key: "envoy", name: "Envoy Proxy" },
    { key: "rabbit", name: "RabbitMQ" },
    { key: "kafka", name: "Apache Kafka" },

    // 🛡️ OS, Système & Sécurité
    { key: "alpine", name: "Alpine Linux" },
    { key: "ubuntu", name: "Ubuntu" },
    { key: "debian", name: "Debian" },
    { key: "centos", name: "CentOS" },
    { key: "redhat", name: "Red Hat Enterprise Linux" },
    { key: "windows-server", name: "Windows Server" },
    { key: "openssl", name: "OpenSSL" },
    { key: "bouncycastle", name: "Bouncy Castle" },
    { key: "bash", name: "Bash" },
    { key: "curl", name: "cURL" },
    { key: "wget", name: "GNU Wget" },
    { key: "glibc", name: "GNU C Library" },
    { key: "zlib", name: "Zlib" },

    // ☕ Frameworks & Libs Backend
    { key: "spring-boot", name: "Spring Boot" },
    { key: "spring-security", name: "Spring Security" },
    { key: "spring", name: "Spring Framework" },
    { key: "hibernate", name: "Hibernate" },
    { key: "log4j", name: "Apache Log4j" },
    { key: "logback", name: "Logback" },
    { key: "slf4j", name: "SLF4J" },
    { key: "jackson", name: "Jackson" },
    { key: "guava", name: "Google Guava" },
    { key: "express", name: "Express.js" },
    { key: "nestjs", name: "NestJS" },
    { key: "django", name: "Django" },
    { key: "flask", name: "Flask" },
    { key: "fastapi", name: "FastAPI" },
    { key: "laravel", name: "Laravel" },
    { key: "symfony", name: "Symfony" },

    // ⚛️ Frameworks & Libs Frontend
    { key: "react-dom", name: "React DOM" },
    { key: "react-router", name: "React Router" },
    { key: "react", name: "React" },
    { key: "vue", name: "Vue.js" },
    { key: "angular", name: "Angular" },
    { key: "svelte", name: "Svelte" },
    { key: "jquery", name: "jQuery" },
    { key: "bootstrap", name: "Bootstrap" },
    { key: "tailwind", name: "Tailwind CSS" },
    { key: "lodash", name: "Lodash" },
    { key: "axios", name: "Axios" },
    { key: "moment", name: "Moment.js" },
    { key: "rxjs", name: "RxJS" },
    { key: "redux", name: "Redux" },
    { key: "webpack", name: "Webpack" },
    { key: "vite", name: "Vite" }
];

const getPrettyName = (rawName) => {
    let n = (rawName || "").toLowerCase();
    
    // 1. Recherche Intelligente : on lit nos règles de haut en bas
    for (let rule of keywordRules) {
        if (n.includes(rule.key)) {
            return rule.name;
        }
    }
    
    // 2. Filet de Sécurité : Si inconnu, on nettoie au mieux
    // On retire les chiffres à la toute fin (ex: "composant3" -> "composant")
    let cleaned = n.replace(/[0-9]+$/, ''); 
    // On remplace les tirets par des espaces et on met des majuscules
    return cleaned.replace(/[-_.]/g, ' ')
                  .replace(/\b\w/g, char => char.toUpperCase())
                  .trim();
};

// --- 1. CONFIGURATION GLOBALE ---
// --- 1. CONFIGURATION GLOBALE ---
const PROXY = "https://api.codetabs.com/v1/proxy?quest=";
const TIMEOUT_VAL = 15000;

// --- 2. INITIALISATION DES CACHES ET DE LA BASE ---
let db = JSON.parse(localStorage.getItem('ra_pilot_db')) || { apps: {}, mappings: {} };
let eolCache = JSON.parse(localStorage.getItem('ra_pilot_eol_cache')) || {};
let osvCache = JSON.parse(localStorage.getItem('ra_pilot_osv_cache')) || {};

const CACHE_TTL_EOL = 7 * 24 * 60 * 60 * 1000; // 7 jours pour EOL
const CACHE_TTL_OSV = 24 * 60 * 60 * 1000;     // 24 heures pour la Sécurité

let curr = 'all';
let eolProducts = []; // Pour l'autocomplétion manuelle

// --- 3. UTILITAIRES DE BASE ---
const $ = id => document.getElementById(id);

const save = () => {
    try { 
        localStorage.setItem('ra_pilot_db', JSON.stringify(db)); 
    } catch(e) { 
        console.warn("Régime Titan activé : Nettoyage des données inutiles pour libérer la RAM.");
        Object.values(db.apps).forEach(a => { 
            if(a.files) a.files.forEach(f => delete f.rawData);
        });
        localStorage.setItem('ra_pilot_db', JSON.stringify(db));
    }
};

// --- UTILITAIRES : CONTRÔLE DU CHARGEMENT (MODE INJECTION) ---
const showLoader = (title, desc) => {
    let loader = document.getElementById('titan-loader');
    
    // S'il n'existe pas, on le fabrique et on le force à la racine (body)
    if (!loader) {
        loader = document.createElement('div');
        loader.id = 'titan-loader';
        loader.className = 'loader-overlay';
        loader.innerHTML = `
            <div class="loader-modal">
                <div class="spinner"></div>
                <h3 id="loader-title"></h3>
                <p id="loader-desc"></p>
            </div>
        `;
        document.body.appendChild(loader);
    }
    
    // On met à jour le texte et on affiche
    document.getElementById('loader-title').innerText = title || "Traitement...";
    document.getElementById('loader-desc').innerText = desc || "Veuillez patienter.";
    loader.style.display = 'flex';
};

const hideLoader = () => {
    const loader = document.getElementById('titan-loader');
    if (loader) loader.style.display = 'none';
};

// --- 4. MOTEUR DE RISQUE (CVSS & PRIORITÉ) ---
const getSeverityData = (v) => {
    let scores = []; 
    const raw = JSON.stringify(v);
    const numMatches = [...raw.matchAll(/["'](?:score|cvss|baseScore)["']\s*:\s*["']?(\d+(?:\.\d+))["']?/gi)];
    numMatches.forEach(m => scores.push(parseFloat(m[1])));
    return { score: scores.length > 0 ? Math.max(...scores.filter(s => s <= 10)) : 0 };
};

// --- CALCUL DE LA PRIORITÉ DU RISQUE ---
const getItemPrio = (item) => {
    // 1. RÈGLE D'OR (OVERRIDE) : La fin de vie absolue = Danger P0
    if (item.eol && item.eol.includes('Expiré')) {
        return 'P0';
    }

    // 2. Anticipation : Si le composant expire dans l'année = Attention P1
    if (item.eol && item.eol.includes('⚠️ Fin le')) {
        return 'P1';
    }

    // 3. Récupération des failles (Compatible avec les doublons fusionnés)
    const vulns = item.allVulns ? Array.from(item.allVulns.values()) : (item.vulns || []);
    const count = vulns.length;

    // 4. Grille de criticité basée sur le volume de failles
    // (Tu pourras ajuster ces seuils selon la politique de ton entreprise)
    if (count >= 50) return 'P0'; // Invasion de failles
    if (count >= 15) return 'P1'; // Critique
    if (count >= 5)  return 'P2'; // Majeur
    if (count > 0)   return 'P3'; // Mineur

    // 5. Par défaut : Tout va bien
    return 'P4';
};

const getCat = n => {
    const l = (n || "").toLowerCase();
    if (l.includes("debian") || l.includes("ubuntu") || l.includes("rhel") || l.includes("alpine")) return "Infra";
    if (l.includes("python") || l.includes("node") || l.includes("java") || l.includes("dotnet")) return "Runtime";
    return "Applicatif";
};

// --- 5. APPELS API EXTERNES & CACHE INTÉLLIGENT ---

// --- OUTIL DE COMPARAISON DE VERSIONS (SemVer) ---
const isNewerOrEqual = (current, target) => {
    if (!current || !target || target === '---') return false;
    // On nettoie les lettres (ex: "v1.2.0" devient [1, 2, 0])
    const cParts = String(current).replace(/[^\d.]/g, '').split('.').map(Number);
    const tParts = String(target).replace(/[^\d.]/g, '').split('.').map(Number);
    const len = Math.max(cParts.length, tParts.length);
    
    for (let i = 0; i < len; i++) {
        const c = cParts[i] || 0;
        const t = tParts[i] || 0;
        if (c > t) return true;  // L'actuelle est plus récente
        if (c < t) return false; // La cible est plus récente
    }
    return true; // Elles sont parfaitement égales
};

const fetchWithTimeout = async (url, options = {}) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_VAL); 
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        throw error; 
    }
};

const normalizeForEOL = (name, purl) => {
    let n = (name || "").toLowerCase();
    
    // Si c'est un PURL Maven, on extrait "groupe:nom"
    if (purl && purl.startsWith('pkg:maven/')) {
        const match = purl.match(/pkg:maven\/(.*?)\/(.*?)@/);
        if (match) n = `${match[1]}:${match[2]}`;
    } 
    // Si c'est du NPM avec un scope (ex: @babel/core)
    else if (n.startsWith('@') && n.includes('/')) {
        n = n.split('@')[1] || n; 
    }

    // Nettoyage des suffixes de versions qui polluent la recherche
    return n.replace(/-(module|v\d+|core|api|starter|client|server)$/, '')
            .replace(/\.final$|\.jre$/gi, '');
};

// --- 6. API : RÉCUPÉRATION DU CYCLE DE VIE (ENDOFLIFE.DATE) ---
async function fetchEOL(rawName, currentVersion) {
    const apiSlug = getEolSlug(rawName);
    if (!apiSlug) return { eol: '---', latest: '---' };

    try {
        // Optionnel : ajoute un console.log ici pour voir l'URL générée dans ta console F12
        // console.log("🔍 Checking EOL for:", `https://endoflife.date/api/${apiSlug}.json`);

        const res = await fetch(`https://endoflife.date/api/${apiSlug}.json`);
        
        // C'est ici qu'on gère proprement le 404
        if (res.status === 404) {
            return { eol: '---', latest: '---' }; 
        }

        if (!res.ok) throw new Error('Erreur API');

        const data = await res.json();
        if (!data || data.length === 0) return { eol: '---', latest: '---' };

        // ... (le reste de ta logique de matching de cycle) ...
        let matched = data.find(c => currentVersion && currentVersion.startsWith(c.cycle)) || data[0];
        
        return {
            eol: matched.eol === false ? '✨ Supporté' : (matched.eol === true ? '☠️ Expiré' : matched.eol),
            latest: data[0].latest
        };

    } catch (e) {
        return { eol: '---', latest: '---' };
    }
}

// --- UTILITAIRE : TRADUCTION PURL -> ÉCOSYSTÈME OSV ---
function getEcosystem(purl) {
    if (!purl) return 'npm'; // Par défaut

    // Un PURL ressemble à : pkg:npm/lodash@4.17.21
    // On extrait la partie entre "pkg:" et "/"
    const parts = purl.split(':');
    if (parts.length < 2) return 'npm';
    
    const type = parts[1].split('/')[0].toLowerCase();

    // Mapping des types PURL vers les noms officiels OSV
    const mapping = {
        'npm': 'npm',
        'maven': 'Maven',
        'pypi': 'PyPI',
        'composer': 'Packagist',
        'golang': 'Go',
        'nuget': 'NuGet',
        'cargo': 'Crates.io',
        'deb': 'Debian',
        'rpm': 'RPM',
        'gem': 'RubyGems'
    };

    return mapping[type] || type; 
}

// --- FORCE LA RÉCUPÉRATION COMPLÈTE ---
async function fetchSecurityBatch(chunk) {
    const queries = chunk.map(item => ({
        // Ici, on utilise la fonction qu'on vient de créer
        package: { 
            name: item.name, 
            ecosystem: getEcosystem(item.purl) 
        },
        version: item.version
    }));

    try {
        const res = await fetch('https://api.osv.dev/v1/querybatch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ queries })
        });
        const data = await res.json();
        
        // IMPORTANT : On renvoie TOUT l'objet vuln (avec details, severity, etc.)
        return data.results.map(r => r.vulns || []); 
    } catch (e) {
        console.error("Erreur réseau OSV:", e);
        return chunk.map(() => []);
    }
}

// --- 6. IMPORT SBOM (LAZY LOADING) ---
async function handleFile(file) {
    if (!file) return;
    let targetId = curr;
    if (targetId === 'all') return alert("Sélectionnez une application spécifique d'abord.");
    
    const raw = await file.text(); 
    const json = JSON.parse(raw);
    const comps = json.components || []; 
    const deps = json.dependencies || [];
    const fileId = "f" + Date.now();
    
    showLoader("Lecture SBOM", "Construction de l'arborescence (Instant)...");
    
    const compMap = {}; 
    comps.forEach(c => compMap[c['bom-ref'] || c.purl || c.name] = c);
    
    const tree = {}; 
    const allC = new Set();
    deps.forEach(d => { 
        tree[d.ref] = d.dependsOn || []; 
        d.dependsOn?.forEach(c => allC.add(c)); 
    });
    
    let topRefs = Object.keys(tree).filter(r => !allC.has(r));
    if (topRefs.length === 0) topRefs = comps.map(c => c['bom-ref'] || c.purl || c.name);
    
    for (const ref of topRefs) {
        const p = compMap[ref]; 
        if (!p) continue;
        const gId = "g" + Math.random().toString(36).slice(2,7);
        
        db.apps[targetId].items.push({ 
            id: gId, name: p.name, version: p.version, purl: p.purl, 
            isParent: true, childCount: (tree[ref]||[]).length, fileId,
            eol: '⏳ Attente...', target: '...', vulns: [], status: 'pending'
        });
        
        for (const cr of (tree[ref] || [])) {
            const c = compMap[cr]; 
            if (!c) continue;
            db.apps[targetId].items.push({ 
                id: "c"+Math.random(), name: c.name, version: c.version, purl: c.purl,
                parentId: gId, fileId, 
                eol: '⏳ Attente...', target: '...', vulns: [], status: 'pending'
            });
        }
    }
    
    if (!db.apps[targetId].files) db.apps[targetId].files = [];
    db.apps[targetId].files.push({ id: fileId, name: file.name, date: new Date().toLocaleString() });
    
    save(); 
    if ($('fileInput')) $('fileInput').value = ""; 
    render(); 
    hideLoader();

    // Lancement du monstre en arrière-plan
    scanAppInBackground(targetId, fileId);
}

// --- UTILITAIRE : LE FREIN MOTEUR ---
const delay = ms => new Promise(res => setTimeout(res, ms));

// --- 7. MOTEUR DE SCAN EN ARRIÈRE-PLAN (TITAN SCANNER) ---
async function scanAppInBackground(appId, fileId) {
    // 1. Récupération des éléments en attente d'analyse
    const itemsToScan = db.apps[appId].items.filter(i => i.fileId === fileId && i.status === 'pending');
    
    // S'il n'y a rien à scanner, on s'assure que le loader est caché et on annule
    if (itemsToScan.length === 0) {
        if (typeof hideLoader === 'function') hideLoader();
        return;
    }

    // 2. 🟢 Affichage de la popup de chargement
    if (typeof showLoader === 'function') {
        showLoader("Scan de Sécurité (OSV & NVD)", `Analyse de ${itemsToScan.length} composants sur le réseau...`);
    }

    // (Optionnel) Mise à jour du texte du bouton si tu en as un
    const btnRef = $('btnRefresh');
    if (btnRef) { 
        btnRef.innerText = `🔄 Scan réseau (0/${itemsToScan.length})...`; 
        btnRef.style.color = "var(--warning)"; 
    }

    // 3. Découpage en paquets (Très efficace pour l'API OSV)
    const CHUNK_SIZE = 100; 

    for (let i = 0; i < itemsToScan.length; i += CHUNK_SIZE) {
        const chunk = itemsToScan.slice(i, i + CHUNK_SIZE);
        
        // --- A. REQUÊTE OSV (Batch : 1 requête = 100 réponses d'un coup) ---
        const batchVulns = await fetchSecurityBatch(chunk);
        
        // --- B. REQUÊTE EOL (Séquentiel : 1 par 1 avec un frein pour éviter l'erreur 429) ---
        for (let j = 0; j < chunk.length; j++) {
            const item = chunk[j];
            
            const eol = await fetchEOL(item.name, item.version, item.purl);
            item.eol = eol?.eol || '---';
            item.target = eol?.latest || '---';
            item.vulns = batchVulns[j];
            item.status = 'scanned'; 
            
            // 🛑 Micro-pause de 50 millisecondes (Le secret anti-bannissement)
            await delay(50); 
        }
        
        // 4. Sauvegarde et mise à jour visuelle après chaque paquet de 100
        save();
        render(); 
        
        // Mise à jour des compteurs du Loader
        const currentCount = Math.min(i + CHUNK_SIZE, itemsToScan.length);
        if (typeof showLoader === 'function') {
            showLoader("Scan de Sécurité (OSV & NVD)", `Analyse en cours : ${currentCount} / ${itemsToScan.length} composants traités...`);
        }
        if (btnRef) {
            btnRef.innerText = `🔄 Scan réseau (${currentCount}/${itemsToScan.length})...`;
        }
    }

    // 5. 🔴 Le scan est terminé, on cache la popup et on remet le bouton à la normale
    if (typeof hideLoader === 'function') hideLoader();
    
    if (btnRef) { 
        btnRef.innerText = `🔄 Rafraîchir Titan`; 
        btnRef.style.color = "var(--primary)"; 
    }
}

// --- 8. MOTEUR DE RENDU : VUE "ACTION PLAN" ÉPURÉE ---
function render() {
    const isAll = curr === 'all';
    const rawItems = isAll ? Object.values(db.apps).flatMap(a => a.items || []) : (db.apps[curr]?.items || []);
    const search = ($('globalSearch')?.value || "").toLowerCase();
    const body = $('table-body');
    if (!body) return;

    // 1. Dédoublonnage par nom normalisé
    const uniqueMap = {};
    rawItems.forEach(i => {
        if (i.isParent && (!i.vulns || i.vulns.length === 0)) return; 
        const key = i.name.toLowerCase(); 

        if (!uniqueMap[key]) {
            uniqueMap[key] = { ...i, occurrences: 1, allVersions: new Set([i.version]), allVulns: new Map((i.vulns || []).map(v => [v.id, v])) };
        } else {
            uniqueMap[key].occurrences++;
            uniqueMap[key].allVersions.add(i.version);
            (i.vulns || []).forEach(v => uniqueMap[key].allVulns.set(v.id, v));
            const currentPrio = getItemPrio(uniqueMap[key]);
            if ("P0P1P2P3P4P-".indexOf(getItemPrio(i)) < "P0P1P2P3P4P-".indexOf(currentPrio)) {
                uniqueMap[key].eol = i.eol; uniqueMap[key].target = i.target;
            }
        }
    });

    let display = Object.values(uniqueMap);
    if (search) display = display.filter(i => i.name.toLowerCase().includes(search) || i.vulns.some(v => v.id.toLowerCase().includes(search)));
    display.sort((a,b) => "P0P1P2P3P4P-".indexOf(getItemPrio(a)) - "P0P1P2P3P4P-".indexOf(getItemPrio(b)));

    // 2. En-tête de tableau
    const head = document.querySelector('thead tr');
    if (head) {
        head.innerHTML = `<th>Composant (Recherche 🔗)</th><th>Catégorie</th><th>Versions</th><th>Date EOL</th><th>Version Cible</th><th>Priorité</th><th align="center">Impact</th>`;
    }

    if (display.length === 0) {
        body.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:#666;">Aucun composant à afficher.</td></tr>`;
        updateKPIs(rawItems);
        renderFiles();
        return;
    }

    // 3. Dessin du tableau avec le badge CVE interactif
    body.innerHTML = display.map(i => {
        const prio = getItemPrio(i);
        const totalVulns = i.allVulns ? i.allVulns.size : (i.vulns?.length || 0); // On compte les CVE uniques fusionnées
        
        let targetText = i.target;
        const allUp = Array.from(i.allVersions).every(v => isNewerOrEqual(v, targetText));
        
        if (targetText !== '---' && allUp) {
            targetText = (prio === 'P0' || prio === 'P1') ? `<span style="color:var(--danger)">🚨 Patch Attendu</span>` : `<span style="color:#666">✨ À jour</span>`;
        } else if (targetText !== '---') {
            targetText = `<b style="color:var(--success)">${targetText}</b>`; 
        }

        const versions = Array.from(i.allVersions);
        const vDisp = versions.length > 2 ? `${versions.length} versions` : versions.join(' / ');

        // LE FAMEUX BOUTON CVE (Seulement s'il y a des vulnérabilités)
        const badgeCveHtml = totalVulns > 0 
            ? `<span class="badge-cve" onclick="openCVE(event, '${i.id}')" title="Voir le détail des vulnérabilités">${totalVulns} CVE</span>` 
            : '';

        return `
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td>
                    <a href="https://www.google.com/search?q=${encodeURIComponent(i.name + ' vulnerabilities')}" target="_blank" style="text-decoration:none; color:inherit;">
                        <b>${i.name}</b> <small style="color:var(--primary); opacity:0.6;">🔍</small>
                    </a>
                    ${badgeCveHtml}
                </td>
                <td><span class="cat-badge cat-${getCat(i.name).toLowerCase()}">${getCat(i.name)}</span></td>
                <td style="font-family:monospace; font-size:0.8rem;">${vDisp}</td>
                <td>${i.eol || '---'}</td>
                <td>${targetText}</td>
                <td><span class="badge-prio badge-${prio.toLowerCase()}">${prio}</span></td>
                <td align="center"><span style="font-size:0.75rem; background:rgba(255,255,255,0.1); padding:4px 8px; border-radius:12px;">💥 ${i.occurrences}x</span></td>
            </tr>`;
    }).join('');

    updateKPIs(rawItems);
    renderFiles();
}

function updateKPIs(data) {
    const counts = { P0:0, P1:0, P2:0, P3:0, P4:0 }; 
    data.forEach(i => { const p = getItemPrio(i); if(counts[p] !== undefined) counts[p]++; });
    
    if ($('comp-count')) $('comp-count').innerText = data.length;
    if ($('vulnerabilities-count')) $('vulnerabilities-count').innerText = data.reduce((a,i) => a + (i.vulns?.length || 0), 0);
    ['p0','p1','p2','p3','p4'].forEach(p => { if ($(p+'-count')) $(p+'-count').innerText = counts[p.toUpperCase()]; });
    
    const scanned = data.filter(i => i.status !== 'pending');
    const s = scanned.length ? Math.max(0, 100 - (counts.P0 * 15) - (counts.P1 * 5)) : 100;
    const g = $('health-gauge'); 
    if (g) { g.innerText = data.length === 0 ? '--%' : Math.round(s) + "%"; g.style.color = s > 70 ? 'var(--success)' : (s > 40 ? 'var(--warning)' : 'var(--danger)'); }
}

function renderFiles() {
    const historySection = $('history-section'); const list = $('file-list');
    if (!list) return;
    if (curr === 'all' || !db.apps[curr]) { if (historySection) historySection.style.display = "none"; else list.style.display = "none"; return; }
    
    const files = db.apps[curr].files || [];
    if (historySection) historySection.style.display = files.length > 0 ? "block" : "none";
    list.style.display = files.length > 0 ? "block" : "none";
    
    list.innerHTML = [...files].reverse().map(f => `
        <li style="display:flex; justify-content:space-between; padding:8px; border-bottom:1px solid #333; background: rgba(255,255,255,0.02); margin-bottom:5px;">
            <span style="color:#58a6ff; font-size:0.8rem;">📄 ${f.name} <small style="color:#888">(${f.date})</small></span>
            <button onclick="delSbom(event, '${f.id}')" style="background:transparent; border:none; color:#f85149; cursor:pointer;">🗑️</button>
        </li>`).join('');
}

// --- 9. INTERFACE & ÉVÉNEMENTS GLOBAUX ---
window.toggle = id => { 
    document.querySelectorAll('.child-of-'+id).forEach(c => c.classList.toggle('is-expanded')); 
    const i = $('icon-'+id); if(i) i.innerText = i.innerText === "▶" ? "▼" : "▶"; 
};

window.openCVE = (e, id) => {
    if (e) e.stopPropagation();
    const item = Object.values(db.apps).flatMap(a => a.items).find(x => x.id === id);
    
    if (!item || !item.vulns || item.vulns.length === 0) return;

    $('cve-modal-title').innerText = item.name;
    $('cve-list-container').innerHTML = item.vulns.map(v => {
        const sev = getSeverityInfo(v);
        // On privilégie 'details' (long), sinon 'summary' (court)
        const desc = v.details || v.summary || "Aucune description technique.";

        return `
        <div style="background:rgba(255,255,255,0.02); border:1px solid #30363d; padding:15px; margin-bottom:12px; border-radius:8px; border-left:4px solid ${sev.color};">
            <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
                <b style="color:#58a6ff; font-family:monospace;">${v.id}</b>
                <span style="background:${sev.color}; color:white; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:bold;">
                    ${sev.label} ${sev.score !== 'N/A' ? sev.score : ''}
                </span>
            </div>
            <div style="color:#e6edf3; font-weight:bold; margin-bottom:8px; font-size:0.9rem;">${v.summary || ''}</div>
            <div style="color:#8b949e; font-size:0.8rem; line-height:1.4; white-space:pre-wrap;">${desc}</div>
        </div>`;
    }).join('');

    $('cve-modal').style.display = 'flex';
};

// --- UTILITAIRE : CALCUL DE LA SÉVÉRITÉ ---
function getSeverityInfo(v) {
    let score = null;
    let label = "UNKNOWN";

    // 1. Cherche dans le standard OSV
    if (v.severity) {
        const cvss = v.severity.find(s => s.type.startsWith('CVSS'));
        if (cvss) score = cvss.score;
    }
    
    // 2. Cherche dans les métadonnées spécifiques (GitHub / NVD)
    if (!score && v.database_specific) {
        const ds = v.database_specific;
        if (ds.cvss && ds.cvss.score) score = ds.cvss.score;
        else if (ds.severity) label = ds.severity.toUpperCase();
    }

    // 3. Attribution des couleurs Titan
    let color = "#6e7681"; // Gris (Inconnu)
    if (score) {
        const s = parseFloat(score);
        if (s >= 9.0) { label = "CRITICAL"; color = "#cf222e"; }
        else if (s >= 7.0) { label = "HIGH"; color = "#d29922"; }
        else if (s >= 4.0) { label = "MEDIUM"; color = "#9e6a03"; }
        else { label = "LOW"; color = "#30363d"; }
    } else if (label !== "UNKNOWN") {
        if (label === "CRITICAL") color = "#cf222e";
        if (label === "HIGH") color = "#d29922";
    }

    return { 
        score: score ? parseFloat(score).toFixed(1) : "N/A", 
        label: label, 
        color: color 
    };
}

window.delSbom = (e, id) => { 
    e.stopPropagation();
    if(confirm('Supprimer ce SBOM et ses composants ?')) { 
        db.apps[curr].files = db.apps[curr].files.filter(f => f.id !== id); 
        db.apps[curr].items = db.apps[curr].items.filter(i => i.fileId !== id); 
        save(); render(); 
    } 
};

window.delApp = () => { if (confirm("Supprimer l'application ?")) { delete db.apps[curr]; save(); location.reload(); } };

document.addEventListener('DOMContentLoaded', () => {
    const sel = $('currentAppSelector');
    if (sel) {
        sel.innerHTML = '<option value="all">🌐 Vue Globale</option>' + Object.values(db.apps).map(a => `<option value="${a.id}">${a.name}</option>`).join('');
        sel.onchange = (e) => { curr = e.target.value; render(); };
    }
    
    if($('globalSearch')) $('globalSearch').oninput = () => render();
    if($('drop-zone')) $('drop-zone').onclick = () => $('fileInput').click();
    if($('fileInput')) $('fileInput').onchange = e => handleFile(e.target.files[0]);
    if($('btnRefresh')) $('btnRefresh').onclick = () => scanAppInBackground(curr, db.apps[curr]?.files[0]?.id); // Rafraîchit le dernier fichier
    
    if($('btnCreateAppConfirm')) $('btnCreateAppConfirm').onclick = () => {
        const n = $('newAppName').value; if(!n) return;
        const id = "app-"+Date.now(); db.apps[id] = { id, name: n, items: [], files: [] };
        save(); location.reload();
    };

    render();
});

function getSeverityInfo(v) {
    let score = null;
    let label = "UNKNOWN";
    let color = "#6e7681"; // Gris

    // 1. Recherche dans le tableau de sévérité standard OSV
    if (v.severity && Array.isArray(v.severity)) {
        const cvss = v.severity.find(s => s.type === 'CVSS_V3' || s.type === 'CVSS_V2');
        if (cvss && cvss.score) {
            score = cvss.score;
        }
    }

    // 2. Backup : Recherche dans database_specific (Format GitHub/GitLab)
    if (!score && v.database_specific) {
        if (v.database_specific.cvss && v.database_specific.cvss.score) {
            score = v.database_specific.cvss.score;
        } else if (v.database_specific.severity) {
            label = v.database_specific.severity.toUpperCase();
        }
    }

    // 3. Traduction du score numérique en Label et Couleur
    if (score) {
        const s = parseFloat(score);
        if (s >= 9.0) { label = "CRITICAL"; color = "#cf222e"; }
        else if (s >= 7.0) { label = "HIGH"; color = "#d29922"; }
        else if (s >= 4.0) { label = "MEDIUM"; color = "#9e6a03"; }
        else { label = "LOW"; color = "#30363d"; }
    } else {
        // Si on a un label texte mais pas de score
        if (label === "CRITICAL") color = "#cf222e";
        if (label === "HIGH") color = "#d29922";
        if (label === "MEDIUM") color = "#9e6a03";
    }

    return { 
        score: score ? parseFloat(score).toFixed(1) : "?.?", 
        label, 
        color 
    };
}

// --- RUSTINE : FONCTION DE CRÉATION D'APP ---
window.createApp = () => { 
    const inputNode = document.getElementById('newAppName');
    const n = inputNode ? inputNode.value : null;
    
    if (n) { 
        const id = "app-" + Date.now(); 
        db.apps[id] = { id, name: n, items: [], files: [] }; 
        save(); 
        location.reload(); 
    } else {
        alert("Veuillez entrer un nom pour l'application.");
    }
};
