/*
  _________________________________________________________________________

     ██████╗ ███████╗██████╗  ██████╗ ███╗   ███╗
    ██╔═══██╗██╔════╝██╔══██╗██╔═══██╗████╗ ████║
    ██║   ██║███████╗██████╔╝██║   ██║██╔████╔██║
    ██║   ██║╚════██║██╔══██╗██║   ██║██║╚██╔╝██║
    ╚██████╔╝███████║██████╔╝╚██████╔╝██║ ╚═╝ ██║
     ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝
  _________________________________________________________________________

  [+] Application : OSBOM (Obsolescence SBOM)
  [+] Creator     : X
  [+] Version     : 1.0 (Build Final)
  [+] Description : Moteur de rendu SBOM, analyse EOL & scan CVE
  [+] Date        : 2026
  _________________________________________________________________________
*/

const $ = id => document.getElementById(id);

// ============================================================================
// FONCTIONS DE SÉCURITÉ (ANTI-XSS & SANITIZATION)
// ============================================================================
const escapeHTML = str => {
    if (!str) return "";
    return String(str).replace(/[&<>'"]/g, tag => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    }[tag] || tag));
};

// ============================================================================
// VARIABLES D'ÉTAT GLOBALES
// ============================================================================
let appProfiles = [];
let currentProfileId = null;
let sbomHistory = [];
let activeWorkspace = { components: [], dependencies: [] };
window.lastProcessedVulns = new Map();
const cache = {};
let currentProxyUrl = "https://corsproxy.io/?{url}";
let currentCVEs = [];

// 🛡️ Dictionnaire local des produits EOL supportés (API)
let validEolSlugs = new Set(); 

// 🛡️ Base de connaissances personnalisée (Apprentissage manuel)
let customEolDb = JSON.parse(localStorage.getItem('titan_custom_eol')) || {};

// 🛡️ Sas d'attente pour les composants orphelins
let pendingOrphans = new Map();

// Fonction pour récupérer all.json au démarrage
async function initEolDictionary() {
    try {
        console.log("[Titan] Téléchargement du dictionnaire EOL...");
        const res = await fetch('https://endoflife.date/api/all.json');
        if (res.ok) {
            const data = await res.json();
            validEolSlugs = new Set(data);
        }
    } catch (e) {
        console.warn("[Titan] ❌ Impossible de charger all.json", e);
    }
}

const EOL_ALIAS_MAP = { 
    'node': 'nodejs', 'nodejs': 'nodejs', 'python3': 'python', 'python': 'python',
    'jdk': 'java', 'jre': 'java', 'openjdk': 'java', 'golang': 'go', 'csharp': 'dotnet',
    'dotnet-core': 'dotnet', 'ruby-lang': 'ruby', 'rustlang': 'rust', 'php': 'php',
    'typescript': 'typescript', 'postgres': 'postgresql', 'postgresql': 'postgresql',
    'mysql': 'mysql', 'mariadb': 'mariadb', 'mongodb': 'mongodb', 'redis': 'redis',
    'elasticsearch': 'elasticsearch', 'cassandra': 'cassandra', 'sqlite3': 'sqlite',
    'nginx': 'nginx', 'apache2': 'httpd', 'apache-httpd': 'httpd', 'apache': 'httpd',
    'tomcat': 'tomcat', 'tomcat-embed-core': 'tomcat', 'haproxy-systemd': 'haproxy',
    'rabbitmq-server': 'rabbitmq', 'ubuntu-linux': 'ubuntu', 'debian-linux': 'debian',
    'alpine-linux': 'alpine', 'rhel': 'rhel', 'redhat': 'rhel', 'centos': 'centos',
    'amazon-linux': 'amazon-linux', 'reactjs': 'react', 'react-dom': 'react',
    'vuejs': 'vue', 'vue3': 'vue', 'angularjs': 'angular', 'nextjs': 'nextjs',
    'nuxtjs': 'nuxtjs', 'expressjs': 'express', 'nestjs': 'nestjs',
    'spring': 'spring-framework', 'spring-core': 'spring-framework',
    'spring-context': 'spring-framework', 'spring-web': 'spring-framework',
    'spring-boot': 'spring-boot', 'spring-boot-starter-web': 'spring-boot',
    'spring-security': 'spring-security', 'hibernate-core': 'hibernate',
    'quarkus': 'quarkus', 'ibexa': 'ibexa-dxp', 'k8s': 'kubernetes',
    'kubelet': 'kubernetes', 'kubectl': 'kubernetes', 'docker-engine': 'docker',
    'docker-ce': 'docker', 'terraform': 'terraform', 'terraform-provider-aws': 'terraform',
    'ansible': 'ansible', 'android': 'android', 'ios': 'ios', 'flutter': 'flutter',
    'react-native': 'react-native'
};

// ============================================================================
// CALCULATEUR DE SCORE CVSS (v3.x & v4.0)
// ============================================================================
function calculateUniversalCVSS(vector) {
    if (!vector) return null;
    
    const v = vector.split('/'); const m = {};
    v.forEach(p => { const [k,val] = p.split(':'); m[k] = val; });

    if (vector.startsWith('CVSS:3')) {
        const w = {
            AV:{N:0.85, A:0.62, L:0.55, P:0.2}, AC:{L:0.77, H:0.44}, 
            PR:{N:0.85, L:0.62, H:0.27}, UI:{N:0.85, R:0.62}, 
            C:{H:0.56, L:0.22, N:0}, I:{H:0.56, L:0.22, N:0}, A:{H:0.56, L:0.22, N:0}
        };
        if (m['S'] === 'C') { w.PR.L = 0.68; w.PR.H = 0.50; }
        
        const iss = 1 - ( (1-(w.C[m.C]||0)) * (1-(w.I[m.I]||0)) * (1-(w.A[m.A]||0)) );
        const impact = m['S'] === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
        const exp = 8.22 * (w.AV[m.AV]||0) * (w.AC[m.AC]||0) * (w.PR[m.PR]||0) * (w.UI[m.UI]||0);
        
        let base = 0;
        if (impact > 0) base = m['S'] === 'U' ? Math.min(impact + exp, 10) : Math.min(1.08 * (impact + exp), 10);
        return (Math.ceil(base * 10) / 10).toFixed(1);
    }
    
    if (vector.startsWith('CVSS:4.0')) {
        const w = {
            AV:{N:0.85, A:0.62, L:0.55, P:0.2}, AC:{L:0.77, H:0.44}, AT:{N:1.0, P:0.5},
            PR:{N:0.85, L:0.62, H:0.27}, UI:{N:0.85, P:0.62, A:0.4, R:0.62},
            V:{H:0.56, L:0.22, N:0}, S:{H:0.56, L:0.22, N:0}
        };
        
        const issV = 1 - ( (1-(w.V[m.VC]||0)) * (1-(w.V[m.VI]||0)) * (1-(w.V[m.VA]||0)) );
        const issS = 1 - ( (1-(w.S[m.SC]||0)) * (1-(w.S[m.SI]||0)) * (1-(w.S[m.SA]||0)) );
        
        const impact = (issV * 6.5) + (issS * 2.0); 
        const exp = 8.22 * (w.AV[m.AV]||0) * (w.AC[m.AC]||0) * (w.AT[m.AT]||1) * (w.PR[m.PR]||0) * (w.UI[m.UI]||0);

        if (impact <= 0) return "0.0";
        let base = Math.min(1.08 * (impact + exp), 10);
        return (Math.ceil(base * 10) / 10).toFixed(1);
    }
    return null;
}

// ============================================================================
// INITIALISATION
// ============================================================================
window.onload = async () => {
    const p = localStorage.getItem('proxyUrl'); 
    if(p) currentProxyUrl = p;

    const storedProfiles = localStorage.getItem('appProfiles');
    if (storedProfiles) {
        appProfiles = JSON.parse(storedProfiles);
        currentProfileId = localStorage.getItem('currentProfileId') || appProfiles[0].id;
    } else {
        const defId = 'prof_' + Date.now();
        appProfiles = [{ id: defId, name: 'Espace par défaut' }];
        currentProfileId = defId;
        localStorage.setItem('appProfiles', JSON.stringify(appProfiles));
        localStorage.setItem('currentProfileId', defId);
    }

    await initEolDictionary();
    loadProfileContext();
};

function loadProfileContext() {
    const h = localStorage.getItem(`${currentProfileId}_sbomHistory`); sbomHistory = h ? JSON.parse(h) : [];
    const w = localStorage.getItem(`${currentProfileId}_activeWorkspace`); activeWorkspace = w ? JSON.parse(w) : { components: [], dependencies: [] };
    
    if($('currentProfileNameDisplay')) $('currentProfileNameDisplay').innerText = appProfiles.find(p => p.id === currentProfileId).name;
    window.lastProcessedVulns.clear();

    renderHistoryUI();
    if(activeWorkspace.components.length > 0) processSbom(activeWorkspace);
    else if($('results')) $('results').innerHTML = "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Espace vide. Importez un SBOM.</p>";
}

function doFetch(url, opts) { 
    if (url.includes('endoflife.date') || url.includes('api.osv.dev')) {
        return fetch(url, opts);
    }
    if(!currentProxyUrl) return fetch(url, opts); 
    if(currentProxyUrl.includes('{url}')) return fetch(currentProxyUrl.replace('{url}', encodeURIComponent(url)), opts); 
    return fetch(currentProxyUrl + url, opts); 
}

function handleProxySelection() { $('customProxyDiv').style.display = $('proxySelect').value === 'custom' ? 'block' : 'none'; }

function saveProxyConfig() {
    currentProxyUrl = $('proxySelect').value === 'custom' ? $('proxyCustomInput').value : $('proxySelect').value;
    localStorage.setItem('proxyUrl', currentProxyUrl);
    closeModal('proxyModal');
    if(activeWorkspace.components.length > 0 && confirm("Proxy sauvegardé. Relancer l'analyse ?")) forceUpdateAnalysis();
}

async function testProxyConnection() {
    const sel = $('proxySelect').value;
    const base = sel === 'custom' ? $('proxyCustomInput').value : sel;
    const res = $('proxyTestResult'); 
    res.innerHTML = '<span style="color:var(--p3)">Test en cours... ⏳</span>';
    try {
        const target = 'https://endoflife.date/api/nodejs.json';
        const url = base ? (base.includes('{url}') ? base.replace('{url}', encodeURIComponent(target)) : base + target) : target;
        const req = await fetch(url);
        res.innerHTML = req.ok ? '<span style="color:#2ea043">✅ Connexion réussie !</span>' : `<span style="color:var(--p0)">❌ Erreur HTTP: ${req.status}</span>`;
    } catch (e) {
        res.innerHTML = '<span style="color:var(--p0)">❌ Échec. URL bloquée ou invalide.</span>'; 
    }
}

// ============================================================================
// OMNI-DÉTECTION DES REGISTRES
// ============================================================================
async function getRegistryInfo(name, version) {
    if (name.includes('/') && !name.startsWith('@')) {
        try {
            const res = await doFetch(`https://repo.packagist.org/p2/${name}.json`);
            if (res.ok) {
                const data = await res.json();
                const versions = data.packages?.[name] || [];
                const match = versions.find(v => v.version === version || v.version.startsWith(version + '.') || v.version.startsWith(version + '-'));
                if (match) return { found: true, correctedVersion: match.version, latest: versions[0]?.version, releaseDate: match.time, ecosystem: 'Packagist', link: `https://packagist.org/packages/${name}` };
            }
        } catch(e) {}
    }

    try {
        const res = await doFetch(`https://pypi.org/pypi/${name}/json`);
        if (res.ok) {
            const data = await res.json();
            const versions = Object.keys(data.releases);
            const match = versions.find(v => v === version || v.startsWith(version + '.') || v.startsWith(version + '-'));
            if (match) return { found: true, correctedVersion: match, latest: data.info.version, releaseDate: data.releases[match]?.[0]?.upload_time, ecosystem: 'PyPI', link: `https://pypi.org/project/${name}/` };
        }
    } catch(e) {}

    try {
        const res = await doFetch(`https://registry.npmjs.org/${name}`);
        if (res.ok) {
            const data = await res.json();
            const versions = Object.keys(data.versions || {});
            const match = versions.sort().reverse().find(v => v === version || v.startsWith(version + '.') || v.startsWith(version + '-'));
            if (match) return { found: true, correctedVersion: match, latest: data['dist-tags']?.latest, releaseDate: data.time?.[match], ecosystem: 'npm', link: `https://www.npmjs.com/package/${name}` };
        }
    } catch(e) {}

    return { found: false, ecosystem: 'npm' }; 
}

// ============================================================================
// MOTEUR D'ANALYSE (DATES ET STATUTS)
// ============================================================================
function isVersionInCycle(version, cycle) {
    const vStr = String(version);
    const cStr = String(cycle);
    return vStr === cStr || vStr.startsWith(cStr + '.') || vStr.startsWith(cStr + '-');
}

function getDeathDateMs(c) {
    if (c.eol === false) return Infinity; 
    let dates = [];
    const parseDate = (d) => {
        if (!d || d === true || d === false) return null;
        const parts = d.toString().split('-'); 
        if (parts.length === 3) return new Date(parts[0], parts[1]-1, parts[2]).getTime();
        return new Date(d).getTime();
    };

    const dSupport = parseDate(c.support);
    const dExtended = parseDate(c.extendedSupport);
    const dEol = parseDate(c.eol);

    if (dSupport) dates.push(dSupport);
    if (dExtended) dates.push(dExtended);
    if (dEol) dates.push(dEol);

    if (dates.length === 0) return 0; 
    return Math.max(...dates); 
}

function calculatePFromMs(timeMs) {
    if (timeMs === Infinity) return 4;
    if (timeMs === 0) return 0;
    const todayMs = new Date().setHours(0,0,0,0);
    const d = Math.ceil((timeMs - todayMs) / 86400000);
    return d <= 0 ? 0 : d < 90 ? 1 : d < 180 ? 2 : d < 365 ? 3 : 4;
}

function isFutureDateStrict(dateVal, isEolField = false) {
    if (dateVal === false) return isEolField; 
    if (dateVal === true || !dateVal) return false; 
    const today = new Date(); today.setHours(0,0,0,0);
    const parts = dateVal.toString().split('-');
    if (parts.length === 3) {
        const targetDate = new Date(parts[0], parts[1] - 1, parts[2]);
        targetDate.setHours(0,0,0,0);
        return targetDate >= today;
    }
    return false;
}

// ============================================================================
// CALCULATEUR DYNAMIQUE DE CYCLE DE VIE (Avec Compte à rebours et Conversion)
// ============================================================================
function evaluateSupportPhase(c, isCustom = false) {
    if (c.isRegistryFallback) return { text: `Actif (${c.registryName})`, color: "var(--p4)", isAlive: true };

    let text = "Obsolète"; 
    let color = "var(--text-muted)"; 
    let isAlive = false;
    
    let prefix = isCustom ? "🛠️ " : ""; 

    const hasSupport = isFutureDateStrict(c.support, false);
    const hasExtended = isFutureDateStrict(c.extendedSupport, false);
    const hasEol = isFutureDateStrict(c.eol, true);

    let daysToEol = null;
    if (c.eol && c.eol !== true && c.eol !== false) {
        const parts = c.eol.toString().split('-');
        if (parts.length === 3) {
            const target = new Date(parts[0], parts[1]-1, parts[2]).setHours(0,0,0,0);
            const today = new Date().setHours(0,0,0,0);
            daysToEol = Math.ceil((target - today) / 86400000);
        }
    }

    if (hasSupport) { 
        text = c.support === false ? "Standard (Permanent)" : `Standard (${c.support})`; 
        color = "var(--p4)"; 
        isAlive = true; 
    } 
    else if (hasExtended) { 
        text = c.extendedSupport === false ? "Commercial (Permanent)" : `Commercial (${c.extendedSupport})`; 
        color = "var(--p3)"; 
        isAlive = true; 
    } 
    else if (hasEol) { 
        if (daysToEol !== null && daysToEol <= 30) {
            text = `⚠️ Expire dans ${daysToEol} jours`;
            color = "#d29922"; 
        } else {
            text = c.eol === false ? "Sécurité (Permanent)" : `Sécurité (${c.eol})`; 
            color = "var(--p2)"; 
        }
        isAlive = true; 
    } 
    else {
        let lastDate = (c.extendedSupport && c.extendedSupport !== true) ? c.extendedSupport : 
                       (c.eol && c.eol !== true) ? c.eol : 
                       (c.support && c.support !== true) ? c.support : null;
        
        // Si c'était un compte à rebours, on affiche depuis combien de temps c'est mort avec conversion
        if (daysToEol !== null && daysToEol < 0) {
            const absDays = Math.abs(daysToEol);
            let timeString = "";

            if (absDays < 30) {
                timeString = `${absDays}j`; // Moins d'un mois : on garde en jours
            } else if (absDays < 365) {
                const months = Math.floor(absDays / 30);
                timeString = `${months} mois`; // Entre 1 et 11 mois
            } else {
                const years = Math.floor(absDays / 365);
                timeString = `${years} an${years > 1 ? 's' : ''}`; // Plus d'un an (avec gestion du pluriel)
            }

            text = `Obsolète (depuis ${timeString})`;
        } else if (lastDate) {
            text = `Obsolète (${lastDate})`;
        }
        color = "var(--p0)"; 
    }

    return { text: prefix + text, color, isAlive };
}

function getEolSlug(name) {
    if (!name) return null;
    let n = name.toLowerCase().trim();
    if (EOL_ALIAS_MAP[n]) return EOL_ALIAS_MAP[n];
    if (n.includes('/')) {
        const parts = n.split('/');
        n = parts[0].startsWith('@') ? parts[0].substring(1) : parts[parts.length - 1];
    }
    n = n.replace(/-(linux|js|lang|framework|core|starter|web)$/g, '');
    return n;
}

// ============================================================================
// MODULE D'APPRENTISSAGE AUTONOME (SAS D'APPROBATION)
// ============================================================================
function renderApprobationTab() {
    const container = $('approbationList');
    const badge = $('approbationBadge'); 
    
    if (badge) {
        badge.innerText = pendingOrphans.size;
        badge.style.display = pendingOrphans.size > 0 ? 'inline-block' : 'none';
    }

    if (!container) return;

    if (pendingOrphans.size === 0) {
        container.innerHTML = "<p style='text-align:center; color:var(--p4); padding:20px;'>✅ Aucun composant orphelin. Votre base de connaissances est à jour.</p>";
        return;
    }

    let html = "";
    pendingOrphans.forEach((data, slug) => {
        html += `
        <div style="background:var(--bg-card); border:1px solid var(--border-color); padding:15px; margin-bottom:10px; border-radius:6px; display:flex; justify-content:space-between; align-items:center;">
            <div>
                <strong style="color:var(--text-main); font-size:1.1em;">${data.name}</strong> <span style="color:var(--text-muted); font-size:0.9em;">(v${data.version})</span>
                <div style="font-size:0.8em; color:var(--accent-blue); margin-top:4px;">Écosystème: ${data.ecosystem || 'Inconnu'}</div>
            </div>
            <button class="btn-sm btn-sm-primary" onclick="openOverrideModal('${slug}', '${data.name}')">Définir le cycle EOL</button>
        </div>`;
    });
    
    container.innerHTML = html;
}

function openOverrideModal(slug, name) {
    $('overrideSlug').value = slug;
    $('overrideTitle').innerText = `Règle EOL pour : ${name}`;
    $('overrideModal').style.display = 'flex';
}

function saveCustomOverride() {
    const slug = document.getElementById('overrideSlug').value;
    const cycle = document.getElementById('overrideCycle').value;
    const date = document.getElementById('overrideDate').value;
    const link = document.getElementById('overrideLink').value;
    const targetVersion = document.getElementById('overrideTargetVersion').value;

    if (!slug) return;

    // 1. On sauvegarde directement dans la bonne variable globale
    customEolDb[slug] = [{
        cycle: cycle || "1.0",
        eol: date || false,
        link: link || "",
        targetVersion: targetVersion || ""
    }];

    // 2. On utilise la BONNE clé d'enregistrement
    localStorage.setItem('titan_custom_eol', JSON.stringify(customEolDb));
    
    closeModal('overrideModal');
    
    // 3. On force le rechargement
    forceUpdateAnalysis(); 
}

// ============================================================================
// MOTEUR D'ANALYSE PRINCIPAL (EOL, Custom DB, Registres, OSV)
// ============================================================================
async function getSecurityData(name, version) {
    const k = `${name.toLowerCase()}_${version}`;
    if (cache[k]) return cache[k];

    let res = { p: 4, currentEol: "Inconnu", supportedCycles: [], sourceLink: "#", cves: [] };
    const originalName = name.toLowerCase();
    
    const slug = getEolSlug(originalName);
    let allCycles = null;
    let isCustomSource = false;

    // 1. Vérification dans la base de connaissances manuelle
    if (customEolDb[slug]) {
        allCycles = customEolDb[slug];
        isCustomSource = true;
        res.sourceLink = allCycles[0].link || "#"; 
    } 
    // 2. Vérification sur l'API officielle
    else if (validEolSlugs.size === 0 || validEolSlugs.has(slug)) {
        try {
            const eolResponse = await doFetch(`https://endoflife.date/api/${slug}.json`);
            if (eolResponse.ok) {
                allCycles = await eolResponse.json();
                res.sourceLink = `https://endoflife.date/${slug}`;
            }
        } catch (e) {}
    }

    // 3. Récupération des infos registre (NPM, Maven, etc.)
    const regInfo = await getRegistryInfo(originalName, version);

    // 4. L'AFFECTATION STRICTE (A, B ou C)
    if (allCycles) {
        // SCÉNARIO A : Connu par API ou par Règle Manuelle
        const currentCycle = allCycles.find(x => isVersionInCycle(version, x.cycle));
        if (currentCycle) {
            const phase = evaluateSupportPhase(currentCycle, isCustomSource);
            res.currentEol = phase.text; 
            res.p = calculatePFromMs(getDeathDateMs(currentCycle));
        } else {
            res.currentEol = "Version Inconnue"; res.p = 0;
        }
        res.supportedCycles = allCycles.filter(c => evaluateSupportPhase(c, isCustomSource).isAlive);
        
    } else if (regInfo.found && regInfo.releaseDate && regInfo.latest) {
        // SCÉNARIO B : Fallback Registre (NPM/Maven a trouvé le composant)
        // -> Il est connu grâce au Fallback. On NE LE MET PAS dans l'apprentissage.
        res.sourceLink = regInfo.link;
        const age = Math.ceil((new Date() - new Date(regInfo.releaseDate)) / 86400000);
        if (age > 1460) { res.p=0; res.currentEol="Obsolète (>4 ans)"; }
        else if (age > 1095) { res.p=2; res.currentEol="Vieux (>3 ans)"; }
        else if (age > 730) { res.p=3; res.currentEol="Vieillissant (>2 ans)"; }
        else { res.p=4; res.currentEol="Récent (<2 ans)"; }
        
        res.supportedCycles = [{ latest: regInfo.latest, isRegistryFallback: true, registryName: regInfo.ecosystem }];
        
    } else {
        // SCÉNARIO C : VRAIMENT INCONNU
        // -> Seulement ici, on l'envoie dans le Sas d'Apprentissage
        if (!pendingOrphans.has(slug)) {
            pendingOrphans.set(slug, { name: originalName, version: version, ecosystem: regInfo.ecosystem || 'Inconnu' });
            if (typeof renderApprobationTab === 'function') renderApprobationTab();
        }
    }

    // 5. Recherche des CVEs (OSV API)
    try {
        const osvPayload = { version, package: { name: originalName, ecosystem: regInfo.ecosystem || 'npm' } };
        const osv = await doFetch('https://api.osv.dev/v1/query', { method:'POST', body: JSON.stringify(osvPayload) });
        
        if (osv.ok) {
            const j = await osv.json();
            if (j.vulns) { 
                res.p = 0; 
                res.cves = j.vulns.map(v => {
                    let exactScore = "N/A";
                    let vector = null;
                    if (v.severity) {
                        const cvss4 = v.severity.find(s => s.type === 'CVSS_V4');
                        const cvss3 = v.severity.find(s => s.type === 'CVSS_V3');
                        if (cvss4) { vector = cvss4.score; exactScore = calculateUniversalCVSS(vector) || "N/A"; }
                        else if (cvss3) { vector = cvss3.score; exactScore = calculateUniversalCVSS(vector) || "N/A"; }
                    }
                    if (exactScore === "N/A" && v.database_specific?.cvss?.score) exactScore = v.database_specific.cvss.score;
                    let sev = v.database_specific?.severity || "UNKNOWN";
                    if (sev === "UNKNOWN" && exactScore !== "N/A") {
                        const s = parseFloat(exactScore);
                        if (s >= 9.0) sev = "CRITICAL"; else if (s >= 7.0) sev = "HIGH"; else if (s >= 4.0) sev = "MEDIUM"; else sev = "LOW";
                    }
                    const fixedVer = v.affected?.[0]?.ranges?.[0]?.events?.find(x=>x.fixed)?.fixed || "Aucune";
                    return {
                        id: v.aliases?.[0] || v.id, severity: sev, exactScore: exactScore,
                        desc: v.summary || v.details || "Description détaillée non fournie par l'API.", 
                        link: `https://osv.dev/vulnerability/${v.id}`, fixed: fixedVer
                    };
                }).sort((a,b) => {
                    const scoreA = a.exactScore === "N/A" ? 0 : parseFloat(a.exactScore);
                    const scoreB = b.exactScore === "N/A" ? 0 : parseFloat(b.exactScore);
                    return scoreB - scoreA;
                });
            }
        }
    } catch(e) {}

    return cache[k] = res;
}

// RESTAURATION : Cette fonction permet de mettre à jour le lien de support quand on change la version cible
function handleVersionChange(selectElement) {
    const data = JSON.parse(selectElement.value);
    if (!data.link) return;

    const summary = selectElement.closest('summary');
    const supportDiv = summary.querySelector('.col-support');
    
    const supportInfo = evaluateSupportPhase(data);
    supportDiv.innerHTML = `<a href="${data.link}" target="_blank" style="color:${supportInfo.color}; text-decoration:none; display:flex; align-items:center; gap:5px;" onclick="event.stopPropagation();" title="Vérifier sur la source de vérité">🔗 ${supportInfo.text}</a>`;
}

// ============================================================================
// AJOUT MANUEL D'UN COMPOSANT
// ============================================================================
async function addManualComponent() {
    const errorMsg = $('manualErrorMsg');
    errorMsg.innerText = ""; 

    let nameInput = $('manualCompName').value.trim().toLowerCase();
    let versionInput = $('manualCompVersion').value.trim();

    if (versionInput.toLowerCase().startsWith('v')) versionInput = versionInput.substring(1);

    const nameRegex = /^[a-z0-9\-._:@/]+$/;
    if (!nameRegex.test(nameInput)) {
        errorMsg.innerText = "❌ Nom invalide. Évitez les espaces et caractères spéciaux.";
        return;
    }
    
    const versionRegex = /^\d+([a-zA-Z0-9.-]+)?$/;
    if (!versionRegex.test(versionInput)) {
        errorMsg.innerText = "❌ Version invalide (Format attendu : x, x.y, ou x.y.z).";
        return;
    }

    const isDuplicate = activeWorkspace.components.some(c => c.name === nameInput && c.version === versionInput);
    if (isDuplicate) {
        errorMsg.innerText = "⚠️ Ce composant est déjà présent dans le tableau de bord.";
        return;
    }

    if(typeof showDynamicLoader === 'function') {
        showDynamicLoader();
        $('loaderCount').innerText = "Vérification du composant...";
        $('loaderPercent').innerText = "🔍";
        $('loaderBar').style.width = "50%";
        $('loaderDetails').innerText = `Recherche de ${nameInput} (v${versionInput}) sur le réseau...`;
    }

    let isValidatedByApi = false;
    const slug = getEolSlug(nameInput);

    try {
        const eolRes = await doFetch(`https://endoflife.date/api/${slug}.json`);
        if (eolRes.ok) {
            const allCycles = await eolRes.json();
            if (allCycles.some(x => isVersionInCycle(versionInput, x.cycle))) isValidatedByApi = true;
        }
    } catch(e) {}

    if (!isValidatedByApi) {
        const regInfo = await getRegistryInfo(nameInput, versionInput);
        if (regInfo.found) {
            isValidatedByApi = true;
            versionInput = regInfo.correctedVersion || versionInput; 
        }
    }

    if (!isValidatedByApi) {
        if(typeof hideDynamicLoader === 'function') hideDynamicLoader(); 
        errorMsg.innerText = "❌ Composant introuvable. Vérifiez l'orthographe ou la version.";
        return;
    }

    const manualAppRef = "manual-app-wrapper";
    let manualApp = activeWorkspace.components.find(c => c['bom-ref'] === manualAppRef);
    if (!manualApp) {
        manualApp = { "bom-ref": manualAppRef, name: "Ajouts Manuels", type: "application", version: "1.0" };
        activeWorkspace.components.push(manualApp);
        activeWorkspace.dependencies.push({ ref: manualAppRef, dependsOn: [] });
    }

    const newRef = "manual-" + Date.now();
    activeWorkspace.components.push({ "bom-ref": newRef, name: nameInput, version: versionInput, type: "library" });

    const appDeps = activeWorkspace.dependencies.find(d => d.ref === manualAppRef);
    if (appDeps) appDeps.dependsOn.push(newRef);

    localStorage.setItem(`${currentProfileId}_activeWorkspace`, JSON.stringify(activeWorkspace));
    
    $('manualCompName').value = ""; 
    $('manualCompVersion').value = "";
    closeModal('addCompModal');
    
    processSbom(activeWorkspace);
}

function deleteManualComponent(event, refId) {
    event.stopPropagation();
    if (!confirm("Voulez-vous vraiment supprimer ce composant ?")) return;

    activeWorkspace.components = activeWorkspace.components.filter(c => c['bom-ref'] !== refId);
    const appDeps = activeWorkspace.dependencies.find(d => d.ref === "manual-app-wrapper");
    if (appDeps && appDeps.dependsOn) {
        appDeps.dependsOn = appDeps.dependsOn.filter(r => r !== refId);
    }

    localStorage.setItem(`${currentProfileId}_activeWorkspace`, JSON.stringify(activeWorkspace));
    processSbom(activeWorkspace);
}

// ============================================================================
// TRAITEMENT DU WORKSPACE ET GÉNÉRATION DU DASHBOARD
// ============================================================================
async function processSbom(workspace) {
    if ($('loading')) $('loading').style.display = 'flex';
    
    
    const comps = workspace.components || [];
    const deps = workspace.dependencies || [];
    
    const cMap = new Map(); 
    comps.forEach(c => cMap.set(c['bom-ref'], c));
    
    const dMap = new Map(); 
    deps.forEach(d => { 
        if (!dMap.has(d.ref)) dMap.set(d.ref, new Set()); 
        (d.dependsOn || []).forEach(r => dMap.get(d.ref).add(r)); 
    });

    const unique = []; 
    const seen = new Set();
    comps.forEach(c => { 
        if (c.type !== 'application') {
            const k = `${c.name.toLowerCase()}|${c.version}`; 
            if (!seen.has(k)) { unique.push(c); seen.add(k); } 
        }
    });
    
    window.lastProcessedVulns.clear();
    pendingOrphans.clear();
    
    if (typeof renderApprobationTab === 'function') renderApprobationTab(); // Met à jour l'affichage

    const BATCH_SIZE = 15;
    for (let i = 0; i < unique.length; i += BATCH_SIZE) {
        const batch = unique.slice(i, i + BATCH_SIZE);
        if ($('progressBar')) {
            const percent = Math.round(((i + batch.length) / unique.length) * 100);
            $('progressBar').style.width = percent + '%';
        }
        await Promise.all(batch.map(c => getSecurityData(c.name, c.version)));
        await new Promise(resolve => requestAnimationFrame(resolve));
        if (i + BATCH_SIZE < unique.length) {
            await new Promise(r => setTimeout(r, 400)); 
        }
    }

    const apps = comps.filter(c => c.type === 'application');
    apps.forEach(app => {
        const queue = [app['bom-ref']];
        const visited = new Set();
        
        while (queue.length > 0) {
            const currentRef = queue.shift();
            if (visited.has(currentRef)) continue;
            visited.add(currentRef);
            
            const childrenRefs = dMap.get(currentRef) || [];
            childrenRefs.forEach(ref => {
                const child = cMap.get(ref);
                if (child) {
                    if (child.type !== 'application') {
                        const info = cache[`${child.name.toLowerCase()}_${child.version}`];
                        if (info) {
                            const k = `${child.name.toLowerCase()}|${child.version}`;
                            if (!window.lastProcessedVulns.has(k)) {
                                window.lastProcessedVulns.set(k, { ...child, ...info, impacted: [] });
                            }
                            const vulnItem = window.lastProcessedVulns.get(k);
                            if (!vulnItem.impacted.includes(app.name)) {
                                vulnItem.impacted.push(app.name);
                            }
                        }
                    }
                    queue.push(ref); 
                }
            });
        }
    });

    let pStats = [0, 0, 0, 0, 0];
    const sortedVulns = Array.from(window.lastProcessedVulns.values()).sort((a, b) => a.p - b.p);

    const html = sortedVulns.map(v => {
        pStats[v.p]++;
        
        // RESTAURATION: On réintègre la génération JSON pour optionsHtml
        // VÉRIFICATION DE LA RÈGLE LOCALE (VERSION CIBLE MANUELLE)
        const slug = getEolSlug(v.name.toLowerCase());
        const localRule = customEolDb[slug] ? customEolDb[slug][0] : null;
        
        let colLongHtml = ""; 
        let colSupportHtml = ""; 

        if (localRule && localRule.targetVersion) {
            // SCÉNARIO 1 : L'utilisateur a forcé une version cible manuellement
            colLongHtml = `<span style="color:var(--accent-blue); font-weight:bold; font-size:12px; padding:5px 8px; border:1px dashed var(--accent-blue); border-radius:4px; display:inline-block; text-align:center; min-width:80px;">v${escapeHTML(localRule.targetVersion)}</span>`;
            
            // On récupère le statut global de la règle locale pour le lien de support
            const supportPhase = evaluateSupportPhase(localRule, true);
            const linkHref = localRule.link ? `href="${escapeHTML(localRule.link)}" target="_blank" onclick="event.stopPropagation();"` : `onclick="event.stopPropagation();" style="cursor:default;"`;
            colSupportHtml = `<a ${linkHref} style="color:${escapeHTML(supportPhase.color)}; text-decoration:none; display:flex; align-items:center; gap:5px;" title="Source de vérité interne">🔗 ${escapeHTML(supportPhase.text)}</a>`;
        } 
        else {
            // SCÉNARIO 2 : COMPORTEMENT API CLASSIQUE (Menu déroulant)
            let optionsHtml = "<option value='{}'>Aucune cible disponible</option>";
            let initialSupportLink = "<span style='color:var(--text-muted)'>Aucune Cible</span>";

            if (v.supportedCycles && v.supportedCycles.length > 0) {
                optionsHtml = v.supportedCycles.map((c, index) => {
                    const label = index === 0 ? `v${c.latest} (Dernière)` : `v${c.latest}`;
                    return `<option value='${escapeHTML(JSON.stringify({
                        support: c.support, extendedSupport: c.extendedSupport, eol: c.eol, 
                        link: v.sourceLink, isRegistryFallback: c.isRegistryFallback, registryName: c.registryName
                    }))}'>${escapeHTML(label)}</option>`;
                }).join('');

                const firstCycle = v.supportedCycles[0];
                const supportPhase = evaluateSupportPhase(firstCycle);
                initialSupportLink = `<a href="${escapeHTML(v.sourceLink)}" target="_blank" style="color:${escapeHTML(supportPhase.color)}; text-decoration:none; display:flex; align-items:center; gap:5px;" onclick="event.stopPropagation();" title="Ouvrir la source de vérité">🔗 ${escapeHTML(supportPhase.text)}</a>`;
            }
            
            colLongHtml = `<select class="version-select" onchange="handleVersionChange(this)" onclick="event.stopPropagation();">${optionsHtml}</select>`;
            colSupportHtml = initialSupportLink;
        }

        // --- GÉNÉRATION DES BADGES ET BOUTONS ---
        const cveBtn = (v.cves && v.cves.length > 0) ? `<button class="cve-badge" onclick="openCVE(event, '${escapeHTML(v.name)}', '${escapeHTML(v.version)}')">🚨 ${v.cves.length} Faille(s)</button>` : '';
        const delBtn = (v['bom-ref'] && v['bom-ref'].startsWith('manual-')) 
            ? `<button class="cve-badge" style="background:rgba(255,68,68,0.1); border-color:var(--p0); color:var(--p0);" onclick="deleteManualComponent(event, '${escapeHTML(v['bom-ref'])}')">🗑️</button>` : '';

        let searchKeywords = `${v.name.toLowerCase()} ${v.version}`;
        if (v.cves && v.cves.length > 0) {
            searchKeywords += " " + v.cves.map(c => c.id.toLowerCase()).join(" ");
        }

        // --- RETOUR DU HTML FINAL ---
        return `
        <details data-search="${escapeHTML(searchKeywords)}">
            <summary>
                <div class="col-prio"><span class="badge" style="background:var(--p${v.p})">P${v.p}</span></div>
                <div class="col-comp" title="${escapeHTML(v.name)}">${escapeHTML(v.name)} <small>v${escapeHTML(v.version)}</small> ${cveBtn} ${delBtn}</div>
                <div class="col-eol" style="color:var(--p${v.p})">${escapeHTML(v.currentEol)}</div>
                
                <!-- Injection dynamique (Select ou Tag manuel) -->
                <div class="col-long">${colLongHtml}</div>
                <div class="col-support">${colSupportHtml}</div>
                
                <div class="col-impact">${v.impacted.length} Apps ⏷</div>
            </summary>
            <div class="content">${v.impacted.map(n => `<span class="parent-tag">${escapeHTML(n)}</span>`).join('')}</div>
        </details>`;
    }).join('');

    if ($('results')) {
        $('results').innerHTML = html || "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Aucun composant parent vulnérable trouvé.</p>";
    }
    
    for (let i = 0; i < 5; i++) { 
        const box = $(`box-p${i}`); 
        if (box) box.querySelector('.count').innerText = pStats[i]; 
    }
    
    if ($('loading')) $('loading').style.display = 'none';
}

// ============================================================================
// HISTORIQUE ET PROFILS
// ============================================================================
function openProfileModal() {
    $('profileList').innerHTML = appProfiles.map(p => `
        <div class="profile-item ${p.id === currentProfileId ? 'active' : ''}">
            <strong>${escapeHTML(p.name)}</strong>
            <div>
                <button class="btn-sm" onclick="switchProfile('${escapeHTML(p.id)}')">Basculer</button>
                <button class="btn-sm btn-sm-danger" onclick="deleteProfile('${escapeHTML(p.id)}')">🗑️</button>
            </div>
        </div>`).join('');
    $('profileModal').style.display = 'flex';
}

function switchProfile(id) { currentProfileId = id; localStorage.setItem('currentProfileId', id); loadProfileContext(); closeModal('profileModal'); }
function createNewProfile() {
    const name = $('newProfileName').value.trim();
    if(!name) return;
    const id = 'prof_' + Date.now();
    appProfiles.push({ id, name });
    localStorage.setItem('appProfiles', JSON.stringify(appProfiles));
    switchProfile(id);
}
function deleteProfile(id) {
    if(appProfiles.length <= 1) return alert("Dernier profil protégé.");
    if(!confirm("Supprimer ce profil ?")) return;
    localStorage.removeItem(`${id}_sbomHistory`); localStorage.removeItem(`${id}_activeWorkspace`);
    appProfiles = appProfiles.filter(p => p.id !== id);
    localStorage.setItem('appProfiles', JSON.stringify(appProfiles));
    if(currentProfileId === id) switchProfile(appProfiles[0].id); else openProfileModal();
}

function saveToHistory(filename, data) {
    const id = Date.now().toString(); 
    sbomHistory.unshift({ id, filename, dateStr: new Date().toLocaleString('fr-FR'), data });
    if(sbomHistory.length > 15) sbomHistory.pop();
    localStorage.setItem(`${currentProfileId}_sbomHistory`, JSON.stringify(sbomHistory)); 
    renderHistoryUI(); return id;
}

function renderHistoryUI() {
    if($('historyList')) $('historyList').innerHTML = sbomHistory.map(i => `
        <div class="history-item">
            <span>📄 ${escapeHTML(i.filename)} <small style="color:var(--text-muted);">${escapeHTML(i.dateStr)}</small></span>
            <div>
                <button class="btn-sm btn-sm-success" onclick="appendHistory('${i.id}')">➕</button>
                <button class="btn-sm btn-sm-primary" onclick="replaceHistory('${i.id}')">🔄</button>
                <button class="btn-sm btn-sm-danger" onclick="deleteHistoryFile('${i.id}')">🗑️</button>
            </div>
        </div>`).join('');
}

function deleteHistoryFile(id) {
    if(!confirm("Voulez-vous vraiment supprimer cet import ? Ses composants seront retirés du tableau de bord.")) return;

    sbomHistory = sbomHistory.filter(i => i.id !== id); 
    localStorage.setItem(`${currentProfileId}_sbomHistory`, JSON.stringify(sbomHistory));
    
    renderHistoryUI();

    activeWorkspace.components = activeWorkspace.components.filter(c => c._sourceId !== id);
    activeWorkspace.dependencies = activeWorkspace.dependencies.filter(d => d._sourceId !== id);
    localStorage.setItem(`${currentProfileId}_activeWorkspace`, JSON.stringify(activeWorkspace));
    
    if(activeWorkspace.components.length > 0) {
        processSbom(activeWorkspace); 
    } else {
        clearWorkspaceUIOnly();
    }
}

function appendHistory(id) {
    const item = sbomHistory.find(x => x.id === id); if(!item) return;
    item.data.components.forEach(c => c._sourceId = id); if(item.data.dependencies) item.data.dependencies.forEach(d => d._sourceId = id);
    activeWorkspace.components = activeWorkspace.components.filter(c => c._sourceId !== id); activeWorkspace.dependencies = activeWorkspace.dependencies.filter(d => d._sourceId !== id);
    activeWorkspace.components.push(...item.data.components); activeWorkspace.dependencies.push(...(item.data.dependencies || []));
    localStorage.setItem(`${currentProfileId}_activeWorkspace`, JSON.stringify(activeWorkspace)); processSbom(activeWorkspace);
}
function replaceHistory(id) {
    const item = sbomHistory.find(x => x.id === id); if(!item) return;
    item.data.components.forEach(c => c._sourceId = id); if(item.data.dependencies) item.data.dependencies.forEach(d => d._sourceId = id);
    activeWorkspace = { components: [...item.data.components], dependencies: [...(item.data.dependencies || [])] };
    localStorage.setItem(`${currentProfileId}_activeWorkspace`, JSON.stringify(activeWorkspace)); 
    processSbom(activeWorkspace);
}

const fileIn = $('fileIn');
if (fileIn) {
    fileIn.addEventListener('change', async e => {
        for(let f of e.target.files) {
            const data = JSON.parse(await f.text()); const nid = saveToHistory(f.name, data);
            if(data.components) { data.components.forEach(c => c._sourceId = nid); activeWorkspace.components.push(...data.components); }
            if(data.dependencies) { data.dependencies.forEach(d => d._sourceId = nid); activeWorkspace.dependencies.push(...data.dependencies); }
        }
        localStorage.setItem(`${currentProfileId}_activeWorkspace`, JSON.stringify(activeWorkspace)); processSbom(activeWorkspace); e.target.value = '';
    });
}

function clearWorkspace() {
    activeWorkspace = { components: [], dependencies: [] }; localStorage.removeItem(`${currentProfileId}_activeWorkspace`);
    clearWorkspaceUIOnly();
}
function clearWorkspaceUIOnly() {
    window.lastProcessedVulns.clear(); 
    [0,1,2,3,4].forEach(i => { const box = $(`box-p${i}`); if(box) box.querySelector('.count').innerText = "0"; }); 
    if($('results')) $('results').innerHTML = "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Espace vidé.</p>"; 
    if($('globalSearch')) $('globalSearch').value = "";
}

function forceUpdateAnalysis() { 
    if(activeWorkspace.components.length > 0) { 
        Object.keys(cache).forEach(k => delete cache[k]); 
        if(typeof showDynamicLoader === 'function') {
            showDynamicLoader();
            if($('loaderCount')) $('loaderCount').innerText = "Re-scan complet en cours...";
        }
        processSbom(activeWorkspace); 
    } 
}

function filterDashboard() { const t = $('globalSearch').value.toLowerCase(); document.querySelectorAll('#results details').forEach(r => { r.style.display = r.getAttribute('data-search').includes(t) ? "" : "none"; }); }

// ============================================================================
// EXPORTS ET MODALS CVE
// ============================================================================
function exportToCSV() {
    if(!lastProcessedVulns.size) return alert("Tableau vide.");
    let csv = "Prio;Composant;Version;EOL_Actuel;Apps\n";
    Array.from(lastProcessedVulns.values()).sort((a,b)=>a.p-b.p).forEach(v => { csv += `"P${v.p}";"${v.name}";"${v.version}";"${v.currentEol}";"${v.impacted.join(',')}"\n`; });
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([new Uint8Array([0xEF,0xBB,0xBF]), csv], {type:"text/csv;charset=utf-8;"})); a.download = `Dashboard_${currentProfileId}.csv`; a.click();
}

function closeModal(id) { $(id).style.display = 'none'; }

function openCVE(e, n, v) {
    e.stopPropagation(); const d = cache[`${n.toLowerCase()}_${v}`]; if(!d||!d.cves) return;
    currentCVEs = d.cves; $('modalCompName').innerText = `${n} (v${v})`; $('cveSearch').value = '';
    renderCVEs(currentCVEs); $('cveModal').style.display = 'flex';
}

function filterCVEs() { 
    const q = $('cveSearch').value.toLowerCase(); 
    renderCVEs(currentCVEs.filter(c => c.id.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q))); 
}

function renderCVEs(list) {
    $('cveList').innerHTML = list.map(c => {
        const sev = c.severity.toUpperCase();
        let bg = '#8b949e'; 
        if (sev === 'CRITICAL') bg = '#ff4444';
        else if (sev === 'HIGH') bg = '#ff7b72';
        else if (sev === 'MEDIUM' || sev === 'MODERATE') bg = '#ffa657';
        else if (sev === 'LOW') bg = '#388bfd';

        const tc = (bg === '#ffa657' || bg === '#8b949e') ? '#000' : '#fff';
        
        const solutionHtml = c.fixed !== "Aucune" 
            ? `<span style="color:var(--accent-blue)">✨ <strong>Solution :</strong> Mettre à jour vers <strong>v${c.fixed.replace('v','')}</strong></span>`
            : `<span style="color:var(--p0)">⚠️ <strong>Solution :</strong> Aucun correctif technique déclaré. Patcher manuellement.</span>`;

        return `
        <div style="border-left:4px solid ${bg}; margin-bottom:15px; background:var(--bg-card); padding:15px; border-radius:6px; border: 1px solid var(--border-color);">
            <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-color); padding-bottom:10px; margin-bottom:10px;">
                <div style="display:flex; align-items:center; gap:15px;">
                    <span style="background:${bg}; color:${tc}; padding:4px 10px; border-radius:4px; font-weight:bold; font-size:14px;">${c.exactScore}</span>
                    <div>
                        <strong style="font-size:1.2em; display:block; color:var(--text-main);">${c.id}</strong>
                        <span style="font-size:10px; font-weight:bold; color:${bg};">${sev}</span>
                    </div>
                </div>
                <a href="${c.link}" target="_blank" style="color:var(--text-muted); text-decoration:none; display:flex; align-items:center; gap:5px; font-size:12px; transition:0.2s;" onmouseover="this.style.color='white'" onmouseout="this.style.color='var(--text-muted)'">🔗 Fiche OSV</a>
            </div>
            
            <p style="margin:0 0 15px 0; color:#a1aab3; line-height:1.5; font-size:12px;">${c.desc}</p>
            
            <div style="background:rgba(88,166,255,0.05); border:1px solid rgba(88,166,255,0.2); padding:10px; border-radius:4px; font-size:12px;">
                ${solutionHtml}
            </div>
        </div>`;
    }).join('');
}

function runDemo() {
    const demo = { components: [], dependencies: [] }; 
    for(let i=1; i<=3; i++) {
        const app = `app-${i}`; demo.components.push({ "bom-ref": app, name: `Service-${i}`, type: 'application', version: `2.${i}` });
        const tr = `p-${i}`;
        if(i===1) demo.components.push({ "bom-ref": tr, name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15' });
        if(i===2) demo.components.push({ "bom-ref": tr, name: 'axios', version: '0.21.1', purl: 'pkg:npm/axios@0.21.1' });
        if(i===3) demo.components.push({ "bom-ref": tr, name: 'spring-boot', version: '3.2.0', purl: 'pkg:maven/spring-boot@3.2.0' });
        demo.dependencies.push({ ref: app, dependsOn: [tr] });
    }
    const nid = saveToHistory("demo.json", demo);
    demo.components.forEach(c => c._sourceId = nid); demo.dependencies.forEach(d => d._sourceId = nid);
    activeWorkspace.components.push(...demo.components); activeWorkspace.dependencies.push(...demo.dependencies);
    localStorage.setItem(`${currentProfileId}_activeWorkspace`, JSON.stringify(activeWorkspace));
    processSbom(activeWorkspace);
}
