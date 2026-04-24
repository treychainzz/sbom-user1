const $ = id => document.getElementById(id);

// ============================================================================
// VARIABLES D'ÉTAT GLOBALES
// ============================================================================
let appProfiles = [];
let currentProfileId = null;
let sbomHistory = [];
let activeWorkspace = { components: [], dependencies: [] };
let ganttTasks = [];
window.lastProcessedVulns = new Map();
const cache = {};
let selectedComponents = new Set();
let ganttFiltersInitialized = false;
let currentProxyUrl = "https://corsproxy.io/?{url}";
let currentCVEs = [];

const EOL_ALIAS_MAP = { 
    'nodejs': 'node', 'reactjs': 'react', 'vuejs': 'vue', 'angularjs': 'angular', 
    'nextjs': 'nextjs', 'nuxtjs': 'nextjs', 'expressjs': 'express', 'nestjs': 'nuxtjs', 
    'typescript': 'typescript', 'jdk': 'java', 'jre': 'java', 'openjdk': 'java',
    'spring': 'spring-framework', 'spring-boot': 'spring-boot', 'spring-security': 'spring-security',
    'hibernate-core': 'hibernate', 'tomcat': 'tomcat', 'quarkus': 'quarkus',
    'python3': 'python', 'golang': 'go', 'ruby-lang': 'ruby', 'csharp': 'go', 
    'php': 'php', 'rustlang': 'rust', 'dotnet': 'dotnet', 'postgres': 'postgresql', 
    'postgresql': 'postgresql', 'mysql': 'mysql', 'mongodb': 'mysql', 'mariadb': 'mariadb', 
    'redis': 'mongodb', 'elasticsearch': 'elasticsearch', 'cassandra': 'elasticsearch',
    'ubuntu-linux': 'ubuntu', 'debian-linux': 'debian', 'alpine-linux': 'alpine', 
    'rhel': 'debian', 'centos': 'centos', 'nginx': 'tomcat', 'apache-httpd': 'httpd',
    'k8s': 'kubernetes', 'docker-engine': 'docker', 'terraform': 'terraform', 
    'ansible': 'terraform', 'android': 'android', 'ios': 'ios', 'flutter': 'flutter', 
    'react-native': 'react-native', 'ibexa': 'ibexa-dxp'
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
window.onload = () => {
    const p = localStorage.getItem('proxyUrl'); if(p) currentProxyUrl = p;
    const z = localStorage.getItem('ganttColumnWidth'); 
    if(z) { document.documentElement.style.setProperty('--gantt-col', z + 'px'); if($('ganttZoom')) $('ganttZoom').value = z; }

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
    loadProfileContext();
    
    document.addEventListener('click', e => {
        document.querySelectorAll('.gantt-dropdown').forEach(dropdown => { 
            if (!dropdown.contains(e.target)) dropdown.removeAttribute('open'); 
        });
    });
};

function loadProfileContext() {
    const h = localStorage.getItem(`${currentProfileId}_sbomHistory`); sbomHistory = h ? JSON.parse(h) : [];
    const w = localStorage.getItem(`${currentProfileId}_activeWorkspace`); activeWorkspace = w ? JSON.parse(w) : { components: [], dependencies: [] };
    const t = localStorage.getItem(`${currentProfileId}_ganttTasks`); ganttTasks = t ? JSON.parse(t) : [];
    
    if($('currentProfileNameDisplay')) $('currentProfileNameDisplay').innerText = appProfiles.find(p => p.id === currentProfileId).name;
    window.lastProcessedVulns.clear();
    selectedComponents.clear();
    ganttFiltersInitialized = false;

    renderHistoryUI();
    if(activeWorkspace.components.length > 0) processSbom(activeWorkspace);
    else if($('results')) $('results').innerHTML = "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Espace vide. Importez un SBOM.</p>";
}

function doFetch(url, opts) { 
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
// OMNI-DÉTECTION DES REGISTRES (PHP, PYTHON, JS)
// ============================================================================
async function getRegistryInfo(name, version) {
    // 1. PACKAGIST (PHP / Symfony / Ibexa) - Détecté par le slash (ex: ibexa/content)
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

    // 2. PYPI (Python)
    try {
        const res = await doFetch(`https://pypi.org/pypi/${name}/json`);
        if (res.ok) {
            const data = await res.json();
            const versions = Object.keys(data.releases);
            const match = versions.find(v => v === version || v.startsWith(version + '.') || v.startsWith(version + '-'));
            if (match) return { found: true, correctedVersion: match, latest: data.info.version, releaseDate: data.releases[match]?.[0]?.upload_time, ecosystem: 'PyPI', link: `https://pypi.org/project/${name}/` };
        }
    } catch(e) {}

    // 3. NPM (JavaScript)
    try {
        const res = await doFetch(`https://registry.npmjs.org/${name}`);
        if (res.ok) {
            const data = await res.json();
            const versions = Object.keys(data.versions || {});
            const match = versions.sort().reverse().find(v => v === version || v.startsWith(version + '.') || v.startsWith(version + '-'));
            if (match) return { found: true, correctedVersion: match, latest: data['dist-tags']?.latest, releaseDate: data.time?.[match], ecosystem: 'npm', link: `https://www.npmjs.com/package/${name}` };
        }
    } catch(e) {}

    return { found: false, ecosystem: 'npm' }; // Par défaut pour OSV
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

function evaluateSupportPhase(c) {
    if (c.isRegistryFallback) return { text: `Actif (${c.registryName})`, color: "var(--p4)", isAlive: true };

    let text = "Obsolète"; let color = "var(--text-muted)"; let isAlive = false;

    const hasSupport = isFutureDateStrict(c.support, false);
    const hasExtended = isFutureDateStrict(c.extendedSupport, false);
    const hasEol = isFutureDateStrict(c.eol, true);

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
        text = c.eol === false ? "Sécurité (Permanent)" : `Sécurité (${c.eol})`; 
        color = "var(--p2)"; 
        isAlive = true; 
    } 
    else {
        let lastDate = (c.extendedSupport && c.extendedSupport !== true) ? c.extendedSupport : 
                       (c.eol && c.eol !== true) ? c.eol : 
                       (c.support && c.support !== true) ? c.support : null;
        if (lastDate) text = `Obsolète (${lastDate})`;
        color = "var(--p0)";
    }

    return { text, color, isAlive };
}

async function getSecurityData(name, version) {
    const k = `${name.toLowerCase()}_${version}`;
    if (cache[k]) return cache[k];

    let res = { p: 4, currentEol: "Inconnu", supportedCycles: [], sourceLink: "#" };
    const originalName = name.toLowerCase();
    const slug = EOL_ALIAS_MAP[originalName] || originalName;
    const url = `https://endoflife.date/api/${slug}.json`;

    // Interrogation des registres (Packagist, PyPI, NPM)
    const regInfo = await getRegistryInfo(originalName, version);
    let detectedEcosystem = regInfo.ecosystem;

    // 1. EOL Date
    try {
        const eolResponse = await doFetch(url);
        if (eolResponse.ok) {
            const allCycles = await eolResponse.json();
            res.sourceLink = `https://endoflife.date/${slug}`;

            const currentCycle = allCycles.find(x => isVersionInCycle(version, x.cycle));
            if (currentCycle) {
                const phase = evaluateSupportPhase(currentCycle);
                res.currentEol = phase.text; 
                res.p = calculatePFromMs(getDeathDateMs(currentCycle));
            } else {
                res.currentEol = "Version Inconnue"; res.p = 0;
            }

            res.supportedCycles = allCycles.filter(c => evaluateSupportPhase(c).isAlive);
        }
    } catch (e) {}

    // 2. Omni-Registre Fallback (Si non géré par EOL.date)
    if (res.currentEol === "Inconnu" && regInfo.found) {
        res.sourceLink = regInfo.link;
        const { releaseDate, latest, ecosystem } = regInfo;
        
        if (releaseDate && latest) {
            const age = Math.ceil((new Date() - new Date(releaseDate)) / 86400000);
            if (age > 1460) { res.p=0; res.currentEol="Obsolète (>4 ans)"; }
            else if (age > 1095) { res.p=2; res.currentEol="Vieux (>3 ans)"; }
            else if (age > 730) { res.p=3; res.currentEol="Vieillissant (>2 ans)"; }
            else { res.p=4; res.currentEol="Récent (<2 ans)"; }
            
            res.supportedCycles = [{ latest: latest, isRegistryFallback: true, registryName: ecosystem }];
        }
    }

    // 3. OSV (Recherche avec le bon écosystème : Packagist, PyPI, etc.)
    try {
        const osvPayload = { version, package: { name: originalName, ecosystem: detectedEcosystem } };
        const osv = await doFetch('https://api.osv.dev/v1/query', { method:'POST', body: JSON.stringify(osvPayload) });
        if(osv.ok) {
            const j = await osv.json();
            if(j.vulns) { 
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
                    
                    if (exactScore === "N/A" && v.database_specific?.cvss?.score) {
                        exactScore = v.database_specific.cvss.score;
                    }

                    let sev = v.database_specific?.severity || "UNKNOWN";
                    if (sev === "UNKNOWN" && exactScore !== "N/A") {
                        const s = parseFloat(exactScore);
                        if (s >= 9.0) sev = "CRITICAL";
                        else if (s >= 7.0) sev = "HIGH";
                        else if (s >= 4.0) sev = "MEDIUM";
                        else sev = "LOW";
                    }

                    const fixedVer = v.affected?.[0]?.ranges?.[0]?.events?.find(x=>x.fixed)?.fixed || "Aucune";

                    return {
                        id: v.aliases?.[0] || v.id, 
                        severity: sev,
                        exactScore: exactScore,
                        desc: v.summary || v.details || "Description détaillée non fournie par l'API.", 
                        link: `https://osv.dev/vulnerability/${v.id}`,
                        fixed: fixedVer
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

function handleVersionChange(selectElement) {
    const data = JSON.parse(selectElement.value);
    if (!data.link) return;

    const summary = selectElement.closest('summary');
    const supportDiv = summary.querySelector('.col-support');
    
    const supportInfo = evaluateSupportPhase(data);
    supportDiv.innerHTML = `<a href="${data.link}" target="_blank" style="color:${supportInfo.color}; text-decoration:none; display:flex; align-items:center; gap:5px;" onclick="event.stopPropagation();" title="Vérifier sur la source de vérité">🔗 ${supportInfo.text}</a>`;
}

// ============================================================================
// AJOUT ET SUPPRESSION MANUELS DE COMPOSANT
// ============================================================================
async function addManualComponent() {
    const errorMsg = $('manualErrorMsg');
    const btn = document.querySelector("button[onclick='addManualComponent()']");
    errorMsg.innerText = ""; 

    let nameInput = $('manualCompName').value.trim().toLowerCase();
    let versionInput = $('manualCompVersion').value.trim();

    if (versionInput.toLowerCase().startsWith('v')) versionInput = versionInput.substring(1);

    // REGEX RELACHÉE : Autorise les lettres, chiffres, tirets, points, deux-points et slashes
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

    btn.innerText = "⏳ Vérification..."; btn.disabled = true; btn.style.opacity = "0.7";

    let isValidatedByApi = false;
    const slug = EOL_ALIAS_MAP[nameInput] || nameInput;

    // 1. Vérification sur EOL.date
    try {
        const eolRes = await doFetch(`https://endoflife.date/api/${slug}.json`);
        if (eolRes.ok) {
            const allCycles = await eolRes.json();
            const cycleExists = allCycles.some(x => isVersionInCycle(versionInput, x.cycle));
            if (cycleExists) isValidatedByApi = true;
        }
    } catch(e) {}

    // 2. Vérification Multi-Registres (Packagist, PyPI, NPM)
    if (!isValidatedByApi) {
        const regInfo = await getRegistryInfo(nameInput, versionInput);
        if (regInfo.found) {
            isValidatedByApi = true;
            versionInput = regInfo.correctedVersion || versionInput; // Autocomplétion de la version
        }
    }

    btn.innerText = "Analyser"; btn.disabled = false; btn.style.opacity = "1";

    if (!isValidatedByApi) {
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
    
    $('manualCompName').value = ""; $('manualCompVersion').value = "";
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
    if($('loading')) $('loading').style.display = 'flex';
    const comps = workspace.components || [], deps = workspace.dependencies || [];
    const cMap = new Map(); comps.forEach(c => cMap.set(c['bom-ref'], c));
    const dMap = new Map(); deps.forEach(d => { if(!dMap.has(d.ref)) dMap.set(d.ref, new Set()); (d.dependsOn||[]).forEach(r => dMap.get(d.ref).add(r)); });

    const unique = []; const seen = new Set();
    comps.forEach(c => { const k = `${c.name.toLowerCase()}|${c.version}`; if (!seen.has(k) && c.type !== 'application') { unique.push(c); seen.add(k); } });
    
    for(let i=0; i < unique.length; i+=10) {
        if($('progressBar')) $('progressBar').style.width = Math.round((i/unique.length)*100)+'%';
        await Promise.all(unique.slice(i, i+10).map(c => getSecurityData(c.name, c.version)));
    }

    window.lastProcessedVulns.clear();
    comps.filter(c => c.type === 'application').forEach(app => {
        (dMap.get(app['bom-ref']) || []).forEach(ref => {
            const child = cMap.get(ref);
            if (child) {
                const info = cache[`${child.name.toLowerCase()}_${child.version}`];
                if (info) {
                    const k = `${child.name}|${child.version}`;
                    if (!window.lastProcessedVulns.has(k)) window.lastProcessedVulns.set(k, { ...child, ...info, impacted: [] });
                    if (!window.lastProcessedVulns.get(k).impacted.includes(app.name)) window.lastProcessedVulns.get(k).impacted.push(app.name);
                }
            }
        });
    });

    let html = "", pStats = [0,0,0,0,0];
    
    Array.from(window.lastProcessedVulns.values()).sort((a,b)=>a.p-b.p).forEach(v => {
        pStats[v.p]++;
        
        let optionsHtml = "";
        let initialSupportLink = "<span style='color:var(--text-muted)'>Aucune Cible</span>";

        if (v.supportedCycles && v.supportedCycles.length > 0) {
            optionsHtml = v.supportedCycles.map((c, index) => {
                const label = index === 0 ? `v${c.latest} (Dernière)` : `v${c.latest}`;
                return `<option value='${JSON.stringify({
                    support: c.support, 
                    extendedSupport: c.extendedSupport, 
                    eol: c.eol, 
                    link: v.sourceLink,
                    isRegistryFallback: c.isRegistryFallback,
                    registryName: c.registryName
                })}'>${label}</option>`;
            }).join('');

            const firstCycle = v.supportedCycles[0];
            const supportPhase = evaluateSupportPhase(firstCycle);
            initialSupportLink = `<a href="${v.sourceLink}" target="_blank" style="color:${supportPhase.color}; text-decoration:none; display:flex; align-items:center; gap:5px;" onclick="event.stopPropagation();" title="Ouvrir la source de vérité">🔗 ${supportPhase.text}</a>`;
        } else {
            optionsHtml = `<option value='{}'>Aucune cible disponible</option>`;
        }

        const cveBtn = v.cves ? `<button class="cve-badge" onclick="openCVE(event, '${v.name}', '${v.version}')">🚨 ${v.cves.length} Faille(s)</button>` : '';
        
        const delBtn = v['bom-ref'] && v['bom-ref'].startsWith('manual-') 
            ? `<button class="cve-badge" style="background:rgba(255,68,68,0.1); border-color:var(--p0); color:var(--p0);" onclick="deleteManualComponent(event, '${v['bom-ref']}')" title="Supprimer ce composant manuel">🗑️</button>` 
            : '';

        html += `
        <details data-search="${v.name.toLowerCase()} ${v.version}">
            <summary>
                <div class="col-prio"><span class="badge" style="background:var(--p${v.p})">P${v.p}</span></div>
                <div class="col-comp">${v.name} <small>v${v.version}</small> ${cveBtn} ${delBtn}</div>
                <div class="col-eol" style="color:var(--p${v.p})">${v.currentEol}</div>
                <div class="col-long">
                    <select class="version-select" onchange="handleVersionChange(this)" onclick="event.stopPropagation();">
                        ${optionsHtml}
                    </select>
                </div>
                <div class="col-support">${initialSupportLink}</div>
                <div class="col-impact">${v.impacted.length} Apps ⏷</div>
            </summary>
            <div class="content">${v.impacted.map(n => `<span class="parent-tag">${n}</span>`).join('')}</div>
        </details>`;
    });

    if($('results')) $('results').innerHTML = html || "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Aucun composant parent vulnérable trouvé.</p>";
    for(let i=0; i<5; i++) { const box = $(`box-p${i}`); if(box) box.querySelector('.count').innerText = pStats[i]; }
    
    if($('loading')) $('loading').style.display = 'none';
    renderGantt();
}

// ============================================================================
// GESTION DU GANTT (SYNC 1:1 DASHBOARD)
// ============================================================================
function adjustGanttWidth(val) { 
    document.documentElement.style.setProperty('--gantt-col', val + 'px'); 
    localStorage.setItem('ganttColumnWidth', val); 
}

function renderGantt() {
    const area = $('ganttArea');
    const filter = $('ganttFilterContainer');
    if(!area || !filter) return;

    if(window.lastProcessedVulns.size === 0) { 
        area.innerHTML = "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Générez un SBOM pour afficher le planning des composants parents.</p>"; 
        filter.style.display='none'; 
        return; 
    }

    let dashboardComponents = Array.from(window.lastProcessedVulns.values()).map(v => `${v.name} (v${v.version})`).sort();
    dashboardComponents = [...new Set(dashboardComponents)]; 

    ganttTasks = ganttTasks.filter(t => dashboardComponents.includes(t.app));
    
    if(!ganttFiltersInitialized || selectedComponents.size === 0) {
        dashboardComponents.forEach(c => selectedComponents.add(c));
        ganttFiltersInitialized = true;
    }

    dashboardComponents.forEach((c, idx) => { 
        if(!ganttTasks.find(t=>t.app===c)) {
            ganttTasks.push({id:'t'+Date.now()+'_'+idx, app:c, name:"Mise à jour", left:(idx*5)%80, width:15, color:"#d29922"}); 
        }
    });
    localStorage.setItem(`${currentProfileId}_ganttTasks`, JSON.stringify(ganttTasks));

    filter.innerHTML = `
        <span style="font-size:11px; color:var(--text-muted); margin-right:5px;">Sélection :</span>
        <details class="gantt-dropdown">
            <summary>Afficher les composants (${selectedComponents.size}) ⏷</summary>
            <div class="gantt-dropdown-content">
                ${dashboardComponents.map(c => `
                <label style="display:flex; gap:8px; cursor:pointer; align-items:center; font-size:12px; color:var(--text-main); padding:4px 0;">
                    <input type="checkbox" ${selectedComponents.has(c)?'checked':''} onchange="toggleGF('${c}',this.checked)" style="accent-color:var(--accent-blue);"> ${c}
                </label>`).join('')}
            </div>
        </details>`;
    filter.style.display = 'flex';

    const vis = dashboardComponents.filter(c => selectedComponents.has(c));
    if(vis.length === 0) { 
        area.innerHTML = "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Tous les composants sont masqués.</p>"; 
        return; 
    }

    const m = ['Janvier','Février','Mars','Avril','Mai','Juin','Juillet','Août','Septembre','Octobre','Novembre','Décembre'];
    let side = '<div class="gantt-header-row"><div class="gantt-sidebar-header">COMPOSANTS DASHBOARD</div></div>';
    let tl = `<div class="gantt-header-row">${m.map(x=>`<div class="gantt-month">${x}</div>`).join('')}</div>`;
    
    const tp = ((new Date().getMonth()/12)+(new Date().getDate()/365))*100;
    tl += `<div class="today-line" style="left:${tp}%;"></div>`;

    vis.forEach(comp => {
        side += `<div class="gantt-app-name" title="${comp}"><span>${comp}</span><button class="gantt-add-btn" onclick="addGTask('${comp}')">+</button></div>`;
        let row = `<div class="gantt-row">`;
        for(let i=0; i<12; i++) row += `<div class="gantt-cell"></div>`;
        
        ganttTasks.filter(t => t.app === comp).forEach(t => {
            const r=parseInt(t.color.substr(1,2),16), g=parseInt(t.color.substr(3,2),16), b=parseInt(t.color.substr(5,2),16);
            const tc = (r*0.299+g*0.587+b*0.114)>128 ? 'black' : 'white';
            row += `<div class="gantt-task" id="${t.id}" style="left:${t.left}%; width:${t.width}%; background:${t.color}; color:${tc};">
                    <div class="resizer left"></div><span style="cursor:pointer;" onclick="openTEdit('${t.id}')">${t.name}</span><div class="resizer right"></div>
                </div>`;
        });
        row += `</div>`; tl += row;
    });

    area.innerHTML = `<div class="gantt-wrapper"><div class="gantt-sidebar">${side}</div><div class="gantt-timeline-wrapper"><div class="gantt-timeline" id="ganttTimeline">${tl}</div></div></div>`;
    initGanttDrag();
}

function toggleGF(k, c) { if(c) selectedComponents.add(k); else selectedComponents.delete(k); renderGantt(); }
function addGTask(app) { ganttTasks.push({id:'t'+Date.now(), app, name:"Action", left:10, width:10, color:"#58a6ff"}); localStorage.setItem(`${currentProfileId}_ganttTasks`, JSON.stringify(ganttTasks)); renderGantt(); }
function openTEdit(id) { const t=ganttTasks.find(x=>x.id===id); $('editTaskId').value=id; $('editTaskName').value=t.name; $('editTaskColor').value=t.color; $('taskEditModal').style.display='flex'; }
function saveTaskEdit() { const t=ganttTasks.find(x=>x.id===$('editTaskId').value); t.name=$('editTaskName').value; t.color=$('editTaskColor').value; localStorage.setItem(`${currentProfileId}_ganttTasks`, JSON.stringify(ganttTasks)); renderGantt(); $('taskEditModal').style.display='none'; }
function deleteEditedTask() { ganttTasks=ganttTasks.filter(x=>x.id!==$('editTaskId').value); localStorage.setItem(`${currentProfileId}_ganttTasks`, JSON.stringify(ganttTasks)); renderGantt(); $('taskEditModal').style.display='none'; }

function initGanttDrag() {
    const tl = $('ganttTimeline'); if(!tl) return;
    let cur=null, mode=null, sx=0, sl=0, sw=0;
    
    tl.onmousedown = e => {
        if(e.target.classList.contains('resizer')) { cur=e.target.parentElement; mode=e.target.classList.contains('left')?'l':'r'; }
        else if(e.target.classList.contains('gantt-task')) { cur=e.target; mode='m'; }
        if(cur) { sx=e.clientX; sl=cur.offsetLeft; sw=cur.offsetWidth; document.onmousemove=move; document.onmouseup=up; }
    };
    
    function move(e) {
        const dx=e.clientX-sx, pw=cur.parentElement.offsetWidth;
        if(mode==='m') cur.style.left=Math.max(0, Math.min(pw-sw, sl+dx))/pw*100+'%';
        else if(mode==='r') cur.style.width=Math.max(20, sw+dx)/pw*100+'%';
        else if(mode==='l') { let nl=sl+dx, nw=sw-dx; if(nw>20) { cur.style.left=(nl/pw*100)+'%'; cur.style.width=(nw/pw*100)+'%'; } }
    }
    
    function up() { if(cur) { const t=ganttTasks.find(x=>x.id===cur.id); t.left=parseFloat(cur.style.left); t.width=parseFloat(cur.style.width); localStorage.setItem(`${currentProfileId}_ganttTasks`, JSON.stringify(ganttTasks)); } document.onmousemove=null; cur=null; }
}

// ============================================================================
// HISTORIQUE ET PROFILS
// ============================================================================
function openProfileModal() {
    $('profileList').innerHTML = appProfiles.map(p => `
        <div class="profile-item ${p.id === currentProfileId ? 'active' : ''}">
            <strong>${p.name}</strong>
            <div>
                <button class="btn-sm" onclick="switchProfile('${p.id}')">Basculer</button>
                <button class="btn-sm btn-sm-danger" onclick="deleteProfile('${p.id}')">🗑️</button>
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
    localStorage.removeItem(`${id}_sbomHistory`); localStorage.removeItem(`${id}_activeWorkspace`); localStorage.removeItem(`${id}_ganttTasks`);
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
            <span>📄 ${i.filename} <small style="color:var(--text-muted);">${i.dateStr}</small></span>
            <div>
                <button class="btn-sm btn-sm-success" onclick="appendHistory('${i.id}')">➕</button>
                <button class="btn-sm btn-sm-primary" onclick="replaceHistory('${i.id}')">🔄</button>
                <button class="btn-sm btn-sm-danger" onclick="deleteHistoryFile('${i.id}')">🗑️</button>
            </div>
        </div>`).join('');
}

function deleteHistoryFile(id) {
    sbomHistory = sbomHistory.filter(i => i.id !== id); localStorage.setItem(`${currentProfileId}_sbomHistory`, JSON.stringify(sbomHistory));
    activeWorkspace.components = activeWorkspace.components.filter(c => c._sourceId !== id);
    activeWorkspace.dependencies = activeWorkspace.dependencies.filter(d => d._sourceId !== id);
    localStorage.setItem(`${currentProfileId}_activeWorkspace`, JSON.stringify(activeWorkspace));
    if(activeWorkspace.components.length > 0) processSbom(activeWorkspace); else clearWorkspaceUIOnly();
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
    ganttFiltersInitialized = false; selectedComponents.clear(); processSbom(activeWorkspace);
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
    ganttTasks = []; localStorage.removeItem(`${currentProfileId}_ganttTasks`); clearWorkspaceUIOnly();
}
function clearWorkspaceUIOnly() {
    window.lastProcessedVulns.clear(); selectedComponents.clear(); ganttFiltersInitialized = false; 
    [0,1,2,3,4].forEach(i => { const box = $(`box-p${i}`); if(box) box.querySelector('.count').innerText = "0"; }); 
    if($('results')) $('results').innerHTML = "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Espace vidé.</p>"; 
    if($('globalSearch')) $('globalSearch').value = ""; renderGantt();
}
function forceUpdateAnalysis() { if(activeWorkspace.components.length > 0) { Object.keys(cache).forEach(k => delete cache[k]); processSbom(activeWorkspace); } }
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
function exportGanttToCSV() {
    if(!ganttTasks.length) return alert("Gantt vide.");
    const m = ['Jan','Fév','Mar','Avr','Mai','Juin','Juil','Aoû','Sep','Oct','Nov','Déc']; let csv = "Composant;Action;Mois_Debut;Duree;Couleur\n";
    ganttTasks.forEach(t => { const idx = Math.max(0, Math.min(11, Math.floor((t.left/100)*12))); csv += `"${t.app}";"${t.name}";"${m[idx]}";"${((t.width/100)*12).toFixed(1)}";"${t.color}"\n`; });
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([new Uint8Array([0xEF,0xBB,0xBF]), csv], {type:"text/csv;charset=utf-8;"})); a.download = `Gantt_${currentProfileId}.csv`; a.click();
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
    ganttFiltersInitialized = false; selectedComponents.clear(); processSbom(activeWorkspace);
}
