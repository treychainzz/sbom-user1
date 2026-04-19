const $ = id => document.getElementById(id);

// ============================================================================
// VARIABLES D'ÉTAT GLOBALES ET CLOISONNÉES (MULTI-PROFILS)
// ============================================================================
let appProfiles = [];
let currentProfileId = null;

// Données mémoire du profil actif
let sbomHistory = [];
let activeWorkspace = { components: [], dependencies: [] };
let ganttTasks = [];

// Cache et calculs volatils
window.lastProcessedVulns = new Map(); 
const cache = {};
let selectedComponents = new Set();
let ganttFiltersInitialized = false;

// Variables Globales (non cloisonnées)
let currentProxyUrl = "https://corsproxy.io/?{url}";
let currentCVEs = [];

const EOL_ALIAS_MAP = { 
    'nodejs': 'node', 'reactjs': 'react', 'jdk': 'java', 
    'jre': 'java', 'spring': 'spring-framework', 'spring-boot': 'spring-boot'
};

// ============================================================================
// FONCTIONS DE STOCKAGE SÉCURISÉ PAR PROFIL
// ============================================================================
function safeGet(key) {
    if (!currentProfileId) return null;
    return localStorage.getItem(`${currentProfileId}_${key}`);
}

function safeSet(key, value) {
    if (!currentProfileId) return;
    localStorage.setItem(`${currentProfileId}_${key}`, value);
}

function safeRemove(key) {
    if (!currentProfileId) return;
    localStorage.removeItem(`${currentProfileId}_${key}`);
}

// ============================================================================
// INITIALISATION ET GESTION DES PROFILS
// ============================================================================
window.onload = () => {
    // 1. Initialisation des paramètres globaux
    const p = localStorage.getItem('proxyUrl'); 
    if(p) currentProxyUrl = p;
    
    const z = localStorage.getItem('ganttColumnWidth'); 
    if(z) { 
        document.documentElement.style.setProperty('--gantt-col', z + 'px'); 
        if($('ganttZoom')) $('ganttZoom').value = z; 
    }

    // 2. Initialisation des Profils
    const storedProfiles = localStorage.getItem('appProfiles');
    if (storedProfiles) {
        appProfiles = JSON.parse(storedProfiles);
        currentProfileId = localStorage.getItem('currentProfileId');
        if (!appProfiles.find(p => p.id === currentProfileId)) {
            currentProfileId = appProfiles[0].id;
        }
    } else {
        // Création du profil par défaut si première visite
        const defaultId = 'profile_' + Date.now();
        appProfiles = [{ id: defaultId, name: 'Espace Principal' }];
        currentProfileId = defaultId;
        localStorage.setItem('appProfiles', JSON.stringify(appProfiles));
        localStorage.setItem('currentProfileId', currentProfileId);
    }

    // 3. Chargement des données du Profil Actif
    loadProfileData();

    // 4. Listeners globaux
    document.addEventListener('click', e => {
        document.querySelectorAll('.gantt-dropdown').forEach(dropdown => { 
            if (!dropdown.contains(e.target)) dropdown.removeAttribute('open'); 
        });
    });
};

function loadProfileData() {
    // Mise à jour de l'affichage du nom du profil
    const activeProfile = appProfiles.find(p => p.id === currentProfileId);
    if($('currentProfileNameDisplay')) {
        $('currentProfileNameDisplay').innerText = activeProfile ? activeProfile.name : 'Inconnu';
    }

    // Réinitialisation de la mémoire vive
    window.lastProcessedVulns.clear();
    selectedComponents.clear();
    ganttFiltersInitialized = false;
    
    // Chargement depuis le LocalStorage cloisonné
    const h = safeGet('sbomHistory'); 
    sbomHistory = h ? JSON.parse(h) : [];
    
    const t = safeGet('ganttTasks'); 
    ganttTasks = t ? JSON.parse(t) : [];
    
    const w = safeGet('activeWorkspace'); 
    activeWorkspace = w ? JSON.parse(w) : { components: [], dependencies: [] };

    // Rendu UI
    renderHistoryUI();
    if (activeWorkspace.components.length > 0) {
        processSbom(activeWorkspace);
    } else {
        clearWorkspaceUIOnly();
    }
}

// LOGIQUE DES MODALS ET BOUTONS DE PROFIL
function openProfileModal() {
    renderProfileModalList();
    $('newProfileName').value = '';
    $('profileModal').style.display = 'flex';
}

function renderProfileModalList() {
    const listDiv = $('profileList');
    listDiv.innerHTML = appProfiles.map(p => `
        <div class="profile-item ${p.id === currentProfileId ? 'active' : ''}">
            <div>
                <strong style="color:var(--text-main); font-size:13px;">${p.name}</strong>
                ${p.id === currentProfileId ? '<span class="badge" style="background:var(--accent-blue); margin-left:8px;">Actif</span>' : ''}
            </div>
            <div>
                ${p.id !== currentProfileId 
                    ? `<button class="btn-sm btn-sm-success" onclick="switchProfile('${p.id}')">Basculer</button>` 
                    : ''}
                <button class="btn-sm btn-sm-danger" onclick="deleteProfile('${p.id}')" ${appProfiles.length === 1 ? 'disabled style="opacity:0.5; cursor:not-allowed;" title="Impossible de supprimer le dernier profil"' : ''}>🗑️</button>
            </div>
        </div>
    `).join('');
}

function createNewProfile() {
    const nameInput = $('newProfileName').value.trim();
    if (!nameInput) return alert("Veuillez entrer un nom de profil.");
    
    const newId = 'profile_' + Date.now();
    appProfiles.push({ id: newId, name: nameInput });
    localStorage.setItem('appProfiles', JSON.stringify(appProfiles));
    
    switchProfile(newId);
    $('newProfileName').value = '';
}

function switchProfile(profileId) {
    if (currentProfileId === profileId) return;
    
    currentProfileId = profileId;
    localStorage.setItem('currentProfileId', currentProfileId);
    
    loadProfileData();
    renderProfileModalList();
}

function deleteProfile(profileId) {
    if (appProfiles.length <= 1) return alert("Vous ne pouvez pas supprimer le dernier profil.");
    
    if (confirm("Supprimer ce profil supprimera tout son historique, son workspace et son Gantt. Continuer ?")) {
        // Supprimer les données du profil en LocalStorage
        localStorage.removeItem(`${profileId}_sbomHistory`);
        localStorage.removeItem(`${profileId}_activeWorkspace`);
        localStorage.removeItem(`${profileId}_ganttTasks`);
        
        // Retirer de la liste
        appProfiles = appProfiles.filter(p => p.id !== profileId);
        localStorage.setItem('appProfiles', JSON.stringify(appProfiles));
        
        // Si c'était le profil actif, on bascule sur le premier dispo
        if (currentProfileId === profileId) {
            switchProfile(appProfiles[0].id);
        } else {
            renderProfileModalList();
        }
    }
}

// ============================================================================
// GESTION DU PROXY (GLOBAL)
// ============================================================================
function handleProxySelection() { 
    $('customProxyDiv').style.display = $('proxySelect').value === 'custom' ? 'block' : 'none'; 
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

function saveProxyConfig() {
    const sel = $('proxySelect').value; 
    currentProxyUrl = sel === 'custom' ? $('proxyCustomInput').value : sel;
    localStorage.setItem('proxyUrl', currentProxyUrl); 
    closeModal('proxyModal');
    if(activeWorkspace.components.length > 0 && confirm("Relancer l'analyse avec ce proxy ?")) {
        forceUpdateAnalysis();
    }
}

function doFetch(url, opts) { 
    if(!currentProxyUrl) return fetch(url, opts); 
    if(currentProxyUrl.includes('{url}')) return fetch(currentProxyUrl.replace('{url}', encodeURIComponent(url)), opts); 
    return fetch(currentProxyUrl + url, opts); 
}

// ============================================================================
// GESTION DE L'HISTORIQUE (CLOISONNÉ)
// ============================================================================
function saveToHistory(filename, data) {
    const id = Date.now().toString(); 
    sbomHistory.unshift({ id, filename, dateStr: new Date().toLocaleString('fr-FR'), data });
    if(sbomHistory.length > 15) sbomHistory.pop();
    safeSet('sbomHistory', JSON.stringify(sbomHistory)); 
    renderHistoryUI(); 
    return id;
}

function renderHistoryUI() {
    const div = $('historyList'); 
    if(sbomHistory.length === 0) { 
        div.innerHTML = "<p style='color:var(--text-muted); font-size:12px; margin:0;'>Aucun fichier importé dans ce profil.</p>"; 
        return; 
    }
    div.innerHTML = sbomHistory.map(item => `
        <div class="history-item">
            <span>
                <strong>📄 ${item.filename}</strong> 
                <span style="color:var(--text-muted); font-size:11px; margin-left:10px;">${item.dateStr}</span>
            </span>
            <div>
                <button class="btn-sm btn-sm-success" onclick="appendHistory('${item.id}')" title="Ajouter au dashboard">➕</button>
                <button class="btn-sm btn-sm-primary" onclick="replaceHistory('${item.id}')" title="Remplacer le dashboard">🔄</button>
                <button class="btn-sm btn-sm-danger" onclick="deleteHistoryFile('${item.id}')" title="Supprimer">🗑️</button>
            </div>
        </div>`).join('');
}

function deleteHistoryFile(id) {
    sbomHistory = sbomHistory.filter(i => i.id !== id); 
    safeSet('sbomHistory', JSON.stringify(sbomHistory));
    
    const len = activeWorkspace.components.length;
    activeWorkspace.components = activeWorkspace.components.filter(c => c._sourceId !== id);
    activeWorkspace.dependencies = activeWorkspace.dependencies.filter(d => d._sourceId !== id);
    
    if(activeWorkspace.components.length !== len) { 
        safeSet('activeWorkspace', JSON.stringify(activeWorkspace)); 
        if(activeWorkspace.components.length > 0) {
            processSbom(activeWorkspace); 
        } else {
            clearWorkspaceUIOnly(); 
        }
    } else { 
        renderHistoryUI(); 
    }
}

function appendHistory(id) {
    const item = sbomHistory.find(x => x.id === id); 
    if(!item) return;
    item.data.components.forEach(c => c._sourceId = id); 
    if(item.data.dependencies) item.data.dependencies.forEach(d => d._sourceId = id);
    
    activeWorkspace.components = activeWorkspace.components.filter(c => c._sourceId !== id); 
    activeWorkspace.dependencies = activeWorkspace.dependencies.filter(d => d._sourceId !== id);
    
    activeWorkspace.components.push(...item.data.components); 
    activeWorkspace.dependencies.push(...(item.data.dependencies || []));
    
    safeSet('activeWorkspace', JSON.stringify(activeWorkspace)); 
    processSbom(activeWorkspace);
}

function replaceHistory(id) {
    const item = sbomHistory.find(x => x.id === id); 
    if(!item) return;
    item.data.components.forEach(c => c._sourceId = id); 
    if(item.data.dependencies) item.data.dependencies.forEach(d => d._sourceId = id);
    
    activeWorkspace = { components: [...item.data.components], dependencies: [...(item.data.dependencies || [])] };
    safeSet('activeWorkspace', JSON.stringify(activeWorkspace)); 
    
    ganttFiltersInitialized = false; 
    selectedComponents.clear(); 
    processSbom(activeWorkspace);
}

const fileIn = $('fileIn');
if (fileIn) {
    fileIn.addEventListener('change', async e => {
        for(let f of e.target.files) {
            const data = JSON.parse(await f.text()); 
            const nid = saveToHistory(f.name, data);
            if(data.components) { 
                data.components.forEach(c => c._sourceId = nid); 
                activeWorkspace.components.push(...data.components); 
            }
            if(data.dependencies) { 
                data.dependencies.forEach(d => d._sourceId = nid); 
                activeWorkspace.dependencies.push(...data.dependencies); 
            }
        }
        safeSet('activeWorkspace', JSON.stringify(activeWorkspace)); 
        processSbom(activeWorkspace); 
        e.target.value = '';
    });
}

function clearWorkspace() {
    activeWorkspace = { components: [], dependencies: [] }; 
    safeRemove('activeWorkspace');
    ganttTasks = []; 
    safeRemove('ganttTasks');
    
    clearWorkspaceUIOnly();
}

function clearWorkspaceUIOnly() {
    window.lastProcessedVulns.clear(); 
    selectedComponents.clear(); 
    ganttFiltersInitialized = false; 
    
    [0,1,2,3,4].forEach(i => {
        const box = $(`box-p${i}`);
        if(box) box.querySelector('.count').innerText = "0";
    }); 
    
    $('results').innerHTML = "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Espace de travail du profil vidé.</p>"; 
    $('globalSearch').value = "";
    renderGantt();
}

function forceUpdateAnalysis() { 
    if(activeWorkspace.components.length > 0) { 
        Object.keys(cache).forEach(k => delete cache[k]); 
        processSbom(activeWorkspace); 
    } 
}

function filterDashboard() { 
    const t = $('globalSearch').value.toLowerCase(); 
    document.querySelectorAll('#results details').forEach(r => {
        r.style.display = r.getAttribute('data-search').includes(t) ? "" : "none";
    }); 
}

// ============================================================================
// EXPORTS CSV ET MODALS
// ============================================================================
function exportToCSV() {
    if(!lastProcessedVulns.size) return alert("Le tableau est vide.");
    let csv = "Prio;Composant;Version;Sante;Court_T;Long_T;CVEs;Apps_Impactees\n";
    Array.from(lastProcessedVulns.values()).sort((a,b)=>a.p-b.p).forEach(v => {
        csv += `"P${v.p}";"${v.name}";"${v.version}";"${v.status}";"${v.short}";"${v.long}";"${v.cves?v.cves.length:0}";"${v.impacted.join(',')}"\n`;
    });
    const a = document.createElement('a'); 
    a.href = URL.createObjectURL(new Blob([new Uint8Array([0xEF,0xBB,0xBF]), csv], {type:"text/csv;charset=utf-8;"})); 
    a.download = `Dashboard_Profil_${currentProfileId}.csv`; 
    a.click();
}

function exportGanttToCSV() {
    if(!ganttTasks.length) return alert("Aucune action dans le Gantt.");
    const m = ['Janvier','Février','Mars','Avril','Mai','Juin','Juillet','Août','Septembre','Octobre','Novembre','Décembre']; 
    let csv = "Application_Parente;Action;Mois_Debut;Duree_Mois;Couleur\n";
    ganttTasks.forEach(t => {
        const idx = Math.max(0, Math.min(11, Math.floor((t.left/100)*12)));
        const dur = ((t.width/100)*12).toFixed(1);
        csv += `"${t.app}";"${t.name}";"${m[idx]}";"${dur}";"${t.color}"\n`;
    });
    const a = document.createElement('a'); 
    a.href = URL.createObjectURL(new Blob([new Uint8Array([0xEF,0xBB,0xBF]), csv], {type:"text/csv;charset=utf-8;"})); 
    a.download = `Gantt_Profil_${currentProfileId}.csv`; 
    a.click();
}

function closeModal(id) { $(id).style.display = 'none'; }

function openCVEModal(event, compName, compVersion) { 
    event.stopPropagation(); 
    const d = cache[`${compName.toLowerCase()}_${compVersion}`]; 
    if(!d || !d.cves) return; 
    currentCVEs = d.cves; 
    $('modalCompName').innerText = `${compName} (v${compVersion})`; 
    $('cveSearch').value = '';
    renderCVEs(currentCVEs); 
    $('cveModal').style.display = 'flex'; 
}

function filterCVEs() { 
    const q = $('cveSearch').value.toLowerCase(); 
    renderCVEs(currentCVEs.filter(c => c.id.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q))); 
}

function renderCVEs(list) {
    $('cveList').innerHTML = list.map(c => {
        const bg = c.severity==='CRITICAL'?'#ff4444':c.severity==='HIGH'?'#ff7b72':(c.severity==='MEDIUM'||c.severity==='MODERATE')?'#ffa657':'#388bfd';
        const tc = (bg==='#ffa657')?'#000':'#fff';
        return `
        <div style="border-left:4px solid ${bg}; margin-bottom:15px; background:var(--bg-card); padding:15px; border-radius:6px; border: 1px solid var(--border-color);">
            <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-color); padding-bottom:10px; margin-bottom:10px;">
                <div style="display:flex; align-items:center; gap:15px;">
                    <span style="background:${bg}; color:${tc}; padding:4px 10px; border-radius:4px; font-weight:bold;">${c.exactScore}</span>
                    <div>
                        <strong style="font-size:1.2em; display:block;">${c.id}</strong>
                        <span style="font-size:10px; color:${bg}; text-transform:uppercase;">${c.severity}</span>
                    </div>
                </div>
                <a href="${c.link}" target="_blank" style="color:var(--text-muted); text-decoration:none;">🔗 OSV</a>
            </div>
            <p style="margin:0 0 10px 0; color:#a1aab3; line-height:1.5;">${c.desc}</p>
            <div style="background:rgba(88,166,255,0.1); padding:8px; border-radius:4px;">
                <strong style="color:var(--accent-blue)">Solution :</strong> Patcher vers v${c.fixed.replace('v','')}
            </div>
        </div>`;
    }).join('');
}

// ============================================================================
// MOTEUR D'ANALYSE DE SÉCURITÉ
// ============================================================================
function calculateUniversalCVSS(v) {
    if(!v || !v.startsWith('CVSS:3')) return "N/A";
    const m = {}; v.split('/').forEach(p => { const [k, val] = p.split(':'); m[k] = val; });
    const AV={'N':0.85,'A':0.62,'L':0.55,'P':0.2}[m.AV]||0, AC={'L':0.77,'H':0.44}[m.AC]||0, UI={'N':0.85,'R':0.62}[m.UI]||0;
    const PR=m.S==='C'?{'N':0.85,'L':0.68,'H':0.50}[m.PR]||0:{'N':0.85,'L':0.62,'H':0.27}[m.PR]||0;
    const C={'H':0.56,'L':0.22,'N':0}[m.C]||0, I={'H':0.56,'L':0.22,'N':0}[m.I]||0, A={'H':0.56,'L':0.22,'N':0}[m.A]||0;
    const iss=1-((1-C)*(1-I)*(1-A)); let imp=m.S==='U'?6.42*iss:7.52*(iss-0.029)-3.25*Math.pow(iss-0.02, 15);
    const exp=8.22*AV*AC*PR*UI; if(imp<=0) return "0.0";
    let base=m.S==='U'?Math.min(imp+exp,10):Math.min(1.08*(imp+exp),10); 
    return (Math.ceil(Math.round(base*100000)/10000)/10).toFixed(1);
}

function calculateP(eol) { 
    const d = Math.ceil((new Date(eol)-new Date())/86400000); 
    return d<=0 ? 0 : d<90 ? 1 : d<180 ? 2 : d<365 ? 3 : 4; 
}

async function getSecurityData(name, version, purl, type) {
    const k = `${name.toLowerCase()}_${version}`; 
    if(cache[k]) return cache[k];
    
    let res = { p:4, status: "Inconnu", short: "v"+version, long: "---" }; 
    if(type === 'application') return res;
    
    const originalName = name.toLowerCase(); 
    const eco = purl?.split(':')[1]?.split('/')[0]?.toLowerCase() || 'npm';
    const slug = EOL_ALIAS_MAP[originalName] || originalName; 
    let isEol = false;
    
    try {
        const eol = await doFetch(`https://endoflife.date/api/${slug}.json`);
        if(eol && eol.ok) {
            const h = await eol.json(); 
            const cy = h.find(x => version.startsWith(String(x.cycle)));
            if(cy) {
                isEol = true;
                if(cy.eol === false) { res.p=4; res.status="Support Actif"; res.short="v"+cy.latest; res.long="v"+h[0].latest; }
                else { res.p=calculateP(cy.eol); res.status=cy.eol; res.short="v"+cy.latest; res.long="v"+h[0].latest; }
            }
        }
    } catch(e) {}

    if(!isEol && eco === 'npm') {
        try {
            const npm = await doFetch(`https://registry.npmjs.org/${originalName}`);
            if(npm && npm.ok) {
                const d = await npm.json(); 
                const lat = d['dist-tags']?.latest; 
                const dt = d.time?.[version];
                if(dt && lat) {
                    const age = (new Date() - new Date(dt)) / 86400000;
                    if(age > 1460) { res.p=0; res.status="Obsolète (> 4 ans)"; } 
                    else if(age > 1095) { res.p=2; res.status="Risque Élevé (> 3 ans)"; } 
                    else if(age > 730) { res.p=3; res.status="Risque Moyen (> 2 ans)"; } 
                    else { res.p=4; res.status="Sain (< 2 ans)"; }
                    res.short = "v"+lat; res.long = "v"+lat;
                }
            }
        } catch(e) {}
    }

    try {
        const osv = await doFetch('https://api.osv.dev/v1/query', { 
            method:'POST', 
            body: JSON.stringify({version, package:{name:originalName, ecosystem:eco==='npm'?'npm':'Maven'}}) 
        });
        
        if(osv && osv.ok) {
            const j = await osv.json();
            if(j.vulns) {
                res.p=0; res.status="VULNÉRABLE";
                res.cves = j.vulns.map(v => ({
                    id: v.aliases?.[0]||v.id, 
                    severity: v.database_specific?.severity||"HIGH",
                    exactScore: v.database_specific?.cvss?.score || calculateUniversalCVSS(v.severity?.[0]?.score) || "N/A",
                    desc: v.summary||v.details, 
                    link: `https://osv.dev/vulnerability/${v.id}`,
                    fixed: v.affected?.[0]?.ranges?.[0]?.events?.find(x=>x.fixed)?.fixed || "Patcher"
                })).sort((a,b)=>b.exactScore-a.exactScore);
            }
        }
    } catch(e) {}
    
    return cache[k] = res;
}

// ============================================================================
// PROCESSEUR SBOM
// ============================================================================
async function processSbom(workspace) {
    $('loading').style.display = 'flex'; 
    $('progressBar').style.width = '0%';
    
    const comps = workspace.components || [], deps = workspace.dependencies || [];
    const cMap = new Map(); comps.forEach(c => cMap.set(c['bom-ref'], c));
    const dMap = new Map(); deps.forEach(d => { if(!dMap.has(d.ref)) dMap.set(d.ref, new Set()); (d.dependsOn||[]).forEach(r => dMap.get(d.ref).add(r)); });

    const u = []; const s = new Set();
    comps.forEach(c => { 
        const k = `${c.name.toLowerCase()}|${c.version}`; 
        if(!s.has(k) && c.type !== 'application') { u.push(c); s.add(k); } 
    });
    
    for(let i=0; i<u.length; i+=10) {
        $('progressBar').style.width = Math.round((i/u.length)*100)+'%';
        await Promise.all(u.slice(i, i+10).map(x => getSecurityData(x.name, x.version, x.purl, x.type)));
    }

    lastProcessedVulns.clear();
    
    comps.filter(c => c.type === 'application').forEach(app => {
        const appLabel = `${app.name} (v${app.version||'?'})`;
        (dMap.get(app['bom-ref'])||[]).forEach(ref => {
            const child = cMap.get(ref);
            if(child) {
                const info = cache[`${child.name.toLowerCase()}_${child.version}`];
                if(info && info.p < 5) {
                    const k = `${child.name}|${child.version}`;
                    if(!lastProcessedVulns.has(k)) lastProcessedVulns.set(k, {...child, ...info, impacted:[]});
                    if(!lastProcessedVulns.get(k).impacted.includes(appLabel)) lastProcessedVulns.get(k).impacted.push(appLabel);
                }
            }
        });
    });

    const pStats = [0,0,0,0,0]; 
    let html = "";
    
    Array.from(lastProcessedVulns.values()).sort((a,b)=>a.p-b.p).forEach(v => {
        pStats[v.p]++;
        const btn = v.cves ? `<button class="cve-badge" onclick="openCVEModal(event, '${v.name}', '${v.version}')">🚨 ${v.cves.length} Faille(s)</button>` : '';
        const search = `${v.name.toLowerCase()} ${v.version} ${v.cves?v.cves.map(x=>x.id.toLowerCase()).join(' '):''}`;
        
        html += `
        <details data-search="${search}">
            <summary>
                <div class="col-prio"><span class="badge p${v.p}">P${v.p}</span></div>
                <div class="col-comp">${v.name} <small>(v${v.version})</small> ${btn}</div>
                <div class="col-eol" style="color:var(--p${v.p})">${v.status}</div>
                <div class="col-short">🎯 ${v.short}</div>
                <div class="col-long">🚀 ${v.long}</div>
                <div class="col-impact">${v.impacted.length} Apps ⏷</div>
            </summary>
            <div class="content">
                <div class="parents-grid">${v.impacted.map(n=>`<div class="parent-tag">${n}</div>`).join('')}</div>
            </div>
        </details>`;
    });
    
    $('results').innerHTML = html || "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Aucune vulnérabilité.</p>";
    for(let i=0; i<5; i++) {
        const box = $(`box-p${i}`);
        if(box) box.querySelector('.count').innerText = pStats[i];
    }
    
    $('loading').style.display = 'none';
    
    if(!ganttFiltersInitialized) { 
        selectedComponents.clear(); 
        ganttFiltersInitialized = true; 
    }
    
    renderGantt();
}

// ============================================================================
// MOTEUR GANTT (STRICT SUR LES PARENTS)
// ============================================================================
function adjustGanttWidth(val) { 
    document.documentElement.style.setProperty('--gantt-col', val + 'px'); 
    localStorage.setItem('ganttColumnWidth', val); 
}

function renderGantt() {
    const area = $('ganttArea');
    const filter = $('ganttFilterContainer');
    
    if(lastProcessedVulns.size === 0) { 
        area.innerHTML = "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Générez un SBOM pour afficher le planning des applications parentes.</p>"; 
        filter.style.display='none'; 
        return; 
    }

    // EXTRACTION EXCLUSIVE DES APPLICATIONS PARENTES
    const pSet = new Set();
    lastProcessedVulns.forEach(v => { 
        if(v.impacted) {
            v.impacted.forEach(a => pSet.add(a)); 
        }
    });
    const parents = Array.from(pSet).sort();

    // Nettoyage des tâches
    ganttTasks = ganttTasks.filter(t => parents.includes(t.app));
    
    if(selectedComponents.size === 0) {
        parents.forEach(p => selectedComponents.add(p));
    }

    parents.forEach((p, idx) => { 
        if(!ganttTasks.find(t=>t.app===p)) {
            ganttTasks.push({id:'t'+Date.now()+'_'+idx, app:p, name:"Mise à jour planifiée", left:(idx*5)%80, width:15, color:"#d29922"}); 
        }
    });
    safeSet('ganttTasks', JSON.stringify(ganttTasks));

    filter.innerHTML = `
        <span style="font-size:11px; color:var(--text-muted); margin-right:5px;">Sélection :</span>
        <details class="gantt-dropdown">
            <summary>Afficher les applications (${selectedComponents.size}) ⏷</summary>
            <div class="gantt-dropdown-content">
                ${parents.map(p => `
                <label style="display:flex; gap:8px; cursor:pointer; align-items:center; font-size:12px; color:var(--text-main); padding:4px 0;">
                    <input type="checkbox" ${selectedComponents.has(p)?'checked':''} onchange="toggleGF('${p}',this.checked)" style="accent-color:var(--accent-blue);"> ${p}
                </label>`).join('')}
            </div>
        </details>`;
    filter.style.display = 'flex';

    const vis = parents.filter(p => selectedComponents.has(p));
    if(vis.length === 0) { 
        area.innerHTML = "<p style='text-align:center; padding:30px; color:var(--text-muted);'>Toutes les applications sont masquées.</p>"; 
        return; 
    }

    const m = ['Janvier','Février','Mars','Avril','Mai','Juin','Juillet','Août','Septembre','Octobre','Novembre','Décembre'];
    let side = '<div class="gantt-header-row"><div class="gantt-sidebar-header">APPLICATIONS IMPACTÉES</div></div>';
    let tl = `<div class="gantt-header-row">${m.map(x=>`<div class="gantt-month">${x}</div>`).join('')}</div>`;
    
    const tp = ((new Date().getMonth()/12)+(new Date().getDate()/365))*100;
    tl += `<div class="today-line" style="left:${tp}%;"></div>`;

    vis.forEach(app => {
        side += `
            <div class="gantt-app-name" title="${app}">
                <span>${app}</span>
                <button class="gantt-add-btn" onclick="addGTask('${app}')">+</button>
            </div>`;
        
        let row = `<div class="gantt-row">`;
        for(let i=0; i<12; i++) {
            row += `<div class="gantt-cell"></div>`;
        }
        
        ganttTasks.filter(t => t.app === app).forEach(t => {
            const r=parseInt(t.color.substr(1,2),16), g=parseInt(t.color.substr(3,2),16), b=parseInt(t.color.substr(5,2),16);
            const tc = (r*0.299+g*0.587+b*0.114)>128 ? 'black' : 'white';
            
            row += `
                <div class="gantt-task" id="${t.id}" style="left:${t.left}%; width:${t.width}%; background:${t.color}; color:${tc};">
                    <div class="resizer left"></div>
                    <span style="cursor:pointer;" onclick="openTEdit('${t.id}')">${t.name}</span>
                    <div class="resizer right"></div>
                </div>`;
        });
        row += `</div>`; 
        tl += row;
    });

    area.innerHTML = `
        <div class="gantt-wrapper">
            <div class="gantt-sidebar">${side}</div>
            <div class="gantt-timeline-wrapper">
                <div class="gantt-timeline" id="ganttTimeline">${tl}</div>
            </div>
        </div>`;
        
    initGanttDrag();
}

function toggleGF(k, c) { 
    if(c) selectedComponents.add(k); else selectedComponents.delete(k); 
    renderGantt(); 
}

function addGTask(app) { 
    ganttTasks.push({id:'t'+Date.now(), app, name:"Action", left:10, width:10, color:"#58a6ff"}); 
    safeSet('ganttTasks', JSON.stringify(ganttTasks)); 
    renderGantt(); 
}

function openTEdit(id) { 
    const t=ganttTasks.find(x=>x.id===id); 
    $('editTaskId').value=id; 
    $('editTaskName').value=t.name; 
    $('editTaskColor').value=t.color; 
    $('taskEditModal').style.display='flex'; 
}

function saveTaskEdit() { 
    const t=ganttTasks.find(x=>x.id===$('editTaskId').value); 
    t.name=$('editTaskName').value; 
    t.color=$('editTaskColor').value; 
    safeSet('ganttTasks', JSON.stringify(ganttTasks)); 
    renderGantt(); 
    $('taskEditModal').style.display='none'; 
}

function deleteEditedTask() { 
    ganttTasks=ganttTasks.filter(x=>x.id!==$('editTaskId').value); 
    safeSet('ganttTasks', JSON.stringify(ganttTasks)); 
    renderGantt(); 
    $('taskEditModal').style.display='none'; 
}

function initGanttDrag() {
    const tl = $('ganttTimeline'); 
    if(!tl) return;
    
    let cur=null, mode=null, sx=0, sl=0, sw=0;
    
    tl.onmousedown = e => {
        if(e.target.classList.contains('resizer')) { 
            cur=e.target.parentElement; 
            mode=e.target.classList.contains('left')?'l':'r'; 
        }
        else if(e.target.classList.contains('gantt-task')) { 
            cur=e.target; 
            mode='m'; 
        }
        
        if(cur) { 
            sx=e.clientX; sl=cur.offsetLeft; sw=cur.offsetWidth; 
            document.onmousemove=move; document.onmouseup=up; 
        }
    };
    
    function move(e) {
        const dx = e.clientX-sx, pw = cur.parentElement.offsetWidth;
        if(mode==='m') {
            cur.style.left = Math.max(0, Math.min(pw-sw, sl+dx))/pw*100 + '%';
        }
        else if(mode==='r') {
            cur.style.width = Math.max(20, sw+dx)/pw*100 + '%';
        }
        else if(mode==='l') { 
            let nl=sl+dx, nw=sw-dx; 
            if(nw>20) { 
                cur.style.left=(nl/pw*100)+'%'; cur.style.width=(nw/pw*100)+'%'; 
            } 
        }
    }
    
    function up() { 
        if(cur) { 
            const t=ganttTasks.find(x=>x.id===cur.id); 
            t.left=parseFloat(cur.style.left); 
            t.width=parseFloat(cur.style.width); 
            safeSet('ganttTasks', JSON.stringify(ganttTasks)); 
        } 
        document.onmousemove=null; cur=null; 
    }
}

function runDemo() {
    const demo = { components: [], dependencies: [] }; 
    for(let i=1; i<=3; i++) {
        const app = `app-${i}`; 
        demo.components.push({ "bom-ref": app, name: `Service-Parent-${i}`, type: 'application', version: `2.${i}.0` });
        const tr = `p-${i}`;
        if(i===1) demo.components.push({ "bom-ref": tr, name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15' });
        if(i===2) demo.components.push({ "bom-ref": tr, name: 'axios', version: '0.21.1', purl: 'pkg:npm/axios@0.21.1' });
        if(i===3) demo.components.push({ "bom-ref": tr, name: 'spring-boot', version: '3.2.0', purl: 'pkg:maven/spring-boot@3.2.0' });
        demo.dependencies.push({ ref: app, dependsOn: [tr] });
    }
    
    demo.components.push({ "bom-ref": "app-x", name: "Serveur-Paiement-API", type: "application", version: "1.0.0" });
    demo.components.push({ "bom-ref": "n1", name: "nodejs", version: "20.5.0", purl: "pkg:npm/nodejs@20.5.0" });
    demo.components.push({ "bom-ref": "n2", name: "nodejs", version: "22.0.0", purl: "pkg:npm/nodejs@22.0.0" });
    demo.dependencies.push({ ref: "app-x", dependsOn: ["n1", "n2"] });

    const nid = saveToHistory("demo_systeme.json", demo);
    demo.components.forEach(c => c._sourceId = nid); 
    demo.dependencies.forEach(d => d._sourceId = nid);
    activeWorkspace.components.push(...demo.components); 
    activeWorkspace.dependencies.push(...demo.dependencies);
    safeSet('activeWorkspace', JSON.stringify(activeWorkspace));
    ganttFiltersInitialized = false; selectedComponents.clear(); 
    processSbom(activeWorkspace);
}
