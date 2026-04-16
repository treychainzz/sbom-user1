/** * RA-Pilot v7.2.1 - ÉDITION SÉCURITÉ ABSOLUE (Code Clair)
 */

// --- 1. LE DICTIONNAIRE DE BASE (Édition Titan) ---
const defaultMappings = {
    "node": "nodejs", "nodejs": "nodejs", "deno": "deno", "bun": "bun",
    "golang": "go", "go": "go", "python": "python", "pypy": "python",
    "ruby": "ruby", "php": "php", "rust": "rust", "swift": "swift",
    "kotlin": "kotlin", "scala": "scala", "perl": "perl", "erlang": "erlang",
    "elixir": "elixir", "jre": "java", "jdk": "java", "openjdk": "java", "oracle-jdk": "oracle-jdk",
    "csharp": "dotnet", "fsharp": "dotnet", "dotnet": "dotnet", "dotnet-core": "dotnet",
    "microsoft.netcore.app": "dotnet", "microsoft.aspnetcore": "dotnet",
    "microsoft.aspnetcore.app": "dotnet", "aspnet": "dotnet", "entityframework": "dotnet",
    "microsoft.entityframeworkcore": "dotnet", "dotnet-framework": "dotnet-framework",
    "system.text.json": "dotnet", "newtonsoft.json": "newtonsoft-json",
    "redhat": "rhel", "rhel-server": "rhel", "rhel": "rhel", "centos": "centos",
    "fedora": "fedora", "rocky-linux": "rocky-linux", "almalinux": "almalinux",
    "debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine", "sles": "sles",
    "amazon-linux": "amazon-linux", "macos": "macos", "windows-server": "windows-server",
    "kubernetes": "kubernetes", "kubelet": "kubernetes", "k8s": "kubernetes",
    "eks": "amazon-eks", "aks": "azure-kubernetes-service", "gke": "google-kubernetes-engine",
    "docker": "docker", "terraform": "terraform", "helm": "helm", "istio": "istio",
    "openshift": "openshift", "gitlab": "gitlab", "jenkins": "jenkins", "ansible": "ansible", "vault": "vault",
    "hibernate-core": "hibernate", "hibernate": "hibernate",
    "spring-boot": "spring-boot", "spring-framework": "spring-framework",
    "log4j-core": "log4j", "log4j": "log4j", "quarkus": "quarkus", "micronaut": "micronaut",
    "tomcat": "tomcat", "wildfly": "wildfly", "struts": "struts",
    "react": "react", "react-dom": "react", "react-scripts": "react",
    "angular": "angular", "vue": "vue", "nextjs": "nextjs",
    "nuxt": "nuxt", "svelte": "svelte", "express": "express", "nestjs": "nestjs",
    "flutter": "flutter", "react-native": "react-native", "ionic": "ionic", "electron": "electron"
};

// --- 2. INITIALISATION ---
let db = JSON.parse(localStorage.getItem('ra_pilot_db')) || { apps: {}, mappings: {} };

if (!db.mappings) {
    db.mappings = {};
}

let initialLoad = false;
for (const [key, val] of Object.entries(defaultMappings)) {
    if (db.mappings[key] === undefined) { 
        db.mappings[key] = val; 
        initialLoad = true; 
    }
}

if (initialLoad) {
    localStorage.setItem('ra_pilot_db', JSON.stringify(db));
}

let curr = 'all';
let activeVulns = []; 
let eolProducts = [];

const $ = id => document.getElementById(id);
const save = () => localStorage.setItem('ra_pilot_db', JSON.stringify(db));

// --- GESTION DU LOADER ---
const showLoader = (title, status) => {
    const loader = $('loader-overlay');
    if (loader) {
        loader.style.display = 'flex';
        $('loader-title').innerText = title;
        $('loader-status').innerText = status;
    }
};

const hideLoader = () => { 
    if ($('loader-overlay')) $('loader-overlay').style.display = 'none'; 
};

// --- AUTOCOMPLÉTION (API ENDOFLIFE) ---
async function fetchEolDatalist() {
    try {
        const res = await fetch('https://corsproxy.io/?' + encodeURIComponent('https://endoflife.date/api/all.json'));
        eolProducts = await res.json();
        const dl = document.createElement('datalist');
        dl.id = 'eolDatalist';
        dl.innerHTML = eolProducts.map(p => `<option value="${p}">`).join('');
        document.body.appendChild(dl);
    } catch (e) { 
        console.error("Erreur de récupération du dictionnaire EOL"); 
    }
}

// --- MOTEURS CVSS & PRIORITÉ ---
const calculateCVSS = (vector) => {
    if (!vector) return 0;
    if (vector.includes("CVSS:4.0")) {
        const p = {}; 
        vector.split('/').forEach(v => { const [k, val] = v.split(':'); p[k] = val; });
        let base = (p.VC === 'H' && p.VI === 'H' && p.VA === 'H') ? 9.3 : (p.VC === 'H' || p.VI === 'H' ? 8.0 : 5.0);
        return Math.min(base, 10);
    }
    if (vector.includes("CVSS:3")) {
        const w = {
            AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 },
            PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.50 } },
            UI: { N: 0.85, R: 0.62 }, S: { U: 6.42, C: 7.52 },
            C: { N: 0, L: 0.22, H: 0.56 }, I: { N: 0, L: 0.22, H: 0.56 }, A: { N: 0, L: 0.22, H: 0.56 }
        };
        const p = {}; 
        vector.split('/').forEach(v => { const [k, val] = v.split(':'); p[k] = val; });
        try {
            const scopeChanged = p.S === 'C';
            const iss = 1 - ((1 - w.C[p.C]) * (1 - w.I[p.I]) * (1 - w.A[p.A]));
            let impact = !scopeChanged ? (6.42 * iss) : (7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15));
            const exploitability = 8.22 * w.AV[p.AV] * w.AC[p.AC] * w.PR[p.S][p.PR] * w.UI[p.UI];
            let score = (impact <= 0) ? 0 : (!scopeChanged ? Math.min(impact + exploitability, 10) : Math.min(1.08 * (impact + exploitability), 10));
            return Math.ceil(score * 10) / 10;
        } catch (e) { return 0; }
    }
    return 0;
};

const getSeverityData = (v) => {
    let scores = []; 
    const raw = JSON.stringify(v);
    const v4Match = raw.match(/CVSS:4\.0\/[^"']+/); if (v4Match) scores.push(calculateCVSS(v4Match[0]));
    const v3Match = raw.match(/CVSS:3\.[01]\/[^"']+/); if (v3Match) scores.push(calculateCVSS(v3Match[0]));
    const numMatches = [...raw.matchAll(/["'](?:score|cvss|baseScore)["']\s*:\s*["']?(\d+(?:\.\d+))["']?/gi)];
    numMatches.forEach(m => scores.push(parseFloat(m[1])));
    return { score: scores.length > 0 ? Math.max(...scores.filter(s => s <= 10)) : 0 };
};

const getItemPrio = (item) => {
    let eolScore = 4;
    if (item.eol === "Expiré") {
        eolScore = 0;
    } else if (item.eol && item.eol !== '---' && item.eol !== 'Supporté') {
        try {
            const eolDate = new Date(item.eol);
            if (!isNaN(eolDate.getTime())) {
                if (eolDate < new Date()) {
                    eolScore = 0;
                } else {
                    const diff = (eolDate.getFullYear() - new Date().getFullYear()) * 12 + (eolDate.getMonth() - new Date().getMonth());
                    if (diff <= 12) eolScore = 1; else if (diff <= 24) eolScore = 2; else eolScore = 3;
                }
            }
        } catch(e) {}
    }

    let cveScore = 4;
    if (item.vulns && item.vulns.length > 0) {
        let maxS = Math.max(...item.vulns.map(v => getSeverityData(v).score));
        if (maxS >= 9.0) cveScore = 0; else if (maxS >= 7.0) cveScore = 1; else if (maxS >= 4.0) cveScore = 2; else if (maxS > 0.0) cveScore = 3;
    }
    return "P" + Math.min(eolScore, cveScore);
};

const getCat = n => {
    const l = n.toLowerCase();
    if (l.includes("debian") || l.includes("ubuntu") || l.includes("rhel") || l.includes("alpine")) return "Infra";
    if (l.includes("python") || l.includes("node") || l.includes("java") || l.includes("dotnet")) return "Runtime";
    return "Applicatif";
};

/// --- APPELS API EXTERNES (AVEC TIMEOUT ANTI-BLOCAGE) ---

// --- COUPE-CIRCUIT AJUSTÉ (15 SECONDES) ---
const fetchWithTimeout = async (url, options = {}) => {
    const controller = new AbortController();
    // On passe à 15000ms (15 secondes) pour laisser souffler les API sur les gros scans
    const timeoutId = setTimeout(() => controller.abort(), 15000); 
    
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
    if (purl && db.mappings[purl]) return db.mappings[purl];
    let n = name.toLowerCase();
    if (db.mappings[n]) return db.mappings[n];
    if (n.startsWith('@')) n = n.split('/')[0].substring(1);
    if (n.includes('/')) n = n.split('/')[0];
    const parts = n.split('.'); 
    if (parts.length > 2) n = parts[parts.length - 1];
    return n.replace(/-(core|api|web|starter|client|server)$/, '');
};

async function fetchSecurity(name, version, purl) {
    if (!purl && !name) return [];
    let queryBody = purl ? { package: { purl: purl } } : { version: version, package: { name: name } };
    
    try {
        const res = await fetchWithTimeout('https://api.osv.dev/v1/query', { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify(queryBody) 
        });
        
        if (!res.ok) return [];
        const data = await res.json(); 
        
        if (!data.vulns) return [];

        // --- LE RÉGIME TITAN : On filtre les données avant le stockage ---
        return data.vulns.map(v => ({
            id: v.id,
            summary: v.summary || "Pas de description",
            aliases: v.aliases || [],
            // On garde le bloc severity s'il existe pour le calcul du score
            severity: v.severity || []
        }));

    } catch (e) { 
        console.warn(`[Erreur Sécurité] ${name} :`, e);
        return []; 
    }
}

async function fetchEOL(name, ver, purl = "") {
    const q = normalizeForEOL(name, purl);
    try {
        const res = await fetchWithTimeout(`https://corsproxy.io/?${encodeURIComponent('https://endoflife.date/api/'+q+'.json')}`);
        if (!res.ok) return null;
        const data = await res.json();
        const cycle = ver.replace(/^v/, '').split('.').slice(0,2).join('.');
        const rel = data.find(r => ver.includes(r.cycle) || r.cycle === cycle);
        
        let eolStatus = "---";
        if (rel) {
            if (rel.eol === false) eolStatus = "Supporté";
            else if (rel.eol === true) eolStatus = rel.latestReleaseDate || "Expiré";
            else eolStatus = rel.eol;
        }
        return { eol: eolStatus, latest: data[0].latest };
    } catch (e) { 
        console.warn(`[Timeout ou Erreur] EOL abandonné pour ${name}`);
        return null; 
    }
}

// --- AJOUT MANUEL AVEC VÉRIFICATION DES DOUBLONS ---
function promptManualComponent() {
    if (curr === 'all') return alert("Veuillez sélectionner une application spécifique dans le menu déroulant d'abord.");

    const ov = document.createElement('div');
    ov.style.cssText = "position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.85); backdrop-filter:blur(4px); z-index:10000; display:flex; align-items:center; justify-content:center;";
    
    ov.innerHTML = `
        <div style="background:#161b22; padding:25px; border-radius:8px; border:1px solid #30363d; width:380px; box-shadow:0 15px 30px rgba(0,0,0,0.5);">
            <h3 style="margin-top:0; color:#c9d1d9;">➕ Ajouter un Composant</h3>
            <p style="font-size:0.8rem; color:#8b949e; margin-bottom:15px;">Le système vérifiera l'existence du composant avant de lancer l'analyse.</p>
            <div style="display:flex; flex-direction:column; gap:12px;">
                <input id="manName" list="eolDatalist" placeholder="Nom complet (ex: react)" autocomplete="off" style="padding:10px; background:#0d1117; color:white; border:1px solid #30363d; border-radius:4px;">
                <input id="manVer" list="versionDatalist" placeholder="Version exacte (ex: 18.2.0)" autocomplete="off" style="padding:10px; background:#0d1117; color:white; border:1px solid #30363d; border-radius:4px;">
                <datalist id="versionDatalist"></datalist>
                
                <input id="manEol" placeholder="Date EOL (YYYY-MM-DD) ou laissez vide" autocomplete="off" style="padding:10px; background:#0d1117; color:#58a6ff; border:1px solid #30363d; border-radius:4px; font-weight:bold;">
            </div>
            <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:20px;">
                <button id="manCancel" style="padding:8px 16px; background:transparent; border:1px solid #30363d; color:#ccc; border-radius:4px; cursor:pointer;">Annuler</button>
                <button id="manAdd" style="padding:8px 16px; background:#2ea043; border:none; color:white; border-radius:4px; cursor:pointer; font-weight:bold;">Vérifier & Ajouter</button>
            </div>
        </div>`;
        
    document.body.appendChild(ov);

    $('manName').oninput = (e) => e.target.value = e.target.value.toLowerCase().replace(/\s+/g, '-');
    $('manVer').oninput = (e) => e.target.value = e.target.value.replace(/\s+/g, '');

    $('manName').addEventListener('change', async (e) => {
        const productName = e.target.value;
        $('manVer').value = '';
        $('manEol').value = '';
        if (!productName) return;
        try {
            const queryName = normalizeForEOL(productName, "");
            const res = await fetch(`https://corsproxy.io/?${encodeURIComponent('https://endoflife.date/api/'+queryName+'.json')}`);
            if (res.ok) {
                const data = await res.json();
                $('versionDatalist').innerHTML = data.map(d => d.latest).filter(Boolean).map(v => `<option value="${v}">`).join('');
            }
        } catch (err) {}
    });

    $('manVer').addEventListener('change', async (e) => {
        const productName = $('manName').value;
        const version = e.target.value;
        if (!productName || !version) return;
        try {
            const queryName = normalizeForEOL(productName, "");
            const res = await fetch(`https://corsproxy.io/?${encodeURIComponent('https://endoflife.date/api/'+queryName+'.json')}`);
            if (res.ok) {
                const data = await res.json();
                const cycle = version.replace(/^v/, '').split('.').slice(0,2).join('.');
                const rel = data.find(r => version.includes(r.cycle) || r.cycle === cycle);
                if (rel) {
                    if (rel.eol === false) $('manEol').value = "Supporté";
                    else if (rel.eol === true) $('manEol').value = rel.latestReleaseDate || "Expiré";
                    else $('manEol').value = rel.eol;
                }
            }
        } catch(err) {}
    });

    $('manCancel').onclick = () => { if (document.body.contains(ov)) document.body.removeChild(ov); };
    
    $('manAdd').onclick = async () => {
        const n = $('manName').value.trim();
        const v = $('manVer').value.trim();
        const customEol = $('manEol').value.trim();
        
        if (!n || !v) return alert("Le nom et la version sont obligatoires.");

        // --- NOUVEAU : VÉRIFICATION DOUBLON ---
        const isDuplicate = db.apps[curr].items.some(item => 
            item.name.toLowerCase() === n.toLowerCase() && 
            item.version === v
        );

        if (isDuplicate) {
            return alert(`⛔ Doublon détecté : ${n} (v${v}) est déjà présent dans cet inventaire.`);
        }
        // --- FIN VÉRIFICATION ---

        $('manAdd').disabled = true;
        $('manAdd').innerText = "Vérification...";
        if (document.body.contains(ov)) document.body.removeChild(ov);
        
        showLoader("Analyse", `Scan de ${n} v${v} sur Titan...`);
        
        try {
            const eolData = await fetchEOL(n, v);
            const vulns = await fetchSecurity(n, v);
            let finalEol = customEol || (eolData ? eolData.eol : '---');
            
            db.apps[curr].items.push({
                id: "m-" + Date.now(),
                name: n,
                version: v,
                isParent: true,
                childCount: 0,
                fileId: "manual",
                eol: finalEol,
                target: eolData?.latest || '---',
                vulns: vulns || []
            });
            save(); render(); 
        } catch (error) {
            console.error("Erreur technique :", error);
        } finally {
            hideLoader();
        }
    };
}

// --- SUPPRESSION MANUELLE INTELLIGENTE (COMPATIBLE VUE GLOBALE) ---
const delManualComp = (e, id) => {
    // 1. On stoppe la propagation pour ne pas ouvrir/fermer la ligne du tableau
    e.stopPropagation(); 
    
    if(confirm("Retirer ce composant manuel de l'inventaire ?")) {
        // 2. On cherche dans TOUTES les applications laquelle possède cet ID
        let targetAppId = null;
        
        for (const appId in db.apps) {
            const hasItem = db.apps[appId].items.some(item => item.id === id);
            if (hasItem) {
                targetAppId = appId;
                break; // On a trouvé, on arrête de chercher
            }
        }

        // 3. Si on a trouvé l'application d'origine
        if (targetAppId) {
            // On filtre les items de cette application spécifique
            db.apps[targetAppId].items = db.apps[targetAppId].items.filter(x => x.id !== id);
            
            save();   // On enregistre sur le disque local
            render(); // On rafraîchit l'affichage immédiatement
        } else {
            alert("Erreur : Impossible de localiser ce composant dans la base de données.");
        }
    }
};

// --- IMPORT SBOM ET CHOIX APP ---
function promptAppSelection(appList) {
    return new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.style.cssText = "position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.85); backdrop-filter:blur(4px); z-index:10000; display:flex; align-items:center; justify-content:center;";
        
        overlay.innerHTML = `
            <div style="background:#161b22; padding:25px; border-radius:8px; border:1px solid #30363d; width:350px; display:flex; flex-direction:column; gap:15px;">
                <h3 style="margin:0; color:#c9d1d9;">Destination de l'import</h3>
                <p style="margin:0; font-size:0.85rem; color:#8b949e;">Sélectionnez l'application dans laquelle importer ce SBOM :</p>
                <select id="tempAppSelect" style="padding:10px; background:#0d1117; color:white; border:1px solid #30363d; border-radius:4px;">
                    ${appList.map(a => `<option value="${a.id}">${a.name}</option>`).join('')}
                </select>
                <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:10px;">
                    <button id="btnCancelApp" style="padding:8px 16px; background:transparent; border:1px solid #30363d; color:#ccc; border-radius:4px; cursor:pointer;">Annuler</button>
                    <button id="btnConfirmApp" style="padding:8px 16px; background:#58a6ff; border:none; color:#0d1117; border-radius:4px; cursor:pointer; font-weight:bold;">Importer</button>
                </div>
            </div>`;
            
        document.body.appendChild(overlay);
        
        document.getElementById('btnCancelApp').onclick = () => { 
            document.body.removeChild(overlay); 
            resolve(null); 
        };
        document.getElementById('btnConfirmApp').onclick = () => { 
            const id = document.getElementById('tempAppSelect').value; 
            document.body.removeChild(overlay); 
            resolve(id); 
        };
    });
}

// --- 1. FONCTION HANDLEFILE (Allégée, sans sauvegarde du texte brut) ---
async function handleFile(file) {
    if (!file) return;
    
    let targetId = curr;
    
    if (targetId === 'all') {
        const appList = Object.values(db.apps);
        if (appList.length === 0) { 
            if ($('fileInput')) $('fileInput').value = ""; 
            return alert("Créez d'abord une application."); 
        }
        targetId = await promptAppSelection(appList);
        if (!targetId) { 
            if ($('fileInput')) $('fileInput').value = ""; 
            return; 
        }
    }
    
    const raw = await file.text(); 
    const json = JSON.parse(raw);
    const comps = json.components || []; 
    const deps = json.dependencies || [];
    const fileId = "f" + Date.now();
    
    showLoader("Analyse", "Reconstitution de l'arbre et Scan PURL...");
    
    const compMap = {}; 
    comps.forEach(c => compMap[c['bom-ref'] || c.purl || c.name] = c);
    
    const tree = {}; 
    const allC = new Set();
    deps.forEach(d => { 
        tree[d.ref] = d.dependsOn || []; 
        d.dependsOn?.forEach(c => allC.add(c)); 
    });
    
    let topRefs = Object.keys(tree).filter(r => !allC.has(r));
    const processed = new Set();
    
    for (const ref of topRefs) {
        const p = compMap[ref]; 
        if (!p) continue;
        
        const eol = await fetchEOL(p.name, p.version, p.purl);
        const vulns = await fetchSecurity(p.name, p.version, p.purl);
        const gId = "g" + Math.random().toString(36).slice(2,7);
        
        db.apps[targetId].items.push({ 
            id: gId, name: p.name, version: p.version, purl: p.purl, 
            isParent: true, eol: eol?.eol || '---', target: eol?.latest || '---', 
            vulns, fileId, childCount: (tree[ref]||[]).length 
        });
        processed.add(ref);
        
        for (const cr of (tree[ref] || [])) {
            const c = compMap[cr]; 
            if (!c) continue;
            
            const v = await fetchSecurity(c.name, c.version, c.purl);
            const ceol = await fetchEOL(c.name, c.version, c.purl);
            
            db.apps[targetId].items.push({ 
                id: "c"+Math.random(), name: c.name, version: c.version, 
                parentId: gId, fileId, purl: c.purl, vulns: v, 
                eol: ceol?.eol || '---', target: ceol?.latest || '---' 
            });
            processed.add(cr);
        }
    }
    
    if (!db.apps[targetId].files) db.apps[targetId].files = [];
    
    // CORRECTION ICI : On ne pousse plus rawData dans la base !
    db.apps[targetId].files.push({ id: fileId, name: file.name, date: new Date().toLocaleString() });
    
    save(); 
    if ($('fileInput')) $('fileInput').value = ""; 
    render(); 
    hideLoader();
}

// --- 2. FONCTION RENDERFILES (Sans le bouton Voir brut) ---
function renderFiles() {
    const historySection = $('history-section'); 
    const list = $('file-list');
    
    if (!list) return;
    
    if (curr === 'all' || !db.apps[curr]) { 
        if (historySection) historySection.style.display = "none"; 
        else list.style.display = "none"; 
        return; 
    }
    
    const files = db.apps[curr].files || [];
    if (historySection) historySection.style.display = files.length > 0 ? "block" : "none";
    list.style.display = files.length > 0 ? "block" : "none";
    
    list.innerHTML = [...files].reverse().map(f => `
        <li style="display:flex; flex-direction:column; gap:5px; padding:12px; border-bottom:1px solid #333; background: rgba(255,255,255,0.02); border-radius:4px; margin-bottom:8px; list-style:none;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#58a6ff; font-weight:600; font-size:0.8rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:140px;">📄 ${f.name}</span>
                <div style="display:flex; gap:5px;">
                    <button onclick="delSbom('${f.id}')" title="Supprimer" style="background:rgba(248,81,73,0.1); border:1px solid #f85149; color:#f85149; padding:4px 8px; border-radius:4px; cursor:pointer; font-size:0.7rem;">🗑️</button>
                </div>
            </div>
            <span style="color:#888; font-size:0.65rem;">📅 Importé le : ${f.date || 'Date inconnue'}</span>
        </li>`).join('');
}

const delSbom = id => { 
    if(confirm('Supprimer ce SBOM ?')) { 
        db.apps[curr].files = db.apps[curr].files.filter(f => f.id !== id); 
        db.apps[curr].items = db.apps[curr].items.filter(i => i.fileId !== id); 
        save(); 
        render(); 
    } 
};

// --- RAFRAICHIR TOUS LES COMPOSANTS (AVEC PROTECTION DES DONNÉES MANUELLES) ---
const refresh = async () => {
    if (curr === 'all') return;
    showLoader("Mise à jour", "Scan global Titan (PURL + EOL)...");
    
    const items = db.apps[curr].items;
    let count = 0;
    
    for (const item of items) {
        // 1. On mémorise l'ancienne valeur EOL avant de demander à l'API
        const oldEol = item.eol;
        
        const eolInfo = await fetchEOL(item.name, item.version, item.purl);
        
        if (eolInfo) { 
            // 2. Règle de protection : a-t-on une date forcée manuellement ?
            // On considère que c'est une date manuelle si c'est un composant manuel 
            // ET que la valeur n'est pas un statut standard de l'API.
            const isCustomDate = item.fileId === "manual" && 
                                 oldEol !== "Supporté" && 
                                 oldEol !== "Expiré" && 
                                 oldEol !== "---";
            
            // Si ce N'EST PAS une date personnalisée, on met à jour avec l'API
            if (!isCustomDate) {
                item.eol = eolInfo.eol; 
            }
            
            // On met à jour la "Cible" (dernière version) dans tous les cas
            item.target = eolInfo.latest; 
        }
        
        // 3. On scanne TOUJOURS les nouvelles vulnérabilités, manuel ou pas !
        item.vulns = await fetchSecurity(item.name, item.version, item.purl);
        count++;
    }
    
    save(); 
    render(); 
    hideLoader();
    setTimeout(() => alert(`✅ Scan Titan terminé : ${count} composants analysés.`), 300);
};

// --- MODALE CVE ---
const openCVE = id => {
    let pApp = Object.values(db.apps).find(a => a.items.some(x => x.id === id)); 
    if (!pApp) return;
    
    let cItem = pApp.items.find(x => x.id === id); 
    if (!cItem) return;
    
    let scan = [cItem]; 
    if (cItem.isParent) {
        scan.push(...pApp.items.filter(x => x.parentId === id));
    }
    
    const seen = new Set(); 
    const unique = [];
    
    scan.forEach(item => { 
        if (item.vulns) { 
            item.vulns.forEach(v => { 
                const n = v.aliases?.find(a => a.startsWith("CVE-")) || v.id; 
                if(!seen.has(n)) { 
                    seen.add(n); 
                    unique.push({...v, _n: n, _s: getSeverityData(v).score, _id: v.id, _source: item.name }); 
                }
            });
        }
    });
    
    if (unique.length === 0) return;
    
    activeVulns = unique.sort((a,b) => b._s - a._s); 
    $('cve-modal-title').innerText = "Détails Sécurité : " + cItem.name + (cItem.isParent ? " (et dépendances)" : "");
    
    const draw = (list) => { 
        $('cve-list-container').innerHTML = list.map(v => `
            <div style="background:rgba(255,255,255,0.03); padding:15px; margin-bottom:12px; border-left:4px solid ${v._s >= 7 ? 'var(--danger)' : 'var(--warning)'}; border-radius:4px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <a href="https://osv.dev/vulnerability/${v._id}" target="_blank" style="color:var(--danger); font-weight:bold; text-decoration:none; font-size:1rem;" title="Voir la fiche complète sur OSV.dev">${v._n} 🔗</a>
                        <span style="font-size:0.65rem; background:#222; padding:2px 6px; border-radius:4px; color:#888; border:1px solid #444;">📦 ${v._source}</span>
                    </div>
                    <span style="font-size:0.75rem; background:#333; padding:2px 8px; border-radius:4px; color:white;">Score: ${v._s}</span>
                </div>
                <p style="font-size:0.85rem; color:var(--text-muted); margin:0; line-height:1.4;">${v.summary || v.details || 'Aucune description disponible.'}</p>
            </div>`).join(''); 
    };
    
    draw(activeVulns); 
    $('modalCveSearch').oninput = (e) => { 
        const term = e.target.value.toLowerCase(); 
        draw(activeVulns.filter(v => v._n.toLowerCase().includes(term) || (v.summary && v.summary.toLowerCase().includes(term)))); 
    };
    $('cve-modal').style.display = 'block';
};

const createApp = () => { 
    const n = $('newAppName').value; 
    if (n) { 
        const id = "app-"+Date.now(); 
        db.apps[id] = { id, name: n, items: [], files: [] }; 
        save(); 
        location.reload(); 
    }
};

const delApp = () => { 
    if (confirm("Supprimer l'application ?")) { 
        delete db.apps[curr]; 
        save(); 
        location.reload(); 
    }
};

const switchDashboard = () => { 
    curr = $('currentAppSelector').value; 
    render(); 
};

const toggle = id => { 
    document.querySelectorAll('.child-of-'+id).forEach(c => c.classList.toggle('is-expanded')); 
    const i = $('icon-'+id); 
    if(i) i.innerText = i.innerText === "▶" ? "▼" : "▶"; 
};

// --- MOTEUR DE RENDU DU TABLEAU ---
function render() {
    const isAll = curr === 'all';
    const items = isAll ? Object.values(db.apps).flatMap(a => a.items || []) : (db.apps[curr]?.items || []);
    const search = ($('globalSearch')?.value || "").toLowerCase();
    
    const head = document.querySelector('thead tr');
    if (head) {
        head.innerHTML = `
            ${isAll ? '<th>Appli</th>' : ''}
            <th>Élément & Sécurité</th>
            <th>Catégorie</th>
            <th>Version</th>
            <th>Date EOL</th>
            <th>Cible</th>
            <th>Priorité</th>
            <th align="right">C.</th>`;
    }

    let display = items;
    if (search) {
        const set = new Set();
        items.forEach(i => {
            const nameMatch = i.name && i.name.toLowerCase().includes(search);
            const vulnMatch = i.vulns && i.vulns.some(v => (v.id && v.id.toLowerCase().includes(search)) || (v.aliases && v.aliases.some(a => a.toLowerCase().includes(search))));
            
            if (nameMatch || vulnMatch) { 
                set.add(i); 
                if (i.isParent) {
                    items.filter(c => c.parentId === i.id).forEach(child => set.add(child));
                } else if (i.parentId) { 
                    const parentItem = items.find(x => x.id === i.parentId); 
                    if (parentItem) set.add(parentItem); 
                }
            }
        });
        display = Array.from(set).filter(Boolean);
    }

    const parents = display.filter(i => i.isParent).sort((a,b) => "P0P1P2P3P4".indexOf(getItemPrio(a)) - "P0P1P2P3P4".indexOf(getItemPrio(b)));
    let rows = []; 
    parents.forEach(p => { 
        rows.push(p); 
        rows.push(...display.filter(c => c.parentId === p.id)); 
    });

    const body = $('table-body');
    if (body) {
        body.innerHTML = rows.map(i => {
            const prio = getItemPrio(i);
            const category = getCat(i.name);
            const isClickable = i.isParent && i.childCount > 0;
            const iconZoneWidth = 50; 
            
            let totalVulns = i.vulns?.length || 0;
            if (i.isParent) {
                totalVulns += items.filter(c => c.parentId === i.id).reduce((sum, c) => sum + (c.vulns?.length || 0), 0);
            }

            let nameCellContent = "";
            const manualTag = i.fileId === "manual" ? `<span title="Composant ajouté manuellement" style="margin-left:8px; font-size:0.7rem; color:#888;">🖐️</span> <span onclick="delManualComp(event, '${i.id}')" title="Supprimer ce composant" style="cursor:pointer; margin-left:5px; font-size:0.7rem;">🗑️</span>` : '';

            if (i.isParent) {
                const prefixContent = isClickable ? `<span class="toggle-icon" id="icon-${i.id}" style="width: 20px; display: inline-block; text-align: center;">▶</span><span style="width: 25px; display: inline-block; text-align: center;">📂</span>` : "";
                
                nameCellContent = `
                    <div style="display: flex; align-items: center;">
                        <div style="width: ${iconZoneWidth}px; display: flex; flex-shrink: 0; align-items: center;">${prefixContent}</div>
                        <b style="white-space: nowrap;">${i.name}</b> ${manualTag} 
                        ${totalVulns > 0 ? `<span class="badge-p0" style="cursor:pointer; font-size:0.6rem; padding:1px 4px; margin-left:8px; flex-shrink: 0; background: ${i.vulns?.length > 0 ? 'var(--danger)' : '#d29922'}" onclick="openCVE('${i.id}')" title="Voir les CVEs">${totalVulns} CVE</span>` : ''}
                    </div>`;
            } else {
                nameCellContent = `
                    <div style="display: flex; align-items: center; padding-left: ${iconZoneWidth}px;">
                        <span style="color: #444; margin-right: 10px; flex-shrink: 0;">↳</span>
                        <span style="white-space: nowrap;">${i.name}</span> 
                        ${totalVulns > 0 ? `<span class="badge-p0" style="cursor:pointer; font-size:0.6rem; padding:1px 4px; margin-left:8px; flex-shrink: 0;" onclick="openCVE('${i.id}')">${totalVulns} CVE</span>` : ''}
                    </div>`;
            }

            return `
                <tr class="${i.isParent ? 'row-parent' : 'row-child child-of-'+i.parentId} ${search || i.isParent ? 'is-expanded' : ''}" ${isClickable ? `onclick="toggle('${i.id}')"` : ''} style="cursor: ${isClickable ? 'pointer' : 'default'};">
                    ${isAll ? `<td><span style="font-size:0.7rem; background:#222; padding:2px 5px; border-radius:3px;">${Object.values(db.apps).find(a => a.items.includes(i))?.name.toUpperCase()}</span></td>` : ''}
                    <td style="padding: 10px 15px;">${nameCellContent}</td>
                    <td><span class="cat-badge cat-${category.toLowerCase()}">${category}</span></td>
                    <td>${i.version}</td>
                    <td style="${prio === 'P0' ? 'color:var(--danger); font-weight:bold' : ''}">${i.eol || '---'}</td>
                    <td style="color:var(--success)">${i.target || '---'}</td>
                    <td><span class="badge-prio badge-${prio.toLowerCase()}">${prio}</span></td>
                    <td align="right" style="color:#666; font-size:0.7rem;">${i.isParent ? i.childCount : ''}</td>
                </tr>`;
        }).join('');
    }

    updateKPIs(items);
    renderFiles(); 
    
    if ($('refresh-section')) $('refresh-section').style.display = isAll ? 'none' : 'block';
    if ($('btnAddManual')) $('btnAddManual').style.display = isAll ? 'none' : 'inline-flex';
    
    const btnDelApp = document.querySelector('button[onclick="delApp()"]');
    if (btnDelApp) btnDelApp.style.display = isAll ? 'none' : 'block';
}

function updateKPIs(data) {
    const counts = { P0:0, P1:0, P2:0, P3:0, P4:0 }; 
    data.forEach(i => counts[getItemPrio(i)]++);
    
    if ($('comp-count')) $('comp-count').innerText = data.length;
    if ($('vulnerabilities-count')) $('vulnerabilities-count').innerText = data.reduce((a,i) => a + (i.vulns?.length || 0), 0);
    
    ['p0','p1','p2','p3','p4'].forEach(p => { 
        if ($(p+'-count')) $(p+'-count').innerText = counts[p.toUpperCase()]; 
    });
    
    const s = data.length ? Math.max(0, 100 - (counts.P0 * 15) - (counts.P1 * 5)) : 100;
    const g = $('health-gauge'); 
    if (g) { 
        g.innerText = Math.round(s) + "%"; 
        g.style.color = s > 70 ? 'var(--success)' : (s > 40 ? 'var(--warning)' : 'var(--danger)'); 
    }
}

// --- INTERFACE (BOUTONS DE RECHERCHE) ---
const initControlBarUI = () => {
    const searchBar = $('globalSearch');
    if (!searchBar || !searchBar.parentNode) return;
    
    searchBar.parentNode.style.display = 'flex';
    searchBar.parentNode.style.alignItems = 'center';
    
    if (!$('btnAddManual')) {
        const btnAdd = document.createElement('button');
        btnAdd.id = 'btnAddManual';
        btnAdd.innerHTML = '➕ Composant';
        btnAdd.title = "Ajouter un composant manuellement";
        btnAdd.style.cssText = "background:#2ea043; border:none; color:white; padding:6px 12px; border-radius:6px; cursor:pointer; margin-left:10px; height: 34px; display: inline-flex; align-items: center; white-space: nowrap; font-weight:bold;";
        btnAdd.onclick = promptManualComponent;
        searchBar.parentNode.insertBefore(btnAdd, searchBar.nextSibling);
    }

    if (!$('btnMap')) {
        const btnMap = document.createElement('button');
        btnMap.id = 'btnMap';
        btnMap.innerHTML = '⚙️ Mappings EOL';
        btnMap.style.cssText = "background:#21262d; border:1px solid #333; color:#ccc; padding:6px 12px; border-radius:6px; cursor:pointer; margin-left:10px; height: 34px; display: inline-flex; align-items: center; white-space: nowrap;";
        btnMap.onclick = () => {
            let hasChanged = false;
            const ov = document.createElement('div'); 
            ov.style.cssText = "position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:10000; display:flex; align-items:center; justify-content:center;";
            ov.innerHTML = `
                <div style="background:#161b22; padding:20px; border-radius:8px; width:450px;">
                    <h3 style="margin-top:0">⚙️ Mappings</h3>
                    <div style="display:flex; gap:5px; margin-bottom:15px;">
                        <input id="mK" placeholder="PURL ou Nom" style="flex:1">
                        <input id="mV" placeholder="Produit EOL" style="flex:1">
                        <button id="mA" style="background:green; color:white; border:none; padding:5px 10px;">+</button>
                    </div>
                    <div id="mL" style="max-height:200px; overflow-y:auto; font-size:0.8rem;"></div>
                    <button id="mC" style="width:100%; margin-top:15px; padding:10px; cursor:pointer;">Fermer</button>
                </div>`;
            document.body.appendChild(ov);
            
            const l = () => { 
                $('mL').innerHTML = Object.entries(db.mappings).map(([k,v]) => `
                    <div style="border-bottom:1px solid #333; padding:5px; display:flex; justify-content:space-between;">
                        <span>${k} ➔ ${v}</span> 
                        <span onclick="window.dM('${k}')" style="color:red; cursor:pointer;">×</span>
                    </div>`).join(''); 
            };
            
            window.dM = (k) => { delete db.mappings[k]; save(); hasChanged = true; l(); };
            
            $('mA').onclick = () => { 
                if ($('mK').value && $('mV').value) { 
                    db.mappings[$('mK').value] = $('mV').value; 
                    save(); hasChanged = true; 
                    $('mK').value=''; $('mV').value=''; 
                    l(); 
                    $('mC').innerText="Fermer & Rafraîchir"; 
                    $('mC').style.background="#58a6ff"; 
                    $('mC').style.color="#0d1117"; 
                }
            };
            $('mC').onclick = () => { document.body.removeChild(ov); if(hasChanged) refresh(); };
            l();
        };
        searchBar.parentNode.insertBefore(btnMap, searchBar.nextSibling.nextSibling);
    }
};

// --- DÉMARRAGE ---
document.addEventListener('DOMContentLoaded', () => {
    fetchEolDatalist(); // Charge le dictionnaire d'autocomplétion EOL au démarrage
    initControlBarUI(); // Place les boutons à côté de la recherche
    
    const s = $('currentAppSelector');
    if (s) {
        s.innerHTML = '<option value="all">🌐 Vue Globale</option>' + Object.values(db.apps).map(a => `<option value="${a.id}">${a.name}</option>`).join('');
        $('drop-zone').onclick = () => $('fileInput').click();
        $('fileInput').onchange = e => handleFile(e.target.files[0]);
        render();
    }
});