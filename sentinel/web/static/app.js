/**
 * SentinelGate - Third-Party API Access Security Platform
 * Cyberpunk / Neon Red Dynamic Application Engine v1.3
 */

let state = {
    overview: {},
    audits: [],
    logs: [],
    currentFilter: 'ALL',
    searchQuery: '',
    logSearchQuery: '',
    activeTab: 'audits',
    selectedCredId: null,
    currentDemo: null,
    currentPlan: null,
    tunerScopes: new Set(),
    tunerCred: null,
    soundEnabled: true,
    canvasNodes: [],
    canvasEdges: [],
    canvasParticles: [],
    dragNode: null,
    isDragging: false,
    animFrameId: null
};

// Scope risk weight catalog
const SCOPE_WEIGHTS = {
    "payment:write": 35.0,
    "ssn:read": 30.0,
    "pay_statement:read": 25.0,
    "payment:read": 20.0,
    "benefits:write": 25.0,
    "benefits:read": 15.0,
    "individual:read": 18.0,
    "employment:read": 10.0,
    "directory:read": 5.0,
    "company:read": 5.0,
    "system:admin": 40.0,
    "webhook:manage": 30.0,
    "scanner:configure": 25.0,
    "repository:delete": 25.0,
    "project:admin": 25.0,
    "repository:push": 20.0,
    "artifact:delete": 18.0,
    "artifact:read": 8.0,
    "repository:pull": 5.0
};

// -------------------------------------------------------------
// Cyber Audio Synthesizer (Web Audio API - Zero Dependencies)
// -------------------------------------------------------------
let audioCtx = null;

function getAudioContext() {
    if (!audioCtx) {
        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
        if (AudioContextClass) audioCtx = new AudioContextClass();
    }
    if (audioCtx && audioCtx.state === 'suspended') {
        audioCtx.resume();
    }
    return audioCtx;
}

function playCyberSound(type) {
    if (!state.soundEnabled) return;
    try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const now = ctx.currentTime;

        if (type === 'laser') {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(880, now);
            osc.frequency.exponentialRampToValueAtTime(110, now + 0.15);
            gain.gain.setValueAtTime(0.12, now);
            gain.gain.linearRampToValueAtTime(0.01, now + 0.15);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.15);
        } else if (type === 'alarm') {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'square';
            osc.frequency.setValueAtTime(650, now);
            osc.frequency.setValueAtTime(440, now + 0.1);
            gain.gain.setValueAtTime(0.18, now);
            gain.gain.linearRampToValueAtTime(0.01, now + 0.28);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.28);
        } else if (type === 'blocked') {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(220, now);
            osc.frequency.setValueAtTime(130, now + 0.1);
            gain.gain.setValueAtTime(0.2, now);
            gain.gain.linearRampToValueAtTime(0.01, now + 0.22);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.22);
        } else if (type === 'chime') {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(523.25, now);
            osc.frequency.exponentialRampToValueAtTime(1046.5, now + 0.2);
            gain.gain.setValueAtTime(0.15, now);
            gain.gain.linearRampToValueAtTime(0.01, now + 0.25);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.25);
        }
    } catch (e) {
        // Audio policy safeguard
    }
}

// -------------------------------------------------------------
// Cyber Floating Toast Notification System
// -------------------------------------------------------------
function showCyberToast(title, message, type = 'danger') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `cyber-toast ${type}`;

    let icon = '🚨';
    let titleColor = '#ff0055';
    if (type === 'blocked') { icon = '🛡️'; titleColor = '#00f0ff'; }
    else if (type === 'success') { icon = '✓'; titleColor = '#00ff88'; }

    toast.innerHTML = `
        <div class="toast-header" style="color: ${titleColor};">
            <span>${icon} ${title}</span>
            <span style="cursor:pointer; font-size:14px; opacity:0.7;" onclick="this.parentElement.parentElement.remove()">&times;</span>
        </div>
        <div class="toast-body">${message}</div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(120%)';
        setTimeout(() => toast.remove(), 400);
    }, 4500);
}

// -------------------------------------------------------------
// Initialization & Event Listeners
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    initCanvas();
    refreshAll();
    setInterval(fetchLogs, 6000);
});

function setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const tab = e.currentTarget.getAttribute('data-tab');
            switchTab(tab);
            playCyberSound('laser');
        });
    });

    // System Filters
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.currentTarget.classList.add('active');
            state.currentFilter = e.currentTarget.getAttribute('data-filter');
            renderAuditsTable();
            playCyberSound('laser');
        });
    });

    // Search filters
    document.getElementById('auditSearchInput').addEventListener('input', (e) => {
        state.searchQuery = e.target.value.toLowerCase();
        renderAuditsTable();
    });

    document.getElementById('logSearchInput').addEventListener('input', (e) => {
        state.logSearchQuery = e.target.value.toLowerCase();
        renderLogsTable();
    });

    // Proxy Mode Selector
    document.querySelectorAll('.btn-mode').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const mode = e.currentTarget.getAttribute('data-mode');
            setProxyMode(mode);
        });
    });

    // Sound toggle button
    const btnSound = document.getElementById('btnToggleSound');
    if (btnSound) {
        btnSound.addEventListener('click', () => {
            state.soundEnabled = !state.soundEnabled;
            btnSound.classList.toggle('active', state.soundEnabled);
            btnSound.innerText = state.soundEnabled ? '🔊 Audio: ON' : '🔇 Audio: MUTED';
            if (state.soundEnabled) playCyberSound('chime');
        });
    }

    // Global Action Buttons
    document.getElementById('btnSimulateTraffic').addEventListener('click', simulateTraffic);
    document.getElementById('btnRefreshAll').addEventListener('click', refreshAll);
    document.getElementById('btnRunDemoManual').addEventListener('click', () => {
        const credId = document.getElementById('demoSelectCred').value;
        if (credId) runDemonstrationWithAnimation(credId);
    });
    document.getElementById('btnApplyPlan').addEventListener('click', applyCurrentPlan);
    document.getElementById('btnRollbackPlan').addEventListener('click', rollbackCurrentPlan);

    document.getElementById('demoSelectCred').addEventListener('change', (e) => {
        if (e.target.value) runDemonstrationWithAnimation(e.target.value);
    });

    document.getElementById('blastSelectCred').addEventListener('change', (e) => {
        if (e.target.value) loadBlastRadius(e.target.value);
    });
}

function switchTab(tabName) {
    state.activeTab = tabName;
    document.querySelectorAll('.tab-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-tab') === tabName);
    });
    document.querySelectorAll('.tab-content').forEach(c => {
        c.style.display = (c.id === `tab-${tabName}`) ? 'block' : 'none';
    });

    if (tabName === 'blastradius') {
        const credId = document.getElementById('blastSelectCred').value || state.audits[0]?.credential_id;
        if (credId) loadBlastRadius(credId);
    }
    if (tabName === 'logs') fetchLogs();
}

async function refreshAll() {
    playCyberSound('chime');
    await fetchOverview();
    await fetchAudits();
    await fetchLogs();
    populateSelectDropdowns();
}

// -------------------------------------------------------------
// REST API Communications
// -------------------------------------------------------------
async function fetchOverview() {
    try {
        const res = await fetch('/api/overview');
        const data = await res.json();
        state.overview = data;
        renderOverview();
        updateProxyModeUI(data.current_proxy_mode);
    } catch (err) {
        console.error('Failed to fetch overview:', err);
    }
}

async function fetchAudits() {
    try {
        const res = await fetch('/api/audits');
        const data = await res.json();
        state.audits = data.audits || [];
        renderAuditsTable();
        populateSelectDropdowns();
    } catch (err) {
        console.error('Failed to fetch audits:', err);
    }
}

async function fetchLogs() {
    try {
        const res = await fetch('/api/logs?limit=50');
        const data = await res.json();
        state.logs = data.logs || [];
        renderLogsTable();
    } catch (err) {
        console.error('Failed to fetch logs:', err);
    }
}

async function setProxyMode(mode) {
    playCyberSound('chime');
    try {
        const res = await fetch('/api/proxy/mode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode })
        });
        const data = await res.json();
        updateProxyModeUI(data.mode);
        fetchOverview();
        
        let desc = "Passive monitoring: Logs out-of-baseline calls without blocking.";
        if (mode === 'ENFORCE') desc = "Active Least-Privilege Guard: Rejects excessive & rogue calls with HTTP 403 Forbidden!";
        else if (mode === 'REDACT') desc = "Field-Level Masking: Redacts unapproved PII, SSNs, and salary records in response payloads.";

        showCyberToast(`GATEWAY MODE: ${mode}`, desc, mode === 'ENFORCE' ? 'blocked' : 'success');
        showRadarAlert(`Gateway Mode switched to: ${mode}`);
    } catch (err) {
        showCyberToast('GATEWAY ERROR', err.message, 'danger');
    }
}

async function simulateTraffic() {
    playCyberSound('laser');
    const btn = document.getElementById('btnSimulateTraffic');
    btn.disabled = true;
    btn.innerText = '⚡ Infiltrating...';

    try {
        const res = await fetch('/api/simulate/traffic', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await res.json();
        await refreshAll();
        showCyberToast('API TRAFFIC INJECTED', `Dispatched ${data.generated_events} third-party API packets (normal baseline + out-of-baseline probes).`, 'success');
        showRadarAlert(`Injected ${data.generated_events} third-party API packets.`);
    } catch (err) {
        showCyberToast('SIMULATION FAILED', err.message, 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '⚡ Inject API Traffic';
    }
}

// -------------------------------------------------------------
// Live Targeted Attack Vector Stimulation
// -------------------------------------------------------------
window.simulateSpecificAttack = async function(type) {
    let payload = {};
    let endpoint = "";
    let attackTitle = "";
    let attackDesc = "";

    if (type === 'salary') {
        endpoint = "/proxy/finch";
        payload = {
            token: "fnch_tok_live_89f3a12948b84931bcfa8723",
            method: "GET",
            path: "/employer/pay-statement"
        };
        attackTitle = "SALARY BREACH PROBE";
        attackDesc = "Slack Org & Birthday Bot attempting unauthorized compensation extraction via /employer/pay-statement";
    } else if (type === 'harbor') {
        endpoint = "/proxy/harbor";
        payload = {
            token: "hrbr_sec_9941a87b1c3e4492a8392110c",
            method: "DELETE",
            path: "/api/v2.0/projects/prod-apps/repositories/frontend"
        };
        attackTitle = "CONTAINER SABOTAGE PROBE";
        attackDesc = "ArgoCD Deploy Bot attempting production container deletion on Harbor /prod-apps/repositories/frontend";
    } else if (type === 'wire') {
        endpoint = "/proxy/finch";
        payload = {
            token: "fnch_tok_live_7c44e99120de3b110acb3211",
            method: "POST",
            path: "/employer/payment"
        };
        attackTitle = "PAYROLL WIRE TAMPERING";
        attackDesc = "ExpensifyPro attempting off-cycle direct deposit cash disbursement via /employer/payment";
    }

    showRadarAlert(`🚨 INTRUSION SIMULATED: ${attackTitle}`);

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const status = res.status;
        const data = await res.json();

        await refreshAll();

        if (status === 403 || data.sentinel_action === 'BLOCKED' || data.sentinel_action === 'ENFORCED') {
            playCyberSound('blocked');
            showCyberToast(`🛡️ GATEWAY INTERCEPTED: ${attackTitle}`, `${attackDesc} -> BLOCKED (HTTP 403 FORBIDDEN by Sentinel Least-Privilege Gateway)`, 'blocked');
        } else {
            playCyberSound('alarm');
            showCyberToast(`🚨 ATTACK SUCCEEDED (OVER-PRIVILEGED): ${attackTitle}`, `${attackDesc} -> EXPLOIT ALLOWED (HTTP 200). Sensitive data accessed!`, 'danger');
        }

        switchTab('logs');
    } catch (err) {
        console.error('Attack simulation error:', err);
    }
};

function showRadarAlert(msg) {
    const el = document.getElementById('radarStatusText');
    if (!el) return;
    el.innerText = msg;
    el.style.color = '#ff0055';
    el.style.textShadow = '0 0 14px #ff0055';
    setTimeout(() => {
        el.innerText = 'SURVEILLANCE MODE';
        el.style.color = 'var(--neon-red-bright)';
        el.style.textShadow = 'none';
    }, 7000);
}

function updateProxyModeUI(mode) {
    document.querySelectorAll('.btn-mode').forEach(btn => {
        btn.className = 'btn-mode';
        if (btn.getAttribute('data-mode') === mode) {
            btn.classList.add(`active-${mode.toLowerCase()}`);
        }
    });
}

function renderOverview() {
    const o = state.overview;
    animateCounter('metricIntegrations', o.total_integrations ?? 0);
    animateCounter('metricOverpriv', o.overprivileged_count ?? 0);
    animateCounter('metricCritical', o.critical_risk_count ?? 0);
    animateCounter('metricBlocked', o.blocked_requests_count ?? 0);
    document.getElementById('metricAvgExcess').innerText = `${o.average_excess_ratio ?? 0}%`;
}

function animateCounter(id, targetVal) {
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseInt(el.innerText) || 0;
    if (current === targetVal) {
        el.innerText = targetVal;
        return;
    }
    el.innerText = targetVal;
    el.style.transform = 'scale(1.15)';
    setTimeout(() => { el.style.transform = 'scale(1)'; }, 250);
}

// -------------------------------------------------------------
// Audit Table Rendering
// -------------------------------------------------------------
function renderAuditsTable() {
    const tbody = document.getElementById('auditsTableBody');
    tbody.innerHTML = '';

    const filtered = state.audits.filter(a => {
        if (state.currentFilter !== 'ALL' && a.system_type !== state.currentFilter) {
            return false;
        }
        if (state.searchQuery) {
            const haystack = `${a.client_name} ${a.system_type} ${a.granted_scopes.join(' ')} ${a.threat_vectors.join(' ')}`.toLowerCase();
            return haystack.includes(state.searchQuery);
        }
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">No third-party integrations match the filter criteria.</td></tr>`;
        return;
    }

    filtered.forEach(a => {
        const tr = document.createElement('tr');
        
        const sysBadge = a.system_type === 'FINCH' 
            ? `<span class="badge badge-finch">Finch HRIS</span>`
            : `<span class="badge badge-harbor">Harbor Registry</span>`;

        const riskClass = `badge-${a.risk_level.toLowerCase()}`;
        const riskBadge = `<span class="badge ${riskClass}">${a.risk_level} (${a.risk_score})</span>`;

        const grantedHtml = a.granted_scopes.map(s => {
            const isUnused = a.unused_scopes.includes(s);
            return `<span class="scope-tag ${isUnused ? 'excess' : 'used'}">${s}</span>`;
        }).join('');

        const threatSummary = a.threat_vectors.length > 0 
            ? `<div style="color: #ff4d88; font-size: 11px; text-shadow:0 0 6px rgba(255,0,85,0.4);">⚠️ ${a.threat_vectors[0]}</div>`
            : `<span style="color: var(--neon-green); font-size: 11px;">✓ Least-privilege compliant</span>`;

        tr.innerHTML = `
            <td>
                <div style="font-weight: 800; color: #fff;">${a.client_name}</div>
                <div style="font-size: 11px; color: var(--text-muted);">${a.credential_id}</div>
            </td>
            <td>${sysBadge}</td>
            <td style="max-width: 320px;">${grantedHtml}</td>
            <td>
                <span style="font-size: 15px; font-weight: 800; color: ${a.excess_ratio > 50 ? 'var(--neon-red-bright)' : 'var(--neon-green)'};">
                    ${a.excess_ratio}%
                </span>
                <div style="font-size: 10px; color: var(--text-muted);">${a.unused_scopes.length} of ${a.granted_scopes.length} unused</div>
            </td>
            <td>${riskBadge}</td>
            <td style="max-width: 280px;">${threatSummary}</td>
            <td>
                <div style="display: flex; gap: 6px;">
                    <button class="btn-action" style="padding: 5px 9px;" onclick="startDemonstration('${a.credential_id}')">
                        🔬 Demo Risk
                    </button>
                    <button class="btn-action btn-primary" style="padding: 5px 9px;" onclick="startRemediation('${a.credential_id}')">
                        🛡️ Remediate
                    </button>
                    <button class="btn-action" style="padding: 5px 9px;" onclick="startBlastRadius('${a.credential_id}')">
                        🌐 Blast
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function populateSelectDropdowns() {
    const demoSelect = document.getElementById('demoSelectCred');
    const blastSelect = document.getElementById('blastSelectCred');
    
    demoSelect.innerHTML = '<option value="">-- Choose Integration --</option>';
    blastSelect.innerHTML = '<option value="">-- Choose Integration --</option>';

    state.audits.forEach(a => {
        const opt = `<option value="${a.credential_id}">${a.client_name} (${a.system_type}) - ${a.risk_level}</option>`;
        demoSelect.innerHTML += opt;
        blastSelect.innerHTML += opt;
    });
}

// -------------------------------------------------------------
// Demonstration Studio (Stepped HUD Progression)
// -------------------------------------------------------------
window.startDemonstration = function(credId) {
    switchTab('demonstrate');
    document.getElementById('demoSelectCred').value = credId;
    runDemonstrationWithAnimation(credId);
};

async function runDemonstrationWithAnimation(credId) {
    playCyberSound('laser');
    const terminal = document.getElementById('demoTerminal');
    const container = document.getElementById('demoResultsContainer');
    terminal.style.display = 'flex';
    
    document.getElementById('termLine1').innerText = `Binding to Token ID: ${credId}...`;
    document.getElementById('termLine2').innerText = "Testing normal operational boundary...";
    document.getElementById('termLine3').innerText = "Simulating privilege escalation on unneeded scopes...";

    container.innerHTML = `<div style="text-align:center; padding: 40px; color: var(--neon-red-bright);"><span class="radar-dot" style="display:inline-block; margin-right:8px;"></span> Executing live proof-of-excess simulation...</div>`;

    try {
        const res = await fetch(`/api/demonstrate/${credId}`);
        const demo = await res.json();
        state.currentDemo = demo;

        setTimeout(() => {
            playCyberSound(demo.excessive_demonstration.exploit_allowed ? 'alarm' : 'blocked');
            document.getElementById('termLine1').innerText = `[SUCCESS] Legitimate call to ${demo.legitimate_request.endpoint} executed with ${demo.legitimate_request.scope_used}`;
            document.getElementById('termLine2').innerText = `[ATTACK VECTOR] Attempting unauthorized call to ${demo.excessive_demonstration.endpoint}...`;
            document.getElementById('termLine3').innerText = demo.excessive_demonstration.exploit_allowed 
                ? `[🚨 VULNERABILITY CONFIRMED] Token grants '${demo.excessive_demonstration.scope_abused}' - EXPLOIT PERMITTED!`
                : `[✓ LEAST PRIVILEGE ENFORCED] Out-of-baseline call blocked with HTTP 403 Forbidden!`;
            renderDemonstration(demo);
        }, 500);

    } catch (err) {
        container.innerHTML = `<div style="color:var(--neon-red);">Failed to run demonstration: ${err.message}</div>`;
    }
}

function renderDemonstration(demo) {
    const container = document.getElementById('demoResultsContainer');
    const legit = demo.legitimate_request;
    const exploit = demo.excessive_demonstration;

    container.innerHTML = `
        <div style="margin-bottom: 20px; background: rgba(255,0,85,0.06); padding: 16px; border-radius: 8px; border: 1px solid var(--border-neon); box-shadow:0 0 15px rgba(255,0,85,0.12);">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                <div>
                    <h3 style="color:#fff; font-size:17px; font-weight:800; letter-spacing:0.5px;">PRIVILEGE DIVERGENCE: ${demo.client_name}</h3>
                    <span style="font-size:12px; color:var(--text-muted);">Masked Secret: <code style="color:var(--neon-cyan);">${demo.token_masked}</code> | System: <strong>${demo.system_type}</strong></span>
                </div>
                <div>
                    <span class="badge ${exploit.exploit_allowed ? 'badge-critical' : 'badge-low'}">
                        ${exploit.exploit_allowed ? 'CRITICAL RISK DEMONSTRATED' : 'SECURED'}
                    </span>
                </div>
            </div>
            <div style="margin-top: 10px;">
                <span style="font-size:12px; color:var(--text-muted); font-weight:600;">ACTIVE GRANTED SCOPES: </span>
                ${demo.granted_scopes.map(s => `<span class="scope-tag">${s}</span>`).join('')}
            </div>
        </div>

        <div class="demo-grid">
            <!-- Left Card: Legitimate Work -->
            <div class="demo-card safe">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h4 style="color:var(--neon-green); font-size:14px; font-weight:800;">✓ INTENDED BUSINESS OPERATION</h4>
                    <span class="badge badge-low">HTTP ${legit.status_code} OK</span>
                </div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">
                    <strong>Endpoint:</strong> <code style="color:var(--neon-cyan); font-weight:700;">${legit.method} ${legit.endpoint}</code>
                </div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">
                    <strong>Legitimate Scope Used:</strong> <span class="scope-tag used">${legit.scope_used}</span>
                </div>
                <p style="font-size:12px; color:#d1d5db; margin-bottom:12px;">${legit.description}</p>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:4px; font-weight:700;">Expected Clean API Response:</div>
                <div class="code-box">${JSON.stringify(legit.sample_response, null, 2)}</div>
            </div>

            <!-- Right Card: Excessive Capability Abuse -->
            <div class="demo-card danger">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h4 style="color:var(--neon-red-bright); font-size:14px; font-weight:800;">⚠️ EXCESSIVE CAPABILITY ABUSE</h4>
                    <span class="badge badge-critical">${exploit.exploit_allowed ? 'EXPLOIT PERMITTED (200)' : 'BLOCKED (403)'}</span>
                </div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">
                    <strong>Unauthorized Endpoint:</strong> <code style="color:var(--neon-red-bright); font-weight:700;">${exploit.method} ${exploit.endpoint}</code>
                </div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">
                    <strong>Excessive Scope Leveraged:</strong> <span class="scope-tag excess">${exploit.scope_abused}</span>
                </div>
                <div style="background:rgba(255,0,85,0.15); border-left:3px solid var(--neon-red); padding:10px; font-size:12px; color:#ffccd9; margin-bottom:12px;">
                    <strong>Vulnerability Analysis:</strong> ${exploit.risk_analysis}
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:4px; font-weight:700;">Exfiltrated Sensitive Data Payload:</div>
                <div class="code-box" style="color:#ff3366; text-shadow:0 0 4px rgba(255,0,85,0.3);">${JSON.stringify(exploit.sample_response, null, 2)}</div>
            </div>
        </div>

        <div style="margin-top:24px; text-align:right;">
            <button class="btn-action btn-primary" onclick="startRemediation('${demo.credential_id}')">
                🛡️ Eliminate This Risk: Synthesize Least-Privilege Policy
            </button>
        </div>
    `;
}

// -------------------------------------------------------------
// Interactive Physics Canvas for Blast Radius
// -------------------------------------------------------------
function initCanvas() {
    const canvas = document.getElementById('blastCanvas');
    if (!canvas) return;

    function resize() {
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = canvas.parentElement.clientHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    canvas.addEventListener('mousedown', (e) => {
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;

        for (const n of state.canvasNodes) {
            const dx = mx - n.x;
            const dy = my - n.y;
            if (dx * dx + dy * dy <= n.r * n.r * 1.5) {
                state.dragNode = n;
                state.isDragging = true;
                break;
            }
        }
    });

    canvas.addEventListener('mousemove', (e) => {
        if (state.isDragging && state.dragNode) {
            const rect = canvas.getBoundingClientRect();
            state.dragNode.x = e.clientX - rect.left;
            state.dragNode.y = e.clientY - rect.top;
        }
    });

    window.addEventListener('mouseup', () => {
        state.isDragging = false;
        state.dragNode = null;
    });

    startCanvasLoop();
}

window.resetCanvasPhysics = function() {
    playCyberSound('laser');
    const credId = document.getElementById('blastSelectCred').value;
    if (credId) loadBlastRadius(credId);
};

window.startBlastRadius = function(credId) {
    switchTab('blastradius');
    document.getElementById('blastSelectCred').value = credId;
    loadBlastRadius(credId);
};

async function loadBlastRadius(credId) {
    try {
        const res = await fetch(`/api/audit/${credId}`);
        const audit = await res.json();
        buildPhysicsGraph(audit);
    } catch (err) {
        console.error('Blast radius fetch failed:', err);
    }
}

function buildPhysicsGraph(audit) {
    const canvas = document.getElementById('blastCanvas');
    const width = canvas.width;
    const height = canvas.height;

    const rawNodes = audit.blast_radius_nodes || [];
    const rawEdges = audit.blast_radius_edges || [];

    state.canvasNodes = [];
    state.canvasEdges = [];
    state.canvasParticles = [];

    const tokenX = 140;
    const tokenY = height / 2;

    const scopes = rawNodes.filter(n => n.type.includes('SCOPE'));
    const leaves = rawNodes.filter(n => n.type === 'EXPOSED_ASSET' || n.type === 'THREAT_IMPACT');

    // Root Token Node
    state.canvasNodes.push({
        id: `token_${audit.credential_id}`,
        label: audit.client_name,
        type: 'TOKEN',
        x: tokenX,
        y: tokenY,
        r: 26,
        color: '#00f0ff',
        glow: 'rgba(0, 240, 255, 0.8)'
    });

    // Scopes
    scopes.forEach((s, i) => {
        const step = height / (scopes.length + 1);
        const isExcess = s.type === 'EXCESS_SCOPE';
        state.canvasNodes.push({
            id: s.id,
            label: s.label,
            type: s.type,
            x: width * 0.45,
            y: step * (i + 1),
            r: 16,
            color: isExcess ? '#ff0055' : '#00ff88',
            glow: isExcess ? 'rgba(255, 0, 85, 0.8)' : 'rgba(0, 255, 136, 0.8)'
        });
    });

    // Assets & Threat nodes
    leaves.forEach((l, i) => {
        const step = height / (leaves.length + 1);
        const isThreat = l.type === 'THREAT_IMPACT';
        state.canvasNodes.push({
            id: l.id,
            label: l.label,
            type: l.type,
            x: width * 0.82,
            y: step * (i + 1),
            r: 20,
            color: isThreat ? '#dc2626' : '#ff9900',
            glow: isThreat ? 'rgba(220, 38, 38, 0.9)' : 'rgba(255, 153, 0, 0.8)'
        });
    });

    // Edges
    rawEdges.forEach(e => {
        const sourceNode = state.canvasNodes.find(n => n.id === e.source);
        const targetNode = state.canvasNodes.find(n => n.id === e.target);
        if (sourceNode && targetNode) {
            state.canvasEdges.push({
                source: sourceNode,
                target: targetNode,
                isDashed: e.style === 'dashed',
                color: e.style === 'dashed' ? 'rgba(255, 0, 85, 0.6)' : 'rgba(0, 255, 136, 0.5)'
            });
        }
    });

    // Animated data particles
    for (let i = 0; i < state.canvasEdges.length * 3; i++) {
        const edge = state.canvasEdges[i % state.canvasEdges.length];
        state.canvasParticles.push({
            edge: edge,
            progress: Math.random(),
            speed: 0.007 + Math.random() * 0.007,
            color: edge.isDashed ? '#ff0055' : '#00ff88'
        });
    }
}

function startCanvasLoop() {
    const canvas = document.getElementById('blastCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function loop() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Cyber Grid Background
        ctx.strokeStyle = "rgba(255, 0, 85, 0.04)";
        ctx.lineWidth = 1;
        const gridStep = 36;
        for (let x = 0; x < canvas.width; x += gridStep) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, canvas.height);
            ctx.stroke();
        }
        for (let y = 0; y < canvas.height; y += gridStep) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(canvas.width, y);
            ctx.stroke();
        }

        // Draw Edges
        state.canvasEdges.forEach(e => {
            ctx.save();
            ctx.strokeStyle = e.color;
            ctx.lineWidth = 2;
            if (e.isDashed) {
                ctx.setLineDash([5, 5]);
                ctx.shadowColor = "rgba(255, 0, 85, 0.6)";
                ctx.shadowBlur = 6;
            }
            ctx.beginPath();
            ctx.moveTo(e.source.x, e.source.y);
            ctx.lineTo(e.target.x, e.target.y);
            ctx.stroke();
            ctx.restore();
        });

        // Flowing data packets
        state.canvasParticles.forEach(p => {
            p.progress += p.speed;
            if (p.progress > 1) p.progress = 0;

            const px = p.edge.source.x + (p.edge.target.x - p.edge.source.x) * p.progress;
            const py = p.edge.source.y + (p.edge.target.y - p.edge.source.y) * p.progress;

            ctx.save();
            ctx.fillStyle = p.color;
            ctx.shadowColor = p.color;
            ctx.shadowBlur = 8;
            ctx.beginPath();
            ctx.arc(px, py, 3.5, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
        });

        // Draw Nodes
        const now = Date.now() * 0.003;
        state.canvasNodes.forEach(n => {
            ctx.save();

            // Pulsing shockwaves for threat & token nodes
            if (n.type === 'THREAT_IMPACT' || n.type === 'EXCESS_SCOPE' || n.type === 'TOKEN') {
                const pulseR = n.r + 5 + Math.sin(now) * 4;
                ctx.strokeStyle = n.color;
                ctx.globalAlpha = 0.35 + Math.sin(now) * 0.2;
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.arc(n.x, n.y, pulseR, 0, Math.PI * 2);
                ctx.stroke();
            }

            // Node core
            ctx.globalAlpha = 1.0;
            ctx.fillStyle = n.color;
            ctx.shadowColor = n.glow;
            ctx.shadowBlur = 14;
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
            ctx.fill();

            // Node border
            ctx.strokeStyle = "#ffffff";
            ctx.lineWidth = 2;
            ctx.stroke();

            // Text Label
            ctx.fillStyle = "#ffffff";
            ctx.font = "bold 11px Segoe UI, sans-serif";
            ctx.textAlign = "center";
            ctx.shadowColor = "#000000";
            ctx.shadowBlur = 5;
            ctx.fillText(n.label, n.x, n.y + n.r + 15);

            ctx.restore();
        });

        state.animFrameId = requestAnimationFrame(loop);
    }

    loop();
}

// -------------------------------------------------------------
// Interactive Scope Tuner & Remediation
// -------------------------------------------------------------
window.startRemediation = async function(credId) {
    playCyberSound('laser');
    switchTab('remediation');
    state.selectedCredId = credId;
    
    const container = document.getElementById('remediationContainer');
    container.innerHTML = `<div style="text-align:center; padding: 40px; color: var(--neon-red-bright);"><span class="radar-dot" style="display:inline-block; margin-right:8px;"></span> Synthesizing Least-Privilege Policy Guardrail...</div>`;

    try {
        const res = await fetch(`/api/remediation/plan/${credId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const plan = await res.json();
        state.currentPlan = plan;

        const credRes = await fetch(`/api/credentials`);
        const credData = await credRes.json();
        const cred = credData.credentials.find(c => c.id === credId);
        state.tunerCred = cred;
        state.tunerScopes = new Set(plan.recommended_scopes);

        renderScopeTuner(cred, plan);
        renderRemediationPlan(plan);
    } catch (err) {
        container.innerHTML = `<div style="color:var(--neon-red);">Failed to generate plan: ${err.message}</div>`;
    }
};

function renderScopeTuner(cred, plan) {
    const tunerSection = document.getElementById('scopeTunerSection');
    const checkboxList = document.getElementById('tunerCheckboxList');
    tunerSection.style.display = 'block';
    checkboxList.innerHTML = '';

    const allGranted = cred.granted_scopes;

    allGranted.forEach(scope => {
        const isChecked = state.tunerScopes.has(scope);
        const label = document.createElement('label');
        label.className = `scope-toggle-label ${isChecked ? 'checked' : ''}`;
        label.innerHTML = `
            <input type="checkbox" value="${scope}" ${isChecked ? 'checked' : ''}>
            <span style="font-family:monospace; font-weight:700;">${scope}</span>
            <span style="margin-left:auto; font-size:10px; color:var(--text-muted);">+${SCOPE_WEIGHTS[scope] || 10} pts</span>
        `;
        
        const input = label.querySelector('input');
        input.addEventListener('change', (e) => {
            playCyberSound('laser');
            if (e.target.checked) {
                state.tunerScopes.add(scope);
                label.classList.add('checked');
            } else {
                state.tunerScopes.delete(scope);
                label.classList.remove('checked');
            }
            recalculateLiveTuner();
        });

        checkboxList.appendChild(label);
    });

    recalculateLiveTuner();
}

function recalculateLiveTuner() {
    const selected = Array.from(state.tunerScopes);
    const rawRisk = selected.reduce((acc, s) => acc + (SCOPE_WEIGHTS[s] || 10.0), 0);
    const riskScore = Math.min(100.0, rawRisk);

    const cred = state.tunerCred;
    if (!cred) return;

    const totalGranted = cred.granted_scopes.length;
    const unusedCount = cred.granted_scopes.filter(s => !state.tunerScopes.has(s)).length;
    const excessRatio = totalGranted > 0 ? (unusedCount / totalGranted * 100.0) : 0;

    document.getElementById('liveTunerRisk').innerText = `${Math.round(riskScore)} / 100`;
    document.getElementById('liveTunerExcess').innerText = `${Math.round(excessRatio)}%`;
}

function renderRemediationPlan(plan) {
    const container = document.getElementById('remediationContainer');
    document.getElementById('planHeaderClient').innerText = `${plan.client_name} (${plan.system_type})`;
    document.getElementById('btnApplyPlan').disabled = (plan.status === 'APPLIED');
    document.getElementById('btnRollbackPlan').disabled = (plan.status !== 'APPLIED');

    const revokedHtml = plan.revoked_scopes.map(s => `<span class="scope-tag excess">- ${s}</span>`).join('') || '<span style="color:var(--neon-green);">None</span>';
    const retainedHtml = plan.recommended_scopes.map(s => `<span class="scope-tag used">+ ${s}</span>`).join('');

    let policyPreview = (plan.system_type === 'HARBOR')
        ? JSON.stringify(plan.policy_harbor_json, null, 2)
        : JSON.stringify(plan.policy_finch_json, null, 2);

    container.innerHTML = `
        <div style="background:rgba(255,0,85,0.06); border:1px solid var(--border-neon); border-radius:8px; padding:20px; margin-bottom:20px; box-shadow:0 0 15px rgba(255,0,85,0.1);">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
                <div>
                    <h4 style="color:#fff; font-size:16px; font-weight:800; letter-spacing:0.5px;">REMEDIATION IMPACT METRICS</h4>
                    <span style="font-size:12px; color:var(--text-muted);">Plan ID: <code style="color:var(--neon-cyan);">${plan.id}</code> | Status: <strong style="color:${plan.status === 'APPLIED' ? 'var(--neon-green)' : 'var(--neon-amber)'};">${plan.status}</strong></span>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:28px; font-weight:900; color:var(--neon-green); text-shadow:0 0 12px var(--neon-green-glow);">-${plan.reduction_percentage}%</div>
                    <div style="font-size:11px; color:var(--text-muted);">Risk Score: ${plan.risk_score_before} ➔ ${plan.risk_score_after}</div>
                </div>
            </div>

            <div class="policy-diff-box">
                <div class="diff-pane" style="border-left: 3px solid var(--neon-red);">
                    <h4>Revoked Dangerous Scopes (${plan.revoked_scopes.length})</h4>
                    <div>${revokedHtml}</div>
                </div>
                <div class="diff-pane" style="border-left: 3px solid var(--neon-green);">
                    <h4>Retained Least-Privilege Scopes (${plan.recommended_scopes.length})</h4>
                    <div>${retainedHtml}</div>
                </div>
            </div>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:18px;">
            <div>
                <h4 style="color:#fff; font-size:13px; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.5px;">Synthesized Configuration (${plan.system_type})</h4>
                <div class="code-box" style="height:270px;">${policyPreview}</div>
            </div>
            <div>
                <h4 style="color:#fff; font-size:13px; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.5px;">Open Policy Agent (OPA) Gateway Guardrail</h4>
                <div class="code-box" style="height:270px; color:#7ee787;">${plan.policy_rego}</div>
            </div>
        </div>
    `;
}

async function applyCurrentPlan() {
    if (!state.currentPlan) return;
    const btn = document.getElementById('btnApplyPlan');
    btn.disabled = true;
    btn.innerText = 'Applying Policy...';
    try {
        const res = await fetch(`/api/remediation/apply/${state.currentPlan.id}`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            playCyberSound('chime');
            showCyberToast('LEAST PRIVILEGE APPLIED', `Credentials for ${state.currentPlan.client_name} successfully down-scoped! Risk reduced by ${state.currentPlan.reduction_percentage}%.`, 'success');
            showRadarAlert(`Remediation applied for ${state.currentPlan.client_name}`);
            await refreshAll();
            startRemediation(state.currentPlan.credential_id);
        } else {
            showCyberToast('REMEDIATION ERROR', data.error, 'danger');
        }
    } catch (err) {
        showCyberToast('REMEDIATION FAILED', err.message, 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '🛡️ Apply Least-Privilege Policy';
    }
}

async function rollbackCurrentPlan() {
    if (!state.currentPlan) return;
    try {
        const res = await fetch(`/api/remediation/rollback/${state.currentPlan.id}`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            playCyberSound('chime');
            showCyberToast('CREDENTIAL RESTORED', `Original scopes restored for ${state.currentPlan.client_name}.`, 'blocked');
            showRadarAlert(`Original scopes restored for ${state.currentPlan.client_name}`);
            await refreshAll();
            startRemediation(state.currentPlan.credential_id);
        } else {
            showCyberToast('ROLLBACK ERROR', data.error, 'danger');
        }
    } catch (err) {
        showCyberToast('ROLLBACK FAILED', err.message, 'danger');
    }
}

window.rollbackAllPolicies = async function() {
    playCyberSound('laser');
    try {
        const res = await fetch('/api/remediation/rollback-all', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            playCyberSound('chime');
            showCyberToast('ALL POLICIES RESTORED', data.message, 'blocked');
            showRadarAlert('All least-privilege policies rolled back to original broad scopes.');
            await refreshAll();
            if (state.selectedCredId) {
                startRemediation(state.selectedCredId);
            }
        } else {
            showCyberToast('ROLLBACK ALL ERROR', data.error, 'danger');
        }
    } catch (err) {
        showCyberToast('ROLLBACK ALL FAILED', err.message, 'danger');
    }
};

// -------------------------------------------------------------
// Real-Time Telemetry Stream
// -------------------------------------------------------------
function renderLogsTable() {
    const tbody = document.getElementById('logsTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const filtered = state.logs.filter(l => {
        if (!state.logSearchQuery) return true;
        const haystack = `${l.client_name} ${l.system_type} ${l.endpoint} ${l.matched_scope} ${l.risk_indicator}`.toLowerCase();
        return haystack.includes(state.logSearchQuery);
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No telemetry logged matching query. Click 'Inject API Traffic' to generate live events.</td></tr>`;
        return;
    }

    filtered.forEach((l, idx) => {
        const tr = document.createElement('tr');
        if (idx === 0) tr.classList.add('new-telemetry-row');
        
        let statusBadge = `<span style="color:var(--neon-green); font-weight:700;">${l.status_code}</span>`;
        if (l.blocked) {
            statusBadge = `<span class="badge badge-critical">BLOCKED (403)</span>`;
        } else if (l.status_code >= 400) {
            statusBadge = `<span class="badge badge-high">${l.status_code}</span>`;
        }

        const redactedHtml = l.redacted_fields.length > 0
            ? `<span style="color:var(--neon-amber); font-size:11px; font-weight:600;">Redacted: ${l.redacted_fields.join(', ')}</span>`
            : `<span style="color:var(--text-muted); font-size:11px;">None</span>`;

        const indicatorHtml = l.risk_indicator 
            ? `<span style="color:var(--neon-red-bright); font-size:11px; font-weight:700; text-shadow:0 0 6px var(--neon-red-glow);">⚠️ ${l.risk_indicator}</span>`
            : `<span style="color:var(--text-muted); font-size:11px;">Normal</span>`;

        tr.innerHTML = `
            <td style="font-family:monospace; font-size:11px; color:var(--text-muted);">${l.timestamp.split('T')[1].replace('Z','')}</td>
            <td style="font-weight:700;">${l.client_name}</td>
            <td><span class="badge ${l.system_type === 'FINCH' ? 'badge-finch' : 'badge-harbor'}">${l.system_type}</span></td>
            <td><code style="color:var(--neon-cyan); font-weight:600;">${l.http_method} ${l.endpoint}</code></td>
            <td><span class="scope-tag">${l.matched_scope}</span></td>
            <td>${statusBadge}</td>
            <td>${redactedHtml}</td>
            <td>${indicatorHtml}</td>
        `;
        tbody.appendChild(tr);
    });
}
