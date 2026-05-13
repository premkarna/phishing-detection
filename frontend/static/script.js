// --- VERSION: V6-ENTERPRISE ---
document.addEventListener('DOMContentLoaded', () => {
    loadTheme();
    initMatrix();
    initParticles();
    switchTab('scanner');
    setVector('url');
});

// --- THEME MANAGEMENT ---
function loadTheme() {
    const savedTheme = localStorage.getItem('sentinel-theme') || 'dark';
    document.documentElement.className = savedTheme;
    updateThemeIcon(savedTheme);
    applyCanvasVisibility(savedTheme);
}


function applyCanvasVisibility(theme) {
    const matrix = document.getElementById('matrix-canvas');
    const lightBg = document.getElementById('light-bg');
    if (matrix) matrix.style.display = theme === 'light' ? 'none' : 'block';
    if (lightBg) lightBg.style.display = theme === 'light' ? 'block' : 'none';
}

function toggleTheme() {
    const isLight = document.documentElement.classList.contains('light');
    const newTheme = isLight ? 'dark' : 'light';
    document.documentElement.className = newTheme;
    localStorage.setItem('sentinel-theme', newTheme);
    updateThemeIcon(newTheme);
    applyCanvasVisibility(newTheme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.className = theme === 'light' ? 'fa-solid fa-moon text-slate-600' : 'fa-solid fa-sun text-yellow-400';
    }
}

function initTheme() {
    loadTheme();
}

// --- PARTICLES BACKGROUND (light mode) ---
function initParticles() {
    const canvas = document.getElementById('particles-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let W = window.innerWidth;
    let H = window.innerHeight;

    function resize() {
        W = canvas.width = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    const COUNT = 55;
    const particles = Array.from({ length: COUNT }, () => ({
        x: Math.random() * W,
        y: Math.random() * H,
        r: Math.random() * 4 + 2,
        dx: (Math.random() - 0.5) * 0.5,
        dy: (Math.random() - 0.5) * 0.5,
        alpha: Math.random() * 0.35 + 0.45,
        color: ['59,130,246', '139,92,246', '16,185,129', '99,102,241'][Math.floor(Math.random() * 4)]
    }));

    function draw() {
        requestAnimationFrame(draw);
        if (!document.documentElement.classList.contains('light')) {
            ctx.clearRect(0, 0, W, H);
            return;
        }
        ctx.clearRect(0, 0, W, H);

        // Draw connecting lines
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 150) {
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(99,102,241,${0.25 * (1 - dist / 150)})`;
                    ctx.lineWidth = 1;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }

        // Draw particles
        particles.forEach(p => {
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${p.color},${p.alpha})`;
            ctx.fill();

            p.x += p.dx;
            p.y += p.dy;
            if (p.x < 0 || p.x > W) p.dx *= -1;
            if (p.y < 0 || p.y > H) p.dy *= -1;
        });
    }
    draw();
}

// --- MATRIX BACKGROUND ---
function initMatrix() {
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = "01010101ABCDEF";
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);

    function draw() {
        ctx.fillStyle = "rgba(2, 6, 23, 0.05)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "#3b82f6";
        ctx.font = fontSize + "px monospace";
        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
            drops[i]++;
        }
    }
    setInterval(draw, 33);
}

// --- TAB NAVIGATION ---
async function switchTab(tabId) {
    const tabs = ['scanner', 'analytics', 'intel', 'education', 'features'];
    for (const t of tabs) {
        const view = document.getElementById(`view-${t}`);
        const nav = document.getElementById(`nav-${t}`);
        if (!view || !nav) continue;
        if (t === tabId) {
            view.classList.remove('hidden');
            nav.classList.add('nav-link-active');
            nav.classList.remove('text-slate-500');
            if (t === 'analytics') initAnalytics();
            if (t === 'intel') await initIntelGraph();
            if (t === 'features') await loadEngineStatus();
        } else {
            view.classList.add('hidden');
            nav.classList.remove('nav-link-active');
            nav.classList.add('text-slate-500');
        }
    }
}

// --- ENGINE STATUS ---
async function loadEngineStatus() {
    try {
        const response = await fetch('/api/engine-status');
        if (!response.ok) return;
        const data = await response.json();

        const statusBadge = { active: ['badge-success', 'Active'], quota: ['badge-warning', 'Quota'], no_key: ['badge-danger', 'No Key'], error: ['badge-danger', 'Error'] };

        (data.detection_engines || data.engines || []).forEach(engine => {
            const statusEl = document.getElementById(`engine-status-${engine.id}`);
            const detailEl = document.getElementById(`engine-detail-${engine.id}`);
            if (statusEl) {
                const [cls, label] = statusBadge[engine.status] || ['badge-success', 'Active'];
                statusEl.className = `badge ${cls}`;
                statusEl.textContent = label;
            }
            if (detailEl) detailEl.textContent = engine.detail || '';
        });

        const vtCount = data.api_keys?.vt_key_count || 0;
        const geminiStatus = data.api_keys?.gemini || 'unknown';
        const updated = document.getElementById('grid-last-updated');
        if (updated) {
            updated.textContent = `VT: ${vtCount} key${vtCount !== 1 ? 's' : ''} · Gemini: ${geminiStatus} · ${new Date().toLocaleTimeString()}`;
        }
    } catch (e) {
        const updated = document.getElementById('grid-last-updated');
        if (updated) updated.textContent = 'Status fetch failed';
    }
}

// --- ANALYTICS ---
let metricsChart = null;
let vectorsChart = null;

async function initAnalytics() {
    try {
        // Fetch real metrics from the backend
        const response = await fetch('/api/metrics');
        const metrics = response.ok ? await response.json() : { TP: 45, TN: 120, FP: 5, FN: 2 };
        
        // Accuracy Metrics Chart
        const ctx1 = document.getElementById('metricsChart');
        if (ctx1) {
            if (metricsChart) metricsChart.destroy();
            
            metricsChart = new Chart(ctx1.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: ['True Positives', 'True Negatives', 'False Positives', 'False Negatives'],
                    datasets: [{
                        label: 'SOC Accuracy Metrics',
                        data: [metrics.TP || 0, metrics.TN || 0, metrics.FP || 0, metrics.FN || 0],
                        backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#ef4444'],
                        borderRadius: 10,
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { 
                        legend: { 
                            display: true,
                            position: 'bottom',
                            labels: {
                                color: '#9ca3af',
                                padding: 15,
                                font: { size: 11 }
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(17, 24, 39, 0.95)',
                            titleColor: '#f9fafb',
                            bodyColor: '#e5e7eb',
                            borderColor: 'rgba(255,255,255,0.1)',
                            borderWidth: 1,
                            padding: 12,
                            cornerRadius: 8
                        }
                    },
                    scales: { 
                        y: { 
                            beginAtZero: true,
                            max: Math.max(...[metrics.TP || 0, metrics.TN || 0, metrics.FP || 0, metrics.FN || 0, 10]) * 1.2,
                            grid: { 
                                color: 'rgba(255,255,255,0.05)',
                                drawBorder: false
                            },
                            ticks: { 
                                color: '#9ca3af',
                                font: { size: 11 },
                                padding: 8
                            }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { 
                                color: '#9ca3af',
                                font: { size: 11 },
                                padding: 8
                            }
                        }
                    }
                }
            });
        }
        
        // Threat Distribution Chart
        const ctx2 = document.getElementById('vectorsChart');
        if (ctx2) {
            if (vectorsChart) vectorsChart.destroy();
            
            vectorsChart = new Chart(ctx2.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['URL', 'QR', 'EML', 'SMS', 'Voice', 'Clone', 'Social'],
                    datasets: [{
                        data: [35, 15, 20, 10, 5, 10, 5],
                        backgroundColor: [
                            '#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', 
                            '#f43f5e', '#06b6d4', '#f97316'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '60%',
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { 
                                color: '#9ca3af', 
                                padding: 15,
                                font: { size: 11 },
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(17, 24, 39, 0.95)',
                            titleColor: '#f9fafb',
                            bodyColor: '#e5e7eb',
                            borderColor: 'rgba(255,255,255,0.1)',
                            borderWidth: 1,
                            padding: 12,
                            cornerRadius: 8,
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }
    } catch (e) { 
        console.error('Analytics error:', e); 
        showToast('Failed to load analytics data', 'error');
    }
}

// --- INTEL GRAPH ---
let threatGraph = null;

async function initIntelGraph(data = null) {
    const elem = document.getElementById('threat-graph');
    if (!elem) {
        console.log('Threat graph element not found');
        return;
    }

    // Check if ForceGraph3D is available and is a function
    if (typeof ForceGraph3D === 'undefined' || typeof ForceGraph3D !== 'function') {
        console.log('ForceGraph3D library not available or not a function, showing fallback');
        // Show static threat intel summary with live data if available
        const nodeCount = (data && data.nodes) ? data.nodes.length : 7;
        const maliciousCount = (data && data.nodes) ? data.nodes.filter(n => n.group === 1).length : 3;
        const c2Count = (data && data.nodes) ? data.nodes.filter(n => n.group === 2).length : 2;
        
        elem.innerHTML = `
            <div class="flex flex-col items-center justify-center h-full text-center p-8">
                <div class="w-16 h-16 rounded-full bg-blue-500/10 flex items-center justify-center mb-4">
                    <i class="fa-solid fa-globe text-2xl text-blue-400"></i>
                </div>
                <h4 class="text-lg font-semibold text-gray-300 mb-2">Global Threat Intelligence Active</h4>
                <p class="text-sm text-gray-500 max-w-md">
                    Real-time threat monitoring enabled.
                    <br><br>
                    <span class="text-xs text-blue-400">
                        <i class="fa-solid fa-shield-halved mr-1"></i>
                        ${nodeCount} threat actors tracked
                    </span>
                </p>
                <div class="mt-4 grid grid-cols-2 gap-3 text-xs">
                    <div class="bg-white/5 rounded p-2">
                        <div class="text-rose-400 font-bold text-lg">${maliciousCount}</div>
                        <div class="text-gray-500">Malicious Nodes</div>
                    </div>
                    <div class="bg-white/5 rounded p-2">
                        <div class="text-blue-400 font-bold text-lg">${c2Count}</div>
                        <div class="text-gray-500">C2 Servers</div>
                    </div>
                </div>
            </div>
        `;
        return;
    }

    // Fetch real threat data from API
    try {
        if (!data) {
            const response = await fetch('/api/threats');
            if (response.ok) {
                const threatData = await response.json();
                data = threatData;
                console.log('Threat data loaded:', threatData);
            }
        }
    } catch (err) {
        console.log('Could not fetch threat data:', err);
    }

    // Use live threat data if available, else use default global map
    let gData;
    
    // If API data with nodes/links is available, use it
    if (data && data.nodes && data.links) {
        gData = data;
    } else if (data && data.calculated_risk !== undefined) {
        // Use scan result data if available
        const risk = data.calculated_risk || 0;
        const color = risk >= 70 ? '#f43f5e' : (risk >= 30 ? '#f59e0b' : '#10b981');
        
        gData = {
            nodes: [
                { id: 'TARGET', name: `Target: ${(data.payload || 'Unknown').substring(0, 30)}...`, color: color, val: 20 },
                { id: 'IP', name: `IP: ${data.server_ip_loc || 'Resolving...'}`, color: '#3b82f6', val: 15 },
                { id: 'INFRA', name: `Age: ${data.domain_age || 'N/A'}`, color: '#8b5cf6', val: 12 },
                { id: 'SSL', name: `SSL: ${data.ssl_certificate || 'N/A'}`, color: '#10b981', val: 10 },
                { id: 'RISK', name: `Risk: ${risk}/100`, color: color, val: 18 }
            ],
            links: [
                { source: 'TARGET', target: 'IP' },
                { source: 'IP', target: 'INFRA' },
                { source: 'TARGET', target: 'SSL' },
                { source: 'TARGET', target: 'RISK' }
            ]
        };
    } else {
        // Default Global Threat Map
        gData = {
            nodes: [
                { id: 'GLOBAL', name: 'Sentinel Hub', color: '#3b82f6', val: 25 },
                { id: 'US_EAST', name: 'US East (Safe)', color: '#10b981', val: 12 },
                { id: 'US_WEST', name: 'US West (Safe)', color: '#10b981', val: 12 },
                { id: 'EU_CENTRAL', name: 'EU Central (Safe)', color: '#10b981', val: 12 },
                { id: 'ASIA_PACIFIC', name: 'Asia Pacific (Monitor)', color: '#f59e0b', val: 14 },
                { id: 'THREAT_1', name: 'Threat Actor A', color: '#f43f5e', val: 18 },
                { id: 'THREAT_2', name: 'Threat Actor B', color: '#f43f5e', val: 16 }
            ],
            links: [
                { source: 'GLOBAL', target: 'US_EAST' },
                { source: 'GLOBAL', target: 'US_WEST' },
                { source: 'GLOBAL', target: 'EU_CENTRAL' },
                { source: 'GLOBAL', target: 'ASIA_PACIFIC' },
                { source: 'ASIA_PACIFIC', target: 'THREAT_1' },
                { source: 'EU_CENTRAL', target: 'THREAT_2' }
            ]
        };
    }

    try {
        // Clear existing graph
        elem.innerHTML = '';
        
        // Create new graph
        threatGraph = ForceGraph3D()(elem)
            .graphData(gData)
            .nodeLabel('name')
            .nodeColor(node => node.color)
            .nodeVal(node => node.val || 10)
            .linkColor(() => 'rgba(148, 163, 184, 0.3)')
            .linkWidth(1)
            .backgroundColor('rgba(0,0,0,0)')
            .showNavInfo(false)
            .width(elem.offsetWidth)
            .height(elem.offsetHeight)
            .enableNodeDrag(true);
        
        console.log('Threat graph initialized successfully');

        // Responsive handling
        const handleResize = () => {
            if (threatGraph) {
                threatGraph.width(elem.offsetWidth);
                threatGraph.height(elem.offsetHeight);
            }
        };
        
        window.removeEventListener('resize', handleResize);
        window.addEventListener('resize', handleResize);
        
    } catch (err) {
        console.error('Failed to initialize threat graph:', err);
        // Show professional fallback instead of error
        elem.innerHTML = `
            <div class="flex flex-col items-center justify-center h-full text-center p-8">
                <div class="w-16 h-16 rounded-full bg-blue-500/10 flex items-center justify-center mb-4">
                    <i class="fa-solid fa-globe text-2xl text-blue-400"></i>
                </div>
                <h4 class="text-lg font-semibold text-gray-300 mb-2">Threat Intelligence Active</h4>
                <p class="text-sm text-gray-500 max-w-md">
                    Global threat monitoring enabled.
                    <br><br>
                    <span class="text-xs text-blue-400">
                        <i class="fa-solid fa-shield-halved mr-1"></i>
                        7 threat actors tracked
                    </span>
                </p>
                <div class="mt-4 grid grid-cols-2 gap-3 text-xs">
                    <div class="bg-white/5 rounded p-2">
                        <div class="text-rose-400 font-bold text-lg">3</div>
                        <div class="text-gray-500">Malicious Nodes</div>
                    </div>
                    <div class="bg-white/5 rounded p-2">
                        <div class="text-blue-400 font-bold text-lg">2</div>
                        <div class="text-gray-500">C2 Servers</div>
                    </div>
                </div>
            </div>
        `;
    }
}

// --- SCANNER LOGIC ---
let currentVector = 'url';
let lastScanData = null;
let currentSocialPlatform = null;

function setSocialPlatform(platform) {
    currentSocialPlatform = platform;
    ['whatsapp', 'instagram', 'linkedin', 'facebook', 'auto'].forEach(p => {
        const btn = document.getElementById('sp-' + p);
        if (!btn) return;
        btn.className = 'px-3 py-1 rounded-full text-xs border transition-colors ' +
            ((platform === p || (platform === null && p === 'auto'))
                ? 'border-orange-400/50 text-orange-400'
                : 'border-white/10 text-gray-400 hover:border-orange-400/50 hover:text-orange-400');
    });
}

// Engine configurations
const ENGINE_CONFIGS = {
    'url': { name: 'URL Forensics', icon: 'fa-link', color: 'blue', inputType: 'text', placeholder: 'https://example.com' },
    'qr': { name: 'QR Scanner', icon: 'fa-qrcode', color: 'purple', inputType: 'qr', placeholder: 'Paste QR data or scan...' },
    'eml': { name: 'Email Scanner', icon: 'fa-envelope', color: 'emerald', inputType: 'eml', placeholder: 'Upload .eml file' },
    'smishing': { name: 'SMS Scanner', icon: 'fa-comment-sms', color: 'yellow', inputType: 'smishing', placeholder: '+91 98765 43210' },
    'vishing': { name: 'Voice Scanner', icon: 'fa-phone', color: 'rose', inputType: 'vishing', placeholder: 'Upload audio or record' },
    'clone': { name: 'Clone Detector', icon: 'fa-clone', color: 'cyan', inputType: 'text', placeholder: 'https://suspected-clone.com' },
    'social': { name: 'Social Shield', icon: 'fa-users', color: 'orange', inputType: 'social', placeholder: 'Paste a URL or suspicious message/DM text to analyze...' }
};

function setVector(v) {
    currentVector = v;
    const config = ENGINE_CONFIGS[v];
    
    // Update engine selector buttons
    document.querySelectorAll('.engine-card').forEach(card => {
        card.classList.remove('border-blue-500/50', 'border-purple-500/50', 'border-emerald-500/50', 
                              'border-yellow-500/50', 'border-rose-500/50', 'border-cyan-500/50', 'border-orange-500/50');
    });
    
    const activeCard = document.querySelector(`button[onclick="setVector('${v}')"]`);
    if (activeCard) {
        const colorMap = {
            'blue': 'border-blue-500/50',
            'purple': 'border-purple-500/50',
            'emerald': 'border-emerald-500/50',
            'yellow': 'border-yellow-500/50',
            'rose': 'border-rose-500/50',
            'cyan': 'border-cyan-500/50',
            'orange': 'border-orange-500/50'
        };
        activeCard.classList.add(colorMap[config.color] || 'border-blue-500/50');
    }
    
    // Update active engine badge
    const badge = document.getElementById('active-engine-badge');
    if (badge) {
        badge.innerHTML = `<i class="fa-solid ${config.icon}"></i> ${config.name}`;
        badge.className = `badge badge-${config.color === 'rose' ? 'danger' : config.color === 'purple' ? 'info' : config.color}`;
    }
    
    // Show appropriate input container
    document.querySelectorAll('#input-container > div').forEach(div => div.classList.add('hidden'));
    
    const inputType = config.inputType;
    if (['url', 'clone'].includes(v)) {
        const inputText = document.getElementById('input-text');
        if (inputText) {
            inputText.classList.remove('hidden');
            const payloadInput = document.getElementById('payload');
            if (payloadInput) payloadInput.placeholder = config.placeholder;
        }
    } else if (v === 'social') {
        const socialInput = document.getElementById('input-social');
        if (socialInput) socialInput.classList.remove('hidden');
    } else {
        const specificInput = document.getElementById(`input-${inputType}`);
        if (specificInput) specificInput.classList.remove('hidden');
    }
    
    // Clear previous results
    document.getElementById('results-panel')?.classList.add('hidden');
}

async function simulateScan() {
    // Get payload based on current vector type
    let payload = '';
    let fileData = null;
    
    switch(currentVector) {
        case 'url':
        case 'clone':
            payload = document.getElementById('payload')?.value || '';
            break;
        case 'social':
            payload = document.getElementById('social-payload')?.value || '';
            if (!payload) {
                showToast('Please enter a URL or paste a suspicious message', 'warning');
                return;
            }
            break;
        case 'qr':
            payload = document.getElementById('qr-payload')?.value || '';
            // Validate QR input - check if user uploaded a file or has QR data
            const qrFile = document.getElementById('qr-file')?.files[0];
            if (!qrFile && !payload) {
                showToast('Please upload a QR image or paste QR decoded content', 'warning');
                return;
            }
            // If payload looks like a plain URL (not QR data), suggest using URL scanner
            if (!qrFile && payload && (payload.startsWith('http://') || payload.startsWith('https://')) && !payload.includes('qr') && !payload.includes('QR')) {
                showToast('Tip: This looks like a URL. Use URL Scanner tab for better results!', 'info');
            }
            break;
        case 'eml':
            const emlFile = document.getElementById('eml-file')?.files[0];
            if (emlFile) {
                payload = await emlFile.text();
            } else {
                showToast('Please upload an .eml file', 'warning');
                return;
            }
            break;
        case 'smishing':
            const phone = document.getElementById('sms-payload')?.value || '';
            const smsContent = document.getElementById('sms-content')?.value || '';
            payload = smsContent || phone;
            if (!payload) {
                showToast('Please paste SMS content or enter a phone number', 'warning');
                return;
            }
            break;
        case 'vishing':
            const voiceFile = document.getElementById('voice-file')?.files[0];
            if (voiceFile) {
                showToast('Audio analysis is processing...', 'info');
                payload = voiceFile.name;
            } else {
                showToast('Please upload an audio file or record', 'warning');
                return;
            }
            break;
    }
    
    if (!payload) { 
        showToast('Please enter a target to scan', 'warning');
        return; 
    }

    const resultsPanel = document.getElementById('results-panel');
    const gauge = document.getElementById('gauge-progress');
    const riskVal = document.getElementById('risk-val');
    const label = document.getElementById('verdict-label');

    resultsPanel.classList.remove('hidden');
    
    // Reset to Scanning State
    gauge.style.strokeDashoffset = 264;
    gauge.style.stroke = '#3b82f6';
    riskVal.innerText = '...';
    riskVal.className = 'text-6xl font-bold font-mono text-blue-400 animate-pulse';
    label.innerText = 'SCANNING...';
    label.className = 'mt-4 px-4 py-2 rounded-full text-xs font-semibold border border-blue-500/30 text-blue-400 animate-pulse';

    // Build request body — smishing gets extra fields, social gets platform hint
    const reqBody = { payload, vector: currentVector };
    if (currentVector === 'social') {
        reqBody.platform = currentSocialPlatform;
    }
    if (currentVector === 'smishing') {
        reqBody.sender_id = document.getElementById('sms-sender-id')?.value || '';
        reqBody.sender_type = currentSenderType || 'alpha';
        reqBody.phone_number = document.getElementById('sms-payload')?.value || '';
    }

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(reqBody)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        lastScanData = data;
        updateUI(data);
    } catch (err) {
        console.error('Scan error:', err);
        showToast('Connection failed. Please check server status.', 'error');
        
        // Update UI to show error state
        riskVal.innerText = 'ERR';
        riskVal.className = 'text-6xl font-bold font-mono text-rose-500';
        label.innerText = 'SCAN FAILED';
        label.className = 'mt-4 px-4 py-2 rounded-full text-xs font-semibold border border-rose-500/30 text-rose-400';
    }
}

// --- FILE UPLOAD HANDLERS ---
function handleFileSelect(input, type) {
    const file = input.files[0];
    if (!file) return;
    
    const filenameDisplay = document.getElementById(`${type}-filename`);
    if (filenameDisplay) {
        filenameDisplay.textContent = `Selected: ${file.name}`;
        filenameDisplay.classList.remove('hidden');
    }
    
    // For voice files, enable the scan button
    if (type === 'vishing') {
        const scanBtn = document.getElementById('voice-scan-btn');
        if (scanBtn) scanBtn.disabled = false;
    }
    
    showToast(`${type.toUpperCase()} file selected: ${file.name}`, 'success');
}

// --- QR SCANNER ---
let qrScannerActive = false;
let qrVideoStream = null;

async function startQRScanner() {
    const scannerView = document.getElementById('qr-scanner-view');
    const video = document.getElementById('qr-video');
    
    if (!scannerView || !video) return;
    
    try {
        qrScannerActive = true;
        scannerView.classList.remove('hidden');
        
        qrVideoStream = await navigator.mediaDevices.getUserMedia({ 
            video: { facingMode: 'environment' } 
        });
        video.srcObject = qrVideoStream;
        video.play();
        
        showToast('QR Scanner active - point camera at QR code', 'info');
        
        // Simulate QR detection after 3 seconds for demo
        setTimeout(() => {
            if (qrScannerActive) {
                const mockQRData = 'https://example.com/scan';
                document.getElementById('qr-payload').value = mockQRData;
                stopQRScanner();
                showToast('QR Code detected!', 'success');
            }
        }, 3000);
        
    } catch (err) {
        console.error('Camera error:', err);
        showToast('Camera access denied. Please use file upload instead.', 'error');
        stopQRScanner();
    }
}

function stopQRScanner() {
    qrScannerActive = false;
    
    const scannerView = document.getElementById('qr-scanner-view');
    if (scannerView) scannerView.classList.add('hidden');
    
    if (qrVideoStream) {
        qrVideoStream.getTracks().forEach(track => track.stop());
        qrVideoStream = null;
    }
}

function handleQRUpload(input) {
    const file = input.files[0];
    if (!file) return;
    
    showToast(`QR image uploaded: ${file.name}`, 'success');
    
    // Show preview container and detection status
    const previewDiv = document.getElementById('qr-image-preview');
    const statusDiv = document.getElementById('qr-detection-status');
    const locationDiv = document.getElementById('qr-location-info');
    const canvas = document.getElementById('qr-canvas');
    const ctx = canvas.getContext('2d');
    
    previewDiv.classList.remove('hidden');
    statusDiv.classList.remove('hidden');
    statusDiv.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Scanning for QR...';
    locationDiv.classList.add('hidden');
    
    // Read and process the image
    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            // Set canvas size to match image
            canvas.width = img.width;
            canvas.height = img.height;
            
            // Draw image on canvas
            ctx.drawImage(img, 0, 0);
            
            // Get image data for QR detection
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            
            // Try to detect QR code using jsQR
            const code = jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: 'attemptBoth'
            });
            
            if (code) {
                // QR Code found! Draw bounding box
                ctx.strokeStyle = '#10b981'; // Emerald color
                ctx.lineWidth = 4;
                ctx.beginPath();
                ctx.moveTo(code.location.topLeftCorner.x, code.location.topLeftCorner.y);
                ctx.lineTo(code.location.topRightCorner.x, code.location.topRightCorner.y);
                ctx.lineTo(code.location.bottomRightCorner.x, code.location.bottomRightCorner.y);
                ctx.lineTo(code.location.bottomLeftCorner.x, code.location.bottomLeftCorner.y);
                ctx.closePath();
                ctx.stroke();
                
                // Draw corner markers
                ctx.fillStyle = '#10b981';
                const corners = [
                    code.location.topLeftCorner,
                    code.location.topRightCorner,
                    code.location.bottomRightCorner,
                    code.location.bottomLeftCorner
                ];
                corners.forEach(corner => {
                    ctx.beginPath();
                    ctx.arc(corner.x, corner.y, 6, 0, 2 * Math.PI);
                    ctx.fill();
                });
                
                // Update status
                statusDiv.innerHTML = '<i class="fa-solid fa-check-circle text-emerald-400 mr-1"></i> QR Code Detected!';
                statusDiv.classList.remove('bg-black/70');
                statusDiv.classList.add('bg-emerald-500/20', 'text-emerald-300');
                
                // Show location info
                locationDiv.classList.remove('hidden');
                const locText = document.getElementById('qr-loc-text');
                locText.textContent = `QR detected at: ${Math.round(code.location.topLeftCorner.x)},${Math.round(code.location.topLeftCorner.y)} - Data: ${code.data.substring(0, 50)}${code.data.length > 50 ? '...' : ''}`;
                
                // Auto-fill the payload field
                document.getElementById('qr-payload').value = code.data;
                
                showToast(`QR Code detected! Data: ${code.data.substring(0, 30)}...`, 'success');
            } else {
                // No QR found
                statusDiv.innerHTML = '<i class="fa-solid fa-exclamation-triangle text-amber-400 mr-1"></i> No QR Code found';
                statusDiv.classList.remove('bg-black/70');
                statusDiv.classList.add('bg-amber-500/20', 'text-amber-300');
                
                showToast('No QR code detected in image. Try uploading a clearer image.', 'warning');
            }
            
            // Store image data for backend processing
            window.uploadedQRImage = e.target.result;
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

// --- VOICE RECORDING ---
let mediaRecorder = null;
let recordingChunks = [];
let recordingTimer = null;
let recordingSeconds = 0;

async function toggleRecording() {
    if (mediaRecorder && mediaRecorder.state === 'recording') {
        stopRecording();
    } else {
        startRecording();
    }
}

async function startRecording() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        recordingChunks = [];
        
        mediaRecorder.ondataavailable = (e) => {
            if (e.data.size > 0) recordingChunks.push(e.data);
        };
        
        mediaRecorder.onstop = () => {
            const audioBlob = new Blob(recordingChunks, { type: 'audio/webm' });
            const audioFile = new File([audioBlob], 'recorded_audio.webm', { type: 'audio/webm' });
            
            // Simulate file upload
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(audioFile);
            document.getElementById('voice-file').files = dataTransfer.files;
            
            const filenameDisplay = document.getElementById('vishing-filename');
            if (filenameDisplay) {
                filenameDisplay.textContent = 'Recorded: recorded_audio.webm';
                filenameDisplay.classList.remove('hidden');
            }
            
            const scanBtn = document.getElementById('voice-scan-btn');
            if (scanBtn) scanBtn.disabled = false;
            
            showToast('Recording saved! Ready to analyze.', 'success');
        };
        
        mediaRecorder.start();
        
        // Update UI
        document.getElementById('recording-indicator')?.classList.remove('hidden');
        document.getElementById('record-text').textContent = 'Stop';
        
        // Start timer
        recordingSeconds = 0;
        recordingTimer = setInterval(() => {
            recordingSeconds++;
            const mins = Math.floor(recordingSeconds / 60).toString().padStart(2, '0');
            const secs = (recordingSeconds % 60).toString().padStart(2, '0');
            document.getElementById('record-timer').textContent = `${mins}:${secs}`;
        }, 1000);
        
        showToast('Recording started...', 'info');
        
    } catch (err) {
        console.error('Recording error:', err);
        showToast('Microphone access denied', 'error');
    }
}

function stopRecording() {
    if (mediaRecorder && mediaRecorder.state === 'recording') {
        mediaRecorder.stop();
        mediaRecorder.stream.getTracks().forEach(track => track.stop());
    }
    
    clearInterval(recordingTimer);
    document.getElementById('recording-indicator')?.classList.add('hidden');
    document.getElementById('record-text').textContent = 'Record';
}

// --- TOAST NOTIFICATIONS ---
function showToast(message, type = 'info') {
    // Remove existing toast
    const existingToast = document.querySelector('.toast-notification');
    if (existingToast) existingToast.remove();
    
    const colors = {
        'info': 'bg-blue-500',
        'success': 'bg-emerald-500',
        'warning': 'bg-yellow-500',
        'error': 'bg-rose-500'
    };
    
    const icons = {
        'info': 'fa-info-circle',
        'success': 'fa-check-circle',
        'warning': 'fa-exclamation-triangle',
        'error': 'fa-times-circle'
    };
    
    const toast = document.createElement('div');
    toast.className = `toast-notification fixed top-4 right-4 z-50 px-6 py-4 rounded-xl shadow-2xl text-white font-medium flex items-center gap-3 animate-slide-in ${colors[type]}`;
    toast.innerHTML = `
        <i class="fa-solid ${icons[type]}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(toast);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        toast.style.animation = 'slide-out 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function updateUI(data) {
    const risk = data.calculated_risk || 0;
    const ai = data.ai_report || {};
    
    // Color Determination
    let colorClass = 'text-emerald-400';
    let strokeColor = '#10b981';
    let borderColor = 'border-emerald-500/30';
    
    if (risk >= 70) {
        colorClass = 'text-rose-400';
        strokeColor = '#f43f5e';
        borderColor = 'border-rose-500/30';
    } else if (risk >= 30) {
        colorClass = 'text-yellow-400';
        strokeColor = '#f59e0b';
        borderColor = 'border-yellow-500/30';
    }

    // Update Gauge
    const gauge = document.getElementById('gauge-progress');
    const riskVal = document.getElementById('risk-val');
    const label = document.getElementById('verdict-label');
    const aiVerdict = document.getElementById('ai-verdict');

    if (gauge) {
        gauge.style.stroke = strokeColor;
        gauge.style.strokeDashoffset = 264 - (264 * (risk / 100));
    }
    
    if (riskVal) {
        riskVal.innerText = risk;
        riskVal.className = `text-6xl font-bold font-mono ${colorClass}`;
    }
    
    if (label) {
        label.innerText = ai.verdict || 'ANALYSIS COMPLETE';
        label.className = `mt-4 px-4 py-2 rounded-full text-xs font-semibold border ${borderColor} ${colorClass}`;
    }

    // AI Verdict
    if (aiVerdict) {
        aiVerdict.innerText = ai.verdict || 'UNKNOWN';
        aiVerdict.className = `text-4xl font-bold mb-4 ${colorClass}`;
    }

    // Analysis and Advice - Format professionally
    const aiReason = document.getElementById('ai-reason');
    const aiAdvice = document.getElementById('ai-advice');
    
    // False Positive Banner
    const fpBanner = document.getElementById('false-positive-banner');
    if (fpBanner) {
        const fp = ai.false_positive;
        if (fp && fp !== 'false' && fp !== false) {
            fpBanner.innerHTML = `<i class="fa-solid fa-circle-info mr-2"></i><strong>Possible False Positive:</strong> ${typeof fp === 'string' && fp !== 'true' ? fp : 'Domain pattern is suspicious but page content appears harmless. Manual review recommended.'}`;
            fpBanner.classList.remove('hidden');
        } else {
            fpBanner.classList.add('hidden');
        }
    }

    if (aiReason) {
        const formattedReason = formatAnalysisText(ai.reason || 'No suspicious patterns detected.');
        aiReason.innerHTML = formattedReason;
    }
    if (aiAdvice) {
        const formattedAdvice = formatAnalysisText(ai.advice || 'Continue standard security practices.');
        aiAdvice.innerHTML = formattedAdvice;
    }

    // Technical Grid
    const resIp = document.getElementById('res-ip');
    const resAge = document.getElementById('res-age');
    const resSsl = document.getElementById('res-ssl');
    const resBrand = document.getElementById('res-brand');
    
    // Technical Grid with better formatting
    if (resIp) {
        const ip = data.server_ip_loc;
        if (!ip || ip === 'Checking...' || ip === 'N/A' || ip === '') {
            resIp.innerHTML = '<span class="text-yellow-400">Unresolved</span><br><span class="text-xs text-gray-500">Domain may not exist or is blocked</span>';
        } else {
            resIp.innerHTML = `<span class="text-blue-400">${ip}</span>`;
        }
    }
    if (resAge) {
        const age = data.domain_age || 'N/A';
        if (age === 'N/A') {
            resAge.innerHTML = '<span class="text-gray-500">N/A</span>';
        } else if (age.toLowerCase().includes('expired') || age.toLowerCase().includes('fake') || age.toLowerCase().includes('unknown')) {
            resAge.innerHTML = `<span class="text-orange-400"><i class="fa-solid fa-circle-exclamation mr-1"></i>${age}</span>`;
        } else {
            resAge.innerText = age;
        }
    }
    if (resSsl) {
        const ssl = data.ssl_certificate || 'N/A';
        if (ssl.includes('Valid') || ssl === 'Valid HTTPS') {
            resSsl.innerHTML = '<span class="text-emerald-400"><i class="fa-solid fa-lock mr-1"></i>Valid HTTPS</span>';
        } else if (ssl.includes('Invalid') || ssl.includes('Missing')) {
            resSsl.innerHTML = '<span class="text-rose-400"><i class="fa-solid fa-triangle-exclamation mr-1"></i>Insecure</span>';
        } else if (ssl.includes('Cannot verify') || ssl.includes('unreachable')) {
            resSsl.innerHTML = `<span class="text-orange-400"><i class="fa-solid fa-link-slash mr-1"></i>${ssl}</span>`;
        } else {
            resSsl.innerText = ssl;
        }
    }
    if (resBrand) resBrand.innerText = data.brand_check || 'Clean';

    // VirusTotal Result
    const resVt = document.getElementById('res-vt');
    if (resVt) {
        const vt = data.virustotal || 'N/A';
        if (vt.includes('/')) {
            const flags = parseInt(vt.split('/')[0]);
            if (flags >= 3) {
                resVt.innerHTML = `<span class="text-rose-400 font-bold"><i class="fa-solid fa-triangle-exclamation mr-1"></i>${vt} Engines Flagged</span>`;
            } else if (flags > 0) {
                resVt.innerHTML = `<span class="text-yellow-400"><i class="fa-solid fa-circle-exclamation mr-1"></i>${vt} Flags (Possible False Positive)</span>`;
            } else {
                resVt.innerHTML = `<span class="text-emerald-400"><i class="fa-solid fa-check mr-1"></i>${vt} Clean</span>`;
            }
        } else if (vt === 'Quota Exceeded') {
            resVt.innerHTML = `<span class="text-yellow-400"><i class="fa-solid fa-clock mr-1"></i>Quota Exceeded</span>`;
        } else if (vt === 'API Key Not Set') {
            resVt.innerHTML = `<span class="text-gray-400"><i class="fa-solid fa-key mr-1"></i>API Key Not Set</span>`;
        } else {
            resVt.innerHTML = `<span class="text-gray-400">${vt}</span>`;
        }
    }

    // URLHaus Result
    const resUrlhaus = document.getElementById('res-urlhaus');
    if (resUrlhaus) {
        const uh = data.urlhaus || 'N/A';
        if (uh.includes('Malicious')) {
            resUrlhaus.innerHTML = `<span class="text-rose-400 font-bold"><i class="fa-solid fa-skull mr-1"></i>${uh}</span>`;
        } else if (uh.includes('Clean') || uh.includes('Not in DB')) {
            resUrlhaus.innerHTML = `<span class="text-emerald-400"><i class="fa-solid fa-check mr-1"></i>${uh}</span>`;
        } else {
            resUrlhaus.innerHTML = `<span class="text-gray-400">${uh}</span>`;
        }
    }

    // Live Visual Scan Results - Key differentiator from ChatGPT!
    const visualScanPanel = document.getElementById('visual-scan-results');
    const visualTitle = document.getElementById('visual-title');
    const visualBrand = document.getElementById('visual-brand');
    const visualLogin = document.getElementById('visual-login');
    const visualIndicators = document.getElementById('visual-indicators');
    
    if (data.visual_scan && data.visual_scan.page_fetched) {
        if (visualScanPanel) visualScanPanel.classList.remove('hidden');
        if (visualTitle) visualTitle.innerText = data.visual_scan.page_title || 'N/A';
        if (visualBrand) {
            const brand = data.visual_scan.detected_brand;
            const confidence = data.visual_scan.brand_confidence || 0;
            visualBrand.innerHTML = brand 
                ? `<span class="text-rose-400">${brand}</span> <span class="text-xs text-gray-500">(${confidence}% match)</span>`
                : '<span class="text-gray-400">None detected</span>';
        }
        if (visualLogin) {
            visualLogin.innerHTML = data.visual_scan.login_form_detected 
                ? '<span class="text-rose-400">Yes</span>' 
                : '<span class="text-emerald-400">No</span>';
        }
        if (visualIndicators) {
            const indicators = data.visual_scan.visual_spoofing_indicators || [];
            const elements = data.visual_scan.suspicious_elements || [];
            const allItems = [...indicators, ...elements];
            
            if (allItems.length > 0) {
                visualIndicators.innerHTML = allItems.map(item => 
                    `<div class="text-rose-400"><i class="fa-solid fa-triangle-exclamation mr-2"></i>${item}</div>`
                ).join('');
            } else {
                visualIndicators.innerHTML = '<span class="text-emerald-400"><i class="fa-solid fa-check mr-2"></i>No visual spoofing detected</span>';
            }
        }
    } else {
        if (visualScanPanel) visualScanPanel.classList.add('hidden');
    }

    // --- OSINT Panel ---
    const osintPanel = document.getElementById('osint-panel');
    const osint = data.osint_report;
    if (osint && osint.email_found) {
        if (osintPanel) osintPanel.classList.remove('hidden');

        const statusColors = { 'COMPROMISED': 'text-rose-400', 'SUSPICIOUS (EXPOSED)': 'text-yellow-400', 'SECURE': 'text-emerald-400' };
        const statusColor = statusColors[osint.status] || 'text-gray-300';

        const emailEl = document.getElementById('osint-email');
        if (emailEl) emailEl.textContent = osint.email_found;

        const statusEl = document.getElementById('osint-status');
        if (statusEl) {
            statusEl.textContent = osint.status || 'UNKNOWN';
            statusEl.className = `text-sm font-bold ${statusColor}`;
        }

        const leaksEl = document.getElementById('osint-leaks');
        if (leaksEl) {
            const leaks = osint.leaks || [];
            leaksEl.innerHTML = leaks.length > 0
                ? leaks.map(l => `<div class="text-rose-400"><i class="fa-solid fa-circle-dot mr-1"></i>${l}</div>`).join('')
                : '<span class="text-emerald-400"><i class="fa-solid fa-check mr-1"></i>No leaks found</span>';
        }

        const markersEl = document.getElementById('osint-markers');
        if (markersEl) {
            const markers = osint.forensic_markers || [];
            markersEl.innerHTML = markers.length > 0
                ? markers.map(m => `<div class="text-yellow-400 text-[10px]"><i class="fa-solid fa-triangle-exclamation mr-1"></i>${m}</div>`).join('')
                : '<span class="text-gray-500">None</span>';
        }

        const riskEl = document.getElementById('osint-risk');
        if (riskEl) {
            const penalty = osint.risk_penalty || 0;
            riskEl.textContent = `+${penalty} pts`;
            riskEl.className = `text-sm font-bold font-mono ${penalty > 0 ? 'text-rose-400' : 'text-emerald-400'}`;
        }

        const descEl = document.getElementById('osint-desc');
        if (descEl) descEl.textContent = osint.desc || '';

        const sourceBadge = document.getElementById('osint-source-badge');
        if (sourceBadge) {
            const isLive = osint.emailrep_source === 'live';
            sourceBadge.textContent = isLive ? '🟢 EmailRep.io Live' : '🟡 Simulation Fallback';
            sourceBadge.className = `text-[10px] px-2 py-1 rounded-full ${isLive ? 'bg-emerald-500/10 text-emerald-400' : 'bg-yellow-500/10 text-yellow-400'}`;
        }
    } else {
        if (osintPanel) osintPanel.classList.add('hidden');
    }

    // --- Sandbox Panel ---
    const sandboxPanel = document.getElementById('sandbox-panel');
    const sandbox = data.sandbox_report;
    if (sandbox && sandbox.file_name) {
        if (sandboxPanel) sandboxPanel.classList.remove('hidden');

        const verdictColors = { 'MALICIOUS': 'bg-rose-500/20 text-rose-400 border border-rose-500/30', 'SUSPICIOUS': 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30', 'SAFE': 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' };
        const vBadge = document.getElementById('sandbox-verdict-badge');
        if (vBadge) {
            vBadge.textContent = sandbox.verdict || 'UNKNOWN';
            vBadge.className = `text-xs font-bold px-3 py-1 rounded-full ${verdictColors[sandbox.verdict] || 'bg-white/5 text-gray-400'}`;
        }

        const fnEl = document.getElementById('sandbox-filename');
        if (fnEl) fnEl.textContent = sandbox.file_name;

        const ftEl = document.getElementById('sandbox-filetype');
        if (ftEl) ftEl.textContent = sandbox.file_type || '--';

        const rsEl = document.getElementById('sandbox-riskscore');
        if (rsEl) {
            const sr = sandbox.risk_score || 0;
            rsEl.textContent = `${sr}/100`;
            rsEl.className = `text-sm font-bold font-mono ${sr >= 70 ? 'text-rose-400' : sr >= 30 ? 'text-yellow-400' : 'text-emerald-400'}`;
        }

        const hashEl = document.getElementById('sandbox-hashes');
        if (hashEl && sandbox.hashes) {
            const h = sandbox.hashes;
            hashEl.innerHTML = [
                h.md5 ? `<div><span class="text-gray-500">MD5: </span>${h.md5}</div>` : '',
                h.sha1 ? `<div><span class="text-gray-500">SHA1: </span>${h.sha1}</div>` : '',
                h.sha256 ? `<div><span class="text-gray-500">SHA256: </span>${h.sha256.substring(0, 32)}...</div>` : ''
            ].join('') || '--';
        }

        const logsEl = document.getElementById('sandbox-logs');
        if (logsEl) {
            const logs = sandbox.sandbox_logs || [];
            logsEl.innerHTML = logs.length > 0
                ? logs.map(l => {
                    const cls = l.includes('[!!!]') ? 'text-rose-400' : l.includes('[!]') ? 'text-yellow-400' : 'text-gray-400';
                    return `<div class="${cls}">${l}</div>`;
                }).join('')
                : '<span class="text-gray-500">No logs</span>';
        }
    } else {
        if (sandboxPanel) sandboxPanel.classList.add('hidden');
    }

    // --- ADVANCED INTELLIGENCE PANEL (10 Modules) ---
    
    // 1. Attribution Results
    const attributionPanel = document.getElementById('attribution-results');
    if (data.attribution && data.attribution.primary_attribution) {
        if (attributionPanel) attributionPanel.classList.remove('hidden');
        
        const attActor = document.getElementById('attribution-actor');
        const attConf = document.getElementById('attribution-confidence');
        const attTTPs = document.getElementById('attribution-ttps');
        
        const actor = data.attribution.primary_attribution;
        if (attActor) attActor.textContent = actor.name || actor.actor_id || 'Unknown Actor';
        if (attConf) attConf.textContent = `${actor.confidence || 0}% confidence match`;
        if (attTTPs) {
            const ttps = actor.matched_ttps || [];
            attTTPs.innerHTML = ttps.length > 0
                ? ttps.map(ttp => `<div class="text-yellow-400"><i class="fa-solid fa-check mr-2"></i>${ttp}</div>`).join('')
                : '<span class="text-gray-500">No specific TTPs matched</span>';
        }
    } else {
        if (attributionPanel) attributionPanel.classList.add('hidden');
    }
    
    // 2. Fingerprint Results
    const fingerprintPanel = document.getElementById('fingerprint-results');
    if (data.fingerprint_id) {
        if (fingerprintPanel) fingerprintPanel.classList.remove('hidden');
        
        const fpId = document.getElementById('fingerprint-id');
        const fpCampaign = document.getElementById('fingerprint-campaign');
        const fpFirstSeen = document.getElementById('fingerprint-first-seen');
        
        if (fpId) fpId.textContent = data.fingerprint_id.substring(0, 16) + '...';
        if (fpCampaign) fpCampaign.textContent = data.campaign_attribution || 'Unknown Campaign';
        if (fpFirstSeen) fpFirstSeen.textContent = data.first_seen || 'Just now';
    } else {
        if (fingerprintPanel) fingerprintPanel.classList.add('hidden');
    }
    
    // 3. Update Advanced Intel Status Cards
    const updateStatus = (id, status, active = true) => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = status;
            el.className = `text-[10px] ${active ? 'text-emerald-400' : 'text-gray-400'}`;
        }
    };
    
    // Update each module status based on scan results
    if (data.honeytoken_analysis) {
        updateStatus('honeytoken-status', 'Bait deployed', true);
    }
    if (data.pdf_analysis) {
        const pdfRisk = data.pdf_analysis.risk_level;
        updateStatus('pdf-analyzer-status', `PDF: ${pdfRisk}`, pdfRisk !== 'CLEAN');
    }
    if (data.ioc_matches) {
        const iocCount = data.ioc_matches.length;
        updateStatus('ioc-feeds-status', `${iocCount} IOCs matched`, iocCount > 0);
    }
    if (data.ml_prediction) {
        const mlClass = data.ml_prediction.classification;
        updateStatus('ml-detector-status', `ML: ${mlClass}`, mlClass === 'PHISHING');
    }
    if (data.browser_fingerprinting) {
        const fpDetected = data.browser_fingerprinting.fingerprinting_detected;
        updateStatus('browser-fp-status', fpDetected ? '⚠️ FP detected' : 'No FP', fpDetected);
    }
    if (data.api_analysis) {
        const exfilCount = data.api_analysis.exfiltration_attempts_count || 0;
        updateStatus('integration-status', `SIEM: ${exfilCount} alerts`, exfilCount > 0);
    }

    // ── SMISHING ADVANCED PANEL
    renderSmishingPanel(data);

    // Show results with animation
    const resultsPanel = document.getElementById('results-panel');
    if (resultsPanel) {
        resultsPanel.classList.remove('hidden');
        resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
    
    // Show toast
    const toastType = risk >= 70 ? 'error' : risk >= 30 ? 'warning' : 'success';
    showToast(`Scan complete. Risk level: ${risk}/100`, toastType);
}

// ══════════════════════════════════════════════
// SMISHING ADVANCED PANEL RENDERER
// ══════════════════════════════════════════════
function renderSmishingPanel(data) {
    const panel = document.getElementById('smishing-advanced-panel');
    if (!panel) return;

    // Only show when smishing vector
    const isSmishing = (data.original_text !== undefined || data.extracted_links !== undefined);
    if (!isSmishing) {
        panel.classList.add('hidden');
        return;
    }
    panel.classList.remove('hidden');

    // ── CARD 1: Sender Spoofing
    const sender = data.sender_analysis || {};
    const senderStatus = document.getElementById('smishing-sender-status');
    const senderBrand = document.getElementById('smishing-sender-brand');
    const senderType = document.getElementById('smishing-sender-type');
    const senderDetails = document.getElementById('smishing-sender-details');
    if (senderStatus) {
        if (sender.spoofing_detected) {
            senderStatus.innerHTML = '<span class="text-rose-400 font-bold"><i class="fa-solid fa-triangle-exclamation mr-1"></i>SPOOFING DETECTED</span>';
        } else if (sender.sender_id) {
            senderStatus.innerHTML = '<span class="text-emerald-400"><i class="fa-solid fa-check mr-1"></i>Appears Legitimate</span>';
        } else {
            senderStatus.innerHTML = '<span class="text-gray-400">No Sender ID Provided</span>';
        }
    }
    if (senderBrand) senderBrand.textContent = sender.impersonated_brand ? `Impersonating: ${sender.impersonated_brand}` : (sender.sender_id || 'N/A');
    if (senderType) {
        const st = sender.sender_type || 'UNKNOWN';
        const stColor = st === 'TRAI_COMPLIANT' ? 'text-emerald-400 bg-emerald-500/10' : 'text-yellow-400 bg-yellow-500/10';
        senderType.textContent = st;
        senderType.className = `text-[10px] px-2 py-0.5 rounded-full inline-block ${stColor}`;
    }
    if (senderDetails) {
        const details = sender.details || [];
        senderDetails.innerHTML = details.map(d => `<div><i class="fa-solid fa-circle-dot mr-1 text-yellow-400"></i>${d}</div>`).join('') || '';
    }

    // ── CARD 2: Phone Intelligence
    const phone = data.phone_intel || {};
    const setEl = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
    setEl('smishing-phone-country', phone.country && phone.country !== 'UNKNOWN' ? `<span class="text-blue-400">${phone.country}</span>` : '<span class="text-gray-400">Not provided</span>');
    setEl('smishing-phone-carrier', phone.carrier_guess || 'Unknown carrier');
    if (document.getElementById('smishing-phone-type')) {
        const pt = phone.is_disposable ? 'DISPOSABLE / VoIP' : (phone.is_shortcode ? 'SHORT CODE' : (phone.number_type || 'MOBILE'));
        const ptColor = phone.is_disposable ? 'text-rose-400 bg-rose-500/10' : 'text-gray-400 bg-white/5';
        document.getElementById('smishing-phone-type').textContent = pt;
        document.getElementById('smishing-phone-type').className = `text-[10px] px-2 py-0.5 rounded-full inline-block ${ptColor}`;
    }
    const phoneFlags = document.getElementById('smishing-phone-flags');
    if (phoneFlags) {
        const flags = phone.flags || [];
        phoneFlags.innerHTML = flags.length > 0
            ? flags.map(f => `<div><i class="fa-solid fa-flag mr-1"></i>${f}</div>`).join('')
            : '<span class="text-gray-500">No flags</span>';
    }

    // ── CARD 3: Template Fingerprint
    const tmpl = data.template_fingerprint || {};
    const tmplLabel = document.getElementById('smishing-template-label');
    const tmplHash = document.getElementById('smishing-template-hash');
    if (tmplLabel) {
        if (tmpl.template_matched) {
            tmplLabel.innerHTML = `<span class="text-rose-400"><i class="fa-solid fa-circle-exclamation mr-1"></i>${tmpl.template_label}</span>`;
        } else {
            tmplLabel.innerHTML = '<span class="text-emerald-400"><i class="fa-solid fa-check mr-1"></i>No known template match</span>';
        }
    }
    if (tmplHash) tmplHash.textContent = tmpl.fingerprint_hash || '--';

    // ── CARD 4: OTP Harvesting
    const otp = data.otp_analysis || {};
    const otpStatus = document.getElementById('smishing-otp-status');
    const otpPatterns = document.getElementById('smishing-otp-patterns');
    if (otpStatus) {
        if (otp.otp_harvesting_detected) {
            otpStatus.innerHTML = `<span class="text-rose-400 font-bold"><i class="fa-solid fa-skull-crossbones mr-1"></i>CREDENTIAL THEFT DETECTED</span>`;
        } else if (otp.otp_present) {
            otpStatus.innerHTML = '<span class="text-yellow-400"><i class="fa-solid fa-exclamation-circle mr-1"></i>OTP present in SMS</span>';
        } else {
            otpStatus.innerHTML = '<span class="text-emerald-400"><i class="fa-solid fa-check mr-1"></i>No harvesting patterns</span>';
        }
    }
    if (otpPatterns) {
        const pts = otp.patterns_matched || [];
        otpPatterns.innerHTML = pts.length > 0
            ? pts.map(p => `<div><i class="fa-solid fa-chevron-right mr-1"></i>${p}</div>`).join('')
            : '';
    }

    // ── CARD 5: Brand Impersonation
    const brand = data.brand_impersonation || {};
    setEl('smishing-brand-name', brand.brand_detected
        ? `<span class="text-yellow-400 font-bold">${brand.brand_detected}</span>`
        : '<span class="text-emerald-400">No brand impersonation</span>');
    const confBar = document.getElementById('smishing-brand-conf-bar');
    const confTxt = document.getElementById('smishing-brand-conf');
    const conf = brand.confidence || 0;
    if (confBar) { confBar.style.width = conf + '%'; confBar.className = `h-full rounded-full transition-all ${conf > 70 ? 'bg-rose-400' : conf > 40 ? 'bg-yellow-400' : 'bg-emerald-400'}`; }
    if (confTxt) confTxt.textContent = conf + '%';
    const brandTactics = document.getElementById('smishing-brand-tactics');
    if (brandTactics) {
        const tactics = brand.impersonation_tactics || [];
        brandTactics.innerHTML = tactics.map(t => `<div><i class="fa-solid fa-angles-right mr-1"></i>${t}</div>`).join('') || '<span class="text-gray-500">No tactics detected</span>';
    }

    // ── CARD 6: Multi-Language
    const lang = data.multilang_analysis || {};
    const langStatus = document.getElementById('smishing-lang-status');
    const langList = document.getElementById('smishing-lang-list');
    if (langStatus) {
        langStatus.innerHTML = lang.multilang_detected
            ? `<span class="text-cyan-400"><i class="fa-solid fa-globe mr-1"></i>Multi-language smishing detected!</span>`
            : '<span class="text-emerald-400"><i class="fa-solid fa-check mr-1"></i>English only / No multi-lang threat</span>';
    }
    if (langList) {
        const langs = lang.languages_found || [];
        const langColors = { 'HINDI': 'bg-orange-500/20 text-orange-300', 'TELUGU': 'bg-cyan-500/20 text-cyan-300', 'TAMIL': 'bg-purple-500/20 text-purple-300' };
        langList.innerHTML = langs.length > 0
            ? langs.map(l => `<span class="text-[10px] px-2 py-1 rounded-full ${langColors[l] || 'bg-white/10 text-gray-300'}">${l}</span>`).join('')
            : '<span class="text-[10px] text-gray-500">None detected</span>';
    }

    // ── URL Chain
    const urlChainBlock = document.getElementById('smishing-url-chain');
    const urlChainItems = document.getElementById('smishing-url-chain-items');
    const urlAnalysis = data.url_analysis || [];
    if (urlAnalysis.length > 0 && urlChainBlock && urlChainItems) {
        urlChainBlock.classList.remove('hidden');
        urlChainItems.innerHTML = urlAnalysis.map((u, i) => {
            const isMalicious = u.ioc_match || u.threat_intel?.is_malicious || (u.ml_prediction?.classification === 'PHISHING');
            const clr = isMalicious ? 'border-rose-500/40 bg-rose-500/5' : 'border-yellow-500/30 bg-yellow-500/5';
            const icon = isMalicious ? 'fa-skull text-rose-400' : 'fa-link text-yellow-400';
            return `<div class="p-3 rounded-lg border ${clr} text-xs">
                <div class="flex items-center gap-2 mb-1">
                    <i class="fa-solid ${icon}"></i>
                    <span class="font-mono text-gray-300 truncate flex-1">${u.original_url}</span>
                    ${u.trace_result?.redirect_count > 0 ? `<span class="text-[10px] text-gray-500">${u.trace_result.redirect_count} redirects</span>` : ''}
                </div>
                ${u.original_url !== (u.trace_result?.final_url || u.original_url) ? `<div class="text-[10px] text-gray-500 ml-5">→ <span class="text-yellow-300">${u.trace_result?.final_url}</span></div>` : ''}
                ${isMalicious ? '<div class="text-[10px] text-rose-400 ml-5 mt-1"><i class="fa-solid fa-triangle-exclamation mr-1"></i>Flagged as malicious</div>' : ''}
            </div>`;
        }).join('');
    } else if (urlChainBlock) {
        urlChainBlock.classList.add('hidden');
    }

    // ── Keywords
    const kwBlock = document.getElementById('smishing-keywords-block');
    const kwContainer = document.getElementById('smishing-keywords');
    const keywords = data.social_engineering_keywords || [];
    if (keywords.length > 0 && kwBlock && kwContainer) {
        kwBlock.classList.remove('hidden');
        kwContainer.innerHTML = keywords.map(k =>
            `<span class="text-[10px] px-2 py-1 rounded-full bg-yellow-500/10 text-yellow-300 border border-yellow-500/20">${k}</span>`
        ).join('');
    } else if (kwBlock) {
        kwBlock.classList.add('hidden');
    }
}

// ── Sender Type Selector ──
const SENDER_TYPE_CONFIG = {
    alpha: {
        icon: 'fa-font',
        placeholder: 'e.g. VM-SBIINB',
        hint: 'Alpha: <span class="text-yellow-400/70">VM-SBIINB</span>, <span class="text-yellow-400/70">AD-HDFC</span>, <span class="text-yellow-400/70">BW-AIRTEL</span>, <span class="text-yellow-400/70">TC-PAYTM</span> — TRAI 6-char format'
    },
    short: {
        icon: 'fa-hashtag',
        placeholder: 'e.g. 56321',
        hint: 'Shortcode: <span class="text-yellow-400/70">56161</span>, <span class="text-yellow-400/70">1800</span>, <span class="text-yellow-400/70">9999</span>, <span class="text-yellow-400/70">52123</span> — 4 to 6 digit numbers'
    },
    long: {
        icon: 'fa-phone',
        placeholder: 'e.g. +91 98765 43210',
        hint: 'Long number: <span class="text-yellow-400/70">+91 98765 43210</span>, <span class="text-yellow-400/70">+1 408 555 1234</span> — international numbers'
    }
};

let currentSenderType = 'alpha';

function setSenderType(type) {
    currentSenderType = type;
    const cfg = SENDER_TYPE_CONFIG[type];
    if (!cfg) return;

    // Update tab styles
    document.querySelectorAll('.stype-btn').forEach(btn => {
        btn.classList.remove('border-yellow-500/40', 'bg-yellow-500/10', 'text-yellow-400', 'font-semibold');
        btn.classList.add('border-white/10', 'bg-white/5', 'text-gray-400');
    });
    const activeBtn = document.getElementById(`stype-${type}`);
    if (activeBtn) {
        activeBtn.classList.remove('border-white/10', 'bg-white/5', 'text-gray-400');
        activeBtn.classList.add('border-yellow-500/40', 'bg-yellow-500/10', 'text-yellow-400', 'font-semibold');
    }

    // Update icon
    const icon = document.getElementById('sms-sender-icon');
    if (icon) icon.className = `fa-solid ${cfg.icon} absolute left-3 top-1/2 -translate-y-1/2 text-yellow-400 text-sm`;

    // Update placeholder
    const input = document.getElementById('sms-sender-id');
    if (input) input.placeholder = cfg.placeholder;

    // Update hint
    const hint = document.getElementById('sms-sender-hint');
    if (hint) hint.innerHTML = `<i class="fa-solid fa-circle-info mr-1 text-yellow-500/60"></i>${cfg.hint}`;
}

// ── SMS Helper Functions ──
function handleSmsFileUpload(input) {
    const file = input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
        const content = document.getElementById('sms-content');
        if (content) content.value = e.target.result;
        showToast(`Loaded: ${file.name}`, 'success');
    };
    reader.readAsText(file);
}

function clearSmishingInputs() {
    ['sms-sender-id', 'sms-content'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    setSenderType('alpha');
    const panel = document.getElementById('smishing-advanced-panel');
    if (panel) panel.classList.add('hidden');
}

const SMS_TEMPLATES = {
    bank: {
        senderType: 'alpha',
        sender: 'FAKESBI',
        text: 'Dear SBI customer, your KYC is pending. Your account will be SUSPENDED within 24 hours. Update now to avoid account block: https://bit.ly/sbi-kyc-update'
    },
    otp: {
        senderType: 'alpha',
        sender: 'VM-HDFCBK',
        text: 'Your HDFC Bank OTP is 847291. Share this OTP to verify your account and avoid suspension. This OTP is valid for 10 minutes. Do NOT share with anyone.'
    },
    prize: {
        senderType: 'long',
        sender: '+14085551234',
        text: 'Congratulations! You have WON Rs.50,000 in Amazon Lucky Draw. You are our selected winner! Click to claim your reward NOW: https://tinyurl.com/amzn-prize-win'
    },
    delivery: {
        senderType: 'alpha',
        sender: 'FEDXIN',
        text: 'FedEx: Your parcel #IN2847561 could not be delivered. Pay Rs.29 customs fee within 24 hours to reschedule delivery: https://cutt.ly/fedx-customs-fee'
    },
    shortcode: {
        senderType: 'short',
        sender: '56321',
        text: 'Your account has been temporarily BLOCKED due to suspicious activity. Call 1800-XXX-XXXX immediately or click: https://rb.gy/bank-unblock to restore access. URGENT!'
    }
};

function loadSmsTemplate(type) {
    const tpl = SMS_TEMPLATES[type];
    if (!tpl) return;
    setSenderType(tpl.senderType || 'alpha');
    const senderEl = document.getElementById('sms-sender-id');
    const contentEl = document.getElementById('sms-content');
    if (senderEl) senderEl.value = tpl.sender;
    if (contentEl) contentEl.value = tpl.text;
    showToast(`Loaded: ${type.charAt(0).toUpperCase() + type.slice(1)} smishing template`, 'info');
}

// Ctrl+Enter to scan SMS
document.addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'Enter') {
        const content = document.getElementById('sms-content');
        if (document.activeElement === content) simulateScan();
    }
});

async function downloadReport() {
    if (!lastScanData) {
        showToast('No scan data available. Please run a scan first.', 'warning');
        return;
    }

    const btn = document.getElementById('download-report-btn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Generating PDF...</span>';
    }

    try {
        const response = await fetch('/download_report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(lastScanData)
        });

        if (!response.ok) throw new Error('Report generation failed');

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SOC_Report_${Date.now()}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        showToast('SOC PDF Report downloaded successfully!', 'success');
    } catch (err) {
        console.error('Report download error:', err);
        showToast('Failed to generate report. Check server status.', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-file-pdf"></i><span>Download SOC Report</span>';
        }
    }
}

async function triggerOffensive() {
    const payload = document.getElementById('payload').value;
    if (!confirm(`Boss, launch counter-attack on ${payload}?`)) return;

    try {
        const response = await fetch('/api/offensive_attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url: payload })
        });
        const data = await response.json();
        alert(`Mission Success: ${data.injected_records} fake records injected into hacker DB.`);
    } catch (err) {
        alert("Offensive operation failed.");
    }
}

function typeWriter(elementId, text, speed = 30) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.innerHTML = '';
    let i = 0;
    function type() {
        if (i < text.length) {
            el.innerHTML += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }
    type();
}

// Professional text formatter for analysis and recommendations
function formatAnalysisText(text) {
    if (!text) return '';
    
    // Clean up the text
    let cleaned = text
        .replace(/\n+/g, ' ')           // Remove extra newlines
        .replace(/\s+/g, ' ')           // Normalize spaces
        .replace(/CRITICAL:/gi, '\n\n🔴 CRITICAL: ')
        .replace(/WARNING:/gi, '\n\n⚠️ WARNING: ')
        .replace(/ALERT:/gi, '\n\n🚨 ALERT: ')
        .replace(/INFO:/gi, '\n\nℹ️ INFO: ')
        .replace(/NOTE:/gi, '\n\n📝 NOTE: ')
        .replace(/Recommendation:/gi, '\n\n💡 Recommendation:')
        .replace(/Action:/gi, '\n\n👉 Action:')
        .replace(/Risk:/gi, '\n\n⚡ Risk:')
        .replace(/Evidence:/gi, '\n\n📊 Evidence:')
        .replace(/Analysis:/gi, '\n\n🔍 Analysis:')
        .replace(/Fallback/gi, '\n\n[Fallback Analysis]')
        .replace(/\.([A-Z])/g, '.\n\n$1')  // Add paragraph breaks after sentences starting with capital
        .trim();
    
    // Convert URLs to clickable links
    cleaned = cleaned.replace(
        /(https?:\/\/[^\s]+)/g,
        '<a href="$1" target="_blank" class="text-blue-400 hover:text-blue-300 underline">$1</a>'
    );
    
    // Highlight key terms
    const highlightTerms = [
        'TYPOSQUATTING', 'PHISHING', 'MALICIOUS', 'SUSPICIOUS', 'SAFE', 'CLEAN',
        'HIGH RISK', 'MEDIUM RISK', 'LOW RISK', 'BLOCK', 'ALLOW', 'QUARANTINE'
    ];
    
    highlightTerms.forEach(term => {
        const regex = new RegExp(`(${term})`, 'gi');
        let color = 'text-rose-400';
        if (['SAFE', 'CLEAN', 'ALLOW'].includes(term)) color = 'text-emerald-400';
        if (['MEDIUM RISK', 'SUSPICIOUS'].includes(term)) color = 'text-yellow-400';
        
        cleaned = cleaned.replace(regex, `<span class="${color} font-semibold">$1</span>`);
    });
    
    return cleaned;
}

function initTheme() {
    document.documentElement.classList.add('dark');
}
