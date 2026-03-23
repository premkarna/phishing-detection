const urlInput = document.getElementById('urlInput');
const scanButton = document.getElementById('scanButton');
const resultSection = document.getElementById('resultSection');
const loadingSection = document.getElementById('loadingSection');
const infoGridSection = document.getElementById('infoGridSection');
const historySection = document.getElementById('historySection');
const reportReasons = document.getElementById('reportReasons');
const uiErrorBox = document.getElementById('uiErrorBox');
const historyList = document.getElementById('historyList');
const riskBarFill = document.getElementById('riskBarFill');

let currentReportData = null; 

function parseMarkdown(text) {
    if (!text) return "";
    return text.replace(/\*\*(.*?)\*\*/g, '<strong style="color:#58a6ff;">$1</strong>')
               .replace(/^\* (.*?)$/gm, '<li style="margin-left:20px; margin-bottom:8px;">$1</li>')
               .replace(/\n/g, '<br>');
}

// 🕒 FEATURE: Load History with DELETE logic
function loadHistory() {
    const history = JSON.parse(localStorage.getItem('scanHistory')) || [];
    historyList.innerHTML = '';
    
    if (history.length === 0) {
        historySection.classList.add('hidden');
        return;
    }

    historySection.classList.remove('hidden');
    history.forEach(item => {
        const li = document.createElement('li');
        li.className = `history-item ${item.verdict === 'SAFE' ? 'history-safe' : 'history-phishing'}`;
        
        // Target Link text
        const textSpan = document.createElement('span');
        textSpan.textContent = item.url.length > 25 ? item.url.substring(0,25)+'...' : item.url;
        textSpan.title = item.url; 
        textSpan.onclick = () => { urlInput.value = item.url; scanUrl(); }; 
        
        // ❌ Delete single item button
        const deleteBtn = document.createElement('span');
        deleteBtn.innerHTML = " &times;";
        deleteBtn.style.cssText = "color: #f85149; font-size: 1.1rem; margin-left: 8px; font-weight: bold; cursor: pointer;";
        deleteBtn.onclick = (e) => {
            e.stopPropagation(); // Prevents scanning when clicking delete
            removeFromHistory(item.url);
        };

        li.appendChild(textSpan);
        li.appendChild(deleteBtn);
        historyList.appendChild(li);
    });
}

function saveToHistory(url, verdict) {
    let history = JSON.parse(localStorage.getItem('scanHistory')) || [];
    history = history.filter(item => item.url !== url);
    history.unshift({ url, verdict });
    if (history.length > 6) history.pop(); 
    localStorage.setItem('scanHistory', JSON.stringify(history));
    loadHistory();
}

// 💡 NEW: Remove single item
function removeFromHistory(url) {
    let history = JSON.parse(localStorage.getItem('scanHistory')) || [];
    history = history.filter(item => item.url !== url);
    localStorage.setItem('scanHistory', JSON.stringify(history));
    loadHistory();
}

// 💡 NEW: Clear All button listener (Make sure to add this anywhere at the bottom of script.js)
document.getElementById('clearHistoryBtn').addEventListener('click', function() {
    localStorage.removeItem('scanHistory');
    loadHistory();
});

async function scanUrl() {
    const url = urlInput.value.trim();
    if (!url) return;

    uiErrorBox.classList.add('hidden');
    resultSection.classList.add('hidden');
    infoGridSection.classList.add('hidden'); 
    loadingSection.classList.remove('hidden');
    scanButton.disabled = true;
    scanButton.querySelector('.btn-text').classList.add('hidden');
    scanButton.querySelector('.btn-loader').classList.remove('hidden');
    document.body.classList.remove('phishing-state', 'safe-state');

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url }),
        });

        const data = await response.json();

        loadingSection.classList.add('hidden');
        scanButton.disabled = false;
        scanButton.querySelector('.btn-text').classList.remove('hidden');
        scanButton.querySelector('.btn-loader').classList.add('hidden');

        if (!response.ok || data.status === "error") {
            uiErrorBox.textContent = data.message || "Target server unreachable or API limits exceeded.";
            uiErrorBox.classList.remove('hidden');
            infoGridSection.classList.remove('hidden'); 
            return; 
        }

        resultSection.classList.remove('hidden');
        document.getElementById('scanTime').textContent = new Date().toLocaleString();
        document.getElementById('reportUrl').textContent = data.url;
        
        const existsEl = document.getElementById('reportExists');
        existsEl.innerHTML = data.exists ? "<span style='color:#3fb950'>🟢 ACTIVE</span>" : "<span style='color:#f85149'>🔴 OFFLINE / DEAD</span>";

        document.getElementById('reportLocation').textContent = data.location;
        document.getElementById('reportVt').textContent = data.vt_report;
        document.getElementById('reportAge').textContent = data.domain_age;
        
        const sslEl = document.getElementById('reportSsl');
        sslEl.textContent = data.ssl_info;
        sslEl.style.color = data.ssl_info.includes("❌") ? "#f85149" : "#c9d1d9";

        document.getElementById('reportVerdict').textContent = data.verdict;
        
        // 💡 RISK METER LOGIC
        if (data.verdict === "PHISHING") {
            document.body.classList.add('phishing-state');
            riskBarFill.style.width = "90%";
            riskBarFill.style.backgroundColor = "#f85149";
            riskBarFill.style.boxShadow = "0 0 15px #f85149";
        } else {
            document.body.classList.add('safe-state');
            riskBarFill.style.width = "15%";
            riskBarFill.style.backgroundColor = "#3fb950";
            riskBarFill.style.boxShadow = "0 0 15px #3fb950";
        }

        reportReasons.innerHTML = `<ul>${parseMarkdown(data.ai_report)}</ul>`;
        saveToHistory(data.url, data.verdict);

        // 🏆 THE ULTIMATE EXECUTIVE HTML REPORT DESIGN
        const themeColor = data.verdict === 'SAFE' ? '#2ea043' : '#da3633';
        const vtBadge = data.vt_report.includes('Malicious') ? 'background:#da3633;color:#fff;' : 'background:#2ea043;color:#fff;';

        currentReportData = `
<!DOCTYPE html>
<html>
<head>
    <title>Executive Threat Report - ${data.url}</title>
    <style>
        body { font-family: 'Helvetica Neue', Arial, sans-serif; background: #f6f8fa; color: #24292f; margin: 0; padding: 40px; }
        .page { max-width: 850px; margin: 0 auto; background: #fff; padding: 50px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border-top: 8px solid ${themeColor}; }
        .header { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 2px solid #e1e4e8; padding-bottom: 20px; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: 900; color: #24292f; letter-spacing: -1px; }
        .logo span { color: #0969da; }
        .meta-text { text-align: right; font-size: 12px; color: #57606a; line-height: 1.6; }
        .verdict-banner { background: ${themeColor}15; border: 1px solid ${themeColor}40; padding: 25px; border-radius: 6px; text-align: center; margin-bottom: 30px; }
        .verdict-banner h2 { margin: 0 0 10px 0; font-size: 14px; text-transform: uppercase; color: #57606a; letter-spacing: 1px; }
        .verdict-banner .score { font-size: 36px; font-weight: 800; color: ${themeColor}; margin: 0; letter-spacing: 2px;}
        .section-title { font-size: 16px; color: #24292f; border-bottom: 1px solid #e1e4e8; padding-bottom: 8px; margin: 30px 0 15px 0; font-weight: 600; text-transform: uppercase; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .card { border: 1px solid #d0d7de; padding: 15px; border-radius: 6px; background: #fbfceb; }
        .card .label { font-size: 11px; color: #57606a; text-transform: uppercase; font-weight: 600; margin-bottom: 5px; }
        .card .val { font-size: 14px; font-weight: 500; color: #24292f; word-break: break-all; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; ${vtBadge} }
        .ai-log { background: #24292f; color: #f6f8fa; padding: 25px; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.7; box-shadow: inset 0 0 10px rgba(0,0,0,0.5);}
        .ai-log strong { color: #58a6ff; }
        .footer { text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid #e1e4e8; font-size: 11px; color: #8c959f; }
    </style>
</head>
<body>
    <div class="page">
        <div class="header">
            <div class="logo">Phishing<span>Sentinel</span></div>
            <div class="meta-text">
                <strong>REPORT ID:</strong> SEC-${Math.floor(Math.random() * 90000) + 10000}<br>
                <strong>TIMESTAMP:</strong> ${new Date().toUTCString()}
            </div>
        </div>

        <div class="verdict-banner">
            <h2>Automated Threat Assessment</h2>
            <div class="score">${data.verdict}</div>
            <div style="margin-top:10px; font-size:14px; color:#57606a;">Target: <strong>${data.url}</strong></div>
        </div>

        <div class="section-title">Technical Telemetry</div>
        <div class="grid">
            <div class="card" style="background:#fff;"><div class="label">Server Status & Location</div><div class="val">${data.exists ? "LIVE" : "OFFLINE"} • ${data.location}</div></div>
            <div class="card" style="background:#fff;"><div class="label">VirusTotal Consensus</div><div class="val"><span class="badge">${data.vt_report}</span></div></div>
            <div class="card" style="background:#fff;"><div class="label">Domain Registration</div><div class="val">${data.domain_age}</div></div>
            <div class="card" style="background:#fff;"><div class="label">SSL/TLS Security</div><div class="val">${data.ssl_info}</div></div>
        </div>

        <div class="section-title">AI Heuristic Analysis Log</div>
        <div class="ai-log">
            > Initializing Gemini Neural Engine...<br>
            > Correlating data points...<br><br>
            ${data.ai_report.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>')}
        </div>

        <div class="footer">
            CONFIDENTIAL SECURITY DOCUMENT<br>
            Generated automatically by AI Phishing Sentinel V4.0 Enterprise.<br>
            This report is for informational purposes. Verify critical findings with a security analyst.
        </div>
    </div>
</body>
</html>`;

    } catch (error) {
        loadingSection.classList.add('hidden');
        scanButton.disabled = false;
        scanButton.querySelector('.btn-text').classList.remove('hidden');
        scanButton.querySelector('.btn-loader').classList.add('hidden');
        infoGridSection.classList.remove('hidden');
        uiErrorBox.textContent = "System Error. Check Python backend.";
        uiErrorBox.classList.remove('hidden');
    }
}

document.getElementById('downloadButton').addEventListener('click', () => {
    if (!currentReportData) return;
    const blob = new Blob([currentReportData], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Executive_Report_${new Date().getTime()}.html`;
    a.click();
    URL.revokeObjectURL(url);
});

document.getElementById('resetButton').addEventListener('click', () => {
    resultSection.classList.add('hidden');
    infoGridSection.classList.remove('hidden');
    urlInput.value = "";
    urlInput.focus();
    document.body.classList.remove('phishing-state', 'safe-state');
    currentReportData = null;
});

scanButton.addEventListener('click', scanUrl);
urlInput.addEventListener('keypress', e => { if (e.key === 'Enter') scanUrl(); });
loadHistory();

clearHistoryBtn