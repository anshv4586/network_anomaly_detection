// ── Core Application Initialization ─────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initTabs();
    initCharts();
    initOfflineUpload();
    initOnlineSniffer();
    initModal();
    initFilterTabs();
});

// ── Global Flows & Filtering State ──────────────────────────────────────────
let currentOnlineFlows = { alerts: [], benign: [] };
let currentOfflineFlows = { alerts: [], benign: [] };
let currentOnlineFilter = "all";
let currentOfflineFilter = "all";

// ── Clock Widget ───────────────────────────────────────────────────────────
function initClock() {
    const clockEl = document.getElementById("live-clock");
    setInterval(() => {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString();
    }, 1000);
}

// ── Tab Switcher ───────────────────────────────────────────────────────────
function initTabs() {
    const menuItems = document.querySelectorAll(".menu-item");
    const tabContents = document.querySelectorAll(".tab-content");
    const pageTitle = document.getElementById("page-title");
    const pageSubtitle = document.getElementById("page-subtitle");
    const currentMode = document.getElementById("current-mode");

    menuItems.forEach(item => {
        item.addEventListener("click", () => {
            const targetTab = item.dataset.tab;
            
            // Toggle active menu class
            menuItems.forEach(mi => mi.classList.remove("active"));
            item.classList.add("active");
            
            // Toggle active tab content
            tabContents.forEach(content => {
                if (content.id === `tab-${targetTab}`) {
                    content.classList.add("active");
                } else {
                    content.classList.remove("active");
                }
            });
            
            // Update Headers
            if (targetTab === "online") {
                pageTitle.textContent = "Real-Time Sniffing Dashboard";
                pageSubtitle.textContent = "30-Second Sliding Context Window Analysis";
                currentMode.textContent = "Online Monitor";
            } else {
                pageTitle.textContent = "Offline Dataset Triage";
                pageSubtitle.textContent = "Static Log Analysis & Diagnostic Reports";
                currentMode.textContent = "Offline Triage";
            }
        });
    });
}

// ── Chart.js Configurations ────────────────────────────────────────────────
let threatChart = null;
let offlineTimelineChart = null;
let offlineProtocolChart = null;
let offlineAttackChart = null;
const maxChartPoints = 12;
const chartDataHistory = {
    labels: [],
    ratio: [],
    anomalies: [],
    benign: []
};

function initCharts() {
    const ctx = document.getElementById("online-threat-chart").getContext("2d");
    
    // Create baseline empty points
    for (let i = 0; i < maxChartPoints; i++) {
        chartDataHistory.labels.push(`-:${i * 30}s`);
        chartDataHistory.ratio.push(0);
        chartDataHistory.anomalies.push(0);
        chartDataHistory.benign.push(0);
    }
    
    threatChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartDataHistory.labels,
            datasets: [
                {
                    label: 'Threat Ratio (%)',
                    data: chartDataHistory.ratio,
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.08)',
                    borderWidth: 2,
                    pointBackgroundColor: '#00f2fe',
                    pointHoverRadius: 6,
                    tension: 0.35,
                    fill: true,
                    yAxisID: 'y_pct'
                },
                {
                    label: 'Anomaly Count',
                    data: chartDataHistory.anomalies,
                    borderColor: '#ff2a5f',
                    backgroundColor: 'rgba(255, 42, 95, 0.05)',
                    borderWidth: 1.5,
                    pointBackgroundColor: '#ff2a5f',
                    tension: 0.3,
                    fill: false,
                    yAxisID: 'y_cnt'
                },
                {
                    label: 'Benign Count',
                    data: chartDataHistory.benign,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.05)',
                    borderWidth: 1.5,
                    pointBackgroundColor: '#10b981',
                    tension: 0.3,
                    fill: false,
                    yAxisID: 'y_cnt'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    labels: { color: '#bdc3c7', font: { family: 'Plus Jakarta Sans', size: 11 } }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(189, 195, 199, 0.05)' },
                    ticks: { color: '#bdc3c7', font: { family: 'Plus Jakarta Sans' } }
                },
                y_pct: {
                    type: 'linear',
                    position: 'left',
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(189, 195, 199, 0.05)' },
                    ticks: { color: '#bdc3c7', callback: value => `${value}%` }
                },
                y_cnt: {
                    type: 'linear',
                    position: 'right',
                    min: 0,
                    grid: { display: false },
                    ticks: { color: '#bdc3c7', stepSize: 1 }
                }
            }
        }
    });
}

function updateThreatChart(threatRatio, anomalyCount, benignCount) {
    const now = new Date();
    const timeLabel = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    // Shift arrays
    chartDataHistory.labels.push(timeLabel);
    chartDataHistory.ratio.push(threatRatio);
    chartDataHistory.anomalies.push(anomalyCount);
    chartDataHistory.benign.push(benignCount);
    
    if (chartDataHistory.labels.length > maxChartPoints) {
        chartDataHistory.labels.shift();
        chartDataHistory.ratio.shift();
        chartDataHistory.anomalies.shift();
        chartDataHistory.benign.shift();
    }
    
    threatChart.data.labels = chartDataHistory.labels;
    threatChart.data.datasets[0].data = chartDataHistory.ratio;
    threatChart.data.datasets[1].data = chartDataHistory.anomalies;
    threatChart.data.datasets[2].data = chartDataHistory.benign;
    threatChart.update();
}

// ── Mode 1: Offline Analysis Functionality ─────────────────────────────────
let uploadedFileId = null;
let uploadedFileExt = null;
let prepInterval = null;
let predInterval = null;

function initOfflineUpload() {
    const dropzone = document.getElementById("file-dropzone");
    const fileInput = document.getElementById("file-input");
    const fileSummary = document.getElementById("file-summary");
    const btnReset = document.getElementById("btn-reset-upload");
    const btnAnalyze = document.getElementById("btn-start-analyze");
    const previewCard = document.getElementById("file-preview-card");
    const previewContainer = document.getElementById("preview-table-container");

    // Click handler to open select window
    dropzone.addEventListener("click", () => fileInput.click());

    // Drag-over styling
    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });
    
    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("dragover");
    });
    
    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });
    
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) {
            handleFileUpload(fileInput.files[0]);
        }
    });

    btnReset.addEventListener("click", resetOfflineState);
    btnAnalyze.addEventListener("click", startOfflineInference);
}

function handleFileUpload(file) {
    const formData = new FormData();
    formData.append("file", file);

    const dropzone = document.getElementById("file-dropzone");
    const previewContainer = document.getElementById("preview-table-container");
    
    dropzone.innerHTML = `<i class="fa-solid fa-spinner fa-spin cloud-icon"></i><h3>Uploading dataset...</h3><p>Validating schema constraints</p>`;

    fetch("/api/offline/upload", {
        method: "POST",
        body: formData
    })
    .then(res => {
        if (!res.ok) throw new Error("Upload failed. Unsupported file structure.");
        return res.json();
    })
    .then(data => {
        uploadedFileId = data.file_id;
        uploadedFileExt = data.extension;
        
        // Hide Dropzone, show Summary
        document.getElementById("file-dropzone").classList.add("hidden");
        document.getElementById("file-summary").classList.remove("hidden");
        
        document.getElementById("summary-filename").textContent = data.filename;
        document.getElementById("summary-size").textContent = data.size_mb;
        document.getElementById("summary-rows").textContent = data.num_rows.toLocaleString();
        document.getElementById("summary-cols").textContent = data.num_cols;

        renderPreviewTable(data.preview, data.extension);
    })
    .catch(err => {
        alert(err.message);
        resetOfflineState();
    });
}

function renderPreviewTable(rows, ext) {
    const previewContainer = document.getElementById("preview-table-container");
    if (!rows || rows.length === 0) {
        previewContainer.innerHTML = `<div class="table-empty"><i class="fa-solid fa-file-excel"></i><p>No preview rows available.</p></div>`;
        return;
    }

    let headers = Object.keys(rows[0]);
    let html = `<table class="preview-table"><thead><tr>`;
    
    headers.forEach(h => {
        html += `<th>${h}</th>`;
    });
    html += `</tr></thead><tbody>`;

    rows.forEach(r => {
        html += `<tr>`;
        headers.forEach(h => {
            html += `<td>${r[h]}</td>`;
        });
        html += `</tr>`;
    });
    html += `</tbody></table>`;
    previewContainer.innerHTML = html;
}

function resetOfflineState() {
    uploadedFileId = null;
    uploadedFileExt = null;
    
    if (prepInterval) { clearInterval(prepInterval); prepInterval = null; }
    if (predInterval) { clearInterval(predInterval); predInterval = null; }
    
    if (offlineTimelineChart) { offlineTimelineChart.destroy(); offlineTimelineChart = null; }
    if (offlineProtocolChart) { offlineProtocolChart.destroy(); offlineProtocolChart = null; }
    if (offlineAttackChart) { offlineAttackChart.destroy(); offlineAttackChart = null; }
    
    const fileInput = document.getElementById("file-input");
    if (fileInput) fileInput.value = "";
    
    // Reset filters
    currentOfflineFlows = { alerts: [], benign: [] };
    currentOfflineFilter = "all";
    const offlineTabs = document.querySelectorAll("#offline-filter-tabs .filter-tab");
    offlineTabs.forEach(t => {
        if (t.dataset.filter === "all") t.classList.add("active");
        else t.classList.remove("active");
    });
    
    // Reset dropzone
    const dropzone = document.getElementById("file-dropzone");
    dropzone.innerHTML = `
        <i class="fa-solid fa-cloud-arrow-up cloud-icon"></i>
        <h3>Drag & drop your logs or packet capture here</h3>
        <p>Supports CSV, Excel (.xlsx, .xls), and Wireshark PCAPs/PCAPNGs</p>
        <span class="btn btn-secondary">Select File</span>
    `;
    
    dropzone.classList.remove("hidden");
    document.getElementById("file-summary").classList.add("hidden");
    document.getElementById("analysis-progress-box").classList.add("hidden");
    document.getElementById("offline-dashboard").classList.add("hidden");
    
    // Reset preview
    document.getElementById("preview-table-container").innerHTML = `
        <div class="table-empty">
            <i class="fa-solid fa-file-excel"></i>
            <p>Upload a CSV or Excel dataset to view the raw packet preview.</p>
        </div>
    `;
    document.getElementById("file-preview-card").classList.remove("hidden");
}

function startOfflineInference() {
    if (!uploadedFileId) return;

    if (prepInterval) clearInterval(prepInterval);
    if (predInterval) clearInterval(predInterval);

    document.getElementById("analysis-progress-box").classList.remove("hidden");
    document.getElementById("file-preview-card").classList.add("hidden");
    document.getElementById("btn-start-analyze").disabled = true;

    const prepFill = document.getElementById("preprocess-progress-fill");
    const prepPct = document.getElementById("preprocess-pct");
    const predFill = document.getElementById("predict-progress-fill");
    const predPct = document.getElementById("predict-pct");

    prepFill.style.width = "0%";
    prepPct.textContent = "0%";
    predFill.style.width = "0%";
    predPct.textContent = "0%";

    // 1. Simulate Preprocessing
    let prepVal = 0;
    prepInterval = setInterval(() => {
        prepVal += Math.floor(Math.random() * 15) + 5;
        if (prepVal >= 100) {
            prepVal = 100;
            clearInterval(prepInterval);
            prepInterval = null;
            // Trigger prediction simulation
            startPredictionSim();
        }
        prepFill.style.width = `${prepVal}%`;
        prepPct.textContent = `${prepVal}%`;
    }, 150);

    let predVal = 0;
    function startPredictionSim() {
        predInterval = setInterval(() => {
            predVal += Math.floor(Math.random() * 10) + 4;
            if (predVal >= 100) {
                predVal = 100;
                clearInterval(predInterval);
                predInterval = null;
            }
            predFill.style.width = `${predVal}%`;
            predPct.textContent = `${predVal}%`;
        }, 120);
    }

    const formData = new FormData();
    formData.append("file_id", uploadedFileId);
    formData.append("extension", uploadedFileExt);

    fetch("/api/offline/analyze", {
        method: "POST",
        body: formData
    })
    .then(res => {
        if (!res.ok) throw new Error("Inference execution failed.");
        return res.json();
    })
    .then(data => {
        if (prepInterval) { clearInterval(prepInterval); prepInterval = null; }
        if (predInterval) { clearInterval(predInterval); predInterval = null; }
        // Set filled immediately since it finished
        prepFill.style.width = "100%";
        prepPct.textContent = "100%";
        predFill.style.width = "100%";
        predPct.textContent = "100%";

        // Wait briefly for animations to settle
        setTimeout(() => {
            document.getElementById("analysis-progress-box").classList.add("hidden");
            document.getElementById("btn-start-analyze").disabled = false;
            
            showOfflineResults(data);
        }, 1000);
    })
    .catch(err => {
        if (prepInterval) { clearInterval(prepInterval); prepInterval = null; }
        if (predInterval) { clearInterval(predInterval); predInterval = null; }
        alert(err.message);
        resetOfflineState();
    });
}

function showOfflineResults(data) {
    const dashboard = document.getElementById("offline-dashboard");
    dashboard.classList.remove("hidden");

    // Populate general stats
    document.getElementById("off-stat-flows").textContent = data.total_flows.toLocaleString();
    document.getElementById("off-stat-threats").textContent = data.anomalies_count.toLocaleString();
    document.getElementById("off-stat-ratio").textContent = `${data.threat_ratio}%`;
    const offBenignEl = document.getElementById("off-stat-benign");
    if (offBenignEl) {
        offBenignEl.textContent = (data.benign_count || 0).toLocaleString();
    }

    // Populate Metrics (if label targets were present in dataset)
    const evalCard = document.getElementById("labels-eval-card");
    if (data.classification_report && data.classification_report.accuracy !== undefined) {
        evalCard.classList.remove("hidden");
        document.getElementById("metric-acc-circle").textContent = `${data.classification_report.accuracy}%`;
        document.getElementById("metric-prec-circle").textContent = `${data.classification_report.precision}%`;
        document.getElementById("metric-rec-circle").textContent = `${data.classification_report.recall}%`;
        document.getElementById("metric-f1-circle").textContent = `${data.classification_report.f1_score}%`;
    } else {
        evalCard.classList.add("hidden");
    }

    // Store logs globally
    currentOfflineFlows.alerts = data.anomalies || [];
    currentOfflineFlows.benign = data.benign || [];

    // Render offline flows
    renderOfflineFlows();

    // Render charts
    updateOfflineCharts(data);
}

function updateOfflineCharts(data) {
    // 1. Timeline Chart
    const ctxTimeline = document.getElementById("offline-threat-chart").getContext("2d");
    if (offlineTimelineChart) {
        offlineTimelineChart.destroy();
    }
    
    const timeline = data.timeline || [];
    const labels = timeline.map(t => t.time);
    const normalData = timeline.map(t => t.normal);
    const attackData = timeline.map(t => t.attacks);
    const ratioData = timeline.map(t => t.detection_rate);
    
    offlineTimelineChart = new Chart(ctxTimeline, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Threat Ratio (%)',
                    data: ratioData,
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.08)',
                    borderWidth: 2,
                    pointBackgroundColor: '#00f2fe',
                    pointHoverRadius: 6,
                    tension: 0.35,
                    fill: true,
                    yAxisID: 'y_pct'
                },
                {
                    label: 'Anomaly Count',
                    data: attackData,
                    borderColor: '#ff2a5f',
                    backgroundColor: 'rgba(255, 42, 95, 0.05)',
                    borderWidth: 1.5,
                    pointBackgroundColor: '#ff2a5f',
                    tension: 0.3,
                    fill: false,
                    yAxisID: 'y_cnt'
                },
                {
                    label: 'Benign Count',
                    data: normalData,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.05)',
                    borderWidth: 1.5,
                    pointBackgroundColor: '#10b981',
                    tension: 0.3,
                    fill: false,
                    yAxisID: 'y_cnt'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    labels: { color: '#bdc3c7', font: { family: 'Plus Jakarta Sans', size: 10 } }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(189, 195, 199, 0.05)' },
                    ticks: { color: '#bdc3c7', font: { family: 'Plus Jakarta Sans', size: 9 } }
                },
                y_pct: {
                    type: 'linear',
                    position: 'left',
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(189, 195, 199, 0.05)' },
                    ticks: { color: '#bdc3c7', font: { size: 9 }, callback: value => `${value}%` }
                },
                y_cnt: {
                    type: 'linear',
                    position: 'right',
                    min: 0,
                    grid: { display: false },
                    ticks: { color: '#bdc3c7', font: { size: 9 }, stepSize: 1 }
                }
            }
        }
    });

    // 2. Protocol Distribution Chart (Doughnut)
    const ctxProtocol = document.getElementById("offline-protocol-chart").getContext("2d");
    if (offlineProtocolChart) {
        offlineProtocolChart.destroy();
    }
    
    const protocols = data.protocols || [];
    const protocolLabels = protocols.map(p => p.name);
    const protocolValues = protocols.map(p => p.value);
    const protocolColors = ['#00f2fe', '#3b82f6', '#f59e0b', '#10b981', '#ef4444'];
    
    offlineProtocolChart = new Chart(ctxProtocol, {
        type: 'doughnut',
        data: {
            labels: protocolLabels,
            datasets: [{
                data: protocolValues,
                backgroundColor: protocolColors.slice(0, protocolLabels.length),
                borderWidth: 1,
                borderColor: '#1e293b'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#bdc3c7', font: { family: 'Plus Jakarta Sans', size: 9 } }
                }
            }
        }
    });

    // 3. Attack Distribution Chart (Horizontal Bar)
    const ctxAttack = document.getElementById("offline-attack-chart").getContext("2d");
    if (offlineAttackChart) {
        offlineAttackChart.destroy();
    }
    
    const attacks = data.attacks || [];
    const attackLabels = attacks.map(a => a.name);
    const attackValues = attacks.map(a => a.value);
    
    offlineAttackChart = new Chart(ctxAttack, {
        type: 'bar',
        data: {
            labels: attackLabels,
            datasets: [{
                label: 'Flow Count',
                data: attackValues,
                backgroundColor: 'rgba(255, 42, 95, 0.75)',
                borderColor: '#ff2a5f',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(189, 195, 199, 0.05)' },
                    ticks: { color: '#bdc3c7', font: { family: 'Plus Jakarta Sans', size: 9 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#bdc3c7', font: { family: 'Plus Jakarta Sans', size: 9 } }
                }
            }
        }
    });
}

function renderOfflineFlows() {
    const listContainer = document.getElementById("offline-alerts-list");
    listContainer.innerHTML = "";

    // Set badges
    const numThreats = currentOfflineFlows.alerts.length;
    const numBenign = currentOfflineFlows.benign.length;
    const numAll = numThreats + numBenign;

    const bAll = document.getElementById("badge-off-all");
    const bThreats = document.getElementById("badge-off-threats");
    const bBenign = document.getElementById("badge-off-benign");
    if (bAll) bAll.textContent = numAll;
    if (bThreats) bThreats.textContent = numThreats;
    if (bBenign) bBenign.textContent = numBenign;

    let displayFlows = [];
    if (currentOfflineFilter === "all") {
        displayFlows = [...currentOfflineFlows.alerts, ...currentOfflineFlows.benign];
    } else if (currentOfflineFilter === "threats") {
        displayFlows = currentOfflineFlows.alerts;
    } else if (currentOfflineFilter === "benign") {
        displayFlows = currentOfflineFlows.benign;
    }

    if (displayFlows.length === 0) {
        listContainer.innerHTML = `
            <div class="alerts-empty">
                <i class="fa-solid fa-shield-check"></i>
                <p>Clean run. No matching flow indicators found.</p>
            </div>
        `;
        return;
    }

    displayFlows.forEach((flow, idx) => {
        const row = createAnomalyRow(flow, idx, "off");
        listContainer.appendChild(row);
    });
}

// Helper: Generates detailed flow cards (used in both offline and online logs)
function createAnomalyRow(anom, idx, modePrefix) {
    const cardId = `${modePrefix}-alert-${idx}`;
    const row = document.createElement("div");
    const isBenign = anom.prediction === 0;
    row.className = `alert-row ${isBenign ? 'benign' : ''}`;
    row.id = cardId;

    const severityClass = anom.severity.toLowerCase();
    const probSuffix = isBenign ? "Clean" : "";

    row.innerHTML = `
        <div class="alert-summary" onclick="toggleAlertDetails('${cardId}')">
            <div class="alert-ips">
                <span>${anom.src_ip}</span>
                <i class="fa-solid fa-circle-arrow-right"></i>
                <span>${anom.dst_ip}</span>
                <span class="port-num">Port ${anom.dst_port}</span>
            </div>
            <div class="alert-type-badge">
                <span class="severity-pill ${severityClass}">${anom.severity}</span>
                <span class="threat-text">${anom.threat_type}</span>
                <span class="alert-percent">${anom.probability}% ${probSuffix}</span>
            </div>
        </div>
        <div class="alert-details" id="${cardId}-details">
            <div class="flow-features-grid">
                <div class="feature-pill">
                    <span>Flow Duration</span>
                    <strong>${anom.flow_details.flow_duration_s}s</strong>
                </div>
                <div class="feature-pill">
                    <span>Flow Bytes/s</span>
                    <strong>${anom.flow_details.flow_byts_s.toLocaleString()}</strong>
                </div>
                <div class="feature-pill">
                    <span>Flow Packets/s</span>
                    <strong>${anom.flow_details.flow_pkts_s.toLocaleString()}</strong>
                </div>
                <div class="feature-pill">
                    <span>Total Packets</span>
                    <strong>${anom.flow_details.total_pkts}</strong>
                </div>
                <div class="feature-pill">
                    <span>Mean Packet Len</span>
                    <strong>${anom.flow_details.pkt_len_mean} B</strong>
                </div>
                <div class="feature-pill">
                    <span>TCP Flags (S/R/F)</span>
                    <strong>${anom.flow_details.syn_flag} / ${anom.flow_details.rst_flag} / ${anom.flow_details.fin_flag}</strong>
                </div>
            </div>
            <div class="alert-details-footer">
                <button class="btn btn-secondary" onclick="openSHAPModal('${encodeURIComponent(JSON.stringify(anom.shap_explanation))}', '${anom.threat_type}', ${anom.probability})">
                    <i class="fa-solid fa-magnifying-glass-chart"></i> Explain Flow (SHAP)
                </button>
            </div>
        </div>
    `;
    return row;
}

window.toggleAlertDetails = function(cardId) {
    const details = document.getElementById(`${cardId}-details`);
    details.classList.toggle("active");
};

// ── Mode 2: Online Real-Time Sniffing ──────────────────────────────────────
let onlineTimer = null;
let snifferActive = false;
const pollIntervalMs = 2000;  // Poll backend stats count every 2 seconds
let inferenceWindowMs = 30000; // Complete prediction cycle runs dynamically
let inferenceElapsedMs = 0;
const tickRateMs = 200; // Update UI progress bar every 200ms

function initOnlineSniffer() {
    const form = document.getElementById("online-config-form");
    form.addEventListener("submit", (e) => {
        e.preventDefault();
        toggleSniffer();
    });
}

function toggleSniffer() {
    const btn = document.getElementById("btn-toggle-sniff");
    const currentMode = document.getElementById("current-mode");
    const statusDot = document.getElementById("global-status-dot");
    const statusText = document.getElementById("global-status-text");
    const timerBox = document.getElementById("sliding-window-timer-box");

    if (snifferActive) {
        // Stop
        fetch("/api/online/stop", { method: "POST" })
        .then(res => res.json())
        .then(() => {
            snifferActive = false;
            clearInterval(onlineTimer);
            btn.innerHTML = `<i class="fa-solid fa-play"></i> Start Active Sniffing`;
            btn.classList.remove("running");
            statusDot.className = "status-dot green";
            statusText.textContent = "Sniffer Idle";
            timerBox.classList.add("hidden");
            toggleFormFields(false);
            
            // Clear current logs & filters
            currentOnlineFlows = { alerts: [], benign: [] };
            currentOnlineFilter = "all";
            const onlineTabs = document.querySelectorAll("#online-filter-tabs .filter-tab");
            onlineTabs.forEach(t => {
                if (t.dataset.filter === "all") t.classList.add("active");
                else t.classList.remove("active");
            });
            document.getElementById("online-packet-count").textContent = "0";
            document.getElementById("online-flow-count").textContent = "0";
            document.getElementById("online-threat-ratio").textContent = "0.00%";
            document.getElementById("online-anomalies-count").textContent = "0";
            const benignCountEl = document.getElementById("online-benign-count");
            if (benignCountEl) benignCountEl.textContent = "0";
        });
    } else {
        // Start
        const formData = new FormData(document.getElementById("online-config-form"));
        const windowInput = document.getElementById("sniff-window");
        const windowSec = parseInt(windowInput.value) || 30;
        inferenceWindowMs = windowSec * 1000;

        toggleFormFields(true);

        // Update headers and badge dynamically
        document.getElementById("page-subtitle").textContent = `${windowSec}-Second Sliding Context Window Analysis`;
        const badge = document.querySelector(".main-viz .badge");
        if (badge) {
            badge.textContent = `Sliding ${windowSec}s Window`;
        }

        fetch("/api/online/start", {
            method: "POST",
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            snifferActive = true;
            btn.innerHTML = `<i class="fa-solid fa-stop"></i> Stop Active Sniffing`;
            btn.classList.add("running");
            
            const isSim = data.simulated;
            statusDot.className = "status-dot red";
            statusText.textContent = isSim ? "Simulation Snipe Active" : "Sniffing Live Traffic";
            timerBox.classList.remove("hidden");

            // Clear logs
            document.getElementById("online-alerts-empty").classList.remove("hidden");
            document.getElementById("online-alerts-list").innerHTML = "";

            startSnifferTimerLoop();
        })
        .catch(err => {
            toggleFormFields(false);
            alert("Failed to start sniffing: " + err.message);
        });
    }
}

function toggleFormFields(disabled) {
    document.getElementById("sniff-interface").disabled = disabled;
    document.getElementById("sniff-ip").disabled = disabled;
    document.getElementById("sniff-port").disabled = disabled;
    document.getElementById("sniff-window").disabled = disabled;
    document.getElementById("sniff-simulated").disabled = disabled;
}

function startSnifferTimerLoop() {
    inferenceElapsedMs = 0;
    const progressFill = document.getElementById("timer-progress-fill");
    const timerSeconds = document.getElementById("timer-seconds");

    // Clear previous loop
    if (onlineTimer) clearInterval(onlineTimer);

    // Initial load
    fetchOnlineData();

    onlineTimer = setInterval(() => {
        inferenceElapsedMs += tickRateMs;
        
        // Update countdown percentage
        const progressPct = (inferenceElapsedMs / inferenceWindowMs) * 100;
        progressFill.style.width = `${progressPct}%`;
        
        const secondsRemaining = Math.max(0, Math.ceil((inferenceWindowMs - inferenceElapsedMs) / 1000));
        timerSeconds.textContent = `${secondsRemaining}s`;

        // 30-Second Inference Cycle Trigger
        if (inferenceElapsedMs >= inferenceWindowMs) {
            inferenceElapsedMs = 0;
            fetchOnlineData();
        } else if (inferenceElapsedMs % pollIntervalMs === 0) {
            // intermediate small poll to show active packet volume counter in buffer
            pollIntermediateStats();
        }
    }, tickRateMs);
}

function pollIntermediateStats() {
    fetch("/api/online/status")
    .then(res => res.json())
    .then(data => {
        document.getElementById("online-packet-count").textContent = data.packet_count.toLocaleString();
    });
}

function fetchOnlineData() {
    fetch("/api/online/data")
    .then(res => res.json())
    .then(data => {
        const snap = data.snapshot;
        
        // Update stats
        document.getElementById("online-packet-count").textContent = snap.total_packets.toLocaleString();
        document.getElementById("online-flow-count").textContent = snap.total_flows.toLocaleString();
        document.getElementById("online-threat-ratio").textContent = `${snap.threat_ratio}%`;
        document.getElementById("online-anomalies-count").textContent = snap.anomalies_count.toLocaleString();
        const benignCountEl = document.getElementById("online-benign-count");
        if (benignCountEl) {
            benignCountEl.textContent = (snap.benign_count || 0).toLocaleString();
        }

        // Update plot
        updateThreatChart(snap.threat_ratio, snap.anomalies_count, snap.benign_count || 0);

        // Store flows globally
        currentOnlineFlows.alerts = snap.alerts || [];
        currentOnlineFlows.benign = snap.benign_flows || [];

        renderOnlineFlows();
    });
}

function renderOnlineFlows() {
    const emptyEl = document.getElementById("online-alerts-empty");
    const listEl = document.getElementById("online-alerts-list");
    listEl.innerHTML = "";

    // Set badges
    const numThreats = currentOnlineFlows.alerts.length;
    const numBenign = currentOnlineFlows.benign.length;
    const numAll = numThreats + numBenign;

    const bAll = document.getElementById("badge-on-all");
    const bThreats = document.getElementById("badge-on-threats");
    const bBenign = document.getElementById("badge-on-benign");
    if (bAll) bAll.textContent = numAll;
    if (bThreats) bThreats.textContent = numThreats;
    if (bBenign) bBenign.textContent = numBenign;

    let displayFlows = [];
    if (currentOnlineFilter === "all") {
        displayFlows = [...currentOnlineFlows.alerts, ...currentOnlineFlows.benign];
    } else if (currentOnlineFilter === "threats") {
        displayFlows = currentOnlineFlows.alerts;
    } else if (currentOnlineFilter === "benign") {
        displayFlows = currentOnlineFlows.benign;
    }

    if (displayFlows.length === 0) {
        emptyEl.classList.remove("hidden");
    } else {
        emptyEl.classList.add("hidden");
        displayFlows.forEach((flow, idx) => {
            const row = createAnomalyRow(flow, idx, "on");
            listEl.appendChild(row);
        });
    }
}

function initFilterTabs() {
    // Online filter tab setup
    const onlineTabs = document.querySelectorAll("#online-filter-tabs .filter-tab");
    onlineTabs.forEach(tab => {
        tab.addEventListener("click", () => {
            onlineTabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            currentOnlineFilter = tab.dataset.filter;
            renderOnlineFlows();
        });
    });

    // Offline filter tab setup
    const offlineTabs = document.querySelectorAll("#offline-filter-tabs .filter-tab");
    offlineTabs.forEach(tab => {
        tab.addEventListener("click", () => {
            offlineTabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            currentOfflineFilter = tab.dataset.filter;
            renderOfflineFlows();
        });
    });
}

// ── SHAP Explainability Popup Modal ───────────────────────────────────────
function initModal() {
    const modal = document.getElementById("shap-modal");
    const btnClose = document.getElementById("btn-close-modal");

    btnClose.addEventListener("click", () => {
        modal.classList.add("hidden");
    });

    // Close on backdrop click
    modal.addEventListener("click", (e) => {
        if (e.target === modal) {
            modal.classList.add("hidden");
        }
    });
}

window.openSHAPModal = function(encodedShap, threatType, probability) {
    const shapData = JSON.parse(decodeURIComponent(encodedShap));
    const modal = document.getElementById("shap-modal");
    const threatTitle = document.getElementById("shap-threat-type");
    const container = document.getElementById("shap-bars-container");

    threatTitle.textContent = `${threatType} (${probability}% Probability)`;
    container.innerHTML = "";

    // Find max absolute value to normalize bar widths to 100% max
    const maxVal = Math.max(...shapData.map(d => Math.abs(d.impact)), 0.001);

    shapData.forEach(item => {
        const row = document.createElement("div");
        row.className = "shap-bar-row";

        const isPositive = item.impact >= 0;
        const widthPct = (Math.abs(item.impact) / maxVal) * 100;
        const impactSign = isPositive ? "+" : "-";

        row.innerHTML = `
            <div class="shap-bar-label">${item.feature}</div>
            <div class="shap-bar-track">
                <div class="shap-bar-val ${isPositive ? 'positive' : 'negative'}" style="width: ${widthPct}%"></div>
            </div>
            <div class="shap-bar-text ${isPositive ? 'positive' : 'negative'}">
                ${impactSign}${Math.abs(item.impact).toFixed(4)}
            </div>
        `;
        container.appendChild(row);
    });

    modal.classList.remove("hidden");
};
