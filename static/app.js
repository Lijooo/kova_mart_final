// Kova Mart Secure AI Dashboard Logic (SQLite-backed REST Integration)

// Global Error Handler for debugging
window.onerror = function(message, source, lineno, colno, error) {
    const errorMsg = `Error: ${message} at ${source.split('/').pop()}:${lineno}:${colno}`;
    console.error(errorMsg);
    if (typeof showToast === 'function') {
        showToast("JavaScript Error", errorMsg, "critical");
    } else {
        alert(errorMsg);
    }
    return false;
};
let allTransactions = [];
let filteredTransactions = [];
let allAlerts = [];
let filteredAlerts = [];
let allMembers = [];
let statsData = {};
let autoBlockEnabled = false;
let pollingInterval = null;
let maxAlertIdSeen = 0;
let lastSeenAlertId = localStorage.getItem('kovamart_last_seen_alert_id') !== null 
                      ? parseInt(localStorage.getItem('kovamart_last_seen_alert_id')) 
                      : null;

// Pagination state
let currentPage = 1;
const rowsPerPage = 12;

// Sorting state
let currentSortCol = 'customer_id';
let currentSortDir = 'asc';

// Chart instances
let chartRiskDist = null;
let chartFraudTrend = null;
let chartRiskFactors = null;

// Auditor Current Target (Can be a transaction, member, or alert)
let activeAuditTarget = null;
let activeAuditType = null;

// Helper to parse raw user agent strings into readable Device, OS, Browser info
function parseDeviceSignature(ua) {
    if (!ua) return { device: 'Unknown Device', os: 'Unknown OS', browser: 'Unknown Browser', formatted: 'Unknown' };

    let os = 'Unknown OS';
    let device = 'Unknown Device';
    let browser = 'Unknown Browser';

    // 1. Parse OS
    if (ua.includes('Android')) {
        const match = ua.match(/Android\s+([0-9.]+)/);
        os = match ? `Android ${match[1]}` : 'Android';
    } else if (ua.includes('iPhone') || ua.includes('iPad') || ua.includes('iPod')) {
        const match = ua.match(/OS\s+([0-9_]+)/);
        os = match ? `iOS ${match[1].replace(/_/g, '.')}` : 'iOS';
    } else if (ua.includes('Windows NT')) {
        const match = ua.match(/Windows NT\s+([0-9.]+)/);
        if (match) {
            const ver = match[1];
            if (ver === '10.0') os = 'Windows 10/11';
            else if (ver === '6.3') os = 'Windows 8.1';
            else if (ver === '6.2') os = 'Windows 8';
            else if (ver === '6.1') os = 'Windows 7';
            else os = `Windows NT ${ver}`;
        } else {
            os = 'Windows';
        }
    } else if (ua.includes('Macintosh') || ua.includes('Mac OS X')) {
        os = 'macOS';
    } else if (ua.includes('Linux')) {
        os = 'Linux';
    }

    // 2. Parse Browser
    if (ua.includes('Edg/') || ua.includes('Edge/')) {
        browser = 'Edge';
    } else if (ua.includes('OPR/') || ua.includes('Opera/')) {
        browser = 'Opera';
    } else if (ua.includes('Chrome/')) {
        browser = 'Chrome';
    } else if (ua.includes('Firefox/')) {
        browser = 'Firefox';
    } else if (ua.includes('Safari/')) {
        browser = 'Safari';
    }

    // 3. Parse Device Model
    const parenMatch = ua.match(/\(([^)]+)\)/);
    if (parenMatch) {
        const parts = parenMatch[1].split(';').map(s => s.trim());
        const brands = ['Samsung', 'iPhone', 'iPad', 'Xiaomi', 'Oppo', 'Vivo', 'Realme', 'Poco', 'Redmi', 'OnePlus', 'Huawei', 'Pixel'];
        let foundDevice = null;
        
        for (const part of parts) {
            if (brands.some(brand => part.toLowerCase().includes(brand.toLowerCase()))) {
                foundDevice = part;
                break;
            }
        }

        if (foundDevice) {
            device = foundDevice;
        } else {
            if (ua.includes('iPhone')) {
                device = 'iPhone';
            } else if (ua.includes('iPad')) {
                device = 'iPad';
            } else if (ua.includes('Windows') || ua.includes('Macintosh')) {
                device = 'Desktop PC';
            } else if (parts.length >= 3) {
                device = parts[2];
            } else if (parts.length === 2 && ua.includes('Android')) {
                device = parts[1];
            } else {
                device = parts[0];
            }
        }
    } else {
        if (ua.includes('iPhone')) device = 'iPhone';
        else if (ua.includes('Windows') || ua.includes('Macintosh')) device = 'Desktop PC';
    }

    const partsList = [];
    if (device && device !== 'Unknown Device') partsList.push(device);
    if (os && os !== 'Unknown OS') partsList.push(os);
    if (browser && browser !== 'Unknown Browser') partsList.push(browser);
    
    const formatted = partsList.length > 0 ? partsList.join(' · ') : ua;

    return { device, os, browser, formatted };
}

// Renders the device audit details into the auditor slide-over panel
function getDeviceAuditHTML(member, isNewDevice) {
    if (!member) return '';
    const ua = member.device_info || member.device || '';
    const parsed = parseDeviceSignature(ua);
    
    // Count accounts registered on the same device signature
    const sameDeviceCount = allMembers.filter(m => m.device_info === ua).length || 1;
    
    let deviceRiskMeaning = '';
    if (sameDeviceCount > 1) {
        deviceRiskMeaning = `Used by ${sameDeviceCount} accounts — possible duplicate account risk.`;
    } else if (isNewDevice) {
        deviceRiskMeaning = "New device — review if combined with other risk signals.";
    } else {
        deviceRiskMeaning = "Known device for this member.";
    }

    const colorStyle = (sameDeviceCount > 1 || isNewDevice) ? 'var(--color-critical)' : 'var(--color-legit)';

    return `
        <div class="glass-panel" style="padding: 16px; margin-top: 16px; border: 1px solid rgba(255,255,255,0.05); background: rgba(255,255,255,0.01);">
            <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">
                <i data-lucide="smartphone" style="width: 16px; height: 16px; color: #3b82f6;"></i>
                Device & Browser Audit
            </div>
            <div class="detail-grid" style="grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px;">
                <div>
                    <div class="detail-item-label">Device Used</div>
                    <div class="detail-item-val">${parsed.device}</div>
                </div>
                <div>
                    <div class="detail-item-label">Browser</div>
                    <div class="detail-item-val">${parsed.browser}</div>
                </div>
                <div>
                    <div class="detail-item-label">Operating System</div>
                    <div class="detail-item-val">${parsed.os}</div>
                </div>
                <div>
                    <div class="detail-item-label">Accounts on Same Device</div>
                    <div class="detail-item-val">${sameDeviceCount} accounts</div>
                </div>
            </div>
            <div style="margin-top: 12px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.05); font-size: 13px;">
                <div class="detail-item-label">Device Risk Meaning</div>
                <div style="font-weight: 600; color: ${colorStyle}; margin-top: 2px;">
                    ${deviceRiskMeaning}
                </div>
            </div>
            <div style="margin-top: 10px;">
                <details style="cursor: pointer; font-size: 12px; color: var(--text-muted);">
                    <summary style="outline: none; user-select: none;">Technical details</summary>
                    <div style="margin-top: 4px; padding: 6px; background: rgba(0,0,0,0.2); border-radius: 4px; font-family: monospace; word-break: break-all; font-size: 11px;">
                        ${ua}
                    </div>
                </details>
            </div>
        </div>
    `;
}

function toggleSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    if (sidebar && overlay) {
        sidebar.classList.toggle('active');
        overlay.classList.toggle('active');
    }
}

// Initial Load
document.addEventListener("DOMContentLoaded", () => {
    // Initialize Icons
    lucide.createIcons();
   
    // Load Auto-Block State from LocalStorage (kept for user preference)
    autoBlockEnabled = localStorage.getItem('kovamart_autoblock') === 'true';
    document.getElementById('auto-block-checkbox').checked = autoBlockEnabled;
    const sidebarCheckbox = document.getElementById('sidebar-auto-block-checkbox');
    if (sidebarCheckbox) {
        sidebarCheckbox.checked = autoBlockEnabled;
    }
   
    // Fetch dashboard data immediately
    loadAllData();
   
    // Start background poller (every 10 seconds to sync database changes in real-time)
    startDatabasePoller();
});

// View Routing switcher
function switchView(viewName) {
    // Close sidebar on mobile/tablet after navigating
    const sidebar = document.getElementById('app-sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    if (sidebar && sidebar.classList.contains('active')) {
        sidebar.classList.remove('active');
        overlay.classList.remove('active');
    }

    // Hide all view containers
    document.querySelectorAll('.view-container').forEach(el => {
        el.classList.remove('active');
    });
   
    // Show selected container
    const selectedView = document.getElementById(`view-${viewName}`);
    if (selectedView) {
        selectedView.classList.add('active');
    }
   
    // Highlight sidebar button
    document.querySelectorAll('.menu-item-btn').forEach(btn => {
        btn.classList.remove('active');
    });
   
    // Add active class to corresponding menu button
    const activeBtn = Array.from(document.querySelectorAll('.menu-item-btn')).find(btn => {
        const onclickAttr = btn.getAttribute('onclick') || '';
        return onclickAttr.includes(`'${viewName}'`) || onclickAttr.includes(`"${viewName}"`);
    });
    if (activeBtn) {
        activeBtn.classList.add('active');
    }
   
    // Update top header title
    const titles = {
        'dashboard': 'Dashboard Overview',
        'alerts': 'Alert Center (Threat Incidents Log)',
        'operations': 'Operations Console',
        'members': 'Member Registry & Enrollment',
        'simulator': 'Interactive Risk Simulator',
        'upload': 'Batch Data Processing Engine',
        'reports': 'Compliance & Audit Reporting',
        'audit-doc': 'Alert Audit Document'
    };
    document.getElementById('view-title').textContent = titles[viewName] || 'Overview';
   
    // Specific view actions
    if (viewName === 'dashboard') {
        renderAllCharts();
    } else if (viewName === 'reports') {
        loadComplianceReports();
    } else if (viewName === 'alerts') {
        fetchAlerts();
    } else if (viewName === 'members') {
        fetchMembers();
    } else if (viewName === 'audit-doc') {
        fetchAlerts(true);
    }
}

// Fetch all initial data from backend APIs
async function loadAllData() {
    try {
        // 1. Fetch Stats API
        const statsRes = await fetch('/api/stats');
        const statsJson = await statsRes.json();
        if (statsJson.status === 'success') {
            statsData = statsJson;
            await fetchAlerts(true);
            updateOverviewStats();
            updateDashboardRecentActivity(statsJson);
            checkForNewAlerts(statsJson.recent_alerts);
        }
       
        // 2. Fetch Transactions API
        const txRes = await fetch('/api/transactions');
        const txJson = await txRes.json();
        if (txJson.status === 'success') {
            allTransactions = txJson.transactions;
            handleFilterChange(); // Initial filter & sort for operations table
            renderAllCharts();    // Build visual graphics
        }
    } catch (e) {
        console.error("Error loading dashboard data: ", e);
        showToast("Error loading system metrics", "Could not connect to Flask API server.", "critical");
    }
}

// Check if any critical/high alert has newly arrived and fire a Toast
function checkForNewAlerts(recentAlerts) {
    if (!recentAlerts || recentAlerts.length === 0) return;
    
    // On first load, record the highest alert ID
    if (maxAlertIdSeen === 0) {
        maxAlertIdSeen = Math.max(...recentAlerts.map(a => a.id));
        return;
    }
    
    recentAlerts.forEach(alt => {
        if (alt.id > maxAlertIdSeen) {
            maxAlertIdSeen = alt.id;
            // Trigger toast for new alerts (Open status)
            if (alt.status === 'Open') {
                showToast(
                    `🚨 Security Threat (${alt.severity_level})`,
                    `Alert ${alt.alert_id} generated for ${alt.customer_name}: ${alt.fraud_indicators_triggered.join(', ')}`,
                    alt.severity_level.toLowerCase()
                );
            }
        }
    });
}

// Populate stats numbers in dashboard widgets
function updateOverviewStats() {
    if (!statsData.metrics) return;
    const m = statsData.metrics;
   
    document.getElementById('stats-total-tx').textContent = m.total_transactions.toLocaleString();
    document.getElementById('stats-avg-risk').textContent = m.average_risk_score.toFixed(1) + '%';
    document.getElementById('stats-fraud-rate').textContent = m.fraud_rate_pct.toFixed(2);
    document.getElementById('stats-fraud-detected').textContent = `${m.fraud_detected.toLocaleString()} rule-flagged (not verified fraud)`;
    
    document.getElementById('stats-total-members').textContent = m.total_members.toLocaleString();
    document.getElementById('stats-active-members').textContent = m.active_members.toLocaleString();
    document.getElementById('stats-flagged-members').textContent = m.flagged_members.toLocaleString();
    document.getElementById('stats-critical-alerts').textContent = m.critical_alerts.toLocaleString();
    
    // Update alert count badge in top header
    updateAlertBellBadge(m.unresolved_alerts);
}

// Update dashboard activity panels
function updateDashboardRecentActivity(statsJson) {
    // Recent registrations
    const regTbody = document.getElementById('dashboard-recent-registrations');
    regTbody.innerHTML = '';
    if (statsJson.recent_registrations && statsJson.recent_registrations.length > 0) {
        statsJson.recent_registrations.forEach(rm => {
            const tr = document.createElement('tr');
            let badgeClass = 'status-approved';
            if (rm.verification_status === 'Flagged' || rm.verification_status === 'Blocked') badgeClass = 'status-blocked';
            else if (rm.verification_status === 'Under Review') badgeClass = 'status-review';
            
            tr.innerHTML = `
                <td><strong>${rm.name}</strong></td>
                <td style="font-family: monospace;">${rm.nik}</td>
                <td><span class="status-badge ${badgeClass}">${rm.verification_status}</span></td>
            `;
            regTbody.appendChild(tr);
        });
    } else {
        regTbody.innerHTML = `<tr><td colspan="3" style="text-align:center; color:var(--text-muted);">No members registered yet</td></tr>`;
    }

    // Recent Alerts
    const alertTbody = document.getElementById('dashboard-recent-alerts');
    alertTbody.innerHTML = '';
    if (statsJson.recent_alerts && statsJson.recent_alerts.length > 0) {
        statsJson.recent_alerts.forEach(ra => {
            const tr = document.createElement('tr');
            
            let badgeClass = 'badge-low';
            const sev = (ra.severity_level || '').toUpperCase();
            if (sev === 'CRITICAL') badgeClass = 'badge-critical';
            else if (sev === 'HIGH') badgeClass = 'badge-high';
            else if (sev === 'MEDIUM') badgeClass = 'badge-medium';
            
            let statusBadge = `status-pending`;
            if (ra.status === 'Resolved') statusBadge = 'status-approved';
            else if (ra.status === 'Under Review') statusBadge = 'status-review';

            tr.innerHTML = `
                <td style="font-weight:600; font-family: monospace;">${ra.alert_id}</td>
                <td>${ra.customer_name} (#${ra.customer_id})</td>
                <td style="font-size:11px; max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${ra.fraud_indicators_triggered.join(', ')}">
                    ${ra.fraud_indicators_triggered.join(', ')}
                </td>
                <td><strong>${ra.risk_score}%</strong></td>
                <td><span class="badge ${badgeClass}"><span class="badge-dot"></span>${ra.severity_level}</span></td>
                <td><span class="status-badge ${statusBadge}">${ra.status}</span></td>
            `;
            alertTbody.appendChild(tr);
        });
    } else {
        alertTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No security alerts generated</td></tr>`;
    }
}

// Background Database Poller (Runs every 10 seconds)
function startDatabasePoller() {
    pollingInterval = setInterval(() => {
        loadAllData();
        // If Alert Audit Document is currently visible, refresh alerts in background
        const auditDocView = document.getElementById('view-audit-doc');
        if (auditDocView && auditDocView.classList.contains('active')) {
            fetchAlerts(true);
        }
    }, 10000);
}

// ─── ALERTS CENTER INCIDENTS VIEW ────────────────────────────────────────────
async function fetchAlerts(silent = false) {
    try {
        const res = await fetch('/api/alerts');
        const json = await res.json();
        if (json.status === 'success') {
            allAlerts = json.alerts;
            
            // On very first fetch, if lastSeenAlertId is null, initialize it to the highest ID
            if (lastSeenAlertId === null) {
                if (allAlerts.length > 0) {
                    const maxId = Math.max(...allAlerts.map(a => a.id));
                    lastSeenAlertId = maxId;
                    localStorage.setItem('kovamart_last_seen_alert_id', maxId);
                } else {
                    lastSeenAlertId = 0;
                    localStorage.setItem('kovamart_last_seen_alert_id', 0);
                }
            }
            
            const auditDocTable = document.getElementById('audit-doc-table-body');
            if (auditDocTable) handleAuditDocFilter();
            
            updateAlertBellBadge();
        }
    } catch (e) {
        console.error("Alerts fetching error: ", e);
        if (!silent) showToast("Error loading alerts log", "API request failed.", "critical");
    }
}

function handleAlertsFilter() {
    const searchVal = document.getElementById('alerts-search-input').value.toLowerCase().trim();
    const severityFilter = document.getElementById('filter-alert-severity').value;
    const statusFilter = document.getElementById('filter-alert-status').value;
    
    filteredAlerts = allAlerts.filter(alt => {
        const matchSearch = alt.alert_id.toLowerCase().includes(searchVal) ||
                            alt.customer_name.toLowerCase().includes(searchVal) ||
                            alt.customer_id.toString().includes(searchVal);
                            
        const matchSeverity = (severityFilter === 'ALL' || (alt.severity_level || '').toUpperCase() === severityFilter.toUpperCase());
        const matchStatus = (statusFilter === 'ALL' || alt.status === statusFilter);
        
        return matchSearch && matchSeverity && matchStatus;
    });
    
    renderAlertsTable();
}


// ─── MEMBER REGISTRATION MANAGEMENT ──────────────────────────────────────────
async function fetchMembers(silent = false) {
    try {
        const res = await fetch('/api/members');
        const json = await res.json();
        if (json.status === 'success') {
            allMembers = json.members;
            const table = document.getElementById('members-table-body');
            if (table) renderMembersTable();
        }
    } catch (e) {
        console.error("Members fetching error: ", e);
        if (!silent) showToast("Error loading members registry", "API connection failed.", "critical");
    }
}


// ─── OPERATIONS CONSOLE SEARCH & SORTING ─────────────────────────────────────
function handleFilterChange() {
    const searchVal = document.getElementById('op-search-input').value.toLowerCase().trim();
    const riskFilter = document.getElementById('filter-risk').value;
    const channelFilter = document.getElementById('filter-channel').value;
    const statusFilter = document.getElementById('filter-status').value;
   
    filteredTransactions = allTransactions.filter(tx => {
        // 1. Search Query
        const matchSearch = tx.customer_id.toString().includes(searchVal) ||
                            tx.customer_name.toLowerCase().includes(searchVal) ||
                            tx.transaction_amount.toString().includes(searchVal);
       
        // 2. Risk score matching
        const score = tx.final_pct || tx.risk_pct || 0;
        let lvl = '🟢 LOW';
        if (score >= 80) lvl = '🔴 CRITICAL';
        else if (score >= 55) lvl = '🟠 HIGH';
        else if (score >= 40) lvl = '🟡 MEDIUM';
        const matchRisk = (riskFilter === 'ALL' || riskFilter === lvl);
       
        // 3. Kiosk vs App matching
        const kioskVal = tx["app(0) vs kiosk(1)transaction"];
        const matchChannel = (channelFilter === 'ALL' || channelFilter === kioskVal.toString());
       
        // 4. Auditor decision status matching
        const matchStatus = (statusFilter === 'ALL' || statusFilter === tx.status);
       
        return matchSearch && matchRisk && matchChannel && matchStatus;
    });
   
    currentPage = 1; // Reset to page 1
    sortTransactions();
}

function handleSort(column) {
    if (currentSortCol === column) {
        currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
    } else {
        currentSortCol = column;
        currentSortDir = 'asc';
    }
   
    const cols = ['customer_id', 'Initial_Subsidy', 'transaction_amount', 'Subsidy_balance', 'final_pct', 'level', 'status'];
    cols.forEach(c => {
        const el = document.getElementById(`sort-icon-${c}`);
        if (el) el.textContent = '';
    });
   
    const caret = currentSortDir === 'asc' ? ' ▴' : ' ▾';
    document.getElementById(`sort-icon-${column}`).textContent = caret;
   
    sortTransactions();
}

function sortTransactions() {
    filteredTransactions.sort((a, b) => {
        let valA = a[currentSortCol];
        let valB = b[currentSortCol];
       
        if (currentSortCol === 'final_pct') {
            valA = a.final_pct || a.risk_pct || 0;
            valB = b.final_pct || b.risk_pct || 0;
        }
       
        if (typeof valA === 'string') {
            return currentSortDir === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
        } else {
            return currentSortDir === 'asc' ? valA - valB : valB - valA;
        }
    });
   
    renderOperationsTable();
}

function renderOperationsTable() {
    const tbody = document.getElementById('operations-table-body');
    tbody.innerHTML = '';
   
    const totalCount = filteredTransactions.length;
    const startIndex = (currentPage - 1) * rowsPerPage;
    const endIndex = Math.min(startIndex + rowsPerPage, totalCount);
   
    const pageRecords = filteredTransactions.slice(startIndex, endIndex);
   
    if (pageRecords.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">No matching transactions found</td></tr>`;
        document.getElementById('pagination-info-text').textContent = 'Showing 0 to 0 of 0 transactions';
        document.getElementById('pagination-prev').disabled = true;
        document.getElementById('pagination-next').disabled = true;
        return;
    }
   
    pageRecords.forEach(tx => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.onclick = () => openAuditorPanel(tx, 'transaction');
       
        const score = tx.final_pct || tx.risk_pct || 0;
        let badgeHtml = `<span class="badge badge-low"><span class="badge-dot"></span>Low (${score}%)</span>`;
        if (score >= 80) badgeHtml = `<span class="badge badge-critical"><span class="badge-dot"></span>Critical (${score}%)</span>`;
        else if (score >= 55) badgeHtml = `<span class="badge badge-high"><span class="badge-dot"></span>High (${score}%)</span>`;
        else if (score >= 40) badgeHtml = `<span class="badge badge-medium"><span class="badge-dot"></span>Medium (${score}%)</span>`;
       
        let statusBadgeClass = `status-${tx.status}`;
        let statusLabel = tx.status === 'review' ? 'Review' : tx.status;
       
        tr.innerHTML = `
            <td style="font-family: var(--font-heading); font-weight:600;">#${tx.customer_id} (${tx.customer_name || 'Seeded Member'})</td>
            <td>Rp ${parseFloat(tx.Initial_Subsidy).toLocaleString('id-ID')}</td>
            <td style="font-weight: 500;">Rp ${parseFloat(tx.transaction_amount).toLocaleString('id-ID')}</td>
            <td>Rp ${parseFloat(tx.Subsidy_balance).toLocaleString('id-ID')}</td>
            <td><strong>${score}%</strong></td>
            <td>${badgeHtml}</td>
            <td><span class="status-badge ${statusBadgeClass}">${statusLabel}</span></td>
        `;
        tbody.appendChild(tr);
    });
   
    document.getElementById('pagination-info-text').textContent = `Showing ${startIndex + 1} to ${endIndex} of ${totalCount} transactions`;
    document.getElementById('pagination-prev').disabled = currentPage === 1;
    document.getElementById('pagination-next').disabled = endIndex >= totalCount;
}

function changePage(direction) {
    currentPage += direction;
    renderOperationsTable();
}

// Client-side CSV Export
function exportFilteredToCSV() {
    if (filteredTransactions.length === 0) return;
   
    const csvRows = [];
    const headers = [
        "Customer_ID", "Customer_Name", "Initial_Subsidy", "Transaction_Amount", "Subsidy_Balance",
        "Hour_of_Day", "Num_Items", "Failed_Logins", "Payment_Retry",
        "Risk_Score", "Verdict", "Audit_Status", "Notes"
    ];
    csvRows.push(headers.join(","));
   
    filteredTransactions.forEach(tx => {
        const score = tx.final_pct || tx.risk_pct || 0;
        const row = [
            tx.customer_id,
            `"${tx.customer_name || 'Seeded Member'}"`,
            tx.Initial_Subsidy,
            tx.transaction_amount,
            tx.Subsidy_balance,
            tx.hour_of_day,
            tx.num_items,
            tx.failed_login_attempts || 0,
            tx.payment_retry_count || 0,
            score,
            `"${tx.verdict || (score >= 40 ? 'POSSIBLE FRAUD' : 'LEGIT')}"`,
            tx.status,
            `"${(tx.notes || '').replace(/"/g, '""')}"`
        ];
        csvRows.push(row.join(","));
    });
   
    const csvContent = "data:text/csv;charset=utf-8," + csvRows.join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `kovamart_security_operations_export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// ─── AUDITOR SLIDE-OVER INCIDENT PANEL ───────────────────────────────────────
function openAuditorPanel(target, type) {
    activeAuditTarget = target;
    activeAuditType = type; // 'transaction', 'alert', or 'member'
    
    const titleEl = document.getElementById('auditor-panel-title');
    const idTitleEl = document.getElementById('panel-identity-title');
    const idGridEl = document.getElementById('panel-identity-grid');
    const combosSec = document.getElementById('aud-combos-section');
    const combosText = document.getElementById('aud-combos-text');
    const matrixSec = document.getElementById('aud-matrix-section');
    const actionsEl = document.getElementById('aud-decision-actions');
    const notesEl = document.getElementById('aud-notes');
    const logsEl = document.getElementById('aud-logs');
    
    const deviceSec = document.getElementById('aud-device-section');
    if (deviceSec) {
        deviceSec.style.display = 'none';
        deviceSec.innerHTML = '';
    }
    
    // Clear notes field
    notesEl.value = '';
    
    if (type === 'transaction') {
        titleEl.textContent = "Auditor Operations Center";
        idTitleEl.textContent = "Transaction Identity";
        matrixSec.style.display = 'block';
        
        const score = target.final_pct || target.risk_pct || 0;
        const rulesScore = target.rule_based_pct !== undefined ? target.rule_based_pct : 0;
        const aiProb = target.ai_prob !== undefined ? target.ai_prob : 0;

        idGridEl.innerHTML = `
            <div>
                <div class="detail-item-label">Customer ID</div>
                <div class="detail-item-val">#${target.customer_id} (${target.customer_name || 'Seeded'})</div>
            </div>
            <div>
                <div class="detail-item-label">Threat score</div>
                <div class="detail-item-val" style="color:${score >= 55 ? 'var(--color-critical)' : 'var(--color-legit)'}; font-weight:700;">${score}%</div>
            </div>
            <div>
                <div class="detail-item-label">Amount</div>
                <div class="detail-item-val">Rp ${parseFloat(target.transaction_amount).toLocaleString('id-ID')}</div>
            </div>
            <div>
                <div class="detail-item-label">Subsidy Balance</div>
                <div class="detail-item-val">Rp ${parseFloat(target.Subsidy_balance).toLocaleString('id-ID')}</div>
            </div>
            <div>
                <div class="detail-item-label">AI score</div>
                <div class="detail-item-val">${aiProb}%</div>
            </div>
            <div>
                <div class="detail-item-label">Rules score</div>
                <div class="detail-item-val">${rulesScore}%</div>
            </div>
        `;
        
        // Load Flag Matrix
        loadFlagsMatrix(target);
        
        // Setup decision buttons
        actionsEl.innerHTML = `
            <button class="btn btn-approve" style="flex:1;" onclick="applyTransactionAudit('approved')">
                <i data-lucide="check"></i> Approve Tx
            </button>
            <button class="btn btn-block-action" style="flex:1;" onclick="applyTransactionAudit('blocked')">
                <i data-lucide="slash"></i> Block Tx
            </button>
            <button class="btn btn-review" style="flex:1;" onclick="applyTransactionAudit('review')">
                <i data-lucide="eye"></i> Hold Review
            </button>
        `;
        
        // Render history logs
        renderTargetAuditLogs(target.auditHistory);
        
        // Find associated member details & alert details
        const member = allMembers.find(m => m.id === target.customer_id);
        const associatedAlert = allAlerts.find(a => a.target_type === 'transaction' && a.target_id === target.id);
        
        // Update combos section title
        const combosTitleEl = combosSec.querySelector('.detail-section-title');
        if (combosTitleEl) {
            combosTitleEl.textContent = "Associated Customer & Alert Details";
        }
        
        let combosHTML = '';
        if (member) {
            combosHTML += `
                <div style="margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-color);">
                    <div style="font-weight:700; color:var(--text-primary); margin-bottom: 6px; font-size:13px; display:flex; align-items:center; gap:6px;">
                        <i data-lucide="user" style="width:14px; height:14px;"></i> Customer Profile Details
                    </div>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 6px; font-size:12px; color:var(--text-secondary);">
                        <div><span style="color:var(--text-muted);">NIK:</span> <span style="font-family:monospace;">${member.nik}</span></div>
                        <div><span style="color:var(--text-muted);">KKS Card:</span> <span style="font-family:monospace;">${member.kks_card}</span></div>
                        <div><span style="color:var(--text-muted);">Phone:</span> <span>${member.phone}</span></div>
                        <div><span style="color:var(--text-muted);">Status:</span> <span class="status-badge status-${member.verification_status.toLowerCase()}">${member.verification_status}</span></div>
                        <div style="grid-column: span 2;"><span style="color:var(--text-muted);">Address:</span> <span>${member.address}</span></div>
                    </div>
                </div>
            `;
        }
        
        if (associatedAlert) {
            let alertColor = 'var(--color-low)';
            const sev = (associatedAlert.severity_level || '').toUpperCase();
            if (sev === 'CRITICAL') alertColor = 'var(--color-critical)';
            else if (sev === 'HIGH') alertColor = 'var(--color-high)';
            else if (sev === 'MEDIUM') alertColor = 'var(--color-medium)';
            
            combosHTML += `
                <div>
                    <div style="font-weight:700; color:var(--text-primary); margin-bottom: 6px; font-size:13px; display:flex; align-items:center; gap:6px;">
                        <i data-lucide="bell" style="width:14px; height:14px;"></i> Associated Security Alert (${associatedAlert.alert_id})
                    </div>
                    <div style="font-size:12px; color:var(--text-secondary);">
                        <div style="margin-bottom:4px;">
                            <span style="color:var(--text-muted);">Severity:</span> 
                            <span style="color:${alertColor}; font-weight:700;">${associatedAlert.severity_level} (${associatedAlert.risk_score}%)</span>
                            <span style="margin-left: 8px; color:var(--text-muted);">Status:</span> 
                            <span class="status-badge status-${associatedAlert.status === 'Resolved' ? 'approved' : associatedAlert.status === 'Under Review' ? 'review' : 'pending'}">${associatedAlert.status}</span>
                        </div>
                        <div style="margin-bottom:4px;"><span style="color:var(--text-muted);">Vector:</span> <span style="color:var(--color-critical); font-family:monospace;">${associatedAlert.indicators.join(' | ')}</span></div>
                        <div><span style="color:var(--text-muted);">Recommended:</span> <span style="font-style:italic;">${associatedAlert.recommended_action}</span></div>
                    </div>
                </div>
            `;
        } else {
            combosHTML += `
                <div style="font-size:12px; color:var(--text-muted); font-style:italic;">
                    No security alert generated for this transaction (risk score below threat threshold).
                </div>
            `;
        }
        
        combosText.innerHTML = combosHTML;
        combosSec.style.display = 'block';

        // Inject Device Audit info
        if (member && deviceSec) {
            deviceSec.innerHTML = getDeviceAuditHTML(member, target.login_location_changed === 1);
            deviceSec.style.display = 'block';
        }
        
    } else if (type === 'alert') {
        titleEl.textContent = "Incident Threat Response Unit";
        idTitleEl.textContent = "Alert Case Identity";
        combosSec.style.display = 'block';
        matrixSec.style.display = 'none'; // Indicators show in description list
        
        combosText.innerHTML = `
            <div style="font-weight:600; color:var(--text-primary); margin-bottom: 4px;">Triggered Vector Indicators:</div>
            <div style="margin-bottom:8px; color:var(--color-critical); font-family: monospace;">
                ${target.indicators.join(' | ')}
            </div>
            <div style="font-weight:600; color:var(--text-primary); margin-bottom: 4px;">Recommended Response Action:</div>
            <div style="color:var(--text-secondary); font-style:italic;">
                ${target.recommended_action}
            </div>
        `;

        let alertColor = 'var(--color-low)';
        const sev = (target.severity_level || '').toUpperCase();
        if (sev === 'CRITICAL') alertColor = 'var(--color-critical)';
        else if (sev === 'HIGH') alertColor = 'var(--color-high)';
        else if (sev === 'MEDIUM') alertColor = 'var(--color-medium)';

        idGridEl.innerHTML = `
            <div>
                <div class="detail-item-label">Alert Case ID</div>
                <div class="detail-item-val" style="font-family: monospace;">${target.alert_id}</div>
            </div>
            <div>
                <div class="detail-item-label">Incident Threat Score</div>
                <div class="detail-item-val" style="color:${alertColor}; font-weight:700;">${target.risk_score}% (${target.severity_level})</div>
            </div>
            <div>
                <div class="detail-item-label">Target Type</div>
                <div class="detail-item-val">${target.target_type.toUpperCase()} (#${target.target_id})</div>
            </div>
            <div>
                <div class="detail-item-label">Customer Profile</div>
                <div class="detail-item-val">${target.customer_name} (ID: #${target.customer_id})</div>
            </div>
            <div>
                <div class="detail-item-label">Detection Time</div>
                <div class="detail-item-val" style="font-size:11px;">${new Date(target.detection_timestamp).toLocaleString('id-ID')}</div>
            </div>
            <div>
                <div class="detail-item-label">Case Status</div>
                <div class="detail-item-val">${target.status}</div>
            </div>
        `;
        
        actionsEl.innerHTML = `
            <button class="btn btn-approve" style="flex:1;" onclick="applyAlertStatusUpdate('Resolved', 'verified')">
                <i data-lucide="check"></i> Resolve (Approve)
            </button>
            <button class="btn btn-block-action" style="flex:1;" onclick="applyAlertStatusUpdate('Resolved', 'block')">
                <i data-lucide="slash"></i> Resolve (Block Target)
            </button>
            <button class="btn btn-review" style="flex:1;" onclick="applyAlertStatusUpdate('Under Review')">
                <i data-lucide="eye"></i> Mark Investigating
            </button>
        `;
        
        renderTargetAuditLogs(target.auditHistory);
        
        // Inject Device Audit info
        let member = null;
        if (target.customer_id) {
            member = allMembers.find(m => m.id === target.customer_id);
        }
        if (!member && target.target_type === 'member' && target.target_id) {
            member = allMembers.find(m => m.id === target.target_id);
        }
        if (member && deviceSec) {
            const isNewDevice = target.transaction_details ? (target.transaction_details.login_location_changed === 1) : (target.target_type === 'member' && member.verification_status === 'Flagged');
            deviceSec.innerHTML = getDeviceAuditHTML(member, isNewDevice);
            deviceSec.style.display = 'block';
        }
        
    } else if (type === 'member') {
        titleEl.textContent = "Member Profile Inspection";
        idTitleEl.textContent = "Registry Account Details";
        combosSec.style.display = 'block';
        matrixSec.style.display = 'none';
        
        combosText.innerHTML = `
            <div><strong>Home Address:</strong> ${target.address}</div>
            <div style="margin-top: 4px;"><strong>IP Signature:</strong> <span style="font-family: monospace;">${target.ip_address}</span></div>
        `;

        idGridEl.innerHTML = `
            <div>
                <div class="detail-item-label">Member Name</div>
                <div class="detail-item-val"><strong>${target.name}</strong></div>
            </div>
            <div>
                <div class="detail-item-label">National ID (NIK)</div>
                <div class="detail-item-val" style="font-family: monospace;">${target.nik}</div>
            </div>
            <div>
                <div class="detail-item-label">Card KKS Code</div>
                <div class="detail-item-val" style="font-family: monospace;">${target.kks_card}</div>
            </div>
            <div>
                <div class="detail-item-label">Phone Contacts</div>
                <div class="detail-item-val">${target.phone}</div>
            </div>
            <div>
                <div class="detail-item-label">Enrollment Date</div>
                <div class="detail-item-val" style="font-size:11px;">${new Date(target.registration_date).toLocaleString('id-ID')}</div>
            </div>
            <div>
                <div class="detail-item-label">Security Flag</div>
                <div class="detail-item-val">${target.verification_status}</div>
            </div>
        `;
        
        actionsEl.innerHTML = `
            <span style="color:var(--text-muted); font-size:12px; text-align:center; width:100%;">
                To update member status, navigate to Alert Center and resolve the corresponding registration Alert.
            </span>
        `;
        
        renderTargetAuditLogs(target.auditHistory);
        
        // Inject Device Audit info
        if (deviceSec) {
            const sameDeviceCount = allMembers.filter(m => m.device_info === target.device_info).length || 1;
            const isNewDevice = (target.verification_status === 'Flagged' && sameDeviceCount === 1);
            deviceSec.innerHTML = getDeviceAuditHTML(target, isNewDevice);
            deviceSec.style.display = 'block';
        }
    }
    
    // Reload Icons
    lucide.createIcons();
    // Slide Drawer Panel Open
    document.getElementById('decision-backdrop').classList.add('open');
}

function closeAuditorPanel() {
    document.getElementById('decision-backdrop').classList.remove('open');
    activeAuditTarget = null;
    activeAuditType = null;
}

function loadFlagsMatrix(tx) {
    const flagLabelsMap = {
        "IP address (outside Indonesia )": "Foreign IP Address",
        "repeated_product_purchase(>10)": "Repeated Purchase >10",
        "Transaction frequency (>3 per hour)": "Transaction Freq >3/hr",
        "Duplicate_account_detection": "Duplicate Account",
        "same_device_multiple_accounts": "Same Device Multi-Account",
        "login_location_changed": "Login Location Changed",
        "same_product_transcation_count_month": "Same Product count >5/mo",
        "payment_retry_count": "Payment Retry >= 3",
        "failed_login_attempts": "Failed Logins >= 3",
        "National_ID_verification": "ID Verified (Negated)",
        "KKS_card_validation": "KKS Card Valid (Negated)",
        "valid_card": "Card Valid (Negated)"
    };
   
    const grid = document.getElementById('aud-flags-grid');
    grid.innerHTML = '';
   
    Object.keys(flagLabelsMap).forEach(key => {
        let isTriggered = false;
        if (key === "National_ID_verification" || key === "KKS_card_validation" || key === "valid_card") {
            isTriggered = tx[key] === 0;
        } else if (key === "same_product_transcation_count_month") {
            isTriggered = tx[key] > 5;
        } else if (key === "payment_retry_count" || key === "failed_login_attempts") {
            isTriggered = tx[key] >= 3;
        } else {
            isTriggered = tx[key] === 1;
        }
       
        const item = document.createElement('div');
        item.style.padding = '8px';
        item.style.borderRadius = '4px';
        item.style.display = 'flex';
        item.style.alignItems = 'center';
        item.style.gap = '8px';
       
        if (isTriggered) {
            item.style.backgroundColor = 'rgba(255,23,68,0.06)';
            item.style.border = '1px solid rgba(255,23,68,0.2)';
            item.innerHTML = `<span style="color:var(--color-critical);">&#9888;</span> <span>${flagLabelsMap[key]}</span>`;
        } else {
            item.style.backgroundColor = 'rgba(255,255,255,0.01)';
            item.style.border = '1px solid var(--border-color)';
            item.style.color = 'var(--text-muted)';
            item.innerHTML = `<span style="color:var(--color-legit);">&#10003;</span> <span>${flagLabelsMap[key]}</span>`;
        }
        grid.appendChild(item);
    });
}

function renderTargetAuditLogs(history) {
    const list = document.getElementById('aud-logs');
    list.innerHTML = '';
   
    if (!history || history.length === 0) {
        list.innerHTML = `<div style="text-align: center; color: var(--text-muted); font-size:12px; padding: 12px 0;">No audit notes on record</div>`;
        return;
    }
   
    history.forEach(log => {
        const item = document.createElement('div');
        item.className = 'audit-log-item';
       
        let color = '#3b82f6';
        let act = log.action.toLowerCase();
        if (act === 'blocked' || act === 'resolved' || act === 'block') color = 'var(--color-critical)';
        else if (act === 'approved' || act === 'verified') color = 'var(--color-legit)';
        else if (act === 'review' || act === 'under review') color = 'var(--color-medium)';
       
        item.style.borderLeftColor = color;
        item.innerHTML = `
            <div class="audit-meta">
                <strong>Action: ${log.action.toUpperCase()}</strong> &bull; ${log.operator ? log.operator + ' &bull; ' : ''} ${new Date(log.timestamp).toLocaleString('id-ID')}
            </div>
            <div style="font-size:12px; color: var(--text-primary);">${log.note || 'No notes appended.'}</div>
        `;
        list.appendChild(item);
    });
}

// REST Audit calls
async function applyTransactionAudit(decision) {
    if (!activeAuditTarget) return;
    const noteText = document.getElementById('aud-notes').value.trim();
    
    const payload = {
        transaction_id: activeAuditTarget.id,
        status: decision,
        note: noteText || `Transaction marked as ${decision.toUpperCase()}`,
        operator: 'Auditor'
    };

    try {
        const res = await fetch('/api/transactions/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const json = await res.json();
        if (json.status === 'success') {
            showToast("Audit Registered", `Transaction #${activeAuditTarget.id} marked as ${decision.toUpperCase()}`, decision === 'blocked' ? 'critical' : 'success');
            closeAuditorPanel();
            loadAllData(); // reload statistics & tables
        } else {
            showToast("Audit Failed", json.message || "Could not save decision.", "critical");
        }
    } catch (e) {
        console.error("Auditing connection failed: ", e);
        showToast("Connection Error", "API endpoint unreachable.", "critical");
    }
}

async function applyAlertStatusUpdate(newStatus, actionType = '') {
    if (!activeAuditTarget) return;
    let noteText = document.getElementById('aud-notes').value.trim();
    
    if (newStatus === 'Resolved' && actionType) {
        noteText += ` (Resolved decision: ${actionType.toUpperCase()})`;
    }

    const payload = {
        status: newStatus,
        note: noteText || `Alert status updated to ${newStatus}`,
        operator: 'Auditor'
    };

    try {
        const res = await fetch(`/api/alerts/${activeAuditTarget.id}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const json = await res.json();
        if (json.status === 'success') {
            showToast("Alert Updated", `Incidents Alert ${activeAuditTarget.alert_id} status set to ${newStatus.toUpperCase()}`, newStatus === 'Resolved' ? 'success' : 'medium');
            closeAuditorPanel();
            fetchAlerts(); // reload alerts registry
            loadAllData();  // reload stats
        } else {
            showToast("Resolution Failed", json.message || "Could not resolve alert.", "critical");
        }
    } catch (e) {
        console.error("Alert status connection failed: ", e);
        showToast("Connection Error", "API endpoint unreachable.", "critical");
    }
}

// Auto-Block System Config
function toggleAutoBlock() {
    autoBlockEnabled = document.getElementById('auto-block-checkbox').checked;
    localStorage.setItem('kovamart_autoblock', autoBlockEnabled);
    
    const sidebarCheckbox = document.getElementById('sidebar-auto-block-checkbox');
    if (sidebarCheckbox) {
        sidebarCheckbox.checked = autoBlockEnabled;
    }
    
    showToast("Auto-Block Settings Saved", `Auto-block is now ${autoBlockEnabled ? 'ENABLED' : 'DISABLED'}.`, "success");
}

function toggleAutoBlockSidebar() {
    autoBlockEnabled = document.getElementById('sidebar-auto-block-checkbox').checked;
    localStorage.setItem('kovamart_autoblock', autoBlockEnabled);
    
    const topBarCheckbox = document.getElementById('auto-block-checkbox');
    if (topBarCheckbox) {
        topBarCheckbox.checked = autoBlockEnabled;
    }
    
    showToast("Auto-Block Settings Saved", `Auto-block is now ${autoBlockEnabled ? 'ENABLED' : 'DISABLED'}.`, "success");
}

function updateAlertBellBadge() {
    const badge = document.getElementById('alert-counter-badge');
    const count = allAlerts.filter(a => a.status === 'Open' && a.id > lastSeenAlertId).length;
    
    if (count > 0) {
        badge.textContent = count;
        badge.style.display = 'flex';
    } else {
        badge.style.display = 'none';
    }
}

// ─── RISK SIMULATOR PLAYGROUND LOGIC ─────────────────────────────────────────
function updateSliderDisplay(inputEl) {
    const valSpan = document.getElementById(`val-${inputEl.id.replace('sim-', '')}`);
    if (valSpan) {
        const val = parseFloat(inputEl.value);
        valSpan.textContent = 'Rp ' + val.toLocaleString('id-ID');
    }
}

async function triggerSyntheticGeneration() {
    try {
        const res = await fetch('/api/generate');
        const json = await res.json();
        if (json.status === 'success') {
            const tx = json.transaction;
           
            // Set form values
            document.getElementById('sim-Initial_Subsidy').value = tx.Initial_Subsidy;
            updateSliderDisplay(document.getElementById('sim-Initial_Subsidy'));
           
            document.getElementById('sim-transaction_amount').value = tx.transaction_amount;
            updateSliderDisplay(document.getElementById('sim-transaction_amount'));
           
            document.getElementById('sim-hour_of_day').value = tx.hour_of_day;
            document.getElementById('sim-num_items').value = tx.num_items;
            document.getElementById('sim-prev_transactions').value = tx.prev_transactions;
            document.getElementById('sim-failed_login_attempts').value = tx.failed_login_attempts;
            document.getElementById('sim-payment_retry_count').value = tx.payment_retry_count;
            document.getElementById('sim-same_product_transcation_count_month').value = tx.same_product_transcation_count_month || 0;
           
            document.getElementById('sim-is_first_transaction').checked = tx.is_first_transaction === 1;
            document.getElementById('sim-ip_outside').checked = tx["IP address (outside Indonesia )"] === 1;
            document.getElementById('sim-id_not_verified').checked = tx.National_ID_verification === 0;
            document.getElementById('sim-kks_not_valid').checked = tx.KKS_card_validation === 0;
            document.getElementById('sim-duplicate_account').checked = tx.Duplicate_account_detection === 1;
            document.getElementById('sim-high_frequency').checked = tx["Transaction frequency (>3 per hour)"] === 1;
            document.getElementById('sim-card_invalid').checked = tx.valid_card === 0;
           
            document.getElementById('sim-repeated_purchase').checked = tx["repeated_product_purchase(>10)"] === 1;
            document.getElementById('sim-same_device').checked = tx.same_device_multiple_accounts === 1;
            document.getElementById('sim-location_changed').checked = tx.login_location_changed === 1;
            document.getElementById('sim-channel_kiosk').checked = tx["app(0) vs kiosk(1)transaction"] === 1;
           
            // Trigger score evaluate
            runManualAnalysis();
            
            // Reload all dashboard metrics
            loadAllData();
            
            showToast("Simulation Sync", `Generated database transaction under Customer ID #${tx.customer_id}!`, "success");
        }
    } catch (e) {
        console.error("Simulator Generation Error: ", e);
        showToast("Error generating scenario", "Backend simulated data unavailable", "critical");
    }
}

async function runManualAnalysis() {
    const subsidy = parseFloat(document.getElementById('sim-Initial_Subsidy').value);
    const amount = parseFloat(document.getElementById('sim-transaction_amount').value);
   
    const payload = {
        Initial_Subsidy: subsidy,
        transaction_amount: amount,
        hour_of_day: parseInt(document.getElementById('sim-hour_of_day').value) || 12,
        num_items: parseInt(document.getElementById('sim-num_items').value) || 1,
        prev_transactions: parseInt(document.getElementById('sim-prev_transactions').value) || 0,
        failed_login_attempts: parseInt(document.getElementById('sim-failed_login_attempts').value) || 0,
        payment_retry_count: parseInt(document.getElementById('sim-payment_retry_count').value) || 0,
        same_product_transcation_count_month: parseInt(document.getElementById('sim-same_product_transcation_count_month').value) || 0,
       
        is_first_transaction: document.getElementById('sim-is_first_transaction').checked ? 1 : 0,
        "IP address (outside Indonesia )": document.getElementById('sim-ip_outside').checked ? 1 : 0,
        National_ID_verification: document.getElementById('sim-id_not_verified').checked ? 0 : 1,
        KKS_card_validation: document.getElementById('sim-kks_not_valid').checked ? 0 : 1,
        Duplicate_account_detection: document.getElementById('sim-duplicate_account').checked ? 1 : 0,
        "Transaction frequency (>3 per hour)": document.getElementById('sim-high_frequency').checked ? 1 : 0,
        valid_card: document.getElementById('sim-card_invalid').checked ? 0 : 1,
        "repeated_product_purchase(>10)": document.getElementById('sim-repeated_purchase').checked ? 1 : 0,
        same_device_multiple_accounts: document.getElementById('sim-same_device').checked ? 1 : 0,
        login_location_changed: document.getElementById('sim-location_changed').checked ? 1 : 0,
        "app(0) vs kiosk(1)transaction": document.getElementById('sim-channel_kiosk').checked ? 1 : 0
    };
   
    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
       
        const json = await res.json();
        if (json.status === 'success') {
            const r = json.result;
            updateSimulatorOutput(r);
        }
    } catch (e) {
        console.error("Evaluation Error: ", e);
        showToast("Error running risk evaluation", "Backend evaluation server error", "critical");
    }
}

function updateSimulatorOutput(r) {
    const score = r.final_pct;
    const rotation = -135 + (score * 1.8);
    const fill = document.getElementById('pred-gauge-fill');
    fill.style.transform = `rotate(${rotation}deg)`;
   
    let color = 'var(--color-legit)';
    let levelLabel = '🟢 LOW THREAT';
    if (score >= 80) { color = 'var(--color-critical)'; levelLabel = '🔴 CRITICAL RISK'; }
    else if (score >= 55) { color = 'var(--color-high)'; levelLabel = '🟠 HIGH RISK'; }
    else if (score >= 40) { color = 'var(--color-medium)'; levelLabel = '🟡 MEDIUM RISK'; }
   
    fill.style.borderColor = color;
   
    const levelEl = document.getElementById('pred-level');
    levelEl.textContent = levelLabel;
    levelEl.style.color = color;
    levelEl.style.borderColor = color;
   
    document.getElementById('pred-risk-pct').textContent = score.toFixed(1) + '%';
    document.getElementById('pred-rules-score').textContent = r.rule_based_pct.toFixed(1) + '%';
    document.getElementById('pred-ai-score').textContent = r.ai_prob.toFixed(1) + '%';
   
    const finalScoreEl = document.getElementById('pred-final-score');
    finalScoreEl.textContent = score.toFixed(1) + '%';
    finalScoreEl.style.color = color;
   
    document.getElementById('pred-verdict').textContent = r.verdict;
   
    let flagCount = 0;
    Object.values(r.flags).forEach(v => { if (v === 1) flagCount++; });
    document.getElementById('pred-flags-triggered').textContent = `${flagCount} / 14`;
   
    const combosContainer = document.getElementById('sim-combos-container');
    const combosList = document.getElementById('sim-combos-list');
    combosList.innerHTML = '';
   
    if (r.triggered_combos && r.triggered_combos.length > 0) {
        combosContainer.style.display = 'block';
        r.triggered_combos.forEach(c => {
            const li = document.createElement('li');
            li.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
            li.style.paddingBottom = '6px';
            li.innerHTML = `
                <div style="font-weight:600; color:var(--text-primary); margin-bottom: 2px;">
                    [${c.combo_id}] ${c.name} (Risk: ${c.combo_score}%)
                </div>
                <div style="font-size:11px; color:var(--text-muted);">${c.reason}</div>
            `;
            combosList.appendChild(li);
        });
    } else {
        combosContainer.style.display = 'none';
    }
}

// ─── BATCH CSV PROCESSING UPLOADER ───────────────────────────────────────────
let uploadBatchData = [];
let uploadScoredResults = [];

function handleCSVFileSelected(input) {
    const file = input.files[0];
    if (!file) return;
   
    document.getElementById('drag-drop-zone').style.display = 'none';
    document.getElementById('batch-progress-card').style.display = 'block';
    document.getElementById('batch-results-wrapper').style.display = 'none';
   
    Papa.parse(file, {
        header: true,
        dynamicTyping: true,
        complete: function(results) {
            uploadBatchData = results.data.filter(row => row.Initial_Subsidy !== undefined && row.Initial_Subsidy !== null);
            if (uploadBatchData.length === 0) {
                showToast("Invalid CSV File", "Could not locate valid transaction columns.", "critical");
                resetUploader();
                return;
            }
            processBatchScoring();
        },
        error: function(err) {
            showToast("CSV Parsing Error", err.message, "critical");
            resetUploader();
        }
    });
}

async function processBatchScoring() {
    const total = uploadBatchData.length;
    const progressFill = document.getElementById('batch-progress-fill');
    const percentageText = document.getElementById('batch-progress-percentage');
    const statusText = document.getElementById('batch-progress-status');
   
    uploadScoredResults = [];
    const batchSize = 100;
   
    for (let i = 0; i < total; i += batchSize) {
        const slice = uploadBatchData.slice(i, i + batchSize);
        statusText.textContent = `Analyzing records ${i + 1} to ${Math.min(i + batchSize, total)} of ${total}...`;
       
        try {
            const res = await fetch('/api/analyze_batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ transactions: slice })
            });
            const json = await res.json();
           
            if (json.status === 'success') {
                uploadScoredResults = uploadScoredResults.concat(json.results);
            }
        } catch (e) {
            console.error("Batch Scoring Slice Error: ", e);
        }
       
        const pct = Math.round((Math.min(i + batchSize, total) / total) * 100);
        progressFill.style.width = pct + '%';
        percentageText.textContent = pct + '%';
    }
   
    statusText.textContent = 'Evaluation complete!';
    setTimeout(() => {
        document.getElementById('batch-progress-card').style.display = 'none';
        renderBatchResultsTable();
    }, 600);
}

function renderBatchResultsTable() {
    const wrapper = document.getElementById('batch-results-wrapper');
    const tbody = document.getElementById('batch-results-tbody');
   
    tbody.innerHTML = '';
    wrapper.style.display = 'block';
    document.getElementById('batch-results-title').textContent = `Step 2: Evaluation Results (${uploadScoredResults.length} Rows Scored)`;
   
    const preview = uploadScoredResults.slice(0, 10);
    preview.forEach((r, idx) => {
        const tr = document.createElement('tr');
       
        let badgeClass = 'badge-low';
        let level = 'Low';
        if (r.final_pct >= 80) { badgeClass = 'badge-critical'; level = 'Critical'; }
        else if (r.final_pct >= 55) { badgeClass = 'badge-high'; level = 'High'; }
        else if (r.final_pct >= 40) { badgeClass = 'badge-medium'; level = 'Medium'; }
       
        tr.innerHTML = `
            <td>#${r.customer_id || idx + 1}</td>
            <td>Rp ${parseFloat(r.Initial_Subsidy).toLocaleString('id-ID')}</td>
            <td>Rp ${parseFloat(r.transaction_amount).toLocaleString('id-ID')}</td>
            <td>${r["IP address (outside Indonesia )"] === 1 ? 'Yes' : 'No'}</td>
            <td>${r.rule_based_pct}%</td>
            <td>${r.ai_prob}%</td>
            <td><strong>${r.final_pct}%</strong></td>
            <td><span class="badge ${badgeClass}"><span class="badge-dot"></span>${level}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function downloadScoredCSV() {
    if (uploadScoredResults.length === 0) return;
   
    const csvRows = [];
    const headers = [
        "customer_id", "Initial_Subsidy", "transaction_amount", "Subsidy_balance",
        "hour_of_day", "num_items", "failed_login_attempts", "payment_retry_count",
        "IP address (outside Indonesia )", "rule_based_risk_score", "ai_model_prob",
        "final_risk_score", "threat_level", "verdict"
    ];
    csvRows.push(headers.join(","));
   
    uploadScoredResults.forEach((r, idx) => {
        const row = [
            r.customer_id || idx + 1,
            r.Initial_Subsidy,
            r.transaction_amount,
            r.Subsidy_balance,
            r.hour_of_day,
            r.num_items,
            r.failed_login_attempts,
            r.payment_retry_count,
            r["IP address (outside Indonesia )"],
            r.rule_based_pct,
            r.ai_prob,
            r.final_pct,
            r.level.replace(/[^a-zA-Z\s]/g, '').trim(),
            `"${r.verdict.replace(/[^a-zA-Z\s]/g, '').trim()}"`
        ];
        csvRows.push(row.join(","));
    });
   
    const csvContent = "data:text/csv;charset=utf-8," + csvRows.join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `scored_transactions_batch_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
   
    resetUploader();
}

function resetUploader() {
    uploadBatchData = [];
    document.getElementById('drag-drop-zone').style.display = 'flex';
    document.getElementById('batch-progress-card').style.display = 'none';
    document.getElementById('batch-results-wrapper').style.display = 'none';
    document.getElementById('csv-file-input').value = '';
}

// ─── COMPLIANCE & AUDIT REPORTING LOGIC ──────────────────────────────────────
function loadComplianceReports() {
    if (allTransactions.length === 0) return;
   
    let flaggedCount = 0;
    allTransactions.forEach(tx => {
        const score = tx.final_pct || tx.risk_pct || 0;
        if (score >= 40) flaggedCount++;
    });
    const flagRate = (flaggedCount / allTransactions.length) * 100;
    document.getElementById('rep-flag-rate').textContent = flagRate.toFixed(1) + '%';
   
    const customers = {};
    allTransactions.forEach(tx => {
        const cid = tx.customer_id;
        if (!customers[cid]) {
            customers[cid] = { id: cid, spent: 0, subsidy: tx.Initial_Subsidy, maxScore: 0, triggers: 0 };
        }
        customers[cid].spent += tx.transaction_amount;
        const score = tx.final_pct || tx.risk_pct || 0;
        if (score > customers[cid].maxScore) customers[cid].maxScore = score;
        if (score >= 40) customers[cid].triggers++;
    });
   
    const sortedCustomers = Object.values(customers)
        .sort((a, b) => b.maxScore - a.maxScore || b.spent - a.spent)
        .slice(0, 6);
       
    const fBody = document.getElementById('rep-top-fraudsters-tbody');
    fBody.innerHTML = '';
    sortedCustomers.forEach(c => {
        const tr = document.createElement('tr');
        const spentRatio = ((c.spent / c.subsidy) * 100).toFixed(1) + '%';
        tr.innerHTML = `
            <td>#${c.id}</td>
            <td>Rp ${c.subsidy.toLocaleString('id-ID')}</td>
            <td>${spentRatio} (Spent)</td>
            <td>${c.triggers} flagged Tx</td>
            <td style="font-weight:700; color: ${c.maxScore >= 80 ? 'var(--color-critical)' : 'var(--color-high)'};">${c.maxScore}%</td>
        `;
        fBody.appendChild(tr);
    });
   
    const comboPriorityTable = [
        { id: "C1", score: 100, name: "Foreign IP + Failed Logins + Payment Retry" },
        { id: "C2", score: 95, name: "Foreign IP + Location Changed + Same Device" },
        { id: "C3", score: 90, name: "Foreign IP + Duplicate Account" },
        { id: "C4", score: 85, name: "Foreign IP + Subsidy Exhausted" },
        { id: "C5", score: 80, name: "Duplicate Account + Same Device + Location Changed" },
        { id: "C6", score: 75, name: "High Frequency + Repeated Purchase + Same Product" },
        { id: "C7", score: 70, name: "Failed Logins + Payment Retry + High Frequency" },
        { id: "C8", score: 65, name: "Failed Logins + Payment Retry + Invalid Card" },
        { id: "C9", score: 65, name: "Duplicate Account + Payment Retry + Invalid Card" },
        { id: "C10", score: 60, name: "Duplicate Account + Failed Logins" },
        { id: "C11", score: 55, name: "Subsidy Exhausted + High Frequency" },
        { id: "C12", score: 50, name: "Unverified ID + Invalid KKS + Invalid Card" },
        { id: "C13", score: 45, name: "Unverified ID + Duplicate Account" }
    ];
   
    const comboCounts = {};
    comboPriorityTable.forEach(c => comboCounts[c.id] = 0);
    let criticalCount = 0;
   
    allTransactions.forEach(tx => {
        const score = tx.final_pct || tx.risk_pct || 0;
        if (score >= 80) criticalCount++;
       
        const flagMap = {
            "ip_outsider": tx["IP address (outside Indonesia )"] === 1,
            "repeated_purchase": tx["repeated_product_purchase(>10)"] === 1,
            "high_frequency": tx["Transaction frequency (>3 per hour)"] === 1,
            "duplicate_account": tx["Duplicate_account_detection"] === 1,
            "same_device": tx["same_device_multiple_accounts"] === 1,
            "location_changed": tx["login_location_changed"] === 1,
            "same_product_high": tx["same_product_transcation_count_month"] > 5,
            "payment_retry": tx["payment_retry_count"] >= 3,
            "failed_login": tx["failed_login_attempts"] >= 3,
            "id_not_verified": tx["National_ID_verification"] === 0,
            "kks_not_valid": tx["KKS_card_validation"] === 0,
            "card_invalid": tx["valid_card"] === 0,
            "subsidy_exhausted": (tx["Initial_Subsidy"] - tx["Subsidy_balance"]) > 900000
        };
       
        if (flagMap.ip_outsider && flagMap.failed_login && flagMap.payment_retry) comboCounts["C1"]++;
        if (flagMap.ip_outsider && flagMap.location_changed && flagMap.same_device) comboCounts["C2"]++;
        if (flagMap.ip_outsider && flagMap.duplicate_account) comboCounts["C3"]++;
        if (flagMap.ip_outsider && flagMap.subsidy_exhausted) comboCounts["C4"]++;
        if (flagMap.duplicate_account && flagMap.same_device && flagMap.location_changed) comboCounts["C5"]++;
        if (flagMap.high_frequency && flagMap.repeated_purchase && flagMap.same_product_high) comboCounts["C6"]++;
        if (flagMap.failed_login && flagMap.payment_retry && flagMap.high_frequency) comboCounts["C7"]++;
        if (flagMap.failed_login && flagMap.payment_retry && flagMap.card_invalid) comboCounts["C8"]++;
        if (flagMap.duplicate_account && flagMap.payment_retry && flagMap.card_invalid) comboCounts["C9"]++;
        if (flagMap.duplicate_account && flagMap.failed_login) comboCounts["C10"]++;
        if (flagMap.subsidy_exhausted && flagMap.high_frequency) comboCounts["C11"]++;
        if (flagMap.id_not_verified && flagMap.kks_not_valid && flagMap.card_invalid) comboCounts["C12"]++;
        if (flagMap.id_not_verified && flagMap.duplicate_account) comboCounts["C13"]++;
    });
   
    document.getElementById('rep-critical-count').textContent = criticalCount;
   
    const sortedCombos = [...comboPriorityTable].sort((a, b) => comboCounts[b.id] - comboCounts[a.id]);
    document.getElementById('rep-top-combo').textContent = sortedCombos[0].id + ' - ' + sortedCombos[0].name.split('+')[0];
    document.getElementById('rep-top-combo-desc').textContent = `Most triggered vector (${comboCounts[sortedCombos[0].id]} occurrences)`;
   
    const rBody = document.getElementById('rep-rule-matrix-tbody');
    rBody.innerHTML = '';
    comboPriorityTable.forEach(c => {
        const count = comboCounts[c.id];
        const effectiveness = ((count / allTransactions.length) * 100).toFixed(1) + '%';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${c.id}</strong></td>
            <td>${c.name}</td>
            <td>${c.score}%</td>
            <td>${count} triggers</td>
            <td>${effectiveness} Trigger Share</td>
        `;
        rBody.appendChild(tr);
    });
}

function exportReportToExcel() {
    const csvRows = [];
    csvRows.push(["Risk Rule Audit Effectiveness Export"]);
    csvRows.push([]);
    csvRows.push(["Rule ID", "Rule Description", "Risk Threshold Floor", "Trigger Occurrence count", "Trigger Share"]);
   
    document.querySelectorAll('#rep-rule-matrix-tbody tr').forEach(tr => {
        const tds = tr.querySelectorAll('td');
        if (tds.length >= 5) {
            csvRows.push([
                tds[0].innerText,
                `"${tds[1].innerText}"`,
                tds[2].innerText,
                tds[3].innerText,
                tds[4].innerText
            ].join(","));
        }
    });
   
    const csvContent = "data:text/csv;charset=utf-8," + csvRows.join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `kovamart_rule_matrix_report_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// ─── DYNAMIC CHARTS BUILDER (CHART.JS) ───────────────────────────────────────
function renderAllCharts() {
    if (allTransactions.length === 0) return;
   
    // CHART 1: RISK THREAT DISTRIBUTION
    const riskCtx = document.getElementById('chart-risk-distribution').getContext('2d');
    const riskCounts = { 'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0 };
   
    allTransactions.forEach(tx => {
        const score = tx.final_pct || tx.risk_pct;
        if (score >= 80) riskCounts['Critical']++;
        else if (score >= 55) riskCounts['High']++;
        else if (score >= 40) riskCounts['Medium']++;
        else riskCounts['Low']++;
    });
   
    if (chartRiskDist) chartRiskDist.destroy();
    chartRiskDist = new Chart(riskCtx, {
        type: 'bar',
        data: {
            labels: Object.keys(riskCounts),
            datasets: [{
                data: Object.values(riskCounts),
                backgroundColor: ['#81c784', '#ffb74d', '#ff7043', '#ff1744'],
                borderColor: ['#66bb6a', '#ffa726', '#f4511e', '#d50000'],
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#8b9bb4' } },
                y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#8b9bb4' } }
            }
        }
    });

    // CHART 2: FRAUD TREND BY HOUR
    const trendCtx = document.getElementById('chart-fraud-trend').getContext('2d');
    const hourStats = Array.from({length: 24}, () => ({ total: 0, fraud: 0 }));
   
    allTransactions.forEach(tx => {
        const hour = parseInt(tx.hour_of_day);
        if (!isNaN(hour) && hour >= 0 && hour < 24) {
            hourStats[hour].total++;
            const score = tx.final_pct || tx.risk_pct;
            if (score >= 40 || tx["IP address (outside Indonesia )"] === 1) {
                hourStats[hour].fraud++;
            }
        }
    });
   
    const hoursLabels = Array.from({length: 24}, (_, i) => `${i}:00`);
    const hourlyFraudRate = hourStats.map(h => h.total > 0 ? parseFloat(((h.fraud / h.total) * 100).toFixed(1)) : 0);
   
    if (chartFraudTrend) chartFraudTrend.destroy();
    chartFraudTrend = new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: hoursLabels,
            datasets: [{
                label: 'Rule-Based Flag Rate (%)',
                data: hourlyFraudRate,
                fill: true,
                backgroundColor: 'rgba(59, 130, 246, 0.08)',
                borderColor: '#3b82f6',
                pointBackgroundColor: '#00f2fe',
                tension: 0.35,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#8b9bb4' } } },
            scales: {
                x: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#8b9bb4', maxTicksLimit: 8 } },
                y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#8b9bb4' } }
            }
        }
    });

    // CHART 3: KEY FLAG RISK FACTORS
    const factorsCtx = document.getElementById('chart-risk-factors').getContext('2d');
    const flagLabels = {
        "IP address (outside Indonesia )": "Foreign IP Address",
        "repeated_product_purchase(>10)": "Repeated Purchase >10",
        "Transaction frequency (>3 per hour)": "Freq >3 per Hour",
        "Duplicate_account_detection": "Duplicate Account",
        "same_device_multiple_accounts": "Same Device Multi-Account",
        "login_location_changed": "Login Location Changed",
        "same_product_transcation_count_month": "Same Product >5/mo",
        "payment_retry_count": "Payment Retry >= 3",
        "failed_login_attempts": "Failed Logins >= 3",
        "National_ID_verification": "ID Not Verified",
        "KKS_card_validation": "KKS Invalid",
        "valid_card": "Card Not Valid",
        "Initial_Subsidy": "Subsidy Limit"
    };
   
    const flagCounts = {};
    Object.keys(flagLabels).forEach(key => flagCounts[key] = 0);
   
    allTransactions.forEach(tx => {
        if (tx["IP address (outside Indonesia )"] === 1) flagCounts["IP address (outside Indonesia )"]++;
        if (tx["repeated_product_purchase(>10)"] === 1) flagCounts["repeated_product_purchase(>10)"]++;
        if (tx["Transaction frequency (>3 per hour)"] === 1) flagCounts["Transaction frequency (>3 per hour)"]++;
        if (tx["Duplicate_account_detection"] === 1) flagCounts["Duplicate_account_detection"]++;
        if (tx["same_device_multiple_accounts"] === 1) flagCounts["same_device_multiple_accounts"]++;
        if (tx["login_location_changed"] === 1) flagCounts["login_location_changed"]++;
        if (tx["same_product_transcation_count_month"] > 5) flagCounts["same_product_transcation_count_month"]++;
        if (tx["payment_retry_count"] >= 3) flagCounts["payment_retry_count"]++;
        if (tx["failed_login_attempts"] >= 3) flagCounts["failed_login_attempts"]++;
        if (tx["National_ID_verification"] === 0) flagCounts["National_ID_verification"]++;
        if (tx["KKS_card_validation"] === 0) flagCounts["KKS_card_validation"]++;
        if (tx["valid_card"] === 0) flagCounts["valid_card"]++;
    });
   
    const sortedFlags = Object.keys(flagCounts)
        .map(k => ({ label: flagLabels[k], val: flagCounts[k] }))
        .sort((a,b) => b.val - a.val)
        .slice(0, 7);
       
    if (chartRiskFactors) chartRiskFactors.destroy();
    chartRiskFactors = new Chart(factorsCtx, {
        type: 'bar',
        data: {
            labels: sortedFlags.map(sf => sf.label),
            datasets: [{
                data: sortedFlags.map(sf => sf.val),
                backgroundColor: 'rgba(0, 242, 254, 0.4)',
                borderColor: '#00f2fe',
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#8b9bb4' } },
                y: { grid: { color: 'transparent' }, ticks: { color: '#8b9bb4' } }
            }
        }
    });
   
    // GEOGRAPHIC SUMMARY COUNTS
    let domesticCount = 0;
    let foreignCount = 0;
    allTransactions.forEach(tx => {
        if (tx["IP address (outside Indonesia )"] === 1) {
            foreignCount++;
        } else {
            domesticCount++;
        }
    });
    document.getElementById('stats-geo-domestic').textContent = domesticCount.toLocaleString() + ' Tx';
    document.getElementById('stats-geo-foreign').textContent = foreignCount.toLocaleString() + ' Tx';
}

// ─── TOAST NOTIFICATIONS ─────────────────────────────────────────────────────
function showToast(title, desc, type = 'success') {
    const container = document.getElementById('global-toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
   
    let borderClr = 'var(--color-legit)';
    let icon = 'check-circle';
   
    if (type === 'critical') { borderClr = 'var(--color-critical)'; icon = 'alert-octagon'; }
    else if (type === 'high') { borderClr = 'var(--color-high)'; icon = 'alert-triangle'; }
    else if (type === 'medium') { borderClr = 'var(--color-medium)'; icon = 'info'; }
   
    toast.style.borderLeftColor = borderClr;
    toast.innerHTML = `
        <i class="toast-icon" data-lucide="${icon}" style="color: ${borderClr};"></i>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-desc">${desc}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
    `;
    container.appendChild(toast);
   
    lucide.createIcons(); // init toast icon
   
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s forwards';
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}

// Toggle Bell Dropdown
function toggleAlertDropdown(event) {
    if (event) event.stopPropagation();
    const dropdown = document.getElementById('bell-dropdown-menu');
    const isVisible = dropdown.style.display === 'flex';
    
    // Close dropdown on click outside
    if (!isVisible) {
        dropdown.style.display = 'flex';
        populateBellDropdown();
        document.addEventListener('click', closeBellDropdown);
    } else {
        dropdown.style.display = 'none';
        document.removeEventListener('click', closeBellDropdown);
    }
}

function closeBellDropdown() {
    const dropdown = document.getElementById('bell-dropdown-menu');
    if (dropdown) {
        dropdown.style.display = 'none';
    }
    document.removeEventListener('click', closeBellDropdown);
}

// Populate Bell Dropdown
async function populateBellDropdown() {
    const list = document.getElementById('bell-dropdown-list');
    list.innerHTML = '';
    
    // Make sure we have latest alerts list
    try {
        const res = await fetch('/api/alerts');
        const json = await res.json();
        if (json.status === 'success') {
            allAlerts = json.alerts;
            // Mark all currently fetched alerts as seen by updating lastSeenAlertId
            if (allAlerts.length > 0) {
                const maxId = Math.max(...allAlerts.map(a => a.id));
                lastSeenAlertId = maxId;
                localStorage.setItem('kovamart_last_seen_alert_id', maxId);
                updateAlertBellBadge();
            }
        }
    } catch (e) {
        console.error("Error updating alerts in dropdown: ", e);
    }
    
    // Filter open alerts
    const openAlerts = allAlerts.filter(a => a.status === 'Open').slice(0, 5);
    
    if (openAlerts.length === 0) {
        list.innerHTML = `<div style="padding: 16px; text-align: center; color: var(--text-muted); font-size:12px;">No active security alerts</div>`;
        return;
    }
    
    openAlerts.forEach(alt => {
        const item = document.createElement('div');
        item.className = 'dropdown-item';
        item.onclick = () => {
            closeBellDropdown();
            switchView('audit-doc');
            selectAuditDocAlertInTable(alt.id);
        };
        
        let color = 'var(--color-low)';
        const sev = (alt.severity_level || '').toUpperCase();
        if (sev === 'CRITICAL') color = 'var(--color-critical)';
        else if (sev === 'HIGH') color = 'var(--color-high)';
        else if (sev === 'MEDIUM') color = 'var(--color-medium)';
        
        item.innerHTML = `
            <div class="dropdown-item-header">
                <span style="font-family: monospace; font-weight:600;">${alt.alert_id}</span>
                <span style="color: ${color}; font-weight: 700;">${alt.risk_score}%</span>
            </div>
            <div class="dropdown-item-desc">${alt.customer_name}: ${alt.indicators.join(', ')}</div>
        `;
        list.appendChild(item);
    });
}

function viewAllAlerts() {
    closeBellDropdown();
    switchView('audit-doc');
}

// ─── ALERT AUDIT DOCUMENT VIEW & EXPORT ──────────────────────────────────────
let filteredAlertsForDoc = [];

function handleAuditDocFilter() {
    const searchInput = document.getElementById('audit-doc-search-input');
    if (!searchInput) return;
    const searchVal = searchInput.value.toLowerCase().trim();
    const severityFilter = document.getElementById('filter-doc-severity').value;
    const statusFilter = document.getElementById('filter-doc-status').value;
    const ruleFilter = document.getElementById('filter-doc-rule-id').value;
    const dateFilter = document.getElementById('filter-doc-date').value; // 'YYYY-MM-DD' or empty

    filteredAlertsForDoc = allAlerts.filter(alt => {
        const matchSearch = alt.alert_id.toLowerCase().includes(searchVal) ||
                            alt.customer_name.toLowerCase().includes(searchVal) ||
                            alt.customer_id.toString().includes(searchVal);
                            
        const matchSeverity = (severityFilter === 'ALL' || (alt.severity_level || '').toUpperCase() === severityFilter.toUpperCase());
        const matchStatus = (statusFilter === 'ALL' || alt.status === statusFilter);
        
        const combo = findTriggeredCombination(alt);
        const matchRule = (ruleFilter === 'ALL' || (combo && combo.id === ruleFilter));
        
        const matchDate = !dateFilter || alt.detection_timestamp.startsWith(dateFilter);
        
        return matchSearch && matchSeverity && matchStatus && matchRule && matchDate;
    });

    renderAuditDocTable(filteredAlertsForDoc);
}

function getAlertExtraDetails(alt) {
    const member = allMembers.find(m => m.id === alt.customer_id);
    const combo = findTriggeredCombination(alt);
    const txId = alt.target_type === 'transaction' ? alt.target_id : 'N/A';
    const amount = alt.transaction_details ? 'Rp ' + parseFloat(alt.transaction_details.transaction_amount).toLocaleString('id-ID') : 'N/A';
    const notesHistory = alt.auditHistory || [];
    
    // Find latest audit notes
    const latestNoteLog = notesHistory.find(l => l.note && l.note.trim() !== '');
    const notes = latestNoteLog ? latestNoteLog.note : 'No audit notes appended.';
    
    // Find latest action taken (other than the initial trigger)
    const auditLogs = notesHistory.filter(l => l.action !== 'triggered');
    const actionTaken = auditLogs.length > 0 ? auditLogs[0].action.toUpperCase() : 'PENDING AUDIT';
    
    return {
        member,
        combo,
        txId,
        amount,
        notes,
        actionTaken
    };
}

function renderAuditDocTable(alertsList) {
    const tbody = document.getElementById('audit-doc-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (alertsList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding: 20px; color:var(--text-muted);">No matching alerts found</td></tr>';
        return;
    }

    alertsList.forEach(alt => {
        const tr = document.createElement('tr');
        tr.className = 'audit-doc-row';
        tr.id = `alert-row-${alt.id}`;
        
        const details = getAlertExtraDetails(alt);
        
        let badgeClass = 'badge-low';
        const sev = (alt.severity_level || '').toUpperCase();
        if (sev === 'CRITICAL') badgeClass = 'badge-critical';
        else if (sev === 'HIGH') badgeClass = 'badge-high';
        else if (sev === 'MEDIUM') badgeClass = 'badge-medium';

        let statusClass = 'status-pending';
        if (alt.status === 'Resolved') statusClass = 'status-approved';
        else if (alt.status === 'Under Review') statusClass = 'status-review';

        tr.innerHTML = `
            <td style="font-family: monospace; font-weight: 600; color: var(--text-primary);">${alt.alert_id}</td>
            <td>${new Date(alt.detection_timestamp).toLocaleString('id-ID')}</td>
            <td style="font-family: monospace;">${details.txId}</td>
            <td>#${alt.customer_id} ${alt.customer_name}</td>
            <td style="font-weight: 700;">${alt.risk_score}%</td>
            <td><span class="badge ${badgeClass}"><span class="badge-dot"></span>${alt.severity_level}</span></td>
            <td style="font-family: monospace; font-weight: 600;">${details.combo ? details.combo.id : 'N/A'}</td>
            <td>${details.combo ? details.combo.name : (alt.target_type === 'member' ? 'Member Registry Anomaly' : 'Individual Indicators Only')}</td>
            <td><span class="status-badge ${statusClass}">${alt.status}</span></td>
            <td style="font-weight: 600; text-transform: uppercase; font-size: 11px;">${details.actionTaken}</td>
        `;

        // Click handler to toggle details sub-row
        tr.onclick = (e) => {
            // Prevent toggling if user clicks a link or button inside the row
            if (e.target.tagName === 'BUTTON' || e.target.tagName === 'A') return;
            toggleAlertRowDetails(alt.id, tr);
        };

        tbody.appendChild(tr);
    });
}

function toggleAlertRowDetails(id, tr) {
    const nextRow = tr.nextSibling;
    if (nextRow && nextRow.classList && nextRow.classList.contains('alert-details-row')) {
        // Already expanded, remove it
        tr.classList.remove('expanded');
        nextRow.remove();
        return;
    }

    // Collapse any other expanded rows first
    document.querySelectorAll('.audit-doc-row').forEach(row => {
        if (row !== tr && row.classList.contains('expanded')) {
            row.classList.remove('expanded');
            if (row.nextSibling && row.nextSibling.classList && row.nextSibling.classList.contains('alert-details-row')) {
                row.nextSibling.remove();
            }
        }
    });

    tr.classList.add('expanded');
    
    // Find alert details
    const alt = allAlerts.find(a => a.id === id);
    if (!alt) return;
    
    const details = getAlertExtraDetails(alt);
    const member = details.member;
    
    // Build device details section if it exists and is not N/A
    let deviceHTML = '';
    if (member && member.device_info && member.device_info !== 'N/A' && member.device_info !== '') {
        const deviceData = parseDeviceSignature(member.device_info);
        if (deviceData.device !== 'Unknown Device' || deviceData.os !== 'Unknown OS' || deviceData.browser !== 'Unknown Browser') {
            const sameDeviceCount = allMembers.filter(m => m.device_info === member.device_info).length || 1;
            let deviceRiskText = '';
            if (sameDeviceCount > 1) {
                deviceRiskText = `Used by ${sameDeviceCount} accounts — possible duplicate account risk.`;
            } else if (alt.transaction_details && alt.transaction_details.login_location_changed === 1) {
                deviceRiskText = "New device — review if combined with other risk signals.";
            } else {
                deviceRiskText = "Known device for this member.";
            }
            
            deviceHTML = `
                <div class="detail-block" style="grid-column: span 2;">
                    <div class="detail-label">Device & Network Signature</div>
                    <div class="detail-content" style="background: rgba(255, 255, 255, 0.02); padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-color); margin-top: 4px;">
                        <strong>Device Used:</strong> ${deviceData.device} &nbsp;•&nbsp; 
                        <strong>Operating System:</strong> ${deviceData.os} &nbsp;•&nbsp; 
                        <strong>Web Browser:</strong> ${deviceData.browser} &nbsp;•&nbsp; 
                        <strong>IP Address / Log:</strong> ${member.ip_address || 'N/A'}
                        <div style="font-size: 11px; color: var(--color-high); margin-top: 6px; font-weight: 500;">
                            ℹ️ ${deviceRiskText}
                        </div>
                    </div>
                </div>
            `;
        }
    }

    const flagLabelsMap = {
        "flag_ip_outsider": "Foreign IP Address",
        "flag_repeated_purchase": "Repeated Purchase >10",
        "flag_high_frequency": "Transaction Freq >3/hr",
        "flag_duplicate_account": "Duplicate Account",
        "flag_same_device": "Same Device Multi-Account",
        "flag_location_changed": "Login Location Changed",
        "flag_same_product_high": "Same Product count >5/mo",
        "flag_payment_retry": "Payment Retry >= 3",
        "flag_failed_login": "Failed Logins >= 3",
        "flag_id_not_verified": "ID Not Verified",
        "flag_kks_not_valid": "KKS Invalid",
        "flag_card_invalid": "Card Invalid",
        "flag_subsidy_exhausted": "Subsidy Exhausted",
        "flag_kiosk": "Kiosk Transaction"
    };
    const mappedFlags = alt.indicators.map(f => flagLabelsMap[f] || f).join(' | ');

    // Create the details row
    const detailsTr = document.createElement('tr');
    detailsTr.className = 'alert-details-row';
    detailsTr.innerHTML = `
        <td colspan="10">
            <div class="alert-details-container">
                <div class="details-grid">
                    <div class="detail-block">
                        <div class="detail-label">Triggered Heuristic Indicators</div>
                        <div class="detail-content" style="color: var(--color-critical); font-family: monospace; font-weight: 600;">
                            ${mappedFlags}
                        </div>
                    </div>
                    
                    <div class="detail-block">
                        <div class="detail-label">Transaction Specifics</div>
                        <div class="detail-content">
                            <strong>Amount:</strong> ${details.amount} &nbsp;•&nbsp; 
                            <strong>Recommended Action:</strong> <span style="font-style: italic;">${alt.recommended_action}</span>
                        </div>
                    </div>
                    
                    <div class="detail-block" style="grid-column: span 2;">
                        <div class="detail-label">Auditor Recommendation & Notes</div>
                        <div class="detail-content" style="font-style: italic;">
                            ${details.notes}
                        </div>
                    </div>

                    ${deviceHTML}
                </div>
            </div>
        </td>
    `;
    
    // Insert details row after main row
    tr.parentNode.insertBefore(detailsTr, tr.nextSibling);
}

function findTriggeredCombination(alert) {
    const indicators = alert.indicators || [];
    const combinations = [
        { id: "C1", score: 100, name: "Foreign IP + Failed Logins + Payment Retry", flags: ["flag_ip_outsider", "flag_failed_login", "flag_payment_retry"] },
        { id: "C2", score: 95, name: "Foreign IP + Location Changed + Same Device", flags: ["flag_ip_outsider", "flag_location_changed", "flag_same_device"] },
        { id: "C3", score: 90, name: "Foreign IP + Duplicate Account", flags: ["flag_ip_outsider", "flag_duplicate_account"] },
        { id: "C4", score: 85, name: "Foreign IP + Subsidy Exhausted", flags: ["flag_ip_outsider", "flag_subsidy_exhausted"] },
        { id: "C5", score: 80, name: "Duplicate Account + Same Device + Location Changed", flags: ["flag_duplicate_account", "flag_same_device", "flag_location_changed"] },
        { id: "C6", score: 75, name: "High Frequency + Repeated Purchase + Same Product", flags: ["flag_high_frequency", "flag_repeated_purchase", "flag_same_product_high"] },
        { id: "C7", score: 70, name: "Failed Logins + Payment Retry + High Frequency", flags: ["flag_failed_login", "flag_payment_retry", "flag_high_frequency"] },
        { id: "C8", score: 65, name: "Failed Logins + Payment Retry + Invalid Card", flags: ["flag_failed_login", "flag_payment_retry", "flag_card_invalid"] },
        { id: "C9", score: 65, name: "Duplicate Account + Payment Retry + Invalid Card", flags: ["flag_duplicate_account", "flag_payment_retry", "flag_card_invalid"] },
        { id: "C10", score: 60, name: "Duplicate Account + Failed Logins", flags: ["flag_duplicate_account", "flag_failed_login"] },
        { id: "C11", score: 55, name: "Subsidy Exhausted + High Frequency", flags: ["flag_subsidy_exhausted", "flag_high_frequency"] },
        { id: "C12", score: 50, name: "Unverified ID + Invalid KKS + Invalid Card", flags: ["flag_id_not_verified", "flag_kks_not_valid", "flag_card_invalid"] },
        { id: "C13", score: 45, name: "Unverified ID + Duplicate Account", flags: ["flag_id_not_verified", "flag_duplicate_account"] }
    ];
    
    const matches = combinations.filter(c => c.flags.every(f => indicators.includes(f)));
    if (matches.length > 0) {
        matches.sort((a, b) => b.score - a.score);
        return matches[0];
    }
    return null;
}

function selectAuditDocAlertInTable(alertId) {
    const alt = allAlerts.find(a => a.id === alertId);
    if (!alt) return;
    
    // Clear filters to show target alert
    const searchInput = document.getElementById('audit-doc-search-input');
    if (searchInput) searchInput.value = alt.alert_id;
    
    const filterSev = document.getElementById('filter-doc-severity');
    if (filterSev) filterSev.value = 'ALL';
    
    const filterStat = document.getElementById('filter-doc-status');
    if (filterStat) filterStat.value = 'ALL';
    
    const filterRule = document.getElementById('filter-doc-rule-id');
    if (filterRule) filterRule.value = 'ALL';
    
    const filterDate = document.getElementById('filter-doc-date');
    if (filterDate) filterDate.value = '';
    
    handleAuditDocFilter();
    
    setTimeout(() => {
        const tr = document.getElementById(`alert-row-${alt.id}`);
        if (tr) {
            tr.scrollIntoView({ behavior: 'smooth', block: 'center' });
            toggleAlertRowDetails(alt.id, tr);
        }
    }, 150);
}

function exportDocAlertsToPDF() {
    if (filteredAlertsForDoc.length === 0) {
        alert("No alerts to export.");
        return;
    }
    
    const tbody = document.getElementById('print-doc-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    document.getElementById('print-doc-timestamp').textContent = new Date().toLocaleString('id-ID');
    
    filteredAlertsForDoc.forEach(alt => {
        const details = getAlertExtraDetails(alt);
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-family: monospace;">${alt.alert_id}</td>
            <td>${new Date(alt.detection_timestamp).toLocaleString('id-ID')}</td>
            <td style="font-family: monospace;">${details.txId}</td>
            <td>#${alt.customer_id} ${alt.customer_name}</td>
            <td>${alt.risk_score}%</td>
            <td>${alt.severity_level}</td>
            <td style="font-family: monospace;">${details.combo ? details.combo.id : 'N/A'}</td>
            <td>${details.combo ? details.combo.name : (alt.target_type === 'member' ? 'Member Registry Anomaly' : 'Individual Indicators Only')}</td>
            <td>${alt.indicators.join(' | ')}</td>
            <td>${details.amount}</td>
            <td>${alt.status}</td>
            <td style="text-transform: uppercase;">${details.actionTaken}</td>
            <td>${details.notes}</td>
        `;
        tbody.appendChild(tr);
    });
    
    window.print();
}

function exportDocAlertsToDOCX() {
    if (filteredAlertsForDoc.length === 0) {
        alert("No alerts to export.");
        return;
    }
    
    let tableRowsHTML = '';
    filteredAlertsForDoc.forEach(alt => {
        const details = getAlertExtraDetails(alt);
        tableRowsHTML += `
            <tr>
                <td style="font-family: monospace;">${alt.alert_id}</td>
                <td>${new Date(alt.detection_timestamp).toLocaleString('id-ID')}</td>
                <td style="font-family: monospace;">${details.txId}</td>
                <td>#${alt.customer_id} ${alt.customer_name}</td>
                <td>${alt.risk_score}%</td>
                <td>${alt.severity_level}</td>
                <td style="font-family: monospace;">${details.combo ? details.combo.id : 'N/A'}</td>
                <td>${details.combo ? details.combo.name : (alt.target_type === 'member' ? 'Member Registry Anomaly' : 'Individual Indicators Only')}</td>
                <td>${alt.indicators.join(' | ')}</td>
                <td>${details.amount}</td>
                <td>${alt.status}</td>
                <td style="text-transform: uppercase;">${details.actionTaken}</td>
                <td>${details.notes}</td>
            </tr>
        `;
    });
    
    const docHtml = `
        <html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
        <head>
            <title>Kova Mart Alerts Audit Document</title>
            <style>
                body { font-family: Arial, sans-serif; font-size: 10pt; color: #1a1a1a; padding: 20px; }
                h2 { color: #111111; border-bottom: 2px solid #ff1744; padding-bottom: 8px; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; }
                th, td { border: 1px solid #d0d0d0; padding: 6px; text-align: left; vertical-align: top; font-size: 9pt; }
                th { background-color: #f2f2f2; font-weight: bold; }
            </style>
        </head>
        <body>
            <h2>Kova Mart - Alerts Audit Document</h2>
            <p>Generated: ${new Date().toLocaleString('id-ID')}</p>
            <table>
                <thead>
                    <tr>
                        <th>Alert ID</th>
                        <th>Date/Time</th>
                        <th>Transaction ID</th>
                        <th>Customer ID/Name</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                        <th>Rule ID</th>
                        <th>Rule Name</th>
                        <th>Triggered Indicators</th>
                        <th>Amount</th>
                        <th>Status</th>
                        <th>Action Taken</th>
                        <th>Audit Notes</th>
                    </tr>
                </thead>
                <tbody>
                    ${tableRowsHTML}
                </tbody>
            </table>
        </body>
        </html>
    `;
    
    const blob = new Blob(['\ufeff' + docHtml], { type: 'application/msword' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `KovaMart_Alerts_Audit_Report_${Date.now()}.doc`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function exportDocAlertsToCSV() {
    if (filteredAlertsForDoc.length === 0) {
        alert("No alerts to export.");
        return;
    }
    
    const headers = [
        "Alert ID", "Date/Time", "Transaction ID", "Customer ID/Name", 
        "Risk Score", "Risk Level", "Triggered Combo Rule ID", 
        "Triggered Combo Rule Name", "Triggered Indicators", 
        "Transaction Amount", "Status", "Action Taken", "Audit Notes"
    ];
    
    const csvRows = [headers.join(",")];
    
    filteredAlertsForDoc.forEach(alt => {
        const details = getAlertExtraDetails(alt);
        const row = [
            alt.alert_id,
            new Date(alt.detection_timestamp).toLocaleString('id-ID'),
            details.txId,
            `#${alt.customer_id} ${alt.customer_name}`,
            alt.risk_score + "%",
            alt.severity_level,
            details.combo ? details.combo.id : "N/A",
            details.combo ? details.combo.name : (alt.target_type === 'member' ? "Member Registry Anomaly" : "Individual Indicators Only"),
            alt.indicators.join(" | "),
            details.amount,
            alt.status,
            details.actionTaken,
            details.notes
        ];
        
        const escapedRow = row.map(val => {
            const str = val === null || val === undefined ? "" : val.toString();
            return `"${str.replace(/"/g, '""')}"`;
        });
        csvRows.push(escapedRow.join(","));
    });
    
    const blob = new Blob(['\ufeff' + csvRows.join("\r\n")], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `KovaMart_Alerts_Audit_Report_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}
