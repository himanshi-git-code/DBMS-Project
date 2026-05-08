// =============================================
// CYBERSECURITY INCIDENT MANAGEMENT SYSTEM
// All ER diagram tables implemented
// =============================================

class CIMS {
    constructor() {
        this.db = {
            users: this._load('users'),
            assets: this._load('assets'),
            incidents: this._load('incidents'),
            vulnerabilities: this._load('vulnerabilities'),
            threatActors: this._load('threatActors'),
            responseActions: this._load('responseActions'),
            securityControls: this._load('securityControls'),
            incidentCategories: this._load('incidentCategories'),
            incidentStatuses: this._load('incidentStatuses'),
            logs: this._load('logs'),
            incidentVulnerabilities: this._load('incidentVulnerabilities'),
            incidentThreatActors: this._load('incidentThreatActors'),
            assetControls: this._load('assetControls'),
            incidentComments: this._load('incidentComments'),
        };
        this.currentUser = null;
        this._seedDefaults();
        this.init();
    }

    // ── API endpoint map ──────────────────────────────────────────────
    // keys that have a dedicated PHP file or data.php entity parameter
    _apiEndpoint(key) {
        const map = {
            incidents:        { url: 'api/incidents.php' },
            assets:           { url: 'api/assets.php' },
            vulnerabilities:  { url: 'api/data.php', entity: 'vulnerabilities' },
            threatActors:     { url: 'api/data.php', entity: 'threats' },
            responseActions:  { url: 'api/data.php', entity: 'responseActions' },
            logs:             { url: 'api/data.php', entity: 'logs' },
            users:            { url: 'api/auth.php', entity: 'users' },
            securityControls: { url: 'api/data.php', entity: 'securityControls' },
        };
        return map[key] || null;
    }

    // Legacy localStorage helpers (used for lookup-only tables like categories/statuses)
    _load(key) { return JSON.parse(localStorage.getItem('cims_' + key) || '[]'); }
    _save(key) { localStorage.setItem('cims_' + key, JSON.stringify(this.db[key])); }
    _id() { return Date.now() + Math.floor(Math.random() * 1000); }

    // ── Fetch data from API ───────────────────────────────────────────
    async _fetchFromAPI(key) {
        const ep = this._apiEndpoint(key);
        if (!ep) return this._load(key);
        try {
            const url = ep.entity ? `${ep.url}?entity=${ep.entity}` : ep.url;
            console.log(`[CIMS] Fetching ${key} from: ${url}`);
            const res = await fetch(url);
            const text = await res.text();
            console.log(`[CIMS] Response for ${key} (status ${res.status}):`, text.substring(0, 300));
            if (!res.ok) throw new Error('HTTP ' + res.status + ': ' + text.substring(0, 200));
            const data = JSON.parse(text);
            if (data.error) throw new Error(data.error);
            if (Array.isArray(data)) { console.log(`[CIMS] ${key}: ${data.length} records`); return data; }
            return [];
        } catch (e) {
            console.error(`[CIMS] API fetch FAILED for ${key}:`, e.message);
            this._notify(`Data load failed (${key}): ${e.message}`, 'error');
            return [];
        }
    }

    // ── Load all DB tables from API on startup ────────────────────────
    async _loadAllFromAPI() {
        const apiKeys = ['incidents','assets','vulnerabilities','threatActors','responseActions','logs','users','securityControls'];
        const results = await Promise.all(apiKeys.map(k => this._fetchFromAPI(k)));
        apiKeys.forEach((k, i) => { this.db[k] = results[i]; });
    }

    _seedDefaults() {
        if (!this.db.incidentCategories.length) {
            this.db.incidentCategories = [
                { category_id: 1, category_name: 'Malware' },
                { category_id: 2, category_name: 'Phishing' },
                { category_id: 3, category_name: 'DDoS' },
                { category_id: 4, category_name: 'Data Breach' },
                { category_id: 5, category_name: 'Ransomware' },
                { category_id: 6, category_name: 'Insider Threat' },
                { category_id: 7, category_name: 'Zero-Day' },
            ];
            this._save('incidentCategories');
        }
        if (!this.db.incidentStatuses.length) {
            this.db.incidentStatuses = [
                { status_id: 1, status_name: 'Open' },
                { status_id: 2, status_name: 'In Progress' },
                { status_id: 3, status_name: 'Resolved' },
                { status_id: 4, status_name: 'Closed' },
            ];
            this._save('incidentStatuses');
        }
    }

    init() {
        this._bindAuth();
        this._checkSession();
    }

    // =============== AUTH ===============

    _bindAuth() {
        document.getElementById('loginForm').addEventListener('submit', e => { e.preventDefault(); this._login(); });
        document.getElementById('signupForm').addEventListener('submit', e => { e.preventDefault(); this._signup(); });
        document.getElementById('showSignup').addEventListener('click', e => { e.preventDefault(); this._switchModal('signup'); });
        document.getElementById('showLogin').addEventListener('click', e => { e.preventDefault(); this._switchModal('login'); });
        document.getElementById('logoutBtn').addEventListener('click', () => this._logout());
        document.getElementById('menuToggle').addEventListener('click', () => {
            document.getElementById('sidebar').classList.toggle('open');
        });
        document.querySelectorAll('.sidebar a').forEach(link => {
            link.addEventListener('click', e => { e.preventDefault(); this.showPage(link.dataset.page); });
        });
    }

    _switchModal(to) {
        document.getElementById('loginModal').classList.toggle('active', to === 'login');
        document.getElementById('signupModal').classList.toggle('active', to === 'signup');
    }

    _checkSession() {
        const u = localStorage.getItem('cims_session');
        if (u) { this.currentUser = JSON.parse(u); this._enterApp(); }
    }

    async _login() {
        const email = document.getElementById('loginEmail').value.trim();
        const pass = document.getElementById('loginPassword').value;
        try {
            const res = await fetch('api/auth.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'login', email, password: pass })
            });
            const data = await res.json();
            if (data.error) { this._notify(data.error, 'error'); return; }
            this.currentUser = data.user;
            localStorage.setItem('cims_session', JSON.stringify(data.user));
            this._enterApp();
        } catch (e) {
            this._notify('Login failed: ' + e.message, 'error');
        }
    }

    async _signup() {
        const name = document.getElementById('signupName').value.trim();
        const email = document.getElementById('signupEmail').value.trim();
        const phone = document.getElementById('signupPhone').value.trim();
        const dept = document.getElementById('signupDept').value.trim();
        const role = document.getElementById('signupRole').value;
        const pass = document.getElementById('signupPassword').value;

        if (!name || !email || !role || !pass || !dept) { this._notify('Please fill all required fields', 'error'); return; }

        try {
            const res = await fetch('api/auth.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'register', name, email, password: pass, phone, department: dept, role })
            });
            const data = await res.json();
            if (data.error) { this._notify(data.error, 'error'); return; }
            this._notify('Registration successful! Please login.', 'success');
            this._switchModal('login');
        } catch (e) {
            this._notify('Signup failed: ' + e.message, 'error');
        }
    }

    async _enterApp() {
        document.getElementById('loginModal').classList.remove('active');
        document.getElementById('signupModal').classList.remove('active');
        document.getElementById('mainApp').classList.remove('hidden');
        document.getElementById('currentUser').textContent = this.currentUser.name;
        document.getElementById('currentRole').textContent = this.currentUser.role;

        if (this.currentUser.role !== 'Admin') {
            document.querySelectorAll('.admin-only').forEach(el => el.style.display = 'none');
        }
        // Load all data from PHP API before rendering
        await this._loadAllFromAPI();
        this.showPage('dashboard');
    }

    _logout() {
        localStorage.removeItem('cims_session');
        location.reload();
    }

    // =============== NAVIGATION ===============

    showPage(page) {
        document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
        document.querySelectorAll('.sidebar a').forEach(a => a.classList.remove('active'));
        const pageEl = document.getElementById(page + 'Page');
        if (!pageEl) return;
        pageEl.classList.remove('hidden');
        const navLink = document.querySelector(`[data-page="${page}"]`);
        if (navLink) navLink.classList.add('active');

        // Pages that need fresh data from API
        const apiPages = { incidents: 'incidents', assets: 'assets', vulnerabilities: 'vulnerabilities', threatActors: 'threatActors', logs: 'logs', users: 'users' };
        const renders = {
            dashboard: () => this._renderDashboard(),
            incidents: () => this._renderIncidents(),
            assets: () => this._renderAssets(),
            vulnerabilities: () => this._renderVulnerabilities(),
            threatActors: () => this._renderThreatActors(),
            responseActions: () => this._renderResponseActions(),
            securityControls: () => this._renderSecurityControls(),
            logs: () => this._renderLogs(),
            users: () => this._renderUsers(),
            admin: () => this._renderAdmin(),
        };
        if (apiPages[page]) {
            this._fetchFromAPI(apiPages[page]).then(data => {
                this.db[apiPages[page]] = data;
                if (renders[page]) renders[page]();
            });
        } else {
            if (renders[page]) renders[page]();
        }
    }

    // =============== DASHBOARD ===============

    _renderDashboard() {
        const criticals = this.db.incidents.filter(i => i.severity === 'Critical').length;
        document.getElementById('totalIncidents').textContent = this.db.incidents.length;
        document.getElementById('criticalIncidents').textContent = criticals;
        document.getElementById('totalAssets').textContent = this.db.assets.length;
        document.getElementById('totalVulns').textContent = this.db.vulnerabilities.length;
        document.getElementById('totalThreats').textContent = this.db.threatActors.length;
        document.getElementById('totalUsers').textContent = this.db.users.length;

        const recent = [...this.db.incidents].reverse().slice(0, 5);
        const tbody = document.querySelector('#recentIncidentsTable tbody');
        tbody.innerHTML = recent.length ? recent.map(i => `
            <tr>
                <td>#${String(i.incident_id).slice(-5)}</td>
                <td>${i.title}</td>
                <td>${this._sevBadge(i.severity)}</td>
                <td>${this._statusBadge(this._statusName(i.status_id))}</td>
                <td>${i.detected_date || '—'}</td>
            </tr>
        `).join('') : `<tr><td colspan="5"><div class="empty-state"><i class="fas fa-shield-halved"></i>No incidents yet</div></td></tr>`;
    }

    // =============== INCIDENTS ===============

    _renderIncidents(data) {
        const list = data || this.db.incidents;
        const tbody = document.querySelector('#incidentsTable tbody');
        tbody.innerHTML = list.length ? list.map(i => {
            return `<tr>
                <td>#${String(i.incident_id).slice(-5)}</td>
                <td><strong>${i.title}</strong></td>
                <td>${this._sevBadge(i.severity)}</td>
                <td>${this._statusBadge(i.status)}</td>
                <td>${i.asset_name || '—'}</td>
                <td>${i.reporter || '—'}</td>
                <td>${i.detected_date || '—'}</td>
                <td>
                    <button class="action-btn" onclick="app.viewIncident(${i.incident_id})"><i class="fas fa-eye"></i></button>
                    <button class="action-btn" onclick="app.openModal('incident',${i.incident_id})"><i class="fas fa-pen"></i></button>
                    <button class="action-btn del" onclick="app._delete('incidents','incident_id',${i.incident_id},'_renderIncidents')"><i class="fas fa-trash"></i></button>
                </td>
            </tr>`;
        }).join('') : `<tr><td colspan="9"><div class="empty-state"><i class="fas fa-triangle-exclamation"></i>No incidents recorded</div></td></tr>`;
    }

    viewIncident(id) {
        const i = this.db.incidents.find(x => x.incident_id === id);
        if (!i) return;
        const asset = this.db.assets.find(a => a.asset_id === i.asset_id);
        const reporter = this.db.users.find(u => u.user_id === i.reported_by);
        const cat = this.db.incidentCategories.find(c => c.category_id === i.category_id);
        const vulns = this.db.incidentVulnerabilities.filter(iv => iv.incident_id === id)
            .map(iv => this.db.vulnerabilities.find(v => v.vulnerability_id === iv.vulnerability_id))
            .filter(Boolean).map(v => v.cve_id).join(', ');
        const actors = this.db.incidentThreatActors.filter(it => it.incident_id === id)
            .map(it => this.db.threatActors.find(t => t.threat_actor_id === it.threat_actor_id))
            .filter(Boolean).map(t => t.name).join(', ');
        const actions = this.db.responseActions.filter(r => r.incident_id === id);
        const comments = this.db.incidentComments.filter(c => c.incident_id === id);

        document.getElementById('viewModalTitle').textContent = '🔍 Incident Detail';
        document.getElementById('viewModalBody').innerHTML = `
            <div class="detail-grid">
                <div class="detail-item"><label>Title</label><span>${i.title}</span></div>
                <div class="detail-item"><label>Severity</label><span>${this._sevBadge(i.severity)}</span></div>
                <div class="detail-item"><label>Status</label><span>${this._statusBadge(this._statusName(i.status_id))}</span></div>
                <div class="detail-item"><label>Category</label><span>${cat ? cat.category_name : '—'}</span></div>
                <div class="detail-item"><label>Asset</label><span>${asset ? asset.asset_name : '—'}</span></div>
                <div class="detail-item"><label>Reported By</label><span>${reporter ? reporter.name : '—'}</span></div>
                <div class="detail-item"><label>Detected Date</label><span>${i.detected_date || '—'}</span></div>
                <div class="detail-item"><label>Resolution Date</label><span>${i.resolution_date || '—'}</span></div>
                <div class="detail-item full"><label>Description</label><span>${i.description || '—'}</span></div>
                <div class="detail-item"><label>Vulnerabilities</label><span>${vulns || '—'}</span></div>
                <div class="detail-item"><label>Threat Actors</label><span>${actors || '—'}</span></div>
                ${actions.length ? `<div class="detail-item full"><label>Response Actions (${actions.length})</label><span>${actions.map(a=>a.action_description).join(' | ')}</span></div>` : ''}
                ${comments.length ? `<div class="detail-item full"><label>Comments (${comments.length})</label><span>${comments.map(c=>c.comment_text).join(' | ')}</span></div>` : ''}
            </div>`;
        document.getElementById('viewModal').classList.add('active');
    }

    closeViewModal() { document.getElementById('viewModal').classList.remove('active'); }

    filterTable(type) {
        if (type === 'incidents') {
            const q = document.getElementById('incidentSearch').value.toLowerCase();
            const sev = document.getElementById('incidentSeverityFilter').value;
            const sta = document.getElementById('incidentStatusFilter').value;
            const filtered = this.db.incidents.filter(i =>
                (!q || i.title.toLowerCase().includes(q)) &&
                (!sev || i.severity === sev) &&
                (!sta || this._statusName(i.status_id) === sta)
            );
            this._renderIncidents(filtered);
        }
        if (type === 'assets') {
            const q = document.getElementById('assetSearch').value.toLowerCase();
            const type2 = document.getElementById('assetTypeFilter').value;
            const filtered = this.db.assets.filter(a =>
                (!q || a.asset_name.toLowerCase().includes(q)) &&
                (!type2 || a.asset_type === type2)
            );
            this._renderAssets(filtered);
        }
        if (type === 'vulnerabilities') {
            const q = document.getElementById('vulnSearch').value.toLowerCase();
            const risk = document.getElementById('riskFilter').value;
            const filtered = this.db.vulnerabilities.filter(v =>
                (!q || v.cve_id.toLowerCase().includes(q) || v.description.toLowerCase().includes(q)) &&
                (!risk || v.risk_level === risk)
            );
            this._renderVulnerabilities(filtered);
        }
    }

    // =============== ASSETS ===============

    _renderAssets(data) {
        const list = data || this.db.assets;
        const tbody = document.querySelector('#assetsTable tbody');
        tbody.innerHTML = list.length ? list.map(a => {
            const owner = this.db.users.find(u => u.user_id === a.owner_id);
            return `<tr>
                <td>#${String(a.asset_id).slice(-5)}</td>
                <td><strong>${a.asset_name}</strong></td>
                <td>${a.asset_type}</td>
                <td><code style="color:var(--accent);background:rgba(0,229,255,0.07);padding:2px 6px;border-radius:4px">${a.ip_address || '—'}</code></td>
                <td>${a.location || '—'}</td>
                <td>${owner ? owner.name : '—'}</td>
                <td>
                    <button class="action-btn" onclick="app.openModal('asset',${a.asset_id})"><i class="fas fa-pen"></i></button>
                    <button class="action-btn del" onclick="app._delete('assets','asset_id',${a.asset_id},'_renderAssets')"><i class="fas fa-trash"></i></button>
                </td>
            </tr>`;
        }).join('') : `<tr><td colspan="7"><div class="empty-state"><i class="fas fa-server"></i>No assets registered</div></td></tr>`;
    }

    // =============== VULNERABILITIES ===============

    _renderVulnerabilities(data) {
        const list = data || this.db.vulnerabilities;
        const tbody = document.querySelector('#vulnsTable tbody');
        tbody.innerHTML = list.length ? list.map(v => `<tr>
            <td>#${String(v.vulnerability_id).slice(-5)}</td>
            <td><strong>${v.cve_id}</strong></td>
            <td>${v.description || '—'}</td>
            <td>${this._riskBadge(v.risk_level)}</td>
            <td><span style="color:${this._cvssColor(v.cvss_score)};font-weight:700">${v.cvss_score || '—'}</span></td>
            <td>
                <button class="action-btn" onclick="app.openModal('vulnerability',${v.vulnerability_id})"><i class="fas fa-pen"></i></button>
                <button class="action-btn del" onclick="app._delete('vulnerabilities','vulnerability_id',${v.vulnerability_id},'_renderVulnerabilities')"><i class="fas fa-trash"></i></button>
            </td>
        </tr>`).join('') : `<tr><td colspan="6"><div class="empty-state"><i class="fas fa-bug"></i>No vulnerabilities recorded</div></td></tr>`;
    }

    _cvssColor(score) {
        if (!score) return 'var(--text-dim)';
        const s = parseFloat(score);
        if (s >= 9) return 'var(--critical)';
        if (s >= 7) return '#ff8232';
        if (s >= 4) return 'var(--warning)';
        return 'var(--success)';
    }

    // =============== THREAT ACTORS ===============

    _renderThreatActors() {
        const tbody = document.querySelector('#threatActorsTable tbody');
        tbody.innerHTML = this.db.threatActors.length ? this.db.threatActors.map(t => `<tr>
            <td>#${String(t.threat_actor_id).slice(-5)}</td>
            <td><strong>${t.name}</strong></td>
            <td>${t.origin_country || '—'}</td>
            <td>${t.motivation || '—'}</td>
            <td>
                <button class="action-btn" onclick="app.openModal('threatActor',${t.threat_actor_id})"><i class="fas fa-pen"></i></button>
                <button class="action-btn del" onclick="app._delete('threatActors','threat_actor_id',${t.threat_actor_id},'_renderThreatActors')"><i class="fas fa-trash"></i></button>
            </td>
        </tr>`).join('') : `<tr><td colspan="5"><div class="empty-state"><i class="fas fa-user-secret"></i>No threat actors recorded</div></td></tr>`;
    }

    // =============== RESPONSE ACTIONS ===============

    _renderResponseActions() {
        const tbody = document.querySelector('#responseActionsTable tbody');
        tbody.innerHTML = this.db.responseActions.length ? this.db.responseActions.map(r => {
            const incident = this.db.incidents.find(i => i.incident_id === r.incident_id);
            return `<tr>
                <td>#${String(r.action_id).slice(-5)}</td>
                <td>${incident ? incident.title : '—'}</td>
                <td>${r.action_description}</td>
                <td>${r.action_date || '—'}</td>
                <td>
                    <button class="action-btn" onclick="app.openModal('responseAction',${r.action_id})"><i class="fas fa-pen"></i></button>
                    <button class="action-btn del" onclick="app._delete('responseActions','action_id',${r.action_id},'_renderResponseActions')"><i class="fas fa-trash"></i></button>
                </td>
            </tr>`;
        }).join('') : `<tr><td colspan="5"><div class="empty-state"><i class="fas fa-shield-virus"></i>No response actions recorded</div></td></tr>`;
    }

    // =============== SECURITY CONTROLS ===============

    _renderSecurityControls() {
        const tbody = document.querySelector('#securityControlsTable tbody');
        tbody.innerHTML = this.db.securityControls.length ? this.db.securityControls.map(c => `<tr>
            <td>#${String(c.control_id).slice(-5)}</td>
            <td><strong>${c.control_name}</strong></td>
            <td>${c.control_type || '—'}</td>
            <td>${c.implementation_date || '—'}</td>
            <td><span class="${c.status === 'Active' ? 'status-badge status-resolved' : 'status-badge status-closed'}">${c.status || '—'}</span></td>
            <td>
                <button class="action-btn" onclick="app.openModal('securityControl',${c.control_id})"><i class="fas fa-pen"></i></button>
                <button class="action-btn del" onclick="app._delete('securityControls','control_id',${c.control_id},'_renderSecurityControls')"><i class="fas fa-trash"></i></button>
            </td>
        </tr>`).join('') : `<tr><td colspan="6"><div class="empty-state"><i class="fas fa-lock"></i>No security controls defined</div></td></tr>`;
    }

    // =============== LOGS ===============

    _renderLogs() {
        const tbody = document.querySelector('#logsTable tbody');
        tbody.innerHTML = this.db.logs.length ? this.db.logs.map(l => {
            const asset = this.db.assets.find(a => a.asset_id === l.asset_id);
            return `<tr>
                <td>#${String(l.log_id).slice(-5)}</td>
                <td>${asset ? asset.asset_name : '—'}</td>
                <td>${l.log_time || '—'}</td>
                <td>${l.event_type || '—'}</td>
                <td>
                    <button class="action-btn" onclick="app.openModal('log',${l.log_id})"><i class="fas fa-pen"></i></button>
                    <button class="action-btn del" onclick="app._delete('logs','log_id',${l.log_id},'_renderLogs')"><i class="fas fa-trash"></i></button>
                </td>
            </tr>`;
        }).join('') : `<tr><td colspan="5"><div class="empty-state"><i class="fas fa-list-check"></i>No logs recorded</div></td></tr>`;
    }

    // =============== USERS ===============

    _renderUsers() {
        const tbody = document.querySelector('#usersTable tbody');
        tbody.innerHTML = this.db.users.length ? this.db.users.map(u => `<tr>
            <td>#${String(u.user_id).slice(-5)}</td>
            <td><strong>${u.name}</strong></td>
            <td>${u.email}</td>
            <td><span class="status-badge status-inprogress">${u.role}</span></td>
            <td>${u.department || '—'}</td>
            <td>${u.phone_number || '—'}</td>
            <td>
                <button class="action-btn" onclick="app.openModal('user',${u.user_id})"><i class="fas fa-pen"></i></button>
            </td>
        </tr>`).join('') : `<tr><td colspan="7"><div class="empty-state"><i class="fas fa-users"></i>No users found</div></td></tr>`;
    }

    // ---- USER FORM ----
    _userForm(editId) {
        const data = editId ? this.db.users.find(u => u.user_id === editId) : null;
        if (!data) { this._notify('User not found', 'error'); return; }
        document.getElementById('formModalTitle').textContent = '✏️ Edit User';
        document.getElementById('formModalBody').innerHTML = `
        <div class="form-section">
            <div class="form-section-title">User Details</div>
            <div class="form-grid">
                <div class="field-group">
                    <label>Full Name *</label>
                    <input id="f_name" type="text" placeholder="Full name" value="${data.name || ''}">
                </div>
                <div class="field-group">
                    <label>Email *</label>
                    <input id="f_email" type="email" placeholder="email@example.com" value="${data.email || ''}">
                </div>
                <div class="field-group">
                    <label>Role</label>
                    <select id="f_role">
                        ${['Admin','Analyst','Responder','Viewer'].map(r=>`<option ${data.role===r?'selected':''}>${r}</option>`).join('')}
                    </select>
                </div>
                <div class="field-group">
                    <label>Department</label>
                    <input id="f_dept" type="text" placeholder="e.g. IT Security" value="${data.department || ''}">
                </div>
                <div class="field-group full">
                    <label>Phone Number</label>
                    <input id="f_phone" type="text" placeholder="+91 XXXXX XXXXX" value="${data.phone_number || ''}">
                </div>
            </div>
        </div>
        <div class="form-actions">
            <button class="btn-secondary" onclick="app.closeModal()">Cancel</button>
            <button class="btn-primary" onclick="app._saveUser(${editId})"><i class="fas fa-save"></i> Save User</button>
        </div>`;
    }

    async _saveUser(editId) {
        const name = document.getElementById('f_name').value.trim();
        const email = document.getElementById('f_email').value.trim();
        if (!name || !email) { this._notify('Name and email are required', 'error'); return; }
        const record = {
            user_id: editId,
            name,
            email,
            role: document.getElementById('f_role').value,
            department: document.getElementById('f_dept').value.trim(),
            phone_number: document.getElementById('f_phone').value.trim(),
        };
        await this._upsert('users', 'user_id', record);
        this.closeModal(); this._renderUsers();
        this._notify('User updated', 'success');
    }

    // =============== ADMIN ===============

    _renderAdmin() {
        document.getElementById('adminIncidents').textContent = this.db.incidents.length;
        document.getElementById('adminAssets').textContent = this.db.assets.length;
        document.getElementById('adminVulns').textContent = this.db.vulnerabilities.length;
        document.getElementById('adminUsers').textContent = this.db.users.length;
    }

    globalSearch() {
        const q = document.getElementById('globalSearch').value.toLowerCase();
        const results = document.getElementById('globalSearchResults');
        if (!q) { results.innerHTML = ''; return; }
        const sections = [];
        const matchIncidents = this.db.incidents.filter(i => i.title.toLowerCase().includes(q) || (i.description||'').toLowerCase().includes(q));
        if (matchIncidents.length) sections.push(`<div class="result-section"><h4>Incidents (${matchIncidents.length})</h4><div class="table-container"><table><thead><tr><th>Title</th><th>Severity</th><th>Status</th></tr></thead><tbody>${matchIncidents.map(i=>`<tr><td>${i.title}</td><td>${this._sevBadge(i.severity)}</td><td>${this._statusBadge(this._statusName(i.status_id))}</td></tr>`).join('')}</tbody></table></div></div>`);
        const matchAssets = this.db.assets.filter(a => a.asset_name.toLowerCase().includes(q));
        if (matchAssets.length) sections.push(`<div class="result-section"><h4>Assets (${matchAssets.length})</h4><div class="table-container"><table><thead><tr><th>Name</th><th>Type</th><th>IP</th></tr></thead><tbody>${matchAssets.map(a=>`<tr><td>${a.asset_name}</td><td>${a.asset_type}</td><td>${a.ip_address||'—'}</td></tr>`).join('')}</tbody></table></div></div>`);
        const matchUsers = this.db.users.filter(u => u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q));
        if (matchUsers.length) sections.push(`<div class="result-section"><h4>Users (${matchUsers.length})</h4><div class="table-container"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th></tr></thead><tbody>${matchUsers.map(u=>`<tr><td>${u.name}</td><td>${u.email}</td><td>${u.role}</td></tr>`).join('')}</tbody></table></div></div>`);
        results.innerHTML = sections.join('') || '<p style="color:var(--text-dim);padding:1rem">No results found.</p>';
    }

    // =============== MODAL FORMS ===============

    openModal(type, editId = null) {
        const modal = document.getElementById('formModal');
        modal.classList.add('active');
        const forms = {
            incident: () => this._incidentForm(editId),
            asset: () => this._assetForm(editId),
            vulnerability: () => this._vulnForm(editId),
            threatActor: () => this._threatActorForm(editId),
            responseAction: () => this._responseActionForm(editId),
            securityControl: () => this._securityControlForm(editId),
            log: () => this._logForm(editId),
            user: () => this._userForm(editId),
        };
        if (forms[type]) forms[type]();
    }

    closeModal() {
        document.getElementById('formModal').classList.remove('active');
        document.getElementById('formModalBody').innerHTML = '';
    }

    // ---- INCIDENT FORM ----
    _incidentForm(editId) {
        const data = editId ? this.db.incidents.find(i => i.incident_id === editId) : null;
        document.getElementById('formModalTitle').textContent = editId ? '✏️ Edit Incident' : '🚨 New Incident';

        const assetOpts = this.db.assets.map(a => `<option value="${a.asset_id}" ${data && data.asset_id === a.asset_id ? 'selected' : ''}>${a.asset_name}</option>`).join('');
        const catOpts = this.db.incidentCategories.map(c => `<option value="${c.category_id}" ${data && data.category_id === c.category_id ? 'selected' : ''}>${c.category_name}</option>`).join('');
        const statusOpts = this.db.incidentStatuses.map(s => `<option value="${s.status_id}" ${data && data.status_id === s.status_id ? 'selected' : ''}>${s.status_name}</option>`).join('');
        const vulnOpts = this.db.vulnerabilities.map(v => `<option value="${v.vulnerability_id}">${v.cve_id}</option>`).join('');

        document.getElementById('formModalBody').innerHTML = `
        <div class="form-section">
            <div class="form-section-title">Basic Information</div>
            <div class="form-grid">
                <div class="field-group full">
                    <label>Incident Title *</label>
                    <input id="f_title" type="text" placeholder="Brief incident title" value="${data ? data.title : ''}" required>
                </div>
                <div class="field-group">
                    <label>Severity *</label>
                    <select id="f_severity">
                        ${['Low','Medium','High','Critical'].map(s=>`<option ${data&&data.severity===s?'selected':''}>${s}</option>`).join('')}
                    </select>
                </div>
                <div class="field-group">
                    <label>Category</label>
                    <select id="f_category"><option value="">— Select —</option>${catOpts}</select>
                </div>
                <div class="field-group">
                    <label>Status</label>
                    <select id="f_status"><option value="">— Select —</option>${statusOpts}</select>
                </div>
                <div class="field-group">
                    <label>Affected Asset</label>
                    <select id="f_asset"><option value="">— Select Asset —</option>${assetOpts}</select>
                </div>
                <div class="field-group">
                    <label>Detected Date</label>
                    <input id="f_detected" type="date" value="${data ? data.detected_date : new Date().toISOString().split('T')[0]}">
                </div>
                <div class="field-group">
                    <label>Resolution Date</label>
                    <input id="f_resolved" type="date" value="${data ? data.resolution_date || '' : ''}">
                </div>
                <div class="field-group full">
                    <label>Description</label>
                    <textarea id="f_desc" placeholder="Detailed description of the incident...">${data ? data.description || '' : ''}</textarea>
                </div>
            </div>
        </div>
        ${vulnOpts ? `<div class="form-section">
            <div class="form-section-title">Linked Vulnerabilities</div>
            <div class="field-group">
                <label>Select Vulnerabilities (hold Ctrl for multiple)</label>
                <select id="f_vulns" multiple style="min-height:80px">${vulnOpts}</select>
            </div>
        </div>` : ''}
        <div class="form-actions">
            <button class="btn-secondary" onclick="app.closeModal()">Cancel</button>
            <button class="btn-primary" onclick="app._saveIncident(${editId || null})"><i class="fas fa-save"></i> Save Incident</button>
        </div>`;
    }

    async _saveIncident(editId) {
        const title = document.getElementById('f_title').value.trim();
        if (!title) { this._notify('Title is required', 'error'); return; }
        const record = {
            incident_id: editId || null,
            title,
            severity: document.getElementById('f_severity').value,
            category: document.getElementById('f_category').value || null,
            status: document.getElementById('f_status').value || 'Open',
            asset_id: parseInt(document.getElementById('f_asset').value) || null,
            detected_date: document.getElementById('f_detected').value,
            description: document.getElementById('f_desc').value.trim(),
            reported_by: this.currentUser.user_id,
        };

        try {
            const method = editId ? 'PUT' : 'POST';
            const body = editId ? { ...record, incident_id: editId } : record;
            const res = await fetch('api/incidents.php', {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            const data = await res.json();
            if (data.error) throw new Error(data.error);
            // Reload incidents from API
            this.db.incidents = await this._fetchFromAPI('incidents');
        } catch (e) {
            this._notify('Save failed: ' + e.message, 'error'); return;
        }

        this.closeModal();
        this._renderIncidents();
        this._notify(editId ? 'Incident updated' : 'Incident created', 'success');
    }

    // ---- ASSET FORM ----
    _assetForm(editId) {
        const data = editId ? this.db.assets.find(a => a.asset_id === editId) : null;
        document.getElementById('formModalTitle').textContent = editId ? '✏️ Edit Asset' : '🖥️ New Asset';
        const userOpts = this.db.users.map(u => `<option value="${u.user_id}" ${data && data.owner_id === u.user_id ? 'selected' : ''}>${u.name}</option>`).join('');
        const controls = this.db.securityControls.map(c => `<option value="${c.control_id}">${c.control_name}</option>`).join('');

        document.getElementById('formModalBody').innerHTML = `
        <div class="form-section">
            <div class="form-section-title">Asset Details</div>
            <div class="form-grid">
                <div class="field-group">
                    <label>Asset Name *</label>
                    <input id="f_name" type="text" placeholder="e.g. Web Server 01" value="${data ? data.asset_name : ''}">
                </div>
                <div class="field-group">
                    <label>Asset Type *</label>
                    <select id="f_type">
                        ${['Server','Workstation','Router','Firewall','Database','Cloud','IoT','Mobile'].map(t=>`<option ${data&&data.asset_type===t?'selected':''}>${t}</option>`).join('')}
                    </select>
                </div>
                <div class="field-group">
                    <label>IP Address</label>
                    <input id="f_ip" type="text" placeholder="192.168.1.1" value="${data ? data.ip_address || '' : ''}">
                </div>
                <div class="field-group">
                    <label>Location</label>
                    <input id="f_loc" type="text" placeholder="e.g. Data Center A" value="${data ? data.location || '' : ''}">
                </div>
                <div class="field-group full">
                    <label>Owner / Responsible User</label>
                    <select id="f_owner"><option value="">— Select User —</option>${userOpts}</select>
                </div>
            </div>
        </div>
        ${controls ? `<div class="form-section">
            <div class="form-section-title">Applied Security Controls</div>
            <div class="field-group">
                <label>Select Controls (Ctrl for multiple)</label>
                <select id="f_controls" multiple style="min-height:80px">${controls}</select>
            </div>
        </div>` : ''}
        <div class="form-actions">
            <button class="btn-secondary" onclick="app.closeModal()">Cancel</button>
            <button class="btn-primary" onclick="app._saveAsset(${editId || null})"><i class="fas fa-save"></i> Save Asset</button>
        </div>`;
    }

    async _saveAsset(editId) {
        const name = document.getElementById('f_name').value.trim();
        if (!name) { this._notify('Asset name required', 'error'); return; }
        const record = {
            asset_name: name,
            asset_type: document.getElementById('f_type').value,
            ip_address: document.getElementById('f_ip').value.trim(),
            owner_id: parseInt(document.getElementById('f_owner').value) || null,
        };

        try {
            const method = editId ? 'PUT' : 'POST';
            const body = editId ? { ...record, asset_id: editId } : record;
            const res = await fetch('api/assets.php', {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            const data = await res.json();
            if (data.error) throw new Error(data.error);
            // Reload assets from API
            this.db.assets = await this._fetchFromAPI('assets');
        } catch (e) {
            this._notify('Save failed: ' + e.message, 'error'); return;
        }

        this.closeModal(); this._renderAssets();
        this._notify(editId ? 'Asset updated' : 'Asset added', 'success');
    }

    // ---- VULNERABILITY FORM ----
    _vulnForm(editId) {
        const data = editId ? this.db.vulnerabilities.find(v => v.vulnerability_id === editId) : null;
        document.getElementById('formModalTitle').textContent = editId ? '✏️ Edit Vulnerability' : '🐛 New Vulnerability';
        document.getElementById('formModalBody').innerHTML = `
        <div class="form-section">
            <div class="form-section-title">Vulnerability Information</div>
            <div class="form-grid">
                <div class="field-group">
                    <label>CVE ID *</label>
                    <input id="f_cve" type="text" placeholder="CVE-2024-XXXXX" value="${data ? data.cve_id : ''}">
                </div>
                <div class="field-group">
                    <label>Risk Level *</label>
                    <select id="f_risk">
                        ${['Low','Medium','High','Critical'].map(r=>`<option ${data&&data.risk_level===r?'selected':''}>${r}</option>`).join('')}
                    </select>
                </div>
                <div class="field-group">
                    <label>CVSS Score (0.0 – 10.0)</label>
                    <input id="f_cvss" type="number" min="0" max="10" step="0.1" placeholder="e.g. 8.5" value="${data ? data.cvss_score || '' : ''}">
                </div>
                <div class="field-group full">
                    <label>Description</label>
                    <textarea id="f_desc" placeholder="Describe the vulnerability...">${data ? data.description || '' : ''}</textarea>
                </div>
            </div>
        </div>
        <div class="form-actions">
            <button class="btn-secondary" onclick="app.closeModal()">Cancel</button>
            <button class="btn-primary" onclick="app._saveVuln(${editId || null})"><i class="fas fa-save"></i> Save Vulnerability</button>
        </div>`;
    }

    _saveVuln(editId) {
        const cve = document.getElementById('f_cve').value.trim();
        if (!cve) { this._notify('CVE ID required', 'error'); return; }
        const record = {
            vulnerability_id: editId || this._id(),
            cve_id: cve,
            risk_level: document.getElementById('f_risk').value,
            cvss_score: parseFloat(document.getElementById('f_cvss').value) || null,
            description: document.getElementById('f_desc').value.trim(),
        };
        this._upsert('vulnerabilities', 'vulnerability_id', record);
        this.closeModal(); this._renderVulnerabilities();
        this._notify(editId ? 'Vulnerability updated' : 'Vulnerability added', 'success');
    }

    // ---- THREAT ACTOR FORM ----
    _threatActorForm(editId) {
        const data = editId ? this.db.threatActors.find(t => t.threat_actor_id === editId) : null;
        document.getElementById('formModalTitle').textContent = editId ? '✏️ Edit Threat Actor' : '🕵️ New Threat Actor';
        document.getElementById('formModalBody').innerHTML = `
        <div class="form-section">
            <div class="form-section-title">Threat Actor Profile</div>
            <div class="form-grid">
                <div class="field-group">
                    <label>Actor Name / Handle *</label>
                    <input id="f_name" type="text" placeholder="e.g. APT28, Lazarus Group" value="${data ? data.name : ''}">
                </div>
                <div class="field-group">
                    <label>Origin Country</label>
                    <input id="f_country" type="text" placeholder="e.g. Russia, North Korea" value="${data ? data.origin_country || '' : ''}">
                </div>
                <div class="field-group full">
                    <label>Motivation</label>
                    <select id="f_motivation">
                        ${['Financial','Espionage','Hacktivism','Sabotage','Terrorism','Unknown'].map(m=>`<option ${data&&data.motivation===m?'selected':''}>${m}</option>`).join('')}
                    </select>
                </div>
            </div>
        </div>
        <div class="form-actions">
            <button class="btn-secondary" onclick="app.closeModal()">Cancel</button>
            <button class="btn-primary" onclick="app._saveThreatActor(${editId || null})"><i class="fas fa-save"></i> Save Threat Actor</button>
        </div>`;
    }

    _saveThreatActor(editId) {
        const name = document.getElementById('f_name').value.trim();
        if (!name) { this._notify('Name required', 'error'); return; }
        const record = {
            threat_actor_id: editId || this._id(),
            name,
            origin_country: document.getElementById('f_country').value.trim(),
            motivation: document.getElementById('f_motivation').value,
        };
        this._upsert('threatActors', 'threat_actor_id', record);
        this.closeModal(); this._renderThreatActors();
        this._notify(editId ? 'Threat actor updated' : 'Threat actor added', 'success');
    }

    // ---- RESPONSE ACTION FORM ----
    _responseActionForm(editId) {
        const data = editId ? this.db.responseActions.find(r => r.action_id === editId) : null;
        document.getElementById('formModalTitle').textContent = editId ? '✏️ Edit Response Action' : '🛡️ New Response Action';
        const incOpts = this.db.incidents.map(i => `<option value="${i.incident_id}" ${data && data.incident_id === i.incident_id ? 'selected' : ''}>${i.title}</option>`).join('');
        document.getElementById('formModalBody').innerHTML = `
        <div class="form-section">
            <div class="form-section-title">Response Action Details</div>
            <div class="form-grid">
                <div class="field-group full">
                    <label>Related Incident *</label>
                    <select id="f_incident"><option value="">— Select Incident —</option>${incOpts}</select>
                </div>
                <div class="field-group full">
                    <label>Action Description *</label>
                    <textarea id="f_desc" placeholder="Describe the response action taken...">${data ? data.action_description || '' : ''}</textarea>
                </div>
                <div class="field-group">
                    <label>Action Date</label>
                    <input id="f_date" type="date" value="${data ? data.action_date || new Date().toISOString().split('T')[0] : new Date().toISOString().split('T')[0]}">
                </div>
            </div>
        </div>
        <div class="form-actions">
            <button class="btn-secondary" onclick="app.closeModal()">Cancel</button>
            <button class="btn-primary" onclick="app._saveResponseAction(${editId || null})"><i class="fas fa-save"></i> Save Action</button>
        </div>`;
    }

    _saveResponseAction(editId) {
        const desc = document.getElementById('f_desc').value.trim();
        const incId = parseInt(document.getElementById('f_incident').value);
        if (!desc || !incId) { this._notify('All fields required', 'error'); return; }
        const record = { action_id: editId || this._id(), incident_id: incId, action_description: desc, action_date: document.getElementById('f_date').value };
        this._upsert('responseActions', 'action_id', record);
        this.closeModal(); this._renderResponseActions();
        this._notify(editId ? 'Response action updated' : 'Response action added', 'success');
    }

    // ---- SECURITY CONTROL FORM ----
    _securityControlForm(editId) {
        const data = editId ? this.db.securityControls.find(c => c.control_id === editId) : null;
        document.getElementById('formModalTitle').textContent = editId ? '✏️ Edit Security Control' : '🔒 New Security Control';
        document.getElementById('formModalBody').innerHTML = `
        <div class="form-section">
            <div class="form-section-title">Control Details</div>
            <div class="form-grid">
                <div class="field-group">
                    <label>Control Name *</label>
                    <input id="f_name" type="text" placeholder="e.g. Multi-Factor Authentication" value="${data ? data.control_name : ''}">
                </div>
                <div class="field-group">
                    <label>Control Type</label>
                    <select id="f_type">
                        ${['Preventive','Detective','Corrective','Deterrent','Compensating'].map(t=>`<option ${data&&data.control_type===t?'selected':''}>${t}</option>`).join('')}
                    </select>
                </div>
                <div class="field-group">
                    <label>Implementation Date</label>
                    <input id="f_date" type="date" value="${data ? data.implementation_date || '' : ''}">
                </div>
                <div class="field-group">
                    <label>Status</label>
                    <select id="f_status">
                        ${['Active','Inactive','Under Review','Planned'].map(s=>`<option ${data&&data.status===s?'selected':''}>${s}</option>`).join('')}
                    </select>
                </div>
            </div>
        </div>
        <div class="form-actions">
            <button class="btn-secondary" onclick="app.closeModal()">Cancel</button>
            <button class="btn-primary" onclick="app._saveSecurityControl(${editId || null})"><i class="fas fa-save"></i> Save Control</button>
        </div>`;
    }

    _saveSecurityControl(editId) {
        const name = document.getElementById('f_name').value.trim();
        if (!name) { this._notify('Name required', 'error'); return; }
        const record = {
            control_id: editId || this._id(),
            control_name: name,
            control_type: document.getElementById('f_type').value,
            implementation_date: document.getElementById('f_date').value,
            status: document.getElementById('f_status').value,
        };
        this._upsert('securityControls', 'control_id', record);
        this.closeModal(); this._renderSecurityControls();
        this._notify(editId ? 'Control updated' : 'Control added', 'success');
    }

    // ---- LOG FORM ----
    _logForm(editId) {
        const data = editId ? this.db.logs.find(l => l.log_id === editId) : null;
        document.getElementById('formModalTitle').textContent = editId ? '✏️ Edit Log Entry' : '📋 Add Log Entry';
        const assetOpts = this.db.assets.map(a => `<option value="${a.asset_id}" ${data && data.asset_id === a.asset_id ? 'selected' : ''}>${a.asset_name}</option>`).join('');
        const eventTypes = ['Login Attempt','Port Scan','File Access','Policy Violation','Network Anomaly','System Error','Configuration Change','Malware Detected'];
        document.getElementById('formModalBody').innerHTML = `
        <div class="form-section">
            <div class="form-section-title">Log Entry</div>
            <div class="form-grid">
                <div class="field-group">
                    <label>Asset *</label>
                    <select id="f_asset"><option value="">— Select Asset —</option>${assetOpts}</select>
                </div>
                <div class="field-group">
                    <label>Event Type *</label>
                    <select id="f_event">
                        ${eventTypes.map(e=>`<option ${data && data.event_type === e ? 'selected' : ''}>${e}</option>`).join('')}
                    </select>
                </div>
                <div class="field-group full">
                    <label>Log Time</label>
                    <input id="f_time" type="datetime-local" value="${data ? (data.log_time ? data.log_time.replace(' ', 'T').slice(0,16) : new Date().toISOString().slice(0,16)) : new Date().toISOString().slice(0,16)}">
                </div>
            </div>
        </div>
        <div class="form-actions">
            <button class="btn-secondary" onclick="app.closeModal()">Cancel</button>
            <button class="btn-primary" onclick="app._saveLog(${editId || null})"><i class="fas fa-save"></i> Save Log</button>
        </div>`;
    }

    _saveLog(editId) {
        const assetId = parseInt(document.getElementById('f_asset').value);
        if (!assetId) { this._notify('Asset required', 'error'); return; }
        const record = { log_id: editId || this._id(), asset_id: assetId, event_type: document.getElementById('f_event').value, log_time: document.getElementById('f_time').value };
        if (editId) {
            const idx = this.db.logs.findIndex(l => l.log_id === editId);
            if (idx >= 0) this.db.logs[idx] = record;
        } else {
            this.db.logs.push(record);
        }
        this._save('logs');
        this.closeModal(); this._renderLogs();
        this._notify(editId ? 'Log entry updated' : 'Log entry added', 'success');
    }

    // =============== HELPERS ===============

    async _upsert(table, idKey, record) {
        const ep = this._apiEndpoint(table);
        if (ep) {
            try {
                const isEdit = !!(record[idKey] && this.db[table].find(r => r[idKey] === record[idKey]));
                const method = isEdit ? 'PUT' : 'POST';
                const url = ep.entity ? `${ep.url}?entity=${ep.entity}` : ep.url;
                const body = ep.entity ? { ...record, entity: ep.entity } : record;
                const res = await fetch(url, {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const data = await res.json();
                if (data.error) throw new Error(data.error);
                this.db[table] = await this._fetchFromAPI(table);
            } catch (e) {
                this._notify('Save failed: ' + e.message, 'error');
            }
        } else {
            // Fallback: localStorage for lookup-only tables
            const idx = this.db[table].findIndex(r => r[idKey] === record[idKey]);
            if (idx >= 0) this.db[table][idx] = record;
            else this.db[table].push(record);
            this._save(table);
        }
    }

    async _delete(table, idKey, id, renderFn) {
        if (!confirm('Delete this record?')) return;
        const ep = this._apiEndpoint(table);
        if (ep) {
            try {
                const url = ep.entity ? `${ep.url}?entity=${ep.entity}` : ep.url;
                const body = ep.entity ? { [idKey]: id, entity: ep.entity } : { [idKey]: id };
                const res = await fetch(url, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const data = await res.json();
                if (data.error) throw new Error(data.error);
                this.db[table] = await this._fetchFromAPI(table);
            } catch (e) {
                this._notify('Delete failed: ' + e.message, 'error'); return;
            }
        } else {
            this.db[table] = this.db[table].filter(r => r[idKey] !== id);
            this._save(table);
        }
        if (renderFn) this[renderFn]();
        this._notify('Record deleted', 'success');
    }

    _statusName(id) { const s = this.db.incidentStatuses.find(x => x.status_id === id); return s ? s.status_name : '—'; }

    _sevBadge(sev) {
        const cls = { Low: 'sev-low', Medium: 'sev-medium', High: 'sev-high', Critical: 'sev-critical' };
        return `<span class="severity-badge ${cls[sev] || ''}">${sev || '—'}</span>`;
    }
    _statusBadge(name) {
        const cls = { 'Open': 'status-open', 'In Progress': 'status-inprogress', 'Resolved': 'status-resolved', 'Closed': 'status-closed' };
        return `<span class="status-badge ${cls[name] || ''}">${name}</span>`;
    }
    _riskBadge(r) {
        const cls = { Low: 'risk-low', Medium: 'risk-medium', High: 'risk-high', Critical: 'risk-critical' };
        return `<span class="risk-badge ${cls[r] || ''}">${r || '—'}</span>`;
    }

    _notify(msg, type = 'success') {
        const n = document.createElement('div');
        n.style.cssText = `position:fixed;top:80px;right:20px;z-index:9999;padding:12px 20px;border-radius:10px;font-family:Rajdhani,sans-serif;font-weight:600;font-size:0.95rem;animation:slideUp 0.3s ease;box-shadow:0 10px 30px rgba(0,0,0,0.4);${type === 'success' ? 'background:rgba(0,224,150,0.15);border:1px solid rgba(0,224,150,0.4);color:#00e096;' : 'background:rgba(255,71,87,0.15);border:1px solid rgba(255,71,87,0.4);color:#ff4757;'}`;
        n.innerHTML = `<i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i> ${msg}`;
        document.body.appendChild(n);
        setTimeout(() => n.remove(), 3000);
    }

    exportData() {
        const blob = new Blob([JSON.stringify(this.db, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `CIMS_export_${new Date().toISOString().split('T')[0]}.json`;
        a.click();
    }

    clearAllData() {
        if (confirm('⚠️ This will delete ALL data permanently. Are you sure?')) {
            Object.keys(this.db).forEach(k => { localStorage.removeItem('cims_' + k); });
            localStorage.removeItem('cims_session');
            location.reload();
        }
    }
}

const app = new CIMS();
window.app = app;