// Engagement detail page: tabs (Analyse / Graphe AD / Chemins), upload, live progress, Cytoscape graph.
function engagementApp() {
  return {
    user: null,
    engagement: null,
    analyses: [],
    activeAnalysis: null,
    progress: 0,
    progressStage: '',
    progressMessage: '',
    progressFailed: false,
    uploadingPercent: null,
    error: null,
    loading: true,
    ws: null,
    _pollInterval: null,

    // Source mode: 'json' | 'ldap'
    sourceMode: 'json',
    ldapCollecting: false,
    ldapForm: {
      dc_host: '',
      domain: '',
      username: '',
      password: '',
      port: 389,
      use_ssl: false,
    },

    // Tab state
    activeTab: 'analyse',

    // Paths tab
    pathsLoading: false,
    paths: [],
    stats: null,
    filterRisk: '',

    // Remediation
    remediationBannerDismissed: false,
    bundleDownloading: false,
    pdfDownloading: false,

    // Graph tab
    graphLoading: false,
    graphData: null,       // {nodes, edges, paths, stats}
    graphStats: null,
    graphPaths: [],
    graphLayout: 'breadthfirst',
    cyInstance: null,
    selectedNode: null,
    highlightedPath: null,

    async init() {
      this.user = await auth.requireAuth();
      if (!this.user) return;
      auth.renderNav('dashboard');
      const id = new URLSearchParams(location.search).get('id');
      if (!id) { location.href = '/dashboard.html'; return; }
      try {
        this.engagement = await api.getEngagement(id);
        await this.fetchAnalyses();
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
      this.$nextTick(() => this.bindUpload());
    },

    switchTab(tab) {
      this.activeTab = tab;
      if (tab === 'graph' && this.activeAnalysis && this.activeAnalysis.status === 'completed') {
        this.$nextTick(() => this.loadGraph(this.activeAnalysis.id));
      }
    },

    bindUpload() {
      const zone = document.getElementById('upload-zone');
      const input = document.getElementById('upload-input');
      if (!zone || !input) return;
      uploadHelper.setupUploadZone(zone, input, (file) => this.startUpload(file));
    },

    async fetchAnalyses() {
      const data = await api.listAnalyses(this.engagement.id);
      this.analyses = data.items || [];
      const running = this.analyses.find(a =>
        ['pending', 'ingesting', 'extracting_paths', 'analyzing'].includes(a.status)
      );
      if (running) {
        this.attachToAnalysis(running);
      } else {
        const last = this.analyses[0];
        if (last && last.status === 'completed') {
          this.activeAnalysis = last;
          this.progress = 100;
          this.progressStage = 'completed';
          this.progressMessage = 'Analyse terminée';
          this.loadPaths(last.id);
        }
      }
    },

    async startUpload(file) {
      this.error = null;
      this.uploadingPercent = 0;
      try {
        const analysis = await api.uploadAnalysis(this.engagement.id, file, (p) => {
          this.uploadingPercent = Math.round(p);
        });
        this.uploadingPercent = null;
        this.analyses.unshift(analysis);
        this.attachToAnalysis(analysis);
      } catch (e) {
        this.uploadingPercent = null;
        this.error = e.message;
      }
    },

    attachToAnalysis(analysis) {
      this.activeAnalysis = analysis;
      this.progress = analysis.progress || 0;
      this.progressStage = analysis.status;
      this.progressMessage = this.stageLabel(analysis.status);
      this.progressFailed = analysis.status === 'failed';
      this.paths = [];
      this.stats = null;
      this.graphData = null;
      this.graphStats = null;
      this.graphPaths = [];
      this.selectedNode = null;
      this.highlightedPath = null;
      if (this.cyInstance) { this.cyInstance.destroy(); this.cyInstance = null; }

      if (this.ws) { try { this.ws.close(); } catch (_) {} }
      if (this._pollInterval) { clearInterval(this._pollInterval); this._pollInterval = null; }

      if (['completed', 'failed'].includes(analysis.status)) {
        if (analysis.status === 'completed') this.loadPaths(analysis.id);
        return;
      }

      const id = analysis.id;

      // WebSocket for real-time events
      this.ws = wsClient.connectAnalysisWs(id, {
        onEvent: (ev) => {
          if (ev.progress > this.progress) this.progress = ev.progress;
          this.progressStage = ev.stage || this.progressStage;
          this.progressMessage = ev.message_fr || this.progressMessage;
          if (ev.stage === 'completed') {
            this._stopPoll();
            this.progressFailed = false;
            this.refreshAnalysisStatus(id);
            this.loadPaths(id);
          }
          if (ev.stage === 'failed') {
            this._stopPoll();
            this.progressFailed = true;
            this.refreshAnalysisStatus(id);
          }
        },
      });

      // Polling fallback — catches any WebSocket events missed due to race condition
      // (task can start and broadcast before the WS handshake completes)
      this._pollInterval = setInterval(async () => {
        try {
          const fresh = await api.getAnalysis(id);
          if (fresh.progress > this.progress) this.progress = fresh.progress;
          if (fresh.status !== this.progressStage) {
            this.progressStage = fresh.status;
            if (!this.progressMessage || this.progressMessage === this.stageLabel('pending')) {
              this.progressMessage = this.stageLabel(fresh.status);
            }
          }
          if (fresh.status === 'completed') {
            this._stopPoll();
            this.progressFailed = false;
            this.activeAnalysis = fresh;
            const idx = this.analyses.findIndex(a => a.id === id);
            if (idx >= 0) this.analyses[idx] = fresh;
            this.loadPaths(id);
          } else if (fresh.status === 'failed') {
            this._stopPoll();
            this.progressFailed = true;
            this.progressMessage = fresh.error_message || 'Erreur lors de l\'analyse';
            this.activeAnalysis = fresh;
          }
        } catch (_) {}
      }, 3000);
    },

    _stopPoll() {
      if (this._pollInterval) { clearInterval(this._pollInterval); this._pollInterval = null; }
    },

    async refreshAnalysisStatus(id) {
      try {
        const fresh = await api.getAnalysis(id);
        const idx = this.analyses.findIndex(a => a.id === id);
        if (idx >= 0) this.analyses[idx] = fresh;
        if (this.activeAnalysis && this.activeAnalysis.id === id) this.activeAnalysis = fresh;
      } catch (_) {}
    },

    async loadPaths(analysisId) {
      this.pathsLoading = true;
      try {
        const [pathsData, stats] = await Promise.all([
          api.listPaths(analysisId, { limit: 100, risk: this.filterRisk || undefined }),
          api.getStats(analysisId),
        ]);
        this.paths = pathsData.items || [];
        this.stats = stats;
      } catch (e) {
        this.error = e.message;
      } finally {
        this.pathsLoading = false;
      }
    },

    async applyFilter() {
      if (!this.activeAnalysis) return;
      await this.loadPaths(this.activeAnalysis.id);
    },

    async downloadBundle() {
      if (!this.activeAnalysis || this.bundleDownloading) return;
      this.bundleDownloading = true;
      try {
        const code = (this.engagement && this.engagement.code) || 'mission';
        const date = new Date().toISOString().slice(0, 10);
        const filename = `remediation-${code}-${date}.zip`.replace(/[^A-Za-z0-9._-]+/g, '_');
        await api.downloadRemediationBundle(this.activeAnalysis.id, filename);
      } catch (e) {
        alert('Échec du téléchargement : ' + (e.message || e));
      } finally {
        this.bundleDownloading = false;
      }
    },

    async downloadPdf() {
      if (!this.activeAnalysis || this.pdfDownloading) return;
      this.pdfDownloading = true;
      try {
        const code = (this.engagement && this.engagement.code) || 'mission';
        const filename = `rapport-${code}-${this.activeAnalysis.id.slice(0, 8)}.pdf`.replace(/[^A-Za-z0-9._-]+/g, '_');
        await api.downloadReport(this.activeAnalysis.id, filename);
      } catch (e) {
        alert('Échec du téléchargement : ' + (e.message || e));
      } finally {
        this.pdfDownloading = false;
      }
    },

    async downloadPathScript(pathId) {
      if (!this.activeAnalysis) return;
      try {
        const code = (this.engagement && this.engagement.code) || 'mission';
        const filename = `mitigation-${code}-${pathId.slice(0, 8)}.md`.replace(/[^A-Za-z0-9._-]+/g, '_');
        await api.downloadRemediationScript(this.activeAnalysis.id, pathId, filename);
      } catch (e) {
        alert('Échec du téléchargement : ' + (e.message || e));
      }
    },

    selectAnalysis(analysis) {
      this.attachToAnalysis(analysis);
      this.activeTab = 'analyse';
    },

    // ── Graph ──────────────────────────────────────────────────────────────────

    async loadGraph(analysisId) {
      if (this.cyInstance) return; // already rendered
      this.graphLoading = true;
      try {
        const token = api.getAccessToken();
        const res = await fetch(`/api/v1/analyses/${analysisId}/graph`, {
          headers: { 'Authorization': 'Bearer ' + token },
        });
        if (!res.ok) throw new Error('Erreur ' + res.status);
        this.graphData = await res.json();
        this.graphStats = this.graphData.stats;
        this.graphPaths = (this.graphData.paths || []).sort((a, b) => {
          const rank = { critique: 4, eleve: 3, moyen: 2, faible: 1 };
          return (rank[b.risk_level] || 0) - (rank[a.risk_level] || 0);
        });
        this.graphLoading = false;
        this.$nextTick(() => this.renderGraph());
      } catch (e) {
        this.graphLoading = false;
        this.error = e.message;
      }
    },

    renderGraph() {
      const el = document.getElementById('cy');
      if (!el || !this.graphData) return;
      if (this.cyInstance) this.cyInstance.destroy();

      const nodeColor = (type, isPrivileged) => {
        if (isPrivileged) return '#FF3B5C';
        return { 'User': '#4A9EFF', 'Computer': '#8888FF', 'Group': '#BB77FF', 'Domain': '#FF8C00' }[type] || '#888';
      };
      const nodeShape = (type) => {
        return { 'User': 'ellipse', 'Computer': 'rectangle', 'Group': 'diamond', 'Domain': 'star' }[type] || 'ellipse';
      };
      const edgeColor = (type) => {
        const map = { AdminTo: '#FF3B5C', DCSync: '#FF0044', HasSession: '#FF8C00', MemberOf: '#4A9EFF', WriteDACL: '#F5C518', GenericAll: '#FF3B5C', WriteOwner: '#F5C518', ForceChangePassword: '#FF8C00', AllowedToDelegate: '#BB77FF', };
        return map[type] || 'rgba(255,255,255,0.25)';
      };

      this.cyInstance = cytoscape({
        container: el,
        elements: [...this.graphData.nodes, ...this.graphData.edges],
        style: [
          {
            selector: 'node',
            style: {
              'background-color': (n) => nodeColor(n.data('type'), n.data('is_privileged')),
              'shape': (n) => nodeShape(n.data('type')),
              'label': 'data(label)',
              'color': '#ffffff',
              'font-size': '10px',
              'font-family': 'Inter, sans-serif',
              'font-weight': '600',
              'text-valign': 'bottom',
              'text-halign': 'center',
              'text-margin-y': '4px',
              'width': (n) => n.data('is_privileged') ? 36 : 28,
              'height': (n) => n.data('is_privileged') ? 36 : 28,
              'border-width': (n) => n.data('is_privileged') ? 2 : 0,
              'border-color': '#FF3B5C',
              'text-outline-width': 2,
              'text-outline-color': '#0a0d14',
              'text-max-width': '80px',
              'text-wrap': 'ellipsis',
              'overlay-padding': '4px',
            },
          },
          {
            selector: 'edge',
            style: {
              'line-color': (e) => edgeColor(e.data('type')),
              'target-arrow-color': (e) => edgeColor(e.data('type')),
              'target-arrow-shape': 'triangle',
              'arrow-scale': 0.8,
              'curve-style': 'bezier',
              'width': 1.5,
              'label': 'data(type)',
              'font-size': '9px',
              'color': 'rgba(255,255,255,0.4)',
              'font-family': 'JetBrains Mono, monospace',
              'text-rotation': 'autorotate',
              'text-outline-width': 2,
              'text-outline-color': '#0a0d14',
              'overlay-padding': '3px',
              'opacity': 0.7,
            },
          },
          {
            selector: '.highlighted',
            style: { 'width': 3.5, 'opacity': 1, 'z-index': 10 },
          },
          {
            selector: '.dimmed',
            style: { 'opacity': 0.12 },
          },
          {
            selector: 'node.selected',
            style: { 'border-width': 3, 'border-color': '#86BC25', 'border-opacity': 1 },
          },
        ],
        layout: { name: this.graphLayout, animate: true, animationDuration: 600, padding: 40 },
        userZoomingEnabled: true,
        userPanningEnabled: true,
        boxSelectionEnabled: false,
        minZoom: 0.1,
        maxZoom: 4,
      });

      this.cyInstance.on('tap', 'node', (evt) => {
        this.cyInstance.elements().removeClass('selected');
        evt.target.addClass('selected');
        const d = evt.target.data();
        this.selectedNode = { id: d.id, label: d.label, type: d.type, is_privileged: d.is_privileged, risk_level: d.risk_level };
      });

      this.cyInstance.on('tap', (evt) => {
        if (evt.target === this.cyInstance) {
          this.selectedNode = null;
          this.highlightedPath = null;
          this.cyInstance.elements().removeClass('highlighted dimmed selected');
        }
      });
    },

    highlightPath(pathObj) {
      if (!this.cyInstance) return;
      this.highlightedPath = pathObj.path_id;
      this.cyInstance.elements().removeClass('highlighted dimmed');
      const nodeSet = new Set(pathObj.node_ids || []);
      const edgeSet = new Set(pathObj.edge_ids || []);
      this.cyInstance.nodes().forEach(n => {
        if (!nodeSet.has(n.id())) n.addClass('dimmed');
      });
      this.cyInstance.edges().forEach(e => {
        if (edgeSet.has(e.id())) e.addClass('highlighted');
        else e.addClass('dimmed');
      });
    },

    highlightPathById(pathId) {
      const p = this.graphPaths.find(gp => gp.path_id === pathId);
      if (p) {
        this.activeTab = 'graph';
        this.$nextTick(() => {
          if (this.cyInstance) this.highlightPath(p);
          else this.loadGraph(this.activeAnalysis.id).then(() => this.$nextTick(() => this.highlightPath(p)));
        });
      }
    },

    graphFitView() {
      if (this.cyInstance) this.cyInstance.fit(undefined, 40);
    },

    graphReset() {
      if (!this.cyInstance) return;
      this.highlightedPath = null;
      this.selectedNode = null;
      this.cyInstance.elements().removeClass('highlighted dimmed selected');
    },

    graphExportPng() {
      if (!this.cyInstance) return;
      const blob = this.cyInstance.png({ output: 'blob', scale: 2, bg: '#0a0d14' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `graphe_ad_${this.engagement.code}.png`; a.click();
      URL.revokeObjectURL(url);
    },

    applyGraphLayout() {
      if (!this.cyInstance) return;
      this.cyInstance.layout({ name: this.graphLayout, animate: true, animationDuration: 500, padding: 40 }).run();
    },

    nodeAttackPaths() {
      if (!this.selectedNode || !this.graphPaths) return [];
      return this.graphPaths.filter(p => (p.node_ids || []).includes(this.selectedNode.id));
    },

    // ── Helpers ───────────────────────────────────────────────────────────────

    stageLabel(stage) {
      return {
        pending: 'En attente…', ingesting: 'Ingestion du graphe…',
        extracting_paths: 'Extraction des chemins…', analyzing: 'Analyse IA…',
        completed: 'Analyse terminée', failed: 'Analyse échouée',
      }[stage] || stage;
    },

    statusLabel(s) {
      return {
        pending: 'En attente', ingesting: 'Ingestion', extracting_paths: 'Extraction',
        analyzing: 'Analyse', completed: 'Terminée', failed: 'Échec',
        draft: 'Brouillon', in_progress: 'En cours',
        ldap_connecting: 'Connexion AD', ldap_users: 'Utilisateurs',
        ldap_computers: 'Ordinateurs', ldap_groups: 'Groupes',
        ldap_acls: 'ACL', ldap_building_graph: 'Graphe AD',
      }[s] || s;
    },

    currentStages() {
      const isLdap = this.activeAnalysis && this.activeAnalysis.source_type === 'ldap_live';
      if (isLdap) {
        return [
          { key: 'ldap_connecting',     label: 'Connexion' },
          { key: 'ldap_users',          label: 'Utilisateurs' },
          { key: 'ldap_computers',      label: 'Ordinateurs' },
          { key: 'ldap_groups',         label: 'Groupes' },
          { key: 'ldap_acls',           label: 'ACL' },
          { key: 'ldap_building_graph', label: 'Graphe' },
          { key: 'extracting_paths',    label: 'Chemins' },
          { key: 'analyzing',           label: 'Agent IA' },
          { key: 'completed',           label: 'Terminé' },
        ];
      }
      return [
        { key: 'ingesting',         label: 'Import' },
        { key: 'extracting_paths',  label: 'Chemins' },
        { key: 'analyzing',         label: 'Agent IA' },
        { key: 'completed',         label: 'Terminé' },
      ];
    },

    stageClass(key) {
      const order = this.currentStages().map(s => s.key);
      const cur = order.indexOf(this.progressStage);
      const idx = order.indexOf(key);
      if (this.progressFailed && idx <= cur) return 'failed';
      if (idx < cur) return 'done';
      if (idx === cur) return 'active';
      return '';
    },

    stageExplanation() {
      return {
        pending:              'En attente de démarrage — la tâche est dans la file d\'exécution.',
        ldap_connecting:      'Connexion au contrôleur de domaine via LDAP (authentification NTLM)…',
        ldap_users:           'Collecte des comptes utilisateurs AD : sAMAccountName, SID, groupes, état du compte.',
        ldap_computers:       'Collecte des ordinateurs du domaine : DNS, SID, système d\'exploitation.',
        ldap_groups:          'Collecte des groupes et de leurs membres — construction des relations MemberOf.',
        ldap_acls:            'Analyse des délégations et droits d\'administration (AdminTo implicites pour les membres Domain Admins).',
        ldap_building_graph:  'Assemblage du graphe complet Active Directory en mémoire à partir des données collectées.',
        ingesting:            'Lecture du fichier JSON BloodHound et construction du graphe de relations AD en mémoire.',
        extracting_paths:     'NetworkX parcourt tous les chemins simples (max 6 sauts) de chaque compte non-privilégié vers les cibles Domain Admins, Enterprise Admins et Administrators.',
        analyzing:            'L\'agent IA analyse chaque chemin : score d\'exploitabilité, score de furtivité, risque global, explication et recommandation détaillée en français.',
        completed:            'Analyse terminée. Consultez les onglets Graphe AD et Chemins d\'attaque pour explorer les résultats.',
        failed:               'Une erreur est survenue. Vérifiez les paramètres de connexion ou le fichier JSON BloodHound.',
      }[this.progressStage] || '';
    },

    riskLabel(level) {
      return { critique: 'Critique', eleve: 'Élevé', moyen: 'Moyen', faible: 'Faible' }[level] || level || '—';
    },

    riskColor(level) {
      return { critique: 'var(--risk-critique)', eleve: 'var(--risk-eleve)', moyen: 'var(--risk-moyen)', faible: 'var(--risk-faible)' }[level] || 'rgba(255,255,255,0.4)';
    },

    riskBadgeClass(level) {
      return 'badge badge-' + (level || 'neutral');
    },

    scoreColor(score) {
      if (score == null) return 'rgba(255,255,255,0.5)';
      if (score >= 8) return 'var(--risk-critique)';
      if (score >= 6) return 'var(--risk-eleve)';
      if (score >= 4) return 'var(--risk-moyen)';
      return 'var(--risk-faible)';
    },

    formatScore(s) { return s == null ? '—' : Number(s).toFixed(1); },

    formatDate(iso) {
      if (!iso) return '—';
      try { return new Date(iso).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' }); }
      catch (_) { return iso; }
    },

    async downloadReport(analysis) {
      try {
        await api.downloadReport(analysis.id, `rapport_${this.engagement.code}_${analysis.id.slice(0,8)}.pdf`);
      } catch (e) { this.error = e.message; }
    },

    canUpload() {
      return this.user && ['admin', 'manager', 'auditor'].includes(this.user.role);
    },

    resetForNewAnalysis() {
      this.activeAnalysis = null;
      this.progress = 0;
      this.progressMessage = '';
      this.progressFailed = false;
      this.graphData = null; this.graphStats = null; this.graphPaths = [];
      this.selectedNode = null; this.highlightedPath = null;
      if (this.cyInstance) { this.cyInstance.destroy(); this.cyInstance = null; }
      if (this.ws) { try { this.ws.close(); } catch (_) {} this.ws = null; }
      this._stopPoll();
      this.activeTab = 'analyse';
    },

    async useDemoFile() {
      this.error = null;
      try {
        const resp = await fetch('/assets/sample_graph.json');
        if (!resp.ok) throw new Error('Impossible de charger le fichier de démo');
        const blob = await resp.blob();
        await this.startUpload(new File([blob], 'sample_graph.json', { type: 'application/json' }));
      } catch (e) { this.error = e.message; }
    },

    ldapFormValid() {
      const f = this.ldapForm;
      return f.dc_host.trim().length > 0
        && f.domain.trim().length > 2
        && f.username.trim().length > 0
        && f.password.length > 0;
    },

    async submitLdapCollect() {
      if (!this.ldapFormValid() || this.ldapCollecting) return;
      this.error = null;
      this.ldapCollecting = true;
      try {
        const analysis = await api.ldapCollect(this.engagement.id, {
          dc_host:  this.ldapForm.dc_host.trim(),
          domain:   this.ldapForm.domain.trim(),
          username: this.ldapForm.username.trim(),
          password: this.ldapForm.password,
          port:     this.ldapForm.port,
          use_ssl:  this.ldapForm.use_ssl,
        });
        this.analyses.unshift(analysis);
        this.attachToAnalysis(analysis);
      } catch (e) {
        this.error = e.message;
      } finally {
        this.ldapCollecting = false;
      }
    },
  };
}
