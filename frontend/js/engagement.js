// Engagement detail page: tabs (Analyse / Graphe AD / Chemins), upload, live progress, Cytoscape graph.
function engagementApp() {
  return {
    user: null,
    engagement: null,
    analyses: [],
    llmInfo: null,
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

    // Source mode: 'json' | 'zip' | 'ldap'
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

    // MITRE matrix tab
    mitreLoading: false,
    mitreCoverage: null,    // {techniques, count_by_tactic, top_techniques}
    mitreColumns: [],       // pre-built [{tactic, techniques: [...]}] — populated by loadMitre()

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
      if (window.statusChips) statusChips.attach({ wsBound: true });
      const id = new URLSearchParams(location.search).get('id');
      if (!id) { location.href = '/dashboard.html'; return; }
      try {
        this.engagement = await api.getEngagement(id);
        await this.fetchAnalyses();
        api.getLLMConfig().then(c => { this.llmInfo = c; }).catch(() => {});
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
      this.$nextTick(() => this.bindUpload());
    },

    isMockMode() {
      return this.llmInfo && this.llmInfo.provider === 'mock';
    },

    switchTab(tab) {
      this.activeTab = tab;
      if (tab === 'graph' && this.activeAnalysis && this.activeAnalysis.status === 'completed') {
        this.$nextTick(() => this.loadGraph(this.activeAnalysis.id));
      }
      if (tab === 'mitre' && this.activeAnalysis && this.activeAnalysis.status === 'completed') {
        this.$nextTick(() => this.loadMitre(this.activeAnalysis.id));
      }
    },

    async loadMitre(analysisId) {
      if (this.mitreCoverage) return;
      this.mitreLoading = true;
      try {
        const cov = await api.getMitre(analysisId);
        // Augment techniques with per-technique counts (the API returns
        // top 10 with counts, plus the full list without counts).
        const countMap = {};
        (cov.top_techniques || []).forEach(t => { countMap[t.technique_id] = t.count; });
        // Fall back: count by walking loaded paths if available
        if (Object.keys(countMap).length === 0 && this.paths.length) {
          this.paths.forEach(p => (p.mitre_techniques || []).forEach(mt => {
            countMap[mt.technique_id] = (countMap[mt.technique_id] || 0) + 1;
          }));
        }
        cov.techniques.forEach(t => { t.count = countMap[t.technique_id] || 0; });
        this.mitreCoverage = cov;

        // Pre-compute the matrix structure here, in one pass.
        // This avoids relying on nested `<template x-for>` + `x-show` in Alpine,
        // which was the root cause of the matrix appearing empty even with
        // valid data: Alpine 3 evaluates nested x-for expressions during the
        // outer iteration in a way that sometimes mis-binds the loop scope,
        // so the inner filter sees `tactic.name` as undefined.
        const tacticOrder = this.mitreTactics();
        const cols = [];
        for (const tac of tacticOrder) {
          const lc = (tac.name || '').toLowerCase();
          const techs = (cov.techniques || [])
            .filter(t => (t.tactic || '').toLowerCase() === lc)
            .sort((a, b) => (b.count || 0) - (a.count || 0));
          if (techs.length > 0) cols.push({ ...tac, techniques: techs });
        }
        // Append a catch-all for any tactic the backend uses but we didn't list,
        // so we never silently swallow data.
        const known = new Set(tacticOrder.map(t => t.name.toLowerCase()));
        const orphans = {};
        (cov.techniques || []).forEach(t => {
          const k = (t.tactic || 'Unknown');
          if (!known.has(k.toLowerCase())) {
            (orphans[k] = orphans[k] || []).push(t);
          }
        });
        Object.entries(orphans).forEach(([name, techs]) => {
          cols.push({ id: 'orphan-' + name, name, techniques: techs });
        });
        this.mitreColumns = cols;

        console.info('[MITRE] loaded', {
          analysisId, techniques: cov.techniques.length,
          columns: cols.length, tactics: cols.map(c => c.name),
        });
      } catch (e) {
        console.error('[MITRE] load failed', e);
        if (window.toast) toast.error('MITRE : ' + e.message);
      } finally {
        this.mitreLoading = false;
      }
    },

    /** Ordered list of MITRE tactics (TA0001…TA0011). Used as columns of the matrix. */
    mitreTactics() {
      return [
        { id: 'TA0001', name: 'Initial Access' },
        { id: 'TA0002', name: 'Execution' },
        { id: 'TA0003', name: 'Persistence' },
        { id: 'TA0004', name: 'Privilege Escalation' },
        { id: 'TA0005', name: 'Defense Evasion' },
        { id: 'TA0006', name: 'Credential Access' },
        { id: 'TA0007', name: 'Discovery' },
        { id: 'TA0008', name: 'Lateral Movement' },
        { id: 'TA0009', name: 'Collection' },
        { id: 'TA0011', name: 'Command and Control' },
        { id: 'TA0010', name: 'Exfiltration' },
        { id: 'TA0040', name: 'Impact' },
      ];
    },

    /** Techniques in a given tactic, deduped, sorted by count desc. */
    mitreTechByTactic(tacticName) {
      if (!this.mitreCoverage) return [];
      // Some MITRE techniques span multiple tactics; the mapping file picks ONE
      // per entry, so we just match on `tactic` substring (case-insensitive).
      const norm = (tacticName || '').toLowerCase();
      const out = (this.mitreCoverage.techniques || []).filter(
        t => (t.tactic || '').toLowerCase() === norm,
      );
      return out.slice().sort((a, b) => (b.count || 0) - (a.count || 0));
    },

    /** Map a count to a heatmap intensity bucket (1=lightest, 5=hottest). */
    mitreCellHeat(count) {
      if (!count) return '0';
      if (count >= 10) return '5';
      if (count >= 5) return '4';
      if (count >= 3) return '3';
      if (count >= 2) return '2';
      return '1';
    },

    bindUpload() {
      const zone = document.getElementById('upload-zone');
      const input = document.getElementById('upload-input');
      if (zone && input) {
        uploadHelper.setupUploadZone(zone, input, (file) => this.startUpload(file));
      }
      const zoneZip = document.getElementById('upload-zone-zip');
      const inputZip = document.getElementById('upload-input-zip');
      if (zoneZip && inputZip) {
        uploadHelper.setupUploadZone(zoneZip, inputZip, (file) => this.startUpload(file));
      }
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
        if (window.toast) toast.info("Analyse démarrée — pipeline en cours…");
      } catch (e) {
        this.uploadingPercent = null;
        this.error = e.message;
        if (window.toast) toast.error("Upload échoué : " + e.message);
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
      // Reset MITRE state so we re-fetch on next tab visit instead of showing
      // a stale matrix from a previously-viewed analysis.
      this.mitreCoverage = null;
      this.mitreColumns = [];
      this.mitreLoading = false;
      this.selectedNode = null;
      this.highlightedPath = null;
      if (this.cyInstance) { this.cyInstance.destroy(); this.cyInstance = null; }

      if (this.ws) { try { this.ws.close(); } catch (_) {} }
      if (this._pollInterval) { clearInterval(this._pollInterval); this._pollInterval = null; }

      if (['completed', 'failed'].includes(analysis.status)) {
        if (analysis.status === 'completed') {
          this.loadPaths(analysis.id);
          // Prefetch MITRE so the matrix tab is instant when the user clicks it
          this.loadMitre(analysis.id);
        }
        return;
      }

      const id = analysis.id;

      // WebSocket for real-time events
      this.ws = wsClient.connectAnalysisWs(id, {
        onOpen: () => { if (window.statusChips) statusChips.setWs('connected'); },
        onClose: () => { if (window.statusChips) statusChips.setWs('disconnected'); },
        onError: () => { if (window.statusChips) statusChips.setWs('polling'); },
        onEvent: (ev) => {
          if (ev.progress > this.progress) this.progress = ev.progress;
          this.progressStage = ev.stage || this.progressStage;
          this.progressMessage = ev.message_fr || this.progressMessage;
          if (ev.stage === 'completed') {
            this._stopPoll();
            this.progressFailed = false;
            this.refreshAnalysisStatus(id);
            this.loadPaths(id);
            if (window.toast) toast.success("Analyse terminée");
          }
          if (ev.stage === 'failed') {
            this._stopPoll();
            this.progressFailed = true;
            this.refreshAnalysisStatus(id);
            if (window.toast) toast.error("Analyse échouée — voir le détail");
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
        (window.toast ? toast.error : alert)('Échec du téléchargement : ' + (e.message || e));
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
        (window.toast ? toast.error : alert)('Échec du téléchargement : ' + (e.message || e));
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
        (window.toast ? toast.error : alert)('Échec du téléchargement : ' + (e.message || e));
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
        // Use a "preset"-equivalent (skip auto-layout in the constructor) so
        // we can fully control the layout phase below and fit the viewport
        // AFTER the layout settles. Doing the layout in the constructor +
        // animating during it produced a jumbled first paint on dense graphs;
        // the user had to switch layout to force a re-run.
        layout: { name: 'preset' },
        userZoomingEnabled: true,
        userPanningEnabled: true,
        boxSelectionEnabled: false,
        minZoom: 0.1,
        maxZoom: 4,
      });

      // Run the requested layout explicitly and fit the viewport when it
      // finishes. This avoids the "first render is messy until user changes
      // layout" problem — equivalent to what the user used to trigger by
      // switching layouts manually.
      const layoutOpts = this._buildLayoutOptions(this.graphLayout);
      const layout = this.cyInstance.layout(layoutOpts);
      layout.one('layoutstop', () => {
        // Small fudge: fit with padding, otherwise dense graphs render
        // crammed against one edge of the canvas.
        try { this.cyInstance.fit(undefined, 60); } catch (_) {}
      });
      layout.run();

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
      const opts = this._buildLayoutOptions(this.graphLayout);
      const lay = this.cyInstance.layout(opts);
      lay.one('layoutstop', () => {
        try { this.cyInstance.fit(undefined, 60); } catch (_) {}
      });
      lay.run();
    },

    /**
     * Builds Cytoscape layout options that converge cleanly on first run.
     *
     * - `breadthfirst` needs an explicit `roots` hint, otherwise it picks
     *   arbitrary nodes and produces a jumbled tree on first render. We
     *   point it at the privileged target nodes (the "destinations" of
     *   attack paths) so the BFS flows from leaves to root.
     * - `cose` benefits from disabling animation during the first run —
     *   the layout finishes much faster and looks fine animated by `.fit()`.
     * - Defaults to a quality-tuned cose if the layout name isn't recognised.
     */
    _buildLayoutOptions(name) {
      const base = { animate: true, animationDuration: 500, padding: 40 };
      if (name === 'breadthfirst') {
        // Use privileged nodes as roots so the tree has a clear direction.
        const privIds = (this.graphData?.nodes || [])
          .filter(n => n.data && n.data.is_privileged)
          .map(n => n.data.id);
        return Object.assign({}, base, {
          name: 'breadthfirst',
          directed: true,
          roots: privIds.length ? privIds : undefined,
          spacingFactor: 1.4,
          avoidOverlap: true,
          maximal: false,
        });
      }
      if (name === 'cose') {
        return Object.assign({}, base, {
          name: 'cose',
          nodeRepulsion: 8000,
          idealEdgeLength: 80,
          edgeElasticity: 100,
          gravity: 0.25,
          nestingFactor: 1.2,
          numIter: 1000,
          randomize: true,
          animate: false,  // run iterations headless, then fit
        });
      }
      if (name === 'circle') {
        return Object.assign({}, base, { name: 'circle', spacingFactor: 1.3 });
      }
      if (name === 'concentric') {
        return Object.assign({}, base, {
          name: 'concentric',
          concentric: (n) => (n.data('is_privileged') ? 10 : 1),
          levelWidth: () => 1,
          spacingFactor: 1.4,
        });
      }
      if (name === 'grid') {
        return Object.assign({}, base, { name: 'grid', spacingFactor: 1.3 });
      }
      // Fallback
      return Object.assign({}, base, { name: name || 'breadthfirst' });
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
