// Dashboard — Kanban board with drag-and-drop state machine + archive/delete.
function dashboardApp() {
  return {
    user: null,
    loading: true,
    error: null,
    engagements: [],
    archived: [],
    stats: {},
    llmInfo: null,    // {provider, model, has_api_key} from /llm/config
    showModal: false,
    saving: false,
    form: { client_name: '', code: '', description: '' },
    formError: null,

    // drag state
    draggingId: null,
    draggingEngagement: null,
    dragOverCol: null,

    // ⋯ dropdown
    openMenuId: null,

    // archives drawer
    showArchived: false,
    loadingArchived: false,

    // delete confirmation modal
    showDeleteModal: false,
    deleteTarget: null,       // engagement object
    deleteConfirmCode: '',
    deleteError: null,
    deleting: false,

    // archive action feedback
    archiving: null,          // id of engagement being archived

    async init() {
      this.user = await auth.requireAuth();
      if (!this.user) return;
      auth.renderNav('dashboard');
      if (window.statusChips) statusChips.attach({ wsBound: false });
      document.addEventListener('click', (e) => this._closeMenuOnOutsideClick(e));
      await Promise.all([this.fetchEngagements(), this.fetchStats(), this.fetchLLMInfo()]);
      this.loading = false;
    },

    async fetchLLMInfo() {
      try {
        this.llmInfo = await api.getLLMConfig();
      } catch (_) {
        this.llmInfo = null;
      }
    },

    isMockMode() {
      return this.llmInfo && this.llmInfo.provider === 'mock';
    },

    async fetchEngagements() {
      this.error = null;
      try {
        const data = await api.listEngagements(100, 0, false);
        const items = data.items || [];
        await this._enrichAll(items);
        this.engagements = items;
      } catch (e) {
        this.error = e.message;
      }
    },

    async fetchArchived() {
      this.loadingArchived = true;
      try {
        const data = await api.listEngagements(100, 0, true);
        const all = data.items || [];
        const items = all.filter(e => e.status === 'archived');
        await this._enrichAll(items);
        this.archived = items;
      } catch (_) {
        this.archived = [];
      } finally {
        this.loadingArchived = false;
      }
    },

    async fetchStats() {
      try {
        this.stats = await api.getEngagementStats();
      } catch (_) {
        this.stats = {};
      }
    },

    // Attach _analyses_count, _critical_count, _paths_count, _running_analysis
    async _enrichAll(items) {
      await Promise.all(items.map(async (e) => {
        try {
          const data = await api.listAnalyses(e.id);
          const analyses = data.items || [];
          e._analyses_count = analyses.length;
          e._running_analysis = analyses.find(a =>
            ['pending', 'ingesting', 'extracting_paths', 'analyzing'].includes(a.status)
          ) || null;
          const completed = analyses.filter(a => a.status === 'completed');
          e._paths_count = completed.reduce((s, a) => s + (a.total_paths || 0), 0);
          e._critical_count = 0;
          for (const a of completed.slice(0, 3)) {
            try {
              const st = await api.getStats(a.id);
              e._critical_count += (st.by_risk_level && st.by_risk_level.critique) || 0;
            } catch (_) {}
          }
        } catch (_) {
          e._analyses_count = 0;
          e._running_analysis = null;
          e._paths_count = 0;
          e._critical_count = 0;
        }
      }));
    },

    // ── State machine ─────────────────────────────────────────────────────────

    async changeStatus(engagement, newStatus) {
      const oldStatus = engagement.status;
      engagement.status = newStatus;
      try {
        await api.updateEngagement(engagement.id, { status: newStatus });
        await this.fetchStats();
      } catch (e) {
        engagement.status = oldStatus;
        this.error = e.message;
      }
    },

    // ── Archive / Restore ─────────────────────────────────────────────────────

    async archiveEngagement(engagement) {
      this.openMenuId = null;
      this.archiving = engagement.id;
      const idx = this.engagements.findIndex(e => e.id === engagement.id);
      try {
        await api.archiveEngagement(engagement.id);
        if (idx !== -1) this.engagements.splice(idx, 1);
        // Refresh archived list if it's visible
        if (this.showArchived) await this.fetchArchived();
        await this.fetchStats();
      } catch (e) {
        this.error = e.message;
      } finally {
        this.archiving = null;
      }
    },

    async restoreEngagement(engagement) {
      const idx = this.archived.findIndex(e => e.id === engagement.id);
      try {
        await api.restoreEngagement(engagement.id, 'draft');
        if (idx !== -1) this.archived.splice(idx, 1);
        // Add back to active list
        engagement.status = 'draft';
        this.engagements.unshift(engagement);
        await this.fetchStats();
      } catch (e) {
        this.error = e.message;
      }
    },

    toggleArchived() {
      this.showArchived = !this.showArchived;
      if (this.showArchived && this.archived.length === 0) this.fetchArchived();
    },

    // ── Permanent delete ──────────────────────────────────────────────────────

    openDeleteModal(engagement, fromArchive = false) {
      this.openMenuId = null;
      this.deleteTarget = { ...engagement, _fromArchive: fromArchive };
      this.deleteConfirmCode = '';
      this.deleteError = null;
      this.showDeleteModal = true;
    },

    closeDeleteModal() {
      if (this.deleting) return;
      this.showDeleteModal = false;
      this.deleteTarget = null;
      this.deleteConfirmCode = '';
    },

    get deleteCodeMatches() {
      return this.deleteTarget && this.deleteConfirmCode.trim() === this.deleteTarget.code;
    },

    async confirmDelete() {
      if (!this.deleteCodeMatches) return;
      this.deleting = true;
      this.deleteError = null;
      const id = this.deleteTarget.id;
      const fromArchive = this.deleteTarget._fromArchive;
      try {
        await api.permanentDeleteEngagement(id);
        if (fromArchive) {
          this.archived = this.archived.filter(e => e.id !== id);
        } else {
          this.engagements = this.engagements.filter(e => e.id !== id);
        }
        await this.fetchStats();
        this.showDeleteModal = false;
        this.deleteTarget = null;
      } catch (e) {
        this.deleteError = e.message;
      } finally {
        this.deleting = false;
      }
    },

    // ── Dropdown menu ─────────────────────────────────────────────────────────

    toggleMenu(id, event) {
      event.stopPropagation();
      this.openMenuId = this.openMenuId === id ? null : id;
    },

    _closeMenuOnOutsideClick(e) {
      if (!e.target.closest('.card-menu')) this.openMenuId = null;
    },

    canManage() {
      return this.user && ['admin', 'manager'].includes(this.user.role);
    },

    canDelete() {
      return this.user && this.user.role === 'admin';
    },

    // ── Drag and drop ─────────────────────────────────────────────────────────

    /** True if the user can drag this card to change its status.
     *  Mirrors the status buttons' gate (canManage): an admin/manager who can
     *  see the "Démarrer/Terminer" buttons can also drag, even without an
     *  explicit membership. Viewer-only members (manager globally but viewer on
     *  this mission) are still blocked. */
    canDragEngagement(engagement) {
      if (!this.canManage()) return false;
      return engagement.user_role !== 'viewer';
    },

    onDragStart(event, engagement) {
      if (!this.canDragEngagement(engagement)) { event.preventDefault(); return; }
      this.draggingId = engagement.id;
      this.draggingEngagement = engagement;
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', engagement.id);
    },

    onDragEnd(event) {
      this.draggingId = null;
      this.draggingEngagement = null;
      this.dragOverCol = null;
    },

    onDragOver(event, colStatus) {
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
      this.dragOverCol = colStatus;
    },

    onDragLeave(event) {
      if (!event.currentTarget.contains(event.relatedTarget)) {
        this.dragOverCol = null;
      }
    },

    async onDrop(event, targetStatus) {
      event.preventDefault();
      this.dragOverCol = null;
      const eng = this.draggingEngagement;
      this.draggingId = null;
      this.draggingEngagement = null;
      if (!eng || eng.status === targetStatus) return;
      await this.changeStatus(eng, targetStatus);
    },

    // ── Computed helpers ──────────────────────────────────────────────────────

    byStatus(status) {
      return this.engagements.filter(e => e.status === status);
    },

    // ── Posture charts (pure SVG, computed from existing stats) ───────────────

    get postureTotal() {
      return (this.stats.draft || 0) + (this.stats.in_progress || 0) + (this.stats.completed || 0);
    },

    /** Three donut segments (draft / in_progress / completed) as SVG stroke specs. */
    donutSegments() {
      const r = 52, circ = 2 * Math.PI * r;
      const total = this.postureTotal || 1;
      const defs = [
        { key: 'completed',   val: this.stats.completed || 0,   color: '#86BC25' },
        { key: 'in_progress', val: this.stats.in_progress || 0, color: '#4A9EFF' },
        { key: 'draft',       val: this.stats.draft || 0,       color: '#6B7280' },
      ];
      let acc = 0;
      return defs.map((s) => {
        const len = (s.val / total) * circ;
        const seg = { ...s, dash: `${len} ${circ - len}`, offset: -acc, circ };
        acc += len;
        return seg;
      });
    },

    /** Share of analysed paths flagged critical, as a 0–100 percentage. */
    get criticalRatio() {
      const p = this.stats.total_paths || 0;
      if (!p) return 0;
      return Math.min(100, Math.round(((this.stats.total_critical || 0) / p) * 100));
    },

    /** Overall posture verdict derived from the critical ratio. */
    get postureVerdict() {
      const r = this.criticalRatio;
      if ((this.stats.total_paths || 0) === 0) return { label: 'Aucune donnée', cls: 'none', color: '#6B7280' };
      if (r >= 15) return { label: 'Critique', cls: 'critique', color: '#EF4444' };
      if (r >= 7)  return { label: 'Élevé',    cls: 'eleve',    color: '#F97316' };
      if (r >= 2)  return { label: 'Modéré',   cls: 'moyen',    color: '#EAB308' };
      return { label: 'Maîtrisé', cls: 'faible', color: '#86BC25' };
    },

    canCreate() {
      return this.user && ['admin', 'manager'].includes(this.user.role);
    },

    /** French label for the user's per-engagement role. */
    engRoleLabel(engagement) {
      const labels = { lead: 'Lead', contributor: 'Contributeur', viewer: 'Lecteur' };
      return labels[engagement.user_role] || '';
    },

    /** True if the engagement card should show as draggable (visual hint). */
    isDraggable(engagement) {
      return this.canDragEngagement(engagement);
    },

    fmtDate(iso) {
      if (!iso) return '—';
      try {
        return new Date(iso).toLocaleDateString('fr-FR', { day: 'numeric', month: 'short', year: 'numeric' });
      } catch (_) { return iso; }
    },

    logout() {
      api.clearTokens();
      location.href = '/index.html';
    },

    // ── Create modal ──────────────────────────────────────────────────────────

    openCreate() {
      this.form = { client_name: '', code: '', description: '' };
      this.formError = null;
      this.showModal = true;
    },

    closeCreate() {
      if (this.saving) return;
      this.showModal = false;
    },

    autoFillCode() {
      if (!this.form.client_name) return;
      const year = new Date().getFullYear();
      const seq = String(this.engagements.length + 1).padStart(4, '0');
      const slug = this.form.client_name
        .toUpperCase()
        .normalize('NFD').replace(/[̀-ͯ]/g, '')
        .replace(/[^A-Z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 12);
      this.form.code = `${slug}-${year}-${seq}`;
    },

    async submitCreate() {
      this.formError = null;
      if (!this.form.client_name.trim()) {
        this.formError = 'Le nom du client est obligatoire';
        return;
      }
      if (this.form.client_name.trim().length < 2) {
        this.formError = 'Le nom du client doit contenir au moins 2 caractères';
        return;
      }
      if (!this.form.code.trim()) {
        this.formError = 'Le code mission est obligatoire';
        return;
      }
      this.saving = true;
      try {
        const created = await api.createEngagement({
          client_name: this.form.client_name.trim(),
          code: this.form.code.trim(),
          description: this.form.description.trim() || null,
        });
        created._analyses_count = 0;
        created._running_analysis = null;
        created._paths_count = 0;
        created._critical_count = 0;
        this.engagements.unshift(created);
        await this.fetchStats();
        this.showModal = false;
        if (window.toast) toast.success(`Mission "${created.code}" créée`);
        location.href = `/engagement.html?id=${created.id}`;
      } catch (e) {
        this.formError = e.message;
        if (window.toast) toast.error(e.message);
      } finally {
        this.saving = false;
      }
    },
  };
}
