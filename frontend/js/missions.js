// Missions registry — full searchable / filterable list of every mission
// (active + archived). Read-only explorer; does not touch the dashboard board.
function missionsApp() {
  return {
    user: null,
    loading: true,
    error: null,
    all: [],

    // filters
    search: '',
    statusFilter: 'all',
    dateField: 'created_at',   // which date the range applies to
    dateFrom: '',
    dateTo: '',

    // sorting
    sortKey: 'updated_at',
    sortDir: 'desc',

    async init() {
      this.user = await auth.requireAuth();
      if (!this.user) return;
      auth.renderNav('missions');
      if (window.statusChips) statusChips.attach({ wsBound: false });
      await this.fetchAll();
      this.loading = false;
    },

    async fetchAll() {
      this.error = null;
      try {
        const data = await api.listEngagements(100, 0, true);
        const items = data.items || [];
        await this._enrich(items);
        this.all = items;
      } catch (e) {
        this.error = e.message;
      }
    },

    // Attach analyses + paths counts (one call per engagement, parallelised).
    async _enrich(items) {
      await Promise.all(items.map(async (e) => {
        try {
          const data = await api.listAnalyses(e.id);
          const analyses = data.items || [];
          e._analyses_count = analyses.length;
          const completed = analyses.filter(a => a.status === 'completed');
          e._paths_count = completed.reduce((s, a) => s + (a.total_paths || 0), 0);
        } catch (_) {
          e._analyses_count = 0;
          e._paths_count = 0;
        }
      }));
    },

    // ── Filtering + sorting ─────────────────────────────────────────────────

    get filtered() {
      let rows = this.all.slice();

      // text search across code / client / description
      const q = this.search.trim().toLowerCase();
      if (q) {
        rows = rows.filter(e =>
          (e.code || '').toLowerCase().includes(q) ||
          (e.client_name || '').toLowerCase().includes(q) ||
          (e.description || '').toLowerCase().includes(q)
        );
      }

      // status
      if (this.statusFilter !== 'all') {
        rows = rows.filter(e => e.status === this.statusFilter);
      }

      // date range (inclusive) on the chosen date field
      if (this.dateFrom) {
        const from = new Date(this.dateFrom + 'T00:00:00');
        rows = rows.filter(e => new Date(e[this.dateField]) >= from);
      }
      if (this.dateTo) {
        const to = new Date(this.dateTo + 'T23:59:59');
        rows = rows.filter(e => new Date(e[this.dateField]) <= to);
      }

      // sort
      const dir = this.sortDir === 'asc' ? 1 : -1;
      const key = this.sortKey;
      rows.sort((a, b) => {
        let va = a[key], vb = b[key];
        if (key === 'created_at' || key === 'updated_at') {
          va = new Date(va).getTime(); vb = new Date(vb).getTime();
        } else if (typeof va === 'number' || key === '_analyses_count' || key === '_paths_count') {
          va = va || 0; vb = vb || 0;
        } else {
          va = (va || '').toString().toLowerCase();
          vb = (vb || '').toString().toLowerCase();
        }
        if (va < vb) return -1 * dir;
        if (va > vb) return 1 * dir;
        return 0;
      });

      return rows;
    },

    get hasFilters() {
      return this.search.trim() || this.statusFilter !== 'all' || this.dateFrom || this.dateTo;
    },

    resetFilters() {
      this.search = '';
      this.statusFilter = 'all';
      this.dateField = 'created_at';
      this.dateFrom = '';
      this.dateTo = '';
    },

    sortBy(key) {
      if (this.sortKey === key) {
        this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        this.sortKey = key;
        this.sortDir = (key === 'created_at' || key === 'updated_at' || key === '_paths_count' || key === '_analyses_count') ? 'desc' : 'asc';
      }
    },

    sortIcon(key) {
      if (this.sortKey !== key) return '↕';
      return this.sortDir === 'asc' ? '↑' : '↓';
    },

    // counters for the summary chips (reflect current filter)
    countBy(status) {
      return this.all.filter(e => e.status === status).length;
    },

    // ── Display helpers ─────────────────────────────────────────────────────

    statusLabel(s) {
      return ({
        draft: 'En attente',
        in_progress: 'En cours',
        completed: 'Terminée',
        archived: 'Archivée',
      })[s] || s;
    },

    statusClass(s) {
      return ({
        draft: 'st--draft',
        in_progress: 'st--progress',
        completed: 'st--done',
        archived: 'st--archived',
      })[s] || '';
    },

    fmtDate(iso) {
      if (!iso) return '—';
      try {
        return new Date(iso).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' });
      } catch (_) { return iso; }
    },

    open(e) {
      location.href = `/engagement.html?id=${e.id}`;
    },
  };
}
