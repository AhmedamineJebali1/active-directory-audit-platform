// Admin user-management page
function usersApp() {
  return {
    me: {},
    isAdmin: false,
    loading: true,
    users: [],
    total: 0,
    search: '',
    includeDisabled: true,

    inviteOpen: false,
    inviting: false,
    inviteError: null,
    invite: { email: '', full_name: '', role: 'auditor', password: '' },

    async init() {
      const u = await auth.requireAuth();
      if (!u) return;
      this.me = u;
      this.isAdmin = u.role === 'admin';
      auth.renderNav();
      if (window.statusChips) statusChips.attach({ wsBound: false });
      if (this.isAdmin) await this.reload();
      this.loading = false;
    },

    async reload() {
      this.loading = true;
      try {
        const qs = new URLSearchParams();
        qs.set('limit', '100');
        if (this.search.trim()) qs.set('q', this.search.trim());
        qs.set('include_disabled', this.includeDisabled ? 'true' : 'false');
        const data = await this._authFetch('/api/v1/admin/users?' + qs.toString());
        this.users = data.items || [];
        this.total = data.total || 0;
      } catch (e) {
        if (window.toast) toast.error(e.message);
      } finally {
        this.loading = false;
      }
    },

    byRole(role) {
      return this.users.filter(u => u.role === role).length;
    },

    async changeRole(u, newRole) {
      if (newRole === u.role) return;
      if (!confirm(`Changer le rôle de ${u.email} en "${newRole}" ?`)) {
        await this.reload(); return;
      }
      try {
        const updated = await this._authFetch(`/api/v1/admin/users/${u.id}`, {
          method: 'PATCH',
          body: JSON.stringify({ role: newRole }),
          headers: { 'Content-Type': 'application/json' },
        });
        u.role = updated.role;
        if (window.toast) toast.success(`Rôle mis à jour : ${u.email} → ${newRole}`);
      } catch (e) {
        if (window.toast) toast.error(e.message);
        await this.reload();
      }
    },

    async disable(u) {
      if (!confirm(`Désactiver ${u.email} ? L'utilisateur ne pourra plus se connecter.`)) return;
      try {
        await this._authFetch(`/api/v1/admin/users/${u.id}/disable`, { method: 'POST' });
        u.is_active = false;
        if (window.toast) toast.success(`${u.email} désactivé`);
      } catch (e) {
        if (window.toast) toast.error(e.message);
      }
    },

    async enable(u) {
      try {
        await this._authFetch(`/api/v1/admin/users/${u.id}/enable`, { method: 'POST' });
        u.is_active = true;
        if (window.toast) toast.success(`${u.email} réactivé`);
      } catch (e) {
        if (window.toast) toast.error(e.message);
      }
    },

    async forceLogout(u) {
      if (!confirm(`Forcer la déconnexion de ${u.email} ? Toutes ses sessions actives seront invalidées.`)) return;
      try {
        await this._authFetch(`/api/v1/auth/admin/users/${u.id}/force-logout`, { method: 'POST' });
        if (window.toast) toast.success(`Sessions de ${u.email} révoquées`);
      } catch (e) {
        if (window.toast) toast.error(e.message);
      }
    },

    openInvite() {
      this.invite = { email: '', full_name: '', role: 'auditor', password: '' };
      this.inviteError = null;
      this.inviteOpen = true;
    },

    async submitInvite() {
      this.inviteError = null;
      this.inviting = true;
      try {
        const payload = {
          email: this.invite.email.trim().toLowerCase(),
          full_name: this.invite.full_name.trim(),
          role: this.invite.role,
          password: this.invite.password,
        };
        await this._authFetch('/api/v1/auth/register', {
          method: 'POST',
          body: JSON.stringify(payload),
          headers: { 'Content-Type': 'application/json' },
        });
        this.inviteOpen = false;
        if (window.toast) toast.success(`${payload.email} créé`);
        await this.reload();
      } catch (e) {
        this.inviteError = e.message;
      } finally {
        this.inviting = false;
      }
    },

    formatDate(iso) {
      if (!iso) return null;
      try {
        return new Date(iso).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' });
      } catch (_) { return iso; }
    },

    async _authFetch(url, opts = {}) {
      const headers = Object.assign(
        { 'Authorization': 'Bearer ' + api.getAccessToken() },
        opts.headers || {},
      );
      const res = await fetch(url, Object.assign({}, opts, { headers }));
      if (!res.ok) {
        let detail = 'Erreur ' + res.status;
        try { const j = await res.json(); if (j.detail) detail = j.detail; } catch (_) {}
        throw new Error(detail);
      }
      if (res.status === 204) return null;
      return res.json();
    },
  };
}
