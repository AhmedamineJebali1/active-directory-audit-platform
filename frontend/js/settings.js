// LLM provider settings page
function settingsApp() {
  return {
    user: null,
    loading: true,
    saving: false,
    testing: false,
    testResult: null,
    error: null,
    errorIsAuthFail: false,   // true when key is rejected → show force-save button
    success: null,

    providers: {},
    currentConfig: null,
    selected: '',
    selectedModel: '',
    apiKey: '',
    showKey: false,

    async init() {
      this.user = await auth.requireAuth();
      if (!this.user) return;
      auth.renderNav('settings');
      if (window.statusChips) statusChips.attach({ wsBound: false });
      await Promise.all([this.loadProviders(), this.loadConfig()]);
      this.loading = false;
    },

    async _authFetch(url, opts = {}) {
      const headers = Object.assign({ 'Authorization': 'Bearer ' + api.getAccessToken() }, opts.headers || {});
      const res = await fetch(url, Object.assign({}, opts, { headers }));
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.detail || 'Erreur ' + res.status);
      }
      return res.json();
    },

    async loadProviders() {
      try {
        const data = await this._authFetch('/api/v1/llm/providers');
        this.providers = data.providers || {};
      } catch (e) {
        this.error = e.message;
      }
    },

    async loadConfig() {
      try {
        this.currentConfig = await this._authFetch('/api/v1/llm/config');
        this.selected = this.currentConfig.provider;
        this.selectedModel = this.currentConfig.model;
      } catch (e) {
        this.error = e.message;
      }
    },

    selectProvider(key) {
      this.selected = key;
      const meta = this.providers[key];
      if (key === (this.currentConfig && this.currentConfig.provider)) {
        this.selectedModel = this.currentConfig.model;
      } else if (meta && meta.models && meta.models.length > 0) {
        this.selectedModel = meta.models[0];
      } else {
        this.selectedModel = '';
      }
      this.apiKey = '';
      this.success = null;
      this.error = null;
      this.errorIsAuthFail = false;
      this.testResult = null;
    },

    get selectedMeta() {
      return this.providers[this.selected] || {};
    },

    isActive(key) {
      return this.currentConfig && this.currentConfig.provider === key;
    },

    hasKey(key) {
      return this.currentConfig &&
        this.currentConfig.configured_providers &&
        this.currentConfig.configured_providers.includes(key);
    },

    async save(force = false) {
      if (this.user.role !== 'admin') {
        this.error = 'Seuls les administrateurs peuvent modifier la configuration LLM.';
        return;
      }
      this.saving = true;
      this.error = null;
      this.errorIsAuthFail = false;
      this.success = null;
      try {
        const payload = { provider: this.selected, model: this.selectedModel, force };
        if (this.apiKey) payload.api_key = this.apiKey;

        this.currentConfig = await this._authFetch('/api/v1/llm/config', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        this.apiKey = '';
        this.success = `Configuration appliquée — ${this.selectedMeta.label || this.selected} (${this.selectedModel})`;
        if (window.toast) toast.success(`Fournisseur LLM activé : ${this.selectedMeta.label || this.selected}`);
        if (window.statusChips) statusChips.refreshLLM();
      } catch (e) {
        const msg = e.message || '';
        if (msg.startsWith('CLÉ_INVALIDE:')) {
          this.error = msg.replace('CLÉ_INVALIDE:', '').trim();
          this.errorIsAuthFail = true;
        } else {
          this.error = msg;
        }
      } finally {
        this.saving = false;
      }
    },

    async forceSave() {
      await this.save(true);
    },

    async deleteKey(provider) {
      if (!confirm(`Supprimer la clé enregistrée pour ${this.providerLabel(provider)} ?`)) return;
      try {
        const res = await fetch(`/api/v1/llm/key/${provider}`, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + api.getAccessToken() },
        });
        if (!res.ok) throw new Error('Erreur ' + res.status);
        await this.loadConfig();
        this.success = `Clé supprimée : ${this.providerLabel(provider)}`;
      } catch (e) {
        this.error = e.message;
      }
    },

    async testConnection() {
      this.testing = true;
      this.testResult = null;
      this.error = null;
      try {
        const res = await this._authFetch('/api/v1/llm/test', { method: 'POST' });
        this.testResult = res;
        if (window.toast) {
          if (res.success) toast.success(`${this.providerLabel(res.provider)} : connexion réussie`);
          else toast.error(res.message || 'Connexion échouée');
        }
      } catch (e) {
        this.testResult = { success: false, message: e.message, provider: 'unknown' };
        if (window.toast) toast.error(e.message);
      } finally {
        this.testing = false;
      }
    },

    isAdmin() {
      return this.user && this.user.role === 'admin';
    },

    providerLabel(key) {
      return (this.providers[key] && this.providers[key].label) || key;
    },

    providerInitial(key) {
      const icons = {
        mistral: 'Mi', anthropic: 'Cl', openai: 'AI', google: 'Ge',
        openrouter: 'OR', ollama: 'Ol', mock: 'DM', azure: 'Az',
      };
      return icons[key] || key.slice(0, 2).toUpperCase();
    },

    modelLabel(m) {
      return m.replace('-latest', '').replace(':free', '');
    },
  };
}
