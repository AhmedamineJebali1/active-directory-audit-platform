// API client with JWT, auto-refresh on 401, and JSON helpers.
(function (global) {
  const ACCESS_KEY = 'ad_audit_access_token';
  const REFRESH_KEY = 'ad_audit_refresh_token';
  const USER_KEY = 'ad_audit_user';

  function getAccessToken() {
    return localStorage.getItem(ACCESS_KEY);
  }
  function getRefreshToken() {
    return localStorage.getItem(REFRESH_KEY);
  }
  function setTokens(access, refresh) {
    if (access) localStorage.setItem(ACCESS_KEY, access);
    if (refresh) localStorage.setItem(REFRESH_KEY, refresh);
  }
  function clearTokens() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
  }
  function setUser(user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }
  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || 'null');
    } catch (_) {
      return null;
    }
  }

  // Map FastAPI 422 validation errors to readable French messages.
  const _FIELD_LABELS = {
    client_name: 'Nom du client', code: 'Code mission', description: 'Description',
    email: 'Email', password: 'Mot de passe', full_name: 'Nom complet',
    dc_host: 'Contrôleur de domaine', domain: 'Domaine AD',
    username: 'Nom d\'utilisateur', port: 'Port',
  };
  function _fmtError(detail) {
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      return detail.map((err) => {
        const loc = err.loc || [];
        const field = loc[loc.length - 1] || '';
        const label = _FIELD_LABELS[field] || field;
        let msg = (err.msg || 'Valeur invalide')
          .replace(/string should have at least (\d+) characters?/i, 'doit contenir au moins $1 caractères')
          .replace(/string should have at most (\d+) characters?/i, 'doit contenir au plus $1 caractères')
          .replace(/field required/i, 'champ obligatoire')
          .replace(/value is not a valid/i, 'valeur invalide')
          .replace(/ensure this value has at least (\d+) characters?/i, 'doit contenir au moins $1 caractères')
          .replace(/value_error/i, 'valeur invalide');
        return label ? `${label} : ${msg}` : msg;
      }).join(' — ');
    }
    return 'Erreur inattendue';
  }

  let refreshInflight = null;

  async function tryRefresh() {
    const refresh = getRefreshToken();
    if (!refresh) return false;
    if (!refreshInflight) {
      refreshInflight = fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refresh }),
      })
        .then(async (r) => {
          if (!r.ok) throw new Error('refresh_failed');
          const data = await r.json();
          setTokens(data.access_token, data.refresh_token);
          return true;
        })
        .catch(() => {
          clearTokens();
          return false;
        })
        .finally(() => {
          refreshInflight = null;
        });
    }
    return refreshInflight;
  }

  async function request(method, url, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    const token = getAccessToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;

    let body = options.body;
    if (body && !(body instanceof FormData) && typeof body !== 'string') {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }

    let res = await fetch(url, { method, headers, body });

    // Endpoints whose 401 means "credentials/lockout", NOT "your session
    // expired". For these we must NOT try a refresh — there's nothing to
    // refresh — and we must SHOW the real server error (e.g. "Email ou mot
    // de passe incorrect", "Trop de tentatives échouées…") instead of
    // hiding it behind "Session expirée".
    const _isCredsEndpoint = (
      url.includes('/api/v1/auth/login') ||
      url.includes('/api/v1/auth/refresh') ||
      url.includes('/api/v1/auth/forgot-password') ||
      url.includes('/api/v1/auth/reset-password') ||
      url.includes('/api/v1/auth/accept-invite')
    );

    if (res.status === 401 && !options._retried && !_isCredsEndpoint) {
      const ok = await tryRefresh();
      if (ok) {
        return request(method, url, Object.assign({}, options, { _retried: true }));
      }
      // Drop any stale tokens so we don't loop on the login page
      clearTokens();
      if (location.pathname !== '/' && location.pathname !== '/index.html') {
        location.href = '/index.html';
      }
      throw new Error('Session expirée');
    }

    if (options.raw) return res;

    if (!res.ok) {
      let detail = 'Erreur ' + res.status;
      try {
        const j = await res.json();
        if (j.detail) detail = _fmtError(j.detail);
      } catch (_) {}
      throw new Error(detail);
    }

    if (res.status === 204) return null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
  }

  const api = {
    // auth
    login: (email, password) =>
      request('POST', '/api/v1/auth/login', { body: { email, password } }),
    me: () => request('GET', '/api/v1/auth/me'),
    refresh: tryRefresh,

    // engagements
    listEngagements: (limit = 20, offset = 0, includeArchived = false) =>
      request('GET', `/api/v1/engagements?limit=${limit}&offset=${offset}${includeArchived ? '&include_archived=true' : ''}`),
    createEngagement: (payload) =>
      request('POST', '/api/v1/engagements', { body: payload }),
    getEngagement: (id) => request('GET', `/api/v1/engagements/${id}`),
    updateEngagement: (id, payload) =>
      request('PATCH', `/api/v1/engagements/${id}`, { body: payload }),
    archiveEngagement: (id) =>
      request('PATCH', `/api/v1/engagements/${id}`, { body: { status: 'archived' } }),
    restoreEngagement: (id, status = 'draft') =>
      request('PATCH', `/api/v1/engagements/${id}`, { body: { status } }),
    permanentDeleteEngagement: (id) => request('DELETE', `/api/v1/engagements/${id}`),

    // analyses
    listAnalyses: (engagementId) =>
      request('GET', `/api/v1/engagements/${engagementId}/analyses`),
    uploadAnalysis: (engagementId, file, onProgress) => {
      // Use XHR for upload progress
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', `/api/v1/engagements/${engagementId}/analyses`);
        const tok = getAccessToken();
        if (tok) xhr.setRequestHeader('Authorization', 'Bearer ' + tok);
        if (xhr.upload && onProgress) {
          xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) onProgress((e.loaded / e.total) * 100);
          };
        }
        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            try { resolve(JSON.parse(xhr.responseText)); } catch (_) { resolve(null); }
          } else {
            let detail = 'Erreur ' + xhr.status;
            try { const j = JSON.parse(xhr.responseText); if (j.detail) detail = j.detail; } catch (_) {}
            reject(new Error(detail));
          }
        };
        xhr.onerror = () => reject(new Error('Erreur réseau'));
        const fd = new FormData();
        fd.append('file', file);
        xhr.send(fd);
      });
    },
    getAnalysis: (id) => request('GET', `/api/v1/analyses/${id}`),
    listPaths: (analysisId, filters = {}) => {
      const qs = new URLSearchParams();
      Object.entries(filters).forEach(([k, v]) => {
        if (v !== null && v !== undefined && v !== '') qs.append(k, v);
      });
      const q = qs.toString();
      return request('GET', `/api/v1/analyses/${analysisId}/paths${q ? '?' + q : ''}`);
    },
    getPath: (analysisId, pathId) =>
      request('GET', `/api/v1/analyses/${analysisId}/paths/${pathId}`),
    getStats: (analysisId) => request('GET', `/api/v1/analyses/${analysisId}/stats`),
    getMitre: (analysisId) => request('GET', `/api/v1/analyses/${analysisId}/mitre`),
    reportUrl: (analysisId) => `/api/v1/analyses/${analysisId}/report.pdf`,
    downloadReport: async (analysisId, filename) => {
      const res = await request('GET', `/api/v1/analyses/${analysisId}/report.pdf`, { raw: true });
      if (!res.ok) throw new Error('Téléchargement échoué');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename || `rapport_${analysisId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },

    downloadRemediationBundle: async (analysisId, filename) => {
      const res = await request('GET', `/api/v1/analyses/${analysisId}/remediation-bundle.zip`, { raw: true });
      if (!res.ok) {
        let msg = 'Téléchargement échoué';
        try { const j = await res.json(); msg = j.detail || msg; } catch (_) {}
        throw new Error(msg);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename || `remediation_${analysisId}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },

    downloadRemediationScript: async (analysisId, pathId, filename) => {
      const res = await request('GET', `/api/v1/analyses/${analysisId}/paths/${pathId}/remediation-script`, { raw: true });
      if (!res.ok) {
        let msg = 'Téléchargement échoué';
        try { const j = await res.json(); msg = j.detail || msg; } catch (_) {}
        throw new Error(msg);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename || `remediation_${pathId}.ps1`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },

    // engagement stats + notes + members
    getEngagementStats: () => request('GET', '/api/v1/engagements/stats/summary'),
    getNotes: (id) => request('GET', `/api/v1/engagements/${id}/notes`),
    updateNotes: (id, notes) =>
      request('PATCH', `/api/v1/engagements/${id}/notes`, { body: { notes } }),
    getMembers: (id) => request('GET', `/api/v1/engagements/${id}/members`),
    addMember: (id, payload) =>
      request('POST', `/api/v1/engagements/${id}/members`, { body: payload }),
    removeMember: (engagementId, userId) =>
      request('DELETE', `/api/v1/engagements/${engagementId}/members/${userId}`, { raw: true }).then(() => null),

    // LLM settings
    getLLMConfig: () => request('GET', '/api/v1/llm/config'),
    updateLLMConfig: (payload) => request('PUT', '/api/v1/llm/config', { body: payload }),
    testLLMConnection: () => request('POST', '/api/v1/llm/test'),
    getLLMProviders: () => request('GET', '/api/v1/llm/providers'),

    // LDAP live collection
    ldapCollect: (engagementId, payload) =>
      request('POST', `/api/v1/engagements/${engagementId}/ldap-collect`, { body: payload }),

    // Global stats (dashboard)
    getGlobalStats: () => request('GET', '/api/v1/stats/global'),

    // token helpers
    getAccessToken,
    setTokens,
    clearTokens,
    setUser,
    getUser,
  };

  global.api = api;
})(window);
