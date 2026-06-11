// Auth helpers: gate pages, render nav user, logout.
(function (global) {
  async function requireAuth() {
    if (!api.getAccessToken()) {
      location.href = '/index.html';
      return null;
    }
    try {
      const user = await api.me();
      api.setUser(user);
      return user;
    } catch (_) {
      api.clearTokens();
      location.href = '/index.html';
      return null;
    }
  }

  function logout() {
    api.clearTokens();
    location.href = '/index.html';
  }

  function initials(name, email) {
    const src = (name || email || '?').trim();
    const parts = src.split(/\s+/);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return src.slice(0, 2).toUpperCase();
  }

  function renderNav(activeKey) {
    const user = api.getUser() || {};
    const ini = initials(user.full_name, user.email);
    const isAdmin = user.role === 'admin';
    const role = user.role || '';
    const fullName = user.full_name || user.email || '';

    // Lucide-style inline SVG icons (no extra CDN call)
    const ico = {
      dash:  '<svg viewBox="0 0 24 24" fill="none"><rect x="3" y="3" width="7" height="9" rx="1.5" stroke="currentColor" stroke-width="1.8"/><rect x="14" y="3" width="7" height="5" rx="1.5" stroke="currentColor" stroke-width="1.8"/><rect x="14" y="12" width="7" height="9" rx="1.5" stroke="currentColor" stroke-width="1.8"/><rect x="3" y="16" width="7" height="5" rx="1.5" stroke="currentColor" stroke-width="1.8"/></svg>',
      cog:   '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.8"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" stroke="currentColor" stroke-width="1.6"/></svg>',
      users: '<svg viewBox="0 0 24 24" fill="none"><circle cx="9" cy="8" r="3.5" stroke="currentColor" stroke-width="1.8"/><circle cx="17" cy="9" r="2.5" stroke="currentColor" stroke-width="1.8"/><path d="M3 19c0-3 2.5-5 6-5s6 2 6 5M14 14c2.5 0 6 1.5 7 5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
      audit: '<svg viewBox="0 0 24 24" fill="none"><path d="M5 4h11l3 3v13a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z" stroke="currentColor" stroke-width="1.6"/><path d="M9 11h6M9 14h6M9 17h3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
      reg:   '<svg viewBox="0 0 24 24" fill="none"><rect x="3" y="4" width="18" height="16" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M3 9h18M8 13h9M8 16h6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
      out:   '<svg viewBox="0 0 24 24" fill="none"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    };

    const isManager = role === 'manager';
    const navHtml = `
      <aside class="sidebar" id="app-sidebar">
        <a class="sidebar__brand" href="/dashboard.html">
          <img class="sidebar__logo-icon" src="/assets/img/logo-icon.png" alt="AD Audit AI" />
          <span class="sidebar__title">AD Audit AI</span>
        </a>
        <nav class="sidebar__nav">
          <a class="sidebar__item ${activeKey === 'dashboard' ? 'is-active' : ''}" href="/dashboard.html">
            <span class="sidebar__icon">${ico.dash}</span>
            <span class="sidebar__label">Tableau de bord</span>
          </a>
          <a class="sidebar__item ${activeKey === 'missions' ? 'is-active' : ''}" href="/missions.html">
            <span class="sidebar__icon">${ico.reg}</span>
            <span class="sidebar__label">Registre des missions</span>
          </a>
          ${isAdmin ? `<a class="sidebar__item ${activeKey === 'users' ? 'is-active' : ''}" href="/users.html">
            <span class="sidebar__icon">${ico.users}</span>
            <span class="sidebar__label">Utilisateurs</span>
          </a>
          <a class="sidebar__item ${activeKey === 'audit' ? 'is-active' : ''}" href="/audit.html">
            <span class="sidebar__icon">${ico.audit}</span>
            <span class="sidebar__label">Journal d'audit</span>
          </a>` : ''}
          ${(isAdmin || isManager) ? `<a class="sidebar__item ${activeKey === 'settings' ? 'is-active' : ''}" href="/settings.html">
            <span class="sidebar__icon">${ico.cog}</span>
            <span class="sidebar__label">Configuration LLM</span>
          </a>` : ''}
        </nav>
        <div class="sidebar__footer">
          <div class="sidebar__item" style="cursor:default;">
            <span class="topbar__avatar" style="width:28px;height:28px;font-size:11px;flex:0 0 28px;">${ini}</span>
            <span class="sidebar__label" style="display:flex;flex-direction:column;line-height:1.2;overflow:hidden;">
              <strong style="font-size:12px;color:var(--color-text);overflow:hidden;text-overflow:ellipsis;">${fullName}</strong>
              <span style="font-size:10px;color:var(--color-text-muted);text-transform:uppercase;letter-spacing:0.4px;">${role}</span>
            </span>
          </div>
          <button class="sidebar__item" id="nav-logout-btn" type="button" style="background:transparent;border:none;color:var(--color-text-muted);cursor:pointer;font-family:inherit;text-align:left;width:100%;">
            <span class="sidebar__icon">${ico.out}</span>
            <span class="sidebar__label">Déconnexion</span>
          </button>
        </div>
      </aside>
    `;

    const slot = document.getElementById('nav-slot');
    if (slot) {
      slot.innerHTML = navHtml;
      const btn = document.getElementById('nav-logout-btn');
      if (btn) btn.addEventListener('click', logout);
      // Mark body so layout grid kicks in
      document.body.classList.add('has-sidebar');
      // Hover-to-expand for sidebar
      const shell = document.getElementById('app-shell');
      const sidebar = document.getElementById('app-sidebar');
      if (shell && sidebar) {
        sidebar.addEventListener('mouseenter', () => shell.classList.add('is-expanded'));
        sidebar.addEventListener('mouseleave', () => shell.classList.remove('is-expanded'));
      }
    }
  }

  global.auth = { requireAuth, logout, renderNav };
})(window);
