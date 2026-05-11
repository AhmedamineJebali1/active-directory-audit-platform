// Live status chips: WebSocket connection state + active LLM provider.
// Renders into the .topbar element of any page that includes it.
//
// Usage on a page:
//   statusChips.attach({ wsBound: true });    // call after auth.renderNav()
//   statusChips.setWs('connected'|'polling'|'disconnected');
//   statusChips.refreshLLM();                  // re-fetch /llm/config
(function (global) {
  let llmInfo = null;
  let wsState = 'idle';   // idle | connected | polling | disconnected
  let wsBound = false;

  const PROVIDER_LABELS = {
    anthropic: 'Anthropic Claude',
    openai: 'OpenAI',
    mistral: 'Mistral',
    google: 'Gemini',
    openrouter: 'OpenRouter',
    ollama: 'Ollama',
    azure: 'Azure',
    mock: 'Mode démo',
  };

  function ensureContainer() {
    const bar = document.querySelector('.topbar');
    if (!bar) return null;
    let host = bar.querySelector('.status-chips');
    if (!host) {
      host = document.createElement('div');
      host.className = 'status-chips';
      // Insert before the topbar__spacer so chips sit at the right edge
      const spacer = bar.querySelector('.topbar__spacer');
      if (spacer && spacer.parentNode === bar) bar.insertBefore(host, spacer);
      else bar.appendChild(host);
    }
    return host;
  }

  function render() {
    const host = ensureContainer();
    if (!host) return;

    let chips = '';

    // ── WS chip — only on pages that bound it (engagement page, etc.) ──
    if (wsBound) {
      const cls = 'chip-ws chip-ws--' + wsState;
      const label = {
        connected: 'Temps réel',
        polling: 'Polling',
        disconnected: 'Hors-ligne',
        idle: 'En attente',
      }[wsState] || wsState;
      const titleText = {
        connected: 'WebSocket connecté — événements en temps réel',
        polling: 'WebSocket indisponible — fallback HTTP polling',
        disconnected: 'Connexion perdue — reconnecting…',
        idle: 'Aucun pipeline en cours',
      }[wsState] || '';
      chips += `<span class="${cls}" title="${titleText}">
        <span class="chip-ws__dot"></span>
        <span class="chip-ws__label">${label}</span>
      </span>`;
    }

    // ── LLM provider chip ───────────────────────────────────────────────
    if (llmInfo) {
      const provider = llmInfo.provider || 'mock';
      const isMock = provider === 'mock';
      const label = PROVIDER_LABELS[provider] || provider;
      const model = llmInfo.model || '';
      const modelShort = model.replace(':free', '').replace('claude-', 'Claude ');
      const cls = isMock ? 'chip-llm chip-llm--warn' : 'chip-llm';
      const sigil = isMock ? '⚠' : '✦';
      chips += `<a class="${cls}" href="/settings.html"
                   title="Cliquez pour changer de fournisseur">
        <span class="chip-llm__sigil">${sigil}</span>
        <span class="chip-llm__provider">${label}</span>
        ${modelShort ? `<span class="chip-llm__model">${modelShort}</span>` : ''}
      </a>`;
    }

    host.innerHTML = chips;
  }

  async function refreshLLM() {
    try {
      llmInfo = await api.getLLMConfig();
    } catch (_) {
      llmInfo = null;
    }
    render();
  }

  function setWs(state) {
    wsState = state;
    render();
  }

  function attach(opts = {}) {
    wsBound = !!opts.wsBound;
    // Lazy-render after DOM is settled so the topbar exists
    requestAnimationFrame(() => {
      render();
      refreshLLM();
    });
  }

  global.statusChips = { attach, setWs, refreshLLM };
})(window);
