// Lightweight toast notification system. No dependencies.
// API: toast.success(msg), toast.error(msg), toast.info(msg), toast.warn(msg)
//      toast.show(msg, {kind, timeout, action: {label, onclick}})
(function (global) {
  const ROOT_ID = 'toast-root';
  const DEFAULT_TIMEOUT = 4500;
  let counter = 0;

  function root() {
    let r = document.getElementById(ROOT_ID);
    if (!r) {
      r = document.createElement('div');
      r.id = ROOT_ID;
      r.className = 'toast-root';
      document.body.appendChild(r);
    }
    return r;
  }

  const ICONS = {
    success: '<svg viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M6 10.5l2.5 2.5L14 7.5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    error:   '<svg viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M10 6v5M10 14h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    warn:    '<svg viewBox="0 0 20 20" fill="none"><path d="M10 2L1.5 17h17L10 2z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M10 8v4M10 15h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    info:    '<svg viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M10 9v5M10 6h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  };

  function show(message, opts = {}) {
    const kind = opts.kind || 'info';
    const timeout = opts.timeout != null ? opts.timeout : DEFAULT_TIMEOUT;
    const id = 't' + (++counter);

    const el = document.createElement('div');
    el.className = 'toast toast--' + kind;
    el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    el.dataset.id = id;

    const action = opts.action;
    el.innerHTML =
      '<span class="toast__icon">' + (ICONS[kind] || ICONS.info) + '</span>' +
      '<span class="toast__msg"></span>' +
      (action ? '<button class="toast__action" type="button"></button>' : '') +
      '<button class="toast__close" type="button" aria-label="Fermer">×</button>';
    el.querySelector('.toast__msg').textContent = message;

    if (action) {
      const btn = el.querySelector('.toast__action');
      btn.textContent = action.label;
      btn.addEventListener('click', () => {
        try { action.onclick(); } catch (_) {}
        dismiss(el);
      });
    }
    el.querySelector('.toast__close').addEventListener('click', () => dismiss(el));

    root().appendChild(el);
    // trigger enter animation
    requestAnimationFrame(() => el.classList.add('is-visible'));

    if (timeout > 0) {
      setTimeout(() => dismiss(el), timeout);
    }
    return id;
  }

  function dismiss(el) {
    if (!el || el.classList.contains('is-leaving')) return;
    el.classList.add('is-leaving');
    el.addEventListener('transitionend', () => el.remove(), { once: true });
    setTimeout(() => el.remove(), 400); // safety
  }

  global.toast = {
    show,
    success: (m, o) => show(m, Object.assign({ kind: 'success' }, o || {})),
    error:   (m, o) => show(m, Object.assign({ kind: 'error', timeout: 7000 }, o || {})),
    warn:    (m, o) => show(m, Object.assign({ kind: 'warn' }, o || {})),
    info:    (m, o) => show(m, Object.assign({ kind: 'info' }, o || {})),
  };
})(window);
