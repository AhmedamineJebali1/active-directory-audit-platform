// Thin WebSocket wrapper for analysis progress.
(function (global) {
  function connectAnalysisWs(analysisId, handlers = {}) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const token = api.getAccessToken();
    const url = `${proto}//${location.host}/ws/analyses/${analysisId}${token ? '?token=' + encodeURIComponent(token) : ''}`;
    const ws = new WebSocket(url);

    ws.onopen = () => handlers.onOpen && handlers.onOpen();
    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        handlers.onEvent && handlers.onEvent(data);
      } catch (e) {
        // Ignore malformed messages.
      }
    };
    ws.onerror = (e) => handlers.onError && handlers.onError(e);
    ws.onclose = () => handlers.onClose && handlers.onClose();
    return ws;
  }

  global.wsClient = { connectAnalysisWs };
})(window);
