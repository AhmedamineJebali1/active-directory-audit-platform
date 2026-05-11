"""WebSocket endpoint for real-time analysis progress.

The connection manager keeps a small per-analysis replay buffer so a client
that connects after the pipeline has already started still receives every
prior event in order.
"""

import json
import logging
from collections import defaultdict, deque

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.security import decode_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

REPLAY_BUFFER_SIZE = 50


class ConnectionManager:
    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)
        self._events: dict[str, deque] = defaultdict(lambda: deque(maxlen=REPLAY_BUFFER_SIZE))

    def record_event(self, analysis_id: str, event: dict) -> None:
        """Append an event to the per-analysis replay buffer."""
        self._events[analysis_id].append(event)

    def get_events(self, analysis_id: str) -> list[dict]:
        return list(self._events.get(analysis_id, []))

    async def connect(self, analysis_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[analysis_id].append(websocket)
        # Replay buffered events so a late-joining client sees what it missed.
        for ev in self._events.get(analysis_id, []):
            try:
                await websocket.send_text(json.dumps(ev))
            except Exception:
                break
        logger.debug("ws_connected", extra={"analysis_id": analysis_id})

    def disconnect(self, analysis_id: str, websocket: WebSocket) -> None:
        if websocket in self._connections.get(analysis_id, []):
            self._connections[analysis_id].remove(websocket)

    async def broadcast(self, analysis_id: str, event: dict) -> None:
        dead = []
        for ws in self._connections.get(analysis_id, []):
            try:
                await ws.send_text(json.dumps(event))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(analysis_id, ws)


manager = ConnectionManager()


@router.websocket("/ws/analyses/{analysis_id}")
async def analysis_ws(websocket: WebSocket, analysis_id: str):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001)
        return
    try:
        decode_token(token)
    except Exception:
        await websocket.close(code=4001)
        return

    await manager.connect(analysis_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(analysis_id, websocket)
        logger.debug("ws_disconnected", extra={"analysis_id": analysis_id})
