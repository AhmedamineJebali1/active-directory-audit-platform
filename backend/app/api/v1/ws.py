"""WebSocket endpoint for real-time analysis progress."""

import json
import logging
from collections import defaultdict
from typing import Annotated

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from app.core.security import decode_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])


class ConnectionManager:
    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, analysis_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[analysis_id].append(websocket)
        logger.debug("ws_connected", extra={"analysis_id": analysis_id})

    def disconnect(self, analysis_id: str, websocket: WebSocket) -> None:
        if websocket in self._connections[analysis_id]:
            self._connections[analysis_id].remove(websocket)

    async def broadcast(self, analysis_id: str, event: dict) -> None:
        dead = []
        for ws in self._connections[analysis_id]:
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
