"""Integration tests for the WebSocket progress endpoint."""

import asyncio
import json

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

# WS router is mounted without prefix — endpoint is /ws/analyses/{id}
WS_BASE = "/ws/analyses"


class TestWebSocketConnection:
    def test_connect_without_token_is_accepted(self):
        """Unauthenticated connections are allowed (token is optional)."""
        from app.main import app

        analysis_id = "00000000-0000-0000-0000-000000000001"
        with TestClient(app) as tc:
            with tc.websocket_connect(f"{WS_BASE}/{analysis_id}") as ws:
                pass  # clean disconnect via context-manager exit

    def test_broadcast_delivers_event_to_subscriber(self):
        """Events broadcast via ConnectionManager reach connected clients."""
        from app.api.v1.ws import manager
        from app.main import app

        analysis_id = "00000000-0000-0000-0000-000000000002"
        event = {"stage": "ingestion", "progress": 10, "message_fr": "Test de diffusion"}

        with TestClient(app) as tc:
            with tc.websocket_connect(f"{WS_BASE}/{analysis_id}") as ws:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(manager.broadcast(analysis_id, event))
                loop.close()

                data = ws.receive_text()
                parsed = json.loads(data)
                assert parsed["stage"] == "ingestion"
                assert parsed["progress"] == 10
                assert parsed["message_fr"] == "Test de diffusion"

    def test_invalid_token_closes_connection(self):
        """A malformed JWT causes the server to close the WS with code 4001."""
        from app.main import app

        analysis_id = "00000000-0000-0000-0000-000000000003"

        with TestClient(app) as tc:
            try:
                with tc.websocket_connect(
                    f"{WS_BASE}/{analysis_id}?token=invalid.jwt.token"
                ) as ws:
                    ws.receive_text()
                pytest.fail("Expected WebSocketDisconnect was not raised")
            except WebSocketDisconnect as exc:
                assert exc.code == 4001

    def test_disconnect_cleans_up_connection(self):
        """After disconnect, the analysis slot no longer holds the socket."""
        from app.api.v1.ws import manager
        from app.main import app

        analysis_id = "00000000-0000-0000-0000-000000000004"

        with TestClient(app) as tc:
            with tc.websocket_connect(f"{WS_BASE}/{analysis_id}"):
                assert len(manager._connections.get(analysis_id, [])) == 1

        assert len(manager._connections.get(analysis_id, [])) == 0
