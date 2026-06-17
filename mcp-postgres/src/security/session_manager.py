from __future__ import annotations

import threading
import time
from typing import TypedDict

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult


class _SessionInfo(TypedDict):
    """Per-actor session tracking record."""

    created_at: float
    last_active: float
    last_request_id: str


class SessionManager:
    """Tracks actor sessions with TTL, inactivity timeout, and concurrency caps.

    Refactored to support FastMCP middleware: auto-tracks sessions via
    on_call_tool hook (primary path), while keeping touch() for manual use.
    """

    def __init__(
        self,
        session_ttl_minutes: int = 60,
        inactivity_timeout_minutes: int = 15,
        concurrent_sessions_limit: int = 10,
    ):
        self._session_ttl = session_ttl_minutes * 60
        self._inactivity_timeout = inactivity_timeout_minutes * 60
        self._concurrent_limit = concurrent_sessions_limit
        self._lock = threading.RLock()
        self._sessions: dict[str, _SessionInfo] = {}

    def touch(self, actor_id: str, request_id: str) -> None:
        """Register activity for an actor, updating their session timestamp.

        Enforces concurrent session limit by removing oldest sessions if exceeded.
        """
        now = time.time()
        with self._lock:
            self._expire_stale_locked(now)

            if actor_id not in self._sessions:
                if len(self._sessions) >= self._concurrent_limit:
                    oldest = min(
                        self._sessions.keys(),
                        key=lambda k: self._sessions[k]["last_active"],
                    )
                    del self._sessions[oldest]

            self._sessions[actor_id] = {
                "created_at": self._sessions.get(actor_id, {}).get("created_at", now),
                "last_active": now,
                "last_request_id": request_id,
            }

    def expire_stale(self) -> None:
        """Remove sessions that have exceeded TTL or inactivity timeout."""
        with self._lock:
            self._expire_stale_locked(time.time())

    def _expire_stale_locked(self, now: float) -> None:
        stale = []
        for actor_id, session in self._sessions.items():
            age = now - session["created_at"]
            idle = now - session["last_active"]
            if age > self._session_ttl or idle > self._inactivity_timeout:
                stale.append(actor_id)
        for actor_id in stale:
            del self._sessions[actor_id]

    def get_active_count(self) -> int:
        """Return the number of currently active sessions."""
        with self._lock:
            return len(self._sessions)

    # ── FastMCP Middleware integration ────────────────────────────────────

    def as_middleware(self) -> SessionTrackingMiddleware:
        """Wrap this manager as a FastMCP Middleware for automatic session tracking."""
        return SessionTrackingMiddleware(self)


class SessionTrackingMiddleware(Middleware):
    """FastMCP middleware that auto-tracks actor sessions on every tool call.

    Replaces manual ``state.session_manager.touch(actor, request_id)`` calls
    in every tool.  Attach via ``mcp.add_middleware(manager.as_middleware())``.
    """

    def __init__(self, manager: SessionManager) -> None:
        self._manager = manager

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next,
    ) -> ToolResult:
        fmcp_ctx = context.fastmcp_context
        actor = fmcp_ctx.client_id or "anonymous" if fmcp_ctx else "anonymous"
        request_id = fmcp_ctx.request_id or "unknown" if fmcp_ctx else "unknown"
        self._manager.touch(actor, request_id)
        return await call_next(context)
