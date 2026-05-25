from __future__ import annotations

import threading
import time


class SessionManager:
    """Tracks actor sessions with TTL, inactivity timeout, and concurrency caps."""

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
        self._sessions: dict[str, dict[str, float]] = {}

    def touch(self, actor_id: str, request_id: str) -> None:
        """Register activity for an actor, updating their session timestamp.

        Enforces concurrent session limit by removing oldest sessions if exceeded.
        """
        now = time.time()
        with self._lock:
            # Clean expired sessions
            self._expire_stale_locked(now)

            if actor_id not in self._sessions:
                # Enforce concurrent session cap
                if len(self._sessions) >= self._concurrent_limit:
                    oldest = min(
                        self._sessions.keys(),
                        key=lambda k: self._sessions[k].get("last_active", 0),
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
