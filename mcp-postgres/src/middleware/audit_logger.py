from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any


class AuditLogger:
    """Structured JSON audit logger writing to an append-only file."""

    def __init__(self, file_path: str = "/var/log/mcp/audit.log"):
        self._file_path = file_path
        self._lock = threading.Lock()
        # Ensure directory exists
        dirname = os.path.dirname(file_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)

    def log_event(
        self,
        *,
        request_id: str,
        actor: str,
        tool: str,
        instance: str,
        sql: str,
        decision: str,
        latency_ms: int,
        rows: int,
        error_code: str | None = None,
        auth_mode: str | None = None,
        auth_subject: str | None = None,
        privilege_level: str | None = None,
        group_match_result: dict[str, Any] | None = None,
    ) -> None:
        """Write a structured JSON audit event to the log file."""
        sql_hash = hashlib.sha256(sql.encode("utf-8")).hexdigest()[:12]
        entry = {
            "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_id": request_id,
            "actor": actor,
            "tool": tool,
            "instance": instance,
            "sql_hash": sql_hash,
            "decision": decision,
            "latency_ms": latency_ms,
            "rows": rows,
            "error_code": error_code,
            "auth_mode": auth_mode,
            "auth_subject": auth_subject,
            "privilege_level": privilege_level,
        }
        # Only include group_match_result if it has content
        if group_match_result:
            entry["group_match_result"] = group_match_result

        with self._lock:
            try:
                with open(self._file_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True) + "\n")
            except Exception:
                # Audit logging failures should never crash the server
                pass

    def rotate(self, archive_path: str) -> None:
        """Archive the current log file and start a new one."""
        with self._lock:
            if os.path.exists(self._file_path):
                os.rename(self._file_path, archive_path)
