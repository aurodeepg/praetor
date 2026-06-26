"""Provenance / audit — the trail that proves what each agent was, and wasn't,
allowed to do.

Append-only by contract: entries are recorded and read, never mutated. M3 ships the
in-memory log; a file-backed (sqlite) variant can slot in behind the same API when
persistence config lands.
"""

from __future__ import annotations

import json

from praetor.models import AuditEntry


class AuditLog:
    """In-memory append-only audit log."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> AuditEntry:
        self._entries.append(entry)
        return entry

    def entries(self, limit: int | None = None) -> list[AuditEntry]:
        return self._entries[-limit:] if limit else list(self._entries)

    def for_warrant(self, wid: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.warrant_id == wid]


def export_jsonl(log: AuditLog) -> str:
    """The whole trail as newline-delimited JSON — easy to ship to a SIEM."""
    return "\n".join(json.dumps(e.model_dump()) for e in log.entries())
