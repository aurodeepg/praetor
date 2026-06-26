"""The live warrant ledger — the single source of truth for who holds authority.

The ledger is what makes revocation an *architectural* win rather than a hard
problem: there's one place to flip a bit, and because every call is checked against
it, a revoked warrant is dead on the very next call. No outstanding token to chase
across services.
"""

from __future__ import annotations

from praetor.models import RevokeCause, Warrant


class WarrantLedger:
    def __init__(self) -> None:
        self._warrants: dict[str, Warrant] = {}

    def issue(self, warrant: Warrant) -> Warrant:
        self._warrants[warrant.wid] = warrant
        return warrant

    def get(self, wid: str) -> Warrant | None:
        return self._warrants.get(wid)

    def revoke(
        self,
        wid: str,
        now: float,
        cause: RevokeCause = "manual",
        reason: str = "",
    ) -> Warrant | None:
        """Flip a warrant to revoked. Returns it, or None if unknown/already revoked."""
        w = self._warrants.get(wid)
        if w is None or w.revoked:
            return None
        w.revoked = True
        w.revoked_at = now
        w.revoke_cause = cause
        w.revoke_reason = reason
        return w

    def expire_due(self, now: float) -> list[Warrant]:
        """Mark TTL-elapsed warrants revoked (cause=ttl); return the ones just expired."""
        expired: list[Warrant] = []
        for w in self._warrants.values():
            if not w.revoked and now >= w.expires_at:
                w.revoked = True
                w.revoked_at = w.expires_at
                w.revoke_cause = "ttl"
                w.revoke_reason = "TTL elapsed — authority auto-revoked"
                expired.append(w)
        return expired

    def active(self, now: float) -> list[Warrant]:
        return [w for w in self._warrants.values() if w.is_active(now)]

    def for_subject(self, subject: str, now: float) -> list[Warrant]:
        return [w for w in self.active(now) if w.subject == subject]

    def all(self) -> list[Warrant]:
        return list(self._warrants.values())
