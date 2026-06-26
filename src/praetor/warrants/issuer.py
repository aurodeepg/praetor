"""Warrant issuance — mint a scoped, time-boxed, signed grant.

The issuer turns an authorization decision into a concrete, verifiable artifact: it
stamps the timestamps, signs the claims with the identity backend, and hands back a
:class:`~praetor.models.Warrant` ready to drop into the ledger.
"""

from __future__ import annotations

from praetor.identity.base import IdentityProvider
from praetor.models import Warrant


class WarrantIssuer:
    def __init__(self, identity: IdentityProvider) -> None:
        self._identity = identity

    def mint(
        self,
        *,
        subject: str,
        on_behalf_of: str,
        capability: str,
        scope: dict[str, str] | None = None,
        excludes: list[str] | None = None,
        ttl: float,
        now: float,
        trust: str = "unverified",
        reason: str = "",
    ) -> Warrant:
        warrant = Warrant(
            subject=subject,
            on_behalf_of=on_behalf_of,
            capability=capability,
            scope=scope or {},
            excludes=excludes or [],
            trust=trust,
            reason=reason,
            issued_at=now,
            expires_at=now + ttl,
        )
        # The token carries `exp` even though the gateway enforces liveness via the
        # ledger (not the token) — defense in depth: an out-of-band verifier that does
        # check exp will still reject a stale token.
        warrant.token = self._identity.sign(
            {
                "sub": subject,
                "obo": on_behalf_of,
                "cap": capability,
                "scope": warrant.scope,
                "excl": warrant.excludes,
                "wid": warrant.wid,
                "exp": int(warrant.expires_at),
            }
        )
        return warrant
