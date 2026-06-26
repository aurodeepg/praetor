"""The identity-provider contract.

A backend issues verifiable agent identities and signs/verifies the JWT tokens that
carry warrant claims. We deliberately do *not* roll our own crypto — backends wrap
standard JWT signing (M2's local keypair) or, later, standard workload identity
(SPIFFE).
"""

from __future__ import annotations

import abc
from typing import Any

from praetor.models import AgentIdentity


class IdentityProvider(abc.ABC):
    """Issues identities and signs/verifies warrant tokens."""

    #: JWS algorithm used for warrant tokens (e.g. "RS256").
    jwt_alg: str = "RS256"

    @abc.abstractmethod
    def issue_identity(self, name: str, trust: str = "unverified") -> AgentIdentity:
        """Mint a verifiable identity for an agent."""

    @abc.abstractmethod
    def sign(self, claims: dict[str, Any]) -> str:
        """Sign warrant claims, returning a compact JWT."""

    @abc.abstractmethod
    def verify(self, token: str) -> dict[str, Any]:
        """Verify a token's signature and return its claims.

        Raises on an invalid signature. Note: a valid signature proves the token was
        *issued* by this gateway — it does **not** prove the warrant is still live.
        Revocation and expiry are checked separately (against the ledger, in a later
        milestone), which is what makes revocation instant.
        """

    @abc.abstractmethod
    def public_pem(self) -> str | None:
        """Public key material for out-of-band verification, if the backend has one."""
