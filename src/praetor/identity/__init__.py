"""Identity backends — the gateway issues every agent a verifiable identity.

M2 ships the ``local`` keypair backend (RS256 JWT signing). Additional backends
(e.g. SPIFFE/SPIRE) can slot in behind the same :class:`IdentityProvider` contract.
"""

from praetor.identity.base import IdentityProvider
from praetor.identity.local import LocalIdentityProvider

__all__ = ["IdentityProvider", "LocalIdentityProvider"]
