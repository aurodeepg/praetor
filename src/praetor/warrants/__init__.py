"""Warrants — Praetor's unit of authority and the logic that reasons about it.

Pure scope matching (does a warrant cover a call?), the signing issuer (mint a
verifiable grant), and the live ledger (the single source of truth that makes
revocation instant).
"""

from praetor.warrants.issuer import WarrantIssuer
from praetor.warrants.ledger import WarrantLedger
from praetor.warrants.scope import (
    action_matches,
    excluded,
    target_in_scope,
    warrant_authorizes,
)

__all__ = [
    "WarrantIssuer",
    "WarrantLedger",
    "action_matches",
    "excluded",
    "target_in_scope",
    "warrant_authorizes",
]
