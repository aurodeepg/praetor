"""Warrants — Praetor's unit of authority and the logic that reasons about it.

M1 ships the pure scope-matching layer (does a warrant cover a call?). Issuance,
the revocation ledger, and signed tokens arrive in later milestones.
"""

from praetor.warrants.scope import (
    action_matches,
    excluded,
    target_in_scope,
    warrant_authorizes,
)

__all__ = [
    "action_matches",
    "excluded",
    "target_in_scope",
    "warrant_authorizes",
]
