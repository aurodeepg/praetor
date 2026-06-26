"""Scope matching — does a warrant authorize a given call?

Three pure checks, trivial to test and reason about:

1. ``action_matches``   — the call's action falls under the warrant's capability.
2. ``excluded``         — the action isn't on the warrant's explicit deny-list.
3. ``target_in_scope``  — the call's target is within the warrant's scope.

A warrant authorizes a call iff (1) and (3) hold and (2) does not. This layer is
deliberately time-agnostic: expiry and revocation are validity checks the gateway
applies separately (see :meth:`praetor.models.Warrant.is_active`).
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from praetor.models import ToolCall, Warrant

# Use fnmatchcase (not fnmatch): plain fnmatch case-normalizes via os.path.normcase,
# which lowercases on Windows. An authorization decision must be byte-for-byte
# deterministic across platforms, so glob matching here is always case-sensitive.


def _under(action: str, pattern: str) -> bool:
    """True if ``action`` matches ``pattern`` exactly, as a glob, or as a dotted/
    colon-delimited namespace prefix (so ``net.quarantine`` covers
    ``net.quarantine.isolate-host``)."""
    if action == pattern:
        return True
    if ("*" in pattern or "?" in pattern) and fnmatchcase(action, pattern):
        return True
    return action.startswith(pattern + ".") or action.startswith(pattern + ":")


def action_matches(action: str, capability: str) -> bool:
    """The granted capability covers the attempted action."""
    return _under(action, capability)


def excluded(action: str, excludes: list[str]) -> bool:
    """The action is explicitly denied by the warrant, even if the capability matches."""
    return any(_under(action, ex) for ex in excludes)


def target_in_scope(target: str | None, scope: dict[str, str]) -> bool:
    """The call's target satisfies the warrant's scope.

    An empty scope (or no ``target`` constraint) means unconstrained. A ``target``
    constraint is a glob the call's target must match.
    """
    allowed = scope.get("target")
    if not allowed:
        return True
    if target is None:
        return False
    return target == allowed or fnmatchcase(target, allowed)


def warrant_authorizes(warrant: Warrant, call: ToolCall) -> tuple[bool, str]:
    """Return ``(authorized, reason)``. The reason is human-readable for the audit trail."""
    if not action_matches(call.action, warrant.capability):
        return False, f"action {call.action} ∉ capability {warrant.capability}"
    if excluded(call.action, warrant.excludes):
        return False, f"{call.action} is on the warrant's exclude-list — escalation blocked"
    if not target_in_scope(call.target, warrant.scope):
        return False, f"target {call.target} outside scope {warrant.scope.get('target')}"
    return True, "verb + target both match the warrant"
