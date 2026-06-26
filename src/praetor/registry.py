"""Capability registry — the menu the gateway scopes warrants against.

Agents advertise capability manifests here. The registry is the authoritative answer
to "what *could* this agent do?" — distinct from a warrant, which is "what *may* it do
right now?". Registration grants no authority; it only makes an agent's capabilities
visible to the matcher.
"""

from __future__ import annotations

from praetor.models import Capability, CapabilityManifest


class CapabilityRegistry:
    def __init__(self) -> None:
        self._manifests: dict[str, CapabilityManifest] = {}

    def register(self, manifest: CapabilityManifest) -> None:
        self._manifests[manifest.agent] = manifest

    def deregister(self, agent: str) -> None:
        self._manifests.pop(agent, None)

    def manifest(self, agent: str) -> CapabilityManifest | None:
        return self._manifests.get(agent)

    def agents(self) -> list[str]:
        return list(self._manifests)

    def all(self) -> list[CapabilityManifest]:
        return list(self._manifests.values())

    def capabilities(self) -> list[tuple[str, Capability]]:
        """Flat ``(agent, capability)`` pairs across every registered agent."""
        return [(m.agent, c) for m in self._manifests.values() for c in m.capabilities]

    def find(self, agent: str, action: str) -> Capability | None:
        """The registered capability under which ``action`` falls, if any."""
        from praetor.warrants.scope import action_matches

        m = self._manifests.get(agent)
        if not m:
            return None
        for cap in m.capabilities:
            if action_matches(action, cap.name):
                return cap
        return None
