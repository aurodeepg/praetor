"""Seed a gateway with the war-room agents.

Registers the anchor incident-response agents as in-process mock adapters so the
capability-matcher and ``dispatch`` have a real registry + executors to work against.
Swap any of these ``MockAdapter``s for a real adapter (HTTP, MCP, a provider) to
onboard an actual agent — the gateway can't tell the difference.
"""

from __future__ import annotations

from praetor.adapters.mock import MockAdapter
from praetor.gateway import Gateway
from praetor.models import Capability


def war_room_adapters() -> list[MockAdapter]:
    return [
        MockAdapter(
            "containment",
            trust="internal · high-priv",
            description="Isolates compromised hosts. High privilege, tightly scoped.",
            capabilities=[
                Capability(name="net.isolate", description="Quarantine a host from the network",
                           targets="host:*"),
            ],
        ),
        MockAdapter(
            "forensics",
            trust="internal · read-only",
            description="Reads and inspects logs. Never writes or remediates.",
            capabilities=[
                Capability(name="logs.read", description="Read system and application logs",
                           targets="logs:*"),
            ],
        ),
        MockAdapter(
            "threat-intel",
            trust="3rd-party · prob.",
            description="Enriches indicators of compromise via a third-party feed.",
            capabilities=[
                Capability(name="intel.lookup", description="Look up / enrich an indicator"),
            ],
        ),
    ]


def seed_war_room_agents(gateway: Gateway) -> dict[str, str]:
    """Register the roster; return a ``name -> identity id`` map for convenience."""
    return {a.name: gateway.register(a).id for a in war_room_adapters()}
