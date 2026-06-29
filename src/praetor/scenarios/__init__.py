"""Replayable scenarios that exercise the gateway end to end.

Each scenario drives the *real* gateway — every allow/deny is a live verdict, not a
script. They are deliberately backend-agnostic: roles are mock-backed here but named
for the real third-party agents they represent (Claude Agent SDK, OpenAI Agents SDK,
Postgres MCP, Copilot Studio), and swap to HTTP/MCP/provider adapters with no change
to the replay.

``SCENARIOS`` maps a CLI-friendly key to a :class:`~praetor.scenarios.base.Scenario`
subclass so the CLI (and tests) can select one by name.
"""

from praetor.scenarios.base import Frame, LedgerRow, Scenario
from praetor.scenarios.cross_framework import CrossFramework
from praetor.scenarios.least_privilege import LeastPrivilege
from praetor.scenarios.phase2 import Phase2
from praetor.scenarios.recompose import Recompose
from praetor.scenarios.seed import seed_war_room_agents, war_room_adapters
from praetor.scenarios.war_room import WarRoom, play

#: CLI key -> Scenario subclass. The war room is the headline (default).
SCENARIOS: dict[str, type[Scenario]] = {
    "war-room": WarRoom,
    "least-privilege": LeastPrivilege,
    "cross-framework": CrossFramework,
    "recompose": Recompose,
    "phase2": Phase2,
}

__all__ = [
    "SCENARIOS",
    "Frame",
    "LedgerRow",
    "Scenario",
    "WarRoom",
    "LeastPrivilege",
    "CrossFramework",
    "Recompose",
    "Phase2",
    "play",
    "seed_war_room_agents",
    "war_room_adapters",
]
