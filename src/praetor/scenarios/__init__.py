"""Replayable scenarios that exercise the gateway end to end.

Each scenario drives the *real* gateway — every allow/deny is a live verdict, not a
script. Roles are mock-backed but named for the real third-party agents they represent.

Scenarios come in two families, matching the project's two phases:

* **Phase 1** (`phase1-*`) — deterministic identity/authority core: warrants are issued
  on explicit beats; the scenario shows scope, escalation-blocked, revoke, expiry.
* **Phase 2** (`phase2-*`) — the orchestrator *decides* team composition (fit = capability
  × trust × budget × availability) and recomposes on its own (perf swap, budget gate).

``SCENARIOS`` maps a CLI/UI key to a :class:`~praetor.scenarios.base.Scenario` subclass.
"""

from praetor.scenarios.base import Frame, LedgerRow, Scenario
from praetor.scenarios.cross_framework import CrossFramework
from praetor.scenarios.least_privilege import LeastPrivilege
from praetor.scenarios.phase2_cross_framework import Phase2CrossFramework
from praetor.scenarios.phase2_least_privilege import Phase2LeastPrivilege
from praetor.scenarios.phase2_war_room import Phase2WarRoom
from praetor.scenarios.seed import seed_war_room_agents, war_room_adapters
from praetor.scenarios.war_room import WarRoom, play

#: CLI/UI key -> Scenario subclass. `phase1-war-room` is the headline (default).
SCENARIOS: dict[str, type[Scenario]] = {
    "phase1-war-room": WarRoom,
    "phase1-least-privilege": LeastPrivilege,
    "phase1-cross-framework": CrossFramework,
    "phase2-war-room": Phase2WarRoom,
    "phase2-least-privilege": Phase2LeastPrivilege,
    "phase2-cross-framework": Phase2CrossFramework,
}

__all__ = [
    "SCENARIOS",
    "Frame",
    "LedgerRow",
    "Scenario",
    "WarRoom",
    "LeastPrivilege",
    "CrossFramework",
    "Phase2WarRoom",
    "Phase2LeastPrivilege",
    "Phase2CrossFramework",
    "play",
    "seed_war_room_agents",
    "war_room_adapters",
]
