"""Replayable scenarios that exercise the gateway end to end.

The war room drives a Phase-1 incident through the *real* gateway — every allow/deny
is a live verdict, not a script.
"""

from praetor.scenarios.seed import seed_war_room_agents, war_room_adapters
from praetor.scenarios.war_room import Frame, WarRoom, play

__all__ = ["Frame", "WarRoom", "play", "seed_war_room_agents", "war_room_adapters"]
