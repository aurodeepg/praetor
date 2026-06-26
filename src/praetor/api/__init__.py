"""The HTTP gateway — REST + WebSocket over the same `Gateway`, plus the Web UI.

Imported lazily by `praetor serve` so the core install doesn't need FastAPI.
"""

from praetor.api.app import create_app

__all__ = ["create_app"]
