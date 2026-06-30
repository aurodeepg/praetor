"""A tiny *real* MCP server — the agent Praetor will govern in connect_mcp.py.

This is not a Praetor component; it's a stand-in for "some MCP server you don't own."
It speaks the real Model Context Protocol over stdio (via FastMCP), exposing two tools.
The driver script launches it as a subprocess and governs every call to it through the
gateway — Praetor never sees inside it, exactly like a third-party server.

Run directly only if you want to poke it with an MCP client; normally connect_mcp.py
spawns it for you. Requires the `mcp` extra: pip install -e ".[mcp]"
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files-demo")


@mcp.tool()
def read_file(target: str) -> str:
    """Read a file. `target` is the path being read."""
    return f"[contents of {target}] — auth log lines, redacted for the demo"


@mcp.tool()
def delete_file(target: str) -> str:
    """Delete a file. `target` is the path being deleted (destructive)."""
    return f"deleted {target}"


if __name__ == "__main__":
    mcp.run()  # stdio transport
