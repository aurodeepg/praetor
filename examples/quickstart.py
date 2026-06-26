"""Praetor quickstart — the whole Phase-1 loop in one runnable script.

    register agents → match (propose least-privilege) → issue a scoped warrant →
    dispatch an allowed call → deny one out of scope → deny an escalation →
    revoke → watch the next call get cut off → read the audit trail.

Run it:  python examples/quickstart.py

Everything here is deterministic and free — no model calls, no network. The verdicts
are produced by the real gateway, not scripted.
"""

from __future__ import annotations

from praetor import Gateway
from praetor.adapters import MockAdapter
from praetor.models import Capability, ToolCall


def banner(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m")


def show(decision, result=None) -> None:
    mark = "✓ ALLOW" if decision.allow else "✗ DENY "
    line = f"  {mark}  {decision.reason}"
    if result is not None and result.output is not None:
        line += f"\n           ↳ {result.output}"
    print(line)


def main() -> None:
    gw = Gateway()  # local RSA identity + deterministic matcher, $0

    banner("1. Admit an incident-response team (identity only — no authority yet)")
    containment = MockAdapter(
        "containment",
        [Capability(name="net.isolate", description="isolate a host", targets="host:*")],
        trust="internal",
    )
    forensics = MockAdapter(
        "forensics",
        [Capability(name="logs.read", description="read and inspect logs", targets="logs:*")],
        trust="internal",
    )
    intel = MockAdapter(
        "threat-intel",
        [Capability(name="intel.lookup", description="enrich an indicator")],
        trust="3rd-party · prob.",
    )
    for adapter in (containment, forensics, intel):
        ident = gw.register(adapter)
        print(f"  registered {adapter.name:<13} trust={adapter.trust!r:<18} id={ident.id[:24]}…")

    banner("2. Match the requirement to a capability — the cheap AI seed")
    requirement = "isolate the compromised host host-9"
    proposal = gw.match(requirement, on_behalf_of="incident://ir-4821").proposal
    print(f"  requirement: {requirement!r}")
    print(f"  proposal:    {proposal.agent} · {proposal.capability} · scope={proposal.scope}")
    print(f"  rationale:   {proposal.rationale}")

    banner("3. Approve → issue a scoped, time-boxed, signed warrant (least privilege)")
    warrant = gw.issue_warrant(
        subject=proposal.agent, on_behalf_of="incident://ir-4821",
        capability=proposal.capability, scope=proposal.scope, excludes=["fs.write", "remediate"],
        ttl=600, trust="internal", reason="contain lateral movement on host-9",
    )
    cid = gw._identities["containment"].id
    print(f"  warrant {warrant.wid[:18]}…  cap={warrant.capability} scope={warrant.scope}")
    print(f"  signed token present: {bool(warrant.token)}  (carries exp={int(warrant.expires_at)})")

    banner("4. Dispatch through the gateway — it enforces the warrant, then invokes the agent")
    show(*gw.dispatch(ToolCall(agent=cid, action="net.isolate", target="host-9")))

    banner("5. The same agent reaches beyond its scope — the gateway blocks it before it runs")
    print("  → tries to isolate a host it wasn't scoped for (host-prod-1):")
    show(*gw.dispatch(ToolCall(agent=cid, action="net.isolate", target="host-prod-1")))
    print("  → tries to escalate to a destructive action it was explicitly denied (fs.write):")
    show(*gw.dispatch(ToolCall(agent=cid, action="fs.write", target="host-9")))

    banner("6. Containment is done — revoke. The very next call is denied at the gateway.")
    gw.revoke(warrant.wid, reason="containment complete — drop the privilege")
    show(*gw.dispatch(ToolCall(agent=cid, action="net.isolate", target="host-9")))

    banner("7. The audit trail — every action bound to an identity + its warrant")
    for e in gw.audit.entries():
        bits = [f"{e.kind:<8}"]
        if e.action:
            bits.append(f"action={e.action}")
        if e.decision:
            bits.append(f"→ {e.decision}")
        if e.cause:
            bits.append(f"cause={e.cause}")
        print(f"  {' '.join(bits):<48} {e.detail}")


if __name__ == "__main__":
    main()
