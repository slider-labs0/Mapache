"""
opsec_routing.py - hybrid OPSEC routing policy (feature O)

The hybrid middle ground between "all-local" and "freely-cloud". Feature G let
cloud models into the routing pool (warn-don't-block); O decides *which work is
allowed to leave the machine*. Even when `--allow-cloud` is on and the strategy
would send a turn to a cloud model, a **sensitive operation is pinned to a local
model** so captured data (credentials, loot, proprietary code/binaries, target
PII, fragile-target interactions) never crosses the wire.

Where it acts: the *delegation boundary* (feature P). The lead's own cloud use is
the operator's explicit `--allow-cloud` choice and already carries the G warning;
O governs the per-operator sub-agents, which is exactly where the killchain
splits into "early/public recon" (cloud-eligible) vs "exploitation/loot"
(local-only). Two signals pin a child local:

  1. an OPSEC-sensitive operator role (`Operator.prefer_local`), and
  2. a sensitive *shared state* - once credentials have been captured, every
     later delegation carries them in context, so it stays on-box regardless of
     which operator runs it.

The policy is pure logic (no model/provider deps) so it is trivially testable;
the controller turns a `pin_local` decision into a local-pinned model via
`RoutedModel.local_variant()`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class OpsecDecision:
    pin_local: bool
    reason: str


class OpsecPolicy:
    """Decides when a delegated operation must stay on a local model.

    `allow_cloud=False` makes every decision a no-op (`pin_local=False`): the
    routing engine is already local-only, so there is nothing to pin. The policy
    only has teeth once cloud models are in play.
    """

    def __init__(self, allow_cloud: bool = False, pin_sensitive: bool = True) -> None:
        self.allow_cloud = allow_cloud
        # Escape hatch: an operator who explicitly accepts cloud for everything
        # can disable pinning (the G warning still fires per cloud call).
        self.pin_sensitive = pin_sensitive

    def operator_is_sensitive(self, operator: Any) -> bool:
        """An operator is sensitive unless it is explicitly cloud-eligible.

        Defaults to sensitive (fail-closed) for anything without the attribute.
        """
        if operator is None:
            return False
        return bool(getattr(operator, "prefer_local", True))

    def state_is_sensitive(self, attack_state: Any) -> bool:
        """True once secrets have been captured into the shared blackboard.

        Captured credentials are the clear signal that the engagement context now
        carries data that must not leave the host.
        """
        if attack_state is None:
            return False
        return bool(getattr(attack_state, "credentials", None))

    def decide(
        self,
        *,
        operator: Any = None,
        attack_state: Any = None,
    ) -> OpsecDecision:
        if not self.allow_cloud:
            return OpsecDecision(False, "cloud disabled - already local-only")
        if not self.pin_sensitive:
            return OpsecDecision(False, "OPSEC pinning disabled")
        if self.operator_is_sensitive(operator):
            name = getattr(operator, "name", "operator")
            return OpsecDecision(True, f"{name} is an OPSEC-sensitive role - pinned local")
        if self.state_is_sensitive(attack_state):
            return OpsecDecision(
                True, "captured credentials in attack state - pinned local")
        return OpsecDecision(False, "non-sensitive - cloud routing permitted")

    # -- introspection (CLI `/opsec`) ----------------------------------- #

    def explain(self, operators: Optional[list[Any]] = None) -> str:
        if not self.allow_cloud:
            return ("OPSEC routing: cloud disabled - all work runs on local models.")
        if not self.pin_sensitive:
            return ("OPSEC routing: pinning DISABLED - sensitive work may route to "
                    "cloud (per-call cloud warnings still fire).")
        lines = ["OPSEC routing (hybrid): sensitive delegations pinned to local models.",
                 "  Pinned local once credentials are captured, regardless of operator.",
                 ""]
        if operators:
            local = sorted(o.name for o in operators if self.operator_is_sensitive(o))
            cloud = sorted(o.name for o in operators if not self.operator_is_sensitive(o))
            lines.append(f"  Cloud-eligible operators : {', '.join(cloud) or '(none)'}")
            lines.append(f"  Local-pinned operators   : {', '.join(local) or '(none)'}")
        return "\n".join(lines)
