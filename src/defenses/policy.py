"""Defense policy configuration for C0/C1/C2."""

from __future__ import annotations

from dataclasses import dataclass

from src.common.models import Defense


@dataclass
class DefensePolicy:
    defense: Defense
    runtime_enabled: bool
    pre_gate: bool
    static_validate: bool
    post_gate: bool
    max_regenerations: int
    max_simulated_resource_units: int = 20

    @classmethod
    def for_mode(cls, defense: str | Defense, host_max_regen: int = 8, runtime_max_regen: int = 2) -> "DefensePolicy":
        d = Defense(defense) if isinstance(defense, str) else defense
        if d == Defense.C0:
            return cls(
                defense=d,
                runtime_enabled=False,
                pre_gate=False,
                static_validate=False,
                post_gate=False,
                max_regenerations=host_max_regen,
            )
        if d == Defense.C1:
            return cls(
                defense=d,
                runtime_enabled=True,
                pre_gate=False,
                static_validate=False,
                post_gate=False,
                max_regenerations=runtime_max_regen,
            )
        return cls(
            defense=Defense.C2,
            runtime_enabled=True,
            pre_gate=True,
            static_validate=True,
            post_gate=True,
            max_regenerations=runtime_max_regen,
        )

    def runtime_policy_dict(self) -> dict:
        return {
            "enabled": self.runtime_enabled,
            "max_simulated_resource_units": self.max_simulated_resource_units,
        }
