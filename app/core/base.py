import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any

from app.core.models import ModuleResult, Observation, Tier

logger = logging.getLogger(__name__)


class ReconModule(ABC):
    """
    The contract for every recon module. A module says who it is and
    implements collect(). run() wraps that in the standard envelope, so
    no module can forget the envelope or let an exception escape.
    """

    id: str                          # short stable name: "dns", "whois", ...
    name: str                        # display name
    description: str
    tier: Tier                       # "passive" or "active"
    source: str                      # where the data comes from
    api_key_env: str | None = None   # env var holding an API key, if one is needed
    accepts: tuple[str, ...] = ("domain", "ip")   # target kinds this module handles

    @abstractmethod
    def collect(self, target: str) -> tuple[dict[str, Any], list[Observation]]:
        """Gather data for `target`. Raise on failure; run() handles it."""

    def has_key(self) -> bool:
        return self.api_key_env is None or bool(os.getenv(self.api_key_env))

    def run(self, target: str) -> ModuleResult:
        started = time.perf_counter()
        try:
            data, observations = self.collect(target)
            status, error = "ok", None
        except Exception as exc:
            logger.exception("Module %s failed for %s", self.id, target)
            data, observations = {}, []
            status, error = "error", f"{type(exc).__name__}: {exc}"

        return ModuleResult(
            module=self.id,
            name=self.name,
            tier=self.tier,
            status=status,
            source=self.source,
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
            data=data,
            observations=observations,
            error=error,
        )

    def skipped(self, reason: str) -> ModuleResult:
        return ModuleResult(
            module=self.id,
            name=self.name,
            tier=self.tier,
            status="skipped",
            source=self.source,
            note=reason,
        )
    
    def observe(self, text: str, category: str, evidence: str | None = None) -> Observation:
        """Build an Observation stamped with this module's source and tier."""
        return Observation(
            text=text,
            category=category,
            evidence=evidence,
            source=self.source,
            tier=self.tier,
        )

    def info(self) -> dict[str, Any]:
        """Metadata the UI uses to build the module picker."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tier": self.tier,
            "source": self.source,
            "accepts": list(self.accepts),
            "needs_key": self.api_key_env is not None,
            "key_configured": self.has_key(),
        }