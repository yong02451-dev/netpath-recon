from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Tier = Literal["passive", "active"]
Status = Literal["ok", "error", "skipped"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Observation(BaseModel):
    """One plain-language fact a module noticed. No severity, by design."""
    text: str
    category: str
    evidence: str | None = None
    source: str
    tier: Tier


class ModuleResult(BaseModel):
    """The envelope every module returns. The dashboard reads only this."""
    module: str
    name: str
    tier: Tier
    status: Status
    source: str
    collected_at: str = Field(default_factory=utc_now)
    duration_ms: float | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    observations: list[Observation] = Field(default_factory=list)
    error: str | None = None
    note: str | None = None  # e.g. why a module was skipped