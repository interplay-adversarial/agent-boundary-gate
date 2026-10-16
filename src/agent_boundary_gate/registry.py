"""Explicit support inventory. Planned integrations never advertise working adapters."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AdapterInfo:
    id: str
    role: str
    status: str
    capabilities: tuple[str, ...]


ADAPTERS = (
    AdapterInfo("openshell", "boundary", "implemented-unqualified", ("network-egress",)),
    AdapterInfo("loopback", "boundary", "simulation-only", ("network-egress",)),
    AdapterInfo("loopback", "agent", "simulation-only", ("tool-authorization",)),
    AdapterInfo("opencode", "agent", "implemented-unqualified", ("tool-authorization",)),
    AdapterInfo("openclaw", "agent", "planned", ()),
)


def inventory() -> list[dict[str, object]]:
    return [asdict(adapter) for adapter in ADAPTERS]
