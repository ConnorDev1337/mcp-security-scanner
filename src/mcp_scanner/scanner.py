"""End-to-end scan: load inputs, optionally introspect, analyze, check pins."""

from __future__ import annotations

import datetime as _dt
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import engine, loader, manifest
from .introspect import IntrospectionError, introspect
from .jsonloc import SourceDocument
from .models import Finding, Notice, ServerConfig, ServerInventory, Severity
from .pinning import PinError, PinOutcome, PinStore, check_pins


@dataclass
class ScanOptions:
    configs: list[str] = field(default_factory=list)
    discover: bool = False
    tool_manifests: list[str] = field(default_factory=list)
    introspect: bool = False
    timeout: float = 20.0
    pins: Path | None = None
    update_pins: bool = False
    frozen_pins: bool = False


@dataclass
class ScanReport:
    findings: list[Finding]
    servers: list[ServerConfig]
    inventories: list[ServerInventory]
    documents: list[SourceDocument]
    notices: list[Notice]
    pins: PinOutcome | None
    started_at: str
    finished_at: str

    def counts(self, findings: list[Finding] | None = None) -> dict[str, int]:
        """Count ``findings`` (default: all) per severity label, most severe first."""
        tally = Counter(f.severity for f in (self.findings if findings is None else findings))
        return {s.label: tally.get(s, 0) for s in sorted(Severity, reverse=True)}

    @property
    def tool_count(self) -> int:
        return sum(len(inv.tools) for inv in self.inventories)


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


Introspector = Callable[[ServerConfig, float], ServerInventory]


def run_scan(options: ScanOptions, introspector: Introspector | None = None) -> ScanReport:
    """Run a complete scan as described by ``options``.

    Unreadable inputs and failed introspection are reported as notices instead of
    raising. The pin file is saved when pinning changed it. ``introspector``
    replaces :func:`~mcp_scanner.introspect.introspect`, e.g. with a stub.
    """
    started = _now()
    notices: list[Notice] = []

    config_paths: list[str | Path] = list(options.configs)
    if options.discover or (not options.configs and not options.tool_manifests):
        discovered = loader.discover()
        config_paths.extend(path for _, path in discovered)
        if not discovered and not options.configs:
            notices.append(Notice("warning", "no MCP client configuration found on this machine"))
    loaded = loader.load_configs(config_paths)
    notices.extend(loaded.notices)
    documents = list(loaded.documents)

    inventories: list[ServerInventory] = []
    for spec in options.tool_manifests:
        found, manifest_notices = manifest.load_manifest(spec)
        inventories.extend(found)
        notices.extend(manifest_notices)
        documents.extend({id(i.source): i.source for i in found if i.source}.values())

    if options.introspect:
        run = introspector or (lambda server, timeout: introspect(server, timeout))
        known = {inv.server for inv in inventories}
        for server in loaded.servers:
            if server.name in known:
                continue
            if server.raw.get("disabled") is True:
                notices.append(Notice("note", f"{server.name}: disabled, not introspected"))
                continue
            try:
                inventories.append(run(server, options.timeout))
                known.add(server.name)
            except IntrospectionError as exc:
                source = server.source.path if server.source else None
                notices.append(
                    Notice("warning", f"{server.name}: introspection failed: {exc}", source)
                )

    findings = engine.analyze(loaded.servers, inventories, documents)

    outcome: PinOutcome | None = None
    if options.pins is not None:
        try:
            store = PinStore.load(options.pins)
            outcome = check_pins(
                store,
                loaded.servers,
                inventories,
                update=options.update_pins,
                frozen=options.frozen_pins,
            )
            if outcome.dirty:
                store.save()
            findings = engine.finalize([*findings, *outcome.findings])
        except (PinError, OSError) as exc:
            notices.append(Notice("error", f"pinning skipped: {exc}", str(options.pins)))

    return ScanReport(
        findings=findings,
        servers=loaded.servers,
        inventories=inventories,
        documents=documents,
        notices=notices,
        pins=outcome,
        started_at=started,
        finished_at=_now(),
    )
