"""Tool registry — auto-discovers tools from AppConfig.tool_meta.

Each tool app declares metadata in its AppConfig:

    class MyToolConfig(AppConfig):
        name = "apps.my_tool"
        tool_meta = {
            "label": "My Tool",
            "runner": "apps.my_tool.scanner.run_my_tool",
            "phase": 6,
            "requires": ["naabu"],
            "produces_findings": True,
        }

The registry is populated at Django startup by scanning all installed apps.
Core modules read from the registry instead of hardcoded dicts.
"""

import logging

from django.apps import apps

logger = logging.getLogger(__name__)

_registry: dict[str, dict] = {}
_initialized = False


def _discover_tools():
    """Scan all installed AppConfigs for tool_meta and populate registry."""
    global _initialized
    if _initialized:
        return

    for app_config in apps.get_app_configs():
        meta = getattr(app_config, "tool_meta", None)
        if meta is None:
            continue

        tool_name = app_config.label
        _registry[tool_name] = {
            "label": meta.get("label", app_config.verbose_name or tool_name),
            "runner": meta["runner"],
            "phase": meta.get("phase", 99),
            "phase_group": meta.get("phase_group", ""),
            "requires": meta.get("requires", []),
            "produces_findings": meta.get("produces_findings", False),
            "core": meta.get("core", False),
            # active=True means the tool sends packets to the target's own
            # systems (port scans, HTTP/TLS/SSH probes, crawlers, vuln templates)
            # and therefore requires DomainAuthorization. active=False means the
            # tool uses only public / third-party data (CT logs, archives, DNS
            # resolvers, cloud-provider APIs, threat feeds) and never touches the
            # target. Default True is deliberate: an unclassified tool is treated
            # as active, so a missing flag can never let a scanner probe an
            # unauthorized target. (Classification idea seeded by vennela's parked
            # ACTIVE_SCANNING_ENABLED work, commit 4e47c0c.)
            "active": meta.get("active", True),
        }
        logger.debug(f"[registry] Registered tool: {tool_name}")

    _initialized = True
    logger.info(f"[registry] {len(_registry)} tools registered")


def get_registry() -> dict[str, dict]:
    """Return the tool registry, initializing on first call."""
    _discover_tools()
    return _registry


def get_tool_choices() -> list[tuple[str, str]]:
    """Dynamic TOOL_CHOICES for model fields and forms. Excludes core tools."""
    reg = get_registry()
    return sorted(
        [(name, info["label"]) for name, info in reg.items() if not info.get("core")],
        key=lambda x: reg[x[0]]["phase"],
    )


def get_tool_runners() -> dict[str, str]:
    """Dynamic _TOOL_RUNNERS: tool_name → "module.path.function_name"."""
    return {name: info["runner"] for name, info in get_registry().items()}


def get_tool_phases() -> dict[str, int]:
    """Dynamic TOOL_PHASE: tool_name → phase number."""
    return {name: info["phase"] for name, info in get_registry().items()}


def get_tool_requires() -> dict[str, list[str]]:
    """Dynamic TOOL_REQUIRES: tool_name → list of required upstream tools."""
    return {name: info["requires"] for name, info in get_registry().items()}


def get_tool_produces_findings() -> dict[str, bool]:
    """Dynamic map: tool_name → whether the tool writes to the Finding table."""
    return {name: info["produces_findings"] for name, info in get_registry().items()}


def get_tool_active() -> dict[str, bool]:
    """Dynamic map: tool_name → True if the tool actively probes the target.

    Active tools send packets to the target's own infrastructure and require
    DomainAuthorization. Passive tools (active=False) use only public /
    third-party sources and need no authorization.
    """
    return {name: info["active"] for name, info in get_registry().items()}


def is_passive_tool_set(tools) -> bool:
    """True only if EVERY tool in `tools` is passive (active=False).

    Conservative: an empty set is not passive (nothing to authorize, but also
    nothing to run — callers treat it as needing auth), and an unknown tool
    defaults to active. A single active tool makes the whole set active.
    """
    active_map = get_tool_active()
    tools = list(tools)
    if not tools:
        return False
    return all(not active_map.get(t, True) for t in tools)


def get_tool_phase_groups() -> dict[str, str]:
    """Dynamic map: tool_name → phase_group label."""
    return {name: info["phase_group"] for name, info in get_registry().items()}


def get_source_choices() -> list[tuple[str, str]]:
    """Dynamic SOURCE_CHOICES for Finding.source field."""
    reg = get_registry()
    return [
        (name, info["label"]) for name, info in reg.items()
        if info["produces_findings"]
    ]
