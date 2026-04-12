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
            "requires": meta.get("requires", []),
            "produces_findings": meta.get("produces_findings", False),
        }
        logger.debug(f"[registry] Registered tool: {tool_name}")

    _initialized = True
    logger.info(f"[registry] {len(_registry)} tools registered")


def get_registry() -> dict[str, dict]:
    """Return the tool registry, initializing on first call."""
    _discover_tools()
    return _registry


def get_tool_choices() -> list[tuple[str, str]]:
    """Dynamic TOOL_CHOICES for model fields and forms."""
    reg = get_registry()
    return sorted(
        [(name, info["label"]) for name, info in reg.items()],
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


def get_source_choices() -> list[tuple[str, str]]:
    """Dynamic SOURCE_CHOICES for Finding.source field."""
    reg = get_registry()
    return [
        (name, info["label"]) for name, info in reg.items()
        if info["produces_findings"]
    ]
