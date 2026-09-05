"""AI gates — feature availability and the agent's authorization boundary.

The DomainAuthorization gate the manual API enforces lives at the API layer
only; create_subscan_session/run_workflow do no auth check. The agent
therefore re-implements the exact same rule here, at its own tool-dispatch
boundary: an active tool set requires a DomainAuthorization row. This module
must stay the single choke point every agent-initiated subscan passes through.
"""

import logging

from . import client
from .models import AISettings

logger = logging.getLogger(__name__)


def is_ai_active() -> bool:
    """True only when credentials are configured AND the operator enabled the
    feature AND current-version consent is recorded. Checked at every entry
    point, never cached across tasks (revocation is immediate — D-013 4d)."""
    if not client.is_configured():
        return False
    cfg = AISettings.get()
    return cfg.enabled and cfg.consent_current


def gate_subscan_tools(domain: str, tools: list[str]) -> tuple[list[str], str]:
    """Validate an agent-proposed tool list. Returns (allowed_tools, denial_reason).

    Unknown tools are dropped first. If the remaining set is not fully passive
    (is_passive_tool_set is conservative: empty or unknown => active), it
    requires a DomainAuthorization row for the domain — the same rule the
    manual subscan API enforces. No authorization => ([], reason).
    """
    from apps.core.domains.models import DomainAuthorization
    from apps.core.workflows.registry import get_tool_runners, is_passive_tool_set

    known = [t for t in tools if t in get_tool_runners()]
    dropped = set(tools) - set(known)
    if dropped:
        logger.warning("ai: agent proposed unknown tools %s — dropped", sorted(dropped))
    if not known:
        return [], "no known tools in the proposed set"

    if not is_passive_tool_set(known):
        authorized = DomainAuthorization.objects.filter(domain__name=domain).exists()
        if not authorized:
            return [], "active tools require DomainAuthorization for this domain"

    return known, ""
