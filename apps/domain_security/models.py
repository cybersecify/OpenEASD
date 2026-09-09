"""DomainSecurity finding storage has moved to apps.core.data.findings.Finding.

This module is intentionally empty — the old DomainFinding model has been
removed in favour of the unified Finding model. Keeping the app registered
so migration history (for dropping the old table) stays linear.
"""
