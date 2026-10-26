"""check_id backfill — give every finding a stable per-rule identity.

`check_id` identifies the KIND of check (rule), independent of the human `title`
(which gets reworded over time). It is the cross-scan identity the persistent
`Issue` register keys on (see `issues/rollup`).

Most tools ("granular": 1 check_type : 1 rule — tls_checker, web_checker,
ssh_checker, and the single-check_type tools) don't set it explicitly; this
backfill derives `"{source}:{check_type}"` for them. The coarse tools
(domain_security, domain_probe) and the CVE/secret tools (nmap, nuclei,
nuclei_network, js_secrets, github_secrets) set an explicit per-rule check_id at
construction, so this only fills the rows still blank — it never overwrites them.

Called from `_finalize_session` before the issue rollup. Idempotent: re-running
converges (only blank rows are touched).
"""

from django.db.models import CharField, Value
from django.db.models.functions import Concat


def backfill_check_ids(session) -> int:
    """Set `check_id = "{source}:{check_type}"` for this session's findings that
    didn't set one explicitly. Returns the number of rows updated."""
    from .models import Finding

    return Finding.objects.filter(session=session, check_id="").update(
        check_id=Concat("source", Value(":"), "check_type", output_field=CharField())
    )
