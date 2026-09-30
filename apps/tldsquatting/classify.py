"""Pure classification of a registered lookalike into owned / parked / unrelated /
pre_existing / threat, from signals the collector gathered + a passive target
baseline. No network, no side effects. See docs/specs/2026-09-30-tldsquatting-fp-reduction.md.
"""
from .collector import _split_apex

CLASSES = ("pre_existing", "owned", "parked", "unrelated", "threat")


def _registrable(host: str) -> str:
    """Reduce a hostname (arbitrary subdomain depth) to its registrable domain.

    ``_split_apex`` is built for apex-ish input (at most a leading ``www.``): its
    multi-label-suffix branch already drops arbitrary sub-labels correctly (e.g.
    ``ns1.foo.example.co.uk`` -> ``example.co.uk`` in one shot), but its
    single-label-suffix fallback (plain ``rpartition(".")``) only strips ONE
    label — insufficient for NS hostnames like ``ns1.zoho.com`` which carry an
    extra subdomain label under a plain ``.com``. Try shrinking trailing windows
    of the host until ``_split_apex`` reports a clean (dot-free) registrable
    name, which happens as soon as the multi-label branch fires or the window is
    down to exactly ``name.tld``.
    """
    labels = host.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        name, tld = _split_apex(candidate)
        if tld and "." not in name:
            return f"{name}.{tld}"
    return host


def ns_operators(ns_targets) -> set:
    ops = set()
    for t in ns_targets or []:
        host = str(t).strip().rstrip(".").lower()
        if not host:
            continue
        ops.add(_registrable(host))
    return ops


def classify_lookalike(record, target_ns_ops, target_registrant, target_registrar) -> str:
    if record.get("predates_target"):
        return "pre_existing"

    has_web = bool(record.get("has_a") or record.get("has_aaaa"))

    # owned — positive NS or registrant match (wins over the forcing rules below:
    # an attacker cannot publish on your authoritative NS / under your registrant).
    cand_ns = ns_operators(record.get("ns_targets"))
    ns_match = bool(cand_ns & (target_ns_ops or set()))
    reg = (record.get("registrant") or "").strip().lower()
    reg_match = bool(reg and target_registrant and reg == str(target_registrant).strip().lower())
    if ns_match or reg_match:
        return "owned"

    # FN-safety forcing rules → threat (never collapse an impersonation signal).
    if record.get("brand_mentioned"):
        return "threat"
    email_only = (bool(record.get("has_mx")) and not has_web) or \
                 ((bool(record.get("has_spf")) or bool(record.get("has_dmarc"))) and not has_web)
    if email_only:
        return "threat"

    if record.get("parked"):
        return "parked"

    # unrelated — different NS (owned already returned), no brand, serves its own
    # content we actually inspected. A login form alone does not keep it elevated.
    if has_web and record.get("content_checked"):
        return "unrelated"

    return "threat"
