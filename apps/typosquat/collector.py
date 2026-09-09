"""Lookalike / typosquat collector — algorithmic candidate generation + passive
public-DNS registration checks.

Two stages, no external binary:

  1. GENERATE lookalike candidates from the session's apex domain using classic
     typosquatting techniques (homoglyph, adjacent-key substitution, omission,
     insertion, repetition, transposition, hyphenation, TLD swap). Deterministic
     and deduped. Capped at ``MAX_CANDIDATES`` — truncation is logged, never
     silent.
  2. CHECK which candidates are registered / weaponizable via PUBLIC DNS. For
     each candidate we resolve A + MX (and NS only when neither is present). A
     candidate with A or MX records can host a phishing page or receive mail
     (weaponizable); one with only NS is registered/parked. NXDOMAIN = not
     registered → skipped.

Passive contract: every DNS query targets the CANDIDATE domain's public DNS —
the org's own systems are never contacted. FAIL-GRACEFUL, ALWAYS: any resolver
error / timeout / NXDOMAIN on a candidate is treated as "not registered" and
skipped; the collector never raises. There is no binary, so it never raises
ToolBinaryMissing / ToolTimeout.
"""

import logging

import dns.resolver

logger = logging.getLogger(__name__)

# Cap on generated candidates AND the per-scan DNS-lookup budget (one candidate =
# up to a few short lookups). Keeps a scan polite and bounded on domains whose
# names generate a large permutation space.
MAX_CANDIDATES = 300

# Per-lookup DNS timeout / overall lifetime (seconds). Short — most candidates are
# NXDOMAIN and resolve fast; we never want a hung resolver to stall a scan.
_DNS_TIMEOUT = 3

# Curated common TLDs used for TLD-swap candidates (phishing kits favour cheap /
# familiar TLDs). We swap the apex's own TLD out for each of these.
_COMMON_TLDS = [
    "com", "net", "org", "co", "io", "info", "xyz", "online", "site",
    "app", "dev", "biz", "us", "cc", "top", "live", "shop",
]

# Homoglyph / visually-similar single-character substitutions.
_HOMOGLYPHS = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "e": ["3"],
    "a": ["4"],
    "s": ["5", "z"],
    "b": ["8"],
    "g": ["9", "q"],
    "m": ["rn"],
    "w": ["vv"],
    "0": ["o"],
    "1": ["l"],
}

# QWERTY adjacency for adjacent-key (fat-finger) typos.
_KEYBOARD = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc",
    "g": "ftyhbv", "h": "gyujnb", "j": "huikmn", "k": "jiolm",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}


def _split_apex(domain: str) -> tuple[str, str]:
    """Split an apex domain into (name, tld). A leading ``www.`` is stripped.

    Uses a simple last-dot split: ``example.com`` → ``("example", "com")``. For a
    multi-label public suffix (``example.co.uk``) the ``name`` keeps the inner
    label(s); techniques mutate ``name`` and TLD swaps replace only the final
    label. This is deliberately conservative — good enough for candidate seeding.
    """
    d = (domain or "").strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    name, _, tld = d.rpartition(".")
    if not name:  # no dot at all — treat whole thing as the name, no tld
        return d, ""
    return name, tld


def _char_variants(name: str) -> set[str]:
    """Apply the single-string mutation techniques to a domain name label."""
    out: set[str] = set()
    n = len(name)

    # Omission — drop one character.
    for i in range(n):
        out.add(name[:i] + name[i + 1:])

    # Repetition — double one character.
    for i in range(n):
        out.add(name[:i] + name[i] + name[i] + name[i + 1:])

    # Transposition — swap two adjacent characters.
    for i in range(n - 1):
        out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])

    # Hyphenation — insert a hyphen between two characters.
    for i in range(1, n):
        out.add(name[:i] + "-" + name[i:])

    # Adjacent-key substitution (fat-finger typo).
    for i, ch in enumerate(name):
        for repl in _KEYBOARD.get(ch, ""):
            out.add(name[:i] + repl + name[i + 1:])

    # Adjacent-key insertion — insert a neighbouring key next to each character.
    for i, ch in enumerate(name):
        for extra in _KEYBOARD.get(ch, ""):
            out.add(name[:i + 1] + extra + name[i + 1:])

    # Homoglyph substitution — visually similar characters.
    for i, ch in enumerate(name):
        for repl in _HOMOGLYPHS.get(ch, []):
            out.add(name[:i] + repl + name[i + 1:])

    # Drop the identity and any empties.
    out.discard(name)
    out.discard("")
    return out


def generate_candidates(domain: str) -> list[dict]:
    """Generate deduped lookalike candidates for an apex domain.

    Returns a list of ``{"candidate": fqdn, "technique": str}`` dicts, capped at
    ``MAX_CANDIDATES`` (truncation logged). The original domain is never included.
    """
    name, tld = _split_apex(domain)
    if not name:
        return []

    original = f"{name}.{tld}" if tld else name
    # Preserve first-seen technique per candidate; dict keeps insertion order.
    seen: dict[str, str] = {}

    def _add(candidate: str, technique: str):
        candidate = candidate.strip(".")
        if candidate and candidate != original and candidate not in seen:
            seen[candidate] = technique

    # Character-level mutations on the name label, keeping the real TLD.
    for variant in sorted(_char_variants(name)):
        suffix = f".{tld}" if tld else ""
        _add(f"{variant}{suffix}", "typo")

    # TLD swap — same name label, a different common TLD.
    for alt in _COMMON_TLDS:
        if alt != tld:
            _add(f"{name}.{alt}", "tld_swap")

    candidates = [{"candidate": c, "technique": t} for c, t in seen.items()]
    if len(candidates) > MAX_CANDIDATES:
        logger.info(
            "typosquat: generated %d candidates for %s — truncating to %d "
            "(MAX_CANDIDATES)", len(candidates), original, MAX_CANDIDATES,
        )
        candidates = candidates[:MAX_CANDIDATES]
    return candidates


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = _DNS_TIMEOUT
    r.lifetime = _DNS_TIMEOUT
    return r


def _resolve(resolver, name: str, rdtype: str) -> list[str]:
    """Resolve ``name``/``rdtype``. Returns record strings, or [] on any failure
    (NXDOMAIN, no answer, timeout, resolver error). Never raises."""
    try:
        answers = resolver.resolve(name, rdtype)
    except Exception:  # noqa: BLE001 — any resolver failure = "not present"
        return []
    return [str(rdata) for rdata in answers]


def _check_candidate(resolver, candidate: str) -> dict | None:
    """Passive DNS registration check for a single candidate.

    Returns a record dict when the candidate is registered (has A, MX, or NS),
    else None. A/MX presence marks it weaponizable (can serve phishing / receive
    mail). Only NS present = registered / parked.
    """
    a_records = _resolve(resolver, candidate, "A")
    mx_records = _resolve(resolver, candidate, "MX")

    has_a = bool(a_records)
    has_mx = bool(mx_records)
    has_ns = False
    if not has_a and not has_mx:
        # Only pay for the NS lookup when there's no A/MX — catches parked /
        # registered-but-dark lookalikes without a lookup on every candidate.
        has_ns = bool(_resolve(resolver, candidate, "NS"))

    if not (has_a or has_mx or has_ns):
        return None  # NXDOMAIN / unregistered — nothing to report.

    return {
        "candidate": candidate,
        "has_a": has_a,
        "has_mx": has_mx,
        "has_ns": has_ns,
        "resolved_ips": a_records,
    }


def collect(session) -> list[dict]:
    """Generate lookalike candidates for the session's apex domain and return the
    subset that is registered / weaponizable (via passive public DNS).

    Always returns a list; never raises.
    """
    apex = getattr(session, "domain", "") or ""
    candidates = generate_candidates(apex)
    if not candidates:
        logger.info("[typosquat:%s] no candidates generated for %r", session.id, apex)
        return []

    resolver = _resolver()
    results: list[dict] = []
    for cand in candidates:
        record = _check_candidate(resolver, cand["candidate"])
        if record:
            record["technique"] = cand["technique"]
            results.append(record)

    logger.info(
        "[typosquat:%s] checked %d lookalike candidate(s) for %s — %d registered",
        session.id, len(candidates), apex, len(results),
    )
    return results
