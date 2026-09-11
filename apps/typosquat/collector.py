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
import re
import threading
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# Bounded concurrency for the two network-bound passes. Candidate resolution and
# homepage probes are I/O-bound and independent, so a small thread pool collapses
# hundreds of serial round-trips into a few rounds. Kept bounded (and hitting
# only third-party lookalike DNS / sites, never the target) so it stays polite.
_DNS_CONCURRENCY = getattr(settings, "TYPOSQUAT_DNS_CONCURRENCY", 16)
_FETCH_CONCURRENCY = getattr(settings, "TYPOSQUAT_FETCH_CONCURRENCY", 8)

# Cap on generated candidates AND the per-scan DNS-lookup budget (one candidate =
# up to a few short lookups). Keeps a scan polite and bounded on domains whose
# names generate a large permutation space.
MAX_CANDIDATES = 300

# Weaponization content probe (spec: distinguish an ACTIVE phishing lookalike
# from a merely-registered one). For registered, web-serving lookalikes we fetch
# the homepage over HTTPS and look for a login form / brand impersonation. This
# contacts the THIRD-PARTY lookalike, never the user's own domain, so the tool
# stays passive w.r.t. the authorization boundary (like cloud_enum probing
# buckets). Capped + short-timeout + fail-graceful for politeness.
CONTENT_MAX_FETCHES = 25          # homepages fetched per scan
CONTENT_TIMEOUT = 6               # seconds per fetch
_LOGIN_FORM_RE = re.compile(r"<form[^>]*(?:login|sign.?in|auth|password)[^>]*>", re.I)

# Domain-parking detection. A parked lookalike resolves and often carries
# registrar-default MX, which used to read as "weaponizable right now" — but a
# parking lot is speculation, not phishing infrastructure. Two independent
# signals, either one marks the record parked:
#
#   1. Anycast IPs of the major parking / for-sale services. These are stable,
#      well-known landing addresses (GoDaddy/Afternic ride AWS Global
#      Accelerator; Namecheap, Sedo, Bodis, ParkingCrew use their own ranges).
#   2. Sale/parking boilerplate on the fetched homepage.
_PARKING_IPS = frozenset({
    "76.223.54.146", "13.248.169.48",    # Afternic / GoDaddy (AWS Global Accelerator)
    "3.33.130.190", "15.197.148.33",     # GoDaddy parking (AWS Global Accelerator)
    "34.102.136.180",                    # GoDaddy CashParking
    "91.195.240.94", "91.195.241.136",   # Sedo
    "199.59.243.228", "199.59.243.226",  # Bodis
    "192.64.119.87", "192.64.119.254",   # Namecheap parking
    "162.255.119.112",                   # Namecheap registrar default
    "185.53.177.30", "185.53.178.30",    # ParkingCrew / TeamInternet
    "208.91.197.27",                     # Confluence Networks parking
})
_PARKING_PREFIXES = (
    "185.53.177.", "185.53.178.", "185.53.179.",  # ParkingCrew / TeamInternet
    "199.59.243.",                                # Bodis
    "91.195.240.", "91.195.241.",                 # Sedo
)
_PARKED_CONTENT_RE = re.compile(
    r"domain (?:is |may be )?for sale|buy this domain|this domain is parked|"
    r"domain parking|parked free|hugedomains|afternic|sedo\.com|dan\.com|"
    r"godaddy\.com/forsale|is available for purchase",
    re.I,
)


def _parked_by_ip(ips: list[str]) -> bool:
    return any(
        ip in _PARKING_IPS or ip.startswith(_PARKING_PREFIXES) for ip in ips or []
    )

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


# Common multi-label public suffixes — ccTLD second-level registries. NOT the
# full ~9k-entry Public Suffix List: a curated set of the ones real targets use,
# which keeps us dependency-free (tldextract fetches the PSL over the network by
# default — a scanner worker shouldn't). Override/extend via
# settings.TYPOSQUAT_MULTI_LABEL_SUFFIXES.
_MULTI_LABEL_SUFFIXES = (
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za", "web.za",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.kr", "or.kr",
    "com.sg", "com.my", "com.hk", "com.tw", "com.mx", "com.tr", "com.ar",
    "com.ua", "com.ph", "com.pk", "com.ng", "co.id", "co.th", "com.vn", "com.sa",
)


def _split_apex(domain: str) -> tuple[str, str]:
    """Split an apex domain into (registrable_name, public_suffix).

    ``example.com`` → ``("example", "com")``; ``example.co.uk`` →
    ``("example", "co.uk")``. A leading ``www.`` is stripped.

    Multi-label public suffixes (ccTLD second-level registries) are recognised
    from ``_MULTI_LABEL_SUFFIXES`` so char-mutation and TLD-swap operate on the
    registrable label, not a partial suffix. The old last-dot split turned
    ``example.co.uk`` into name=``example.co`` / tld=``uk`` and emitted garbage
    candidates like ``example.co.net`` that never resolve — so ccTLD targets got
    effectively no lookalike detection. Curated, not the full PSL — good enough
    for candidate seeding.
    """
    d = (domain or "").strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]

    suffixes = getattr(settings, "TYPOSQUAT_MULTI_LABEL_SUFFIXES", _MULTI_LABEL_SUFFIXES)
    for suffix in suffixes:
        if d.endswith("." + suffix):
            head = d[: -(len(suffix) + 1)]      # everything before ".<suffix>"
            name = head.rsplit(".", 1)[-1]       # registrable label (drop sub-labels)
            return (name, suffix) if name else (d, "")

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


# One resolver per worker thread — dnspython Resolver isn't documented
# thread-safe, and a thread-local avoids re-reading resolv.conf per candidate.
_thread_local = threading.local()


def _thread_resolver() -> dns.resolver.Resolver:
    r = getattr(_thread_local, "resolver", None)
    if r is None:
        r = _thread_local.resolver = _resolver()
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


def _content_signals(candidate: str, brand: str) -> dict:
    """Fetch a registered lookalike's homepage and look for weaponization signals:
    a login form (credential-phishing) and mentions of the brand (impersonation).

    Contacts only the lookalike domain, never the target. Never raises — any
    fetch failure leaves content_checked=False and no signals.
    """
    # NOTE: no "parked" default here — IP-based parking detection may already
    # have set it on the record, and this dict is update()ed over the record.
    out = {"content_checked": True, "login_form": False,
           "brand_mentioned": False, "brand_mention_count": 0}
    try:
        ua = getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD")
        resp = requests.get(
            f"https://{candidate}/", timeout=CONTENT_TIMEOUT,
            headers={"User-Agent": ua}, allow_redirects=True,
        )
        html = resp.text or ""
        out["login_form"] = bool(_LOGIN_FORM_RE.search(html))
        if _PARKED_CONTENT_RE.search(html):
            out["parked"] = True
        b = (brand or "").lower()
        if b:
            count = html.lower().count(b)
            out["brand_mention_count"] = count
            # A mention on the page, OR a redirect landing on the real brand, is
            # an impersonation signal — but only a SIGNAL. A short brand string
            # legitimately appears in unrelated organizations' own names (a
            # lookalike of "amnic" hit the Armenia Network Information Centre,
            # whose page says AMNIC because that IS its name), so the analyzer
            # never escalates on mentions alone.
            out["brand_mentioned"] = count > 0 or b in (resp.url or "").lower()
    except Exception:  # noqa: BLE001 — never let a lookalike fetch fail the scan
        out["content_checked"] = False
    return out


def collect(session) -> list[dict]:
    """Generate lookalike candidates for the session's apex domain and return the
    subset that is registered / weaponizable (via passive public DNS), enriched
    with weaponization signals (login form / brand impersonation) for the
    web-serving ones.

    Always returns a list; never raises.
    """
    apex = getattr(session, "domain", "") or ""
    candidates = generate_candidates(apex)
    if not candidates:
        logger.info("[typosquat:%s] no candidates generated for %r", session.id, apex)
        return []

    # Registration check — resolve candidates concurrently (I/O-bound). map()
    # preserves input order, so results stay deterministic.
    def _check(cand):
        record = _check_candidate(_thread_resolver(), cand["candidate"])
        if record:
            record["technique"] = cand["technique"]
        return record

    dns_workers = max(1, min(_DNS_CONCURRENCY, len(candidates)))
    with ThreadPoolExecutor(max_workers=dns_workers) as executor:
        results = [r for r in executor.map(_check, candidates) if r]

    # Parking detection by IP works even when the homepage fetch fails (parked
    # domains frequently have no HTTPS), so it runs on every A-bearing record.
    for r in results:
        if r.get("has_a") and _parked_by_ip(r.get("resolved_ips") or []):
            r["parked"] = True

    # Weaponization pass: for registered lookalikes that serve web (have an A
    # record), fetch the homepage to spot active phishing / impersonation. Capped,
    # and probed concurrently — each _content_signals mutates its record in place.
    brand, _ = _split_apex(apex)
    to_fetch = [r for r in results if r.get("has_a")][:CONTENT_MAX_FETCHES]
    if to_fetch:
        def _probe(record):
            record.update(_content_signals(record["candidate"], brand))

        fetch_workers = max(1, min(_FETCH_CONCURRENCY, len(to_fetch)))
        with ThreadPoolExecutor(max_workers=fetch_workers) as executor:
            list(executor.map(_probe, to_fetch))
    fetched = len(to_fetch)

    logger.info(
        "[typosquat:%s] checked %d lookalike candidate(s) for %s — %d registered, "
        "%d homepage(s) probed",
        session.id, len(candidates), apex, len(results), fetched,
    )
    return results
