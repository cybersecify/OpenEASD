"""Risk + threat scoring for registered lookalike domains.

Faithful port of the reference tldsquatting project's two-stage model
(cybersecify/tldsquatting ``src/tldsquatting/{scoring.py,threat_score.py,
reputation.py}``), adapted to OpenEASD's pure collector→analyzer split:

  * ``calculate_risk_score`` scores the *registration + DNS posture* of a
    lookalike — how much infrastructure it carries and how recently it was
    registered. Its dominant rule is **PRE-EXISTING**: a lookalike that IS the
    target's apex, or was registered *before* the target, cannot be
    impersonating it (the ``amnic.net`` 1994 vs ``amnic.com`` 1997 case) — it
    scores 0.0 and is treated as a non-threat.
  * ``calculate_threat_score`` starts from the risk score and layers the
    *live weaponization* signals (login form, brand mentions, parked) gathered
    from the homepage probe. Its band → the Finding severity.

Both functions are **pure**: they take an already-gathered record dict and make
NO network calls (the collector does every DNS / RDAP / HTTP lookup). SSL,
subdomain and IP-reputation signals are not gathered by OpenEASD yet, so those
branches of the reference threat model simply contribute 0 (graceful).

Bands are kept exactly as the reference: risk 8/5/2 (CRITICAL/HIGH/MEDIUM),
threat 12/8/4 — the threat band is what the analyzer maps to severity.
"""

from datetime import datetime, timezone

# --- NS provider tiers (ported verbatim from reputation.py) ------------------
# Used to classify a candidate's nameservers WITHOUT a network call: the
# collector supplies the resolved NS target strings and we pattern-match them.
NS_ENTERPRISE = [
    "awsdns", "route53",                         # AWS
    "azure-dns",                                 # Microsoft Azure
    "googledomains", "google.com", "ns-cloud",   # Google Cloud
    "cloudflare.com",                            # Cloudflare
    "nsone.net",                                 # NS1 (IBM)
]
NS_KNOWN = [
    "domaincontrol.com",      # GoDaddy
    "registrar-servers.com",  # Namecheap
    "dnsimple.com",           # DNSimple
    "digitalocean.com",       # DigitalOcean
    "linode.com",             # Linode/Akamai
    "hetzner.com",            # Hetzner
    "ovh.net",                # OVH
    "name-services.com",      # Enom
    "ui-dns",                 # 1&1/IONOS
    "worldnic.com",           # Network Solutions
    "hostgator.com",          # HostGator
    "bluehost.com",           # Bluehost
    "siteground.net",         # SiteGround
    "wixdns.net",             # Wix
    "squarespace",            # Squarespace
    "hover.com",              # Hover
    "gandi.net",              # Gandi
]
NS_PARKING = [
    "parkingcrew", "sedoparking", "bodis.com", "above.com",
    "parklogic", "domainnameshop", "hugedomains",
]

RISK_BANDS = ((8.0, "CRITICAL"), (5.0, "HIGH"), (2.0, "MEDIUM"))
THREAT_BANDS = ((12.0, "CRITICAL"), (8.0, "HIGH"), (4.0, "MEDIUM"))


def ns_tier_from_targets(ns_targets) -> str:
    """Classify NS targets as ``enterprise`` / ``known`` / ``parking`` /
    ``unknown`` (no network — pure string match over supplied NS targets).

    Port of ``reputation.check_ns_tier`` with the DNS query removed: enterprise
    wins over parking wins over known (same precedence as the reference).
    """
    targets = [str(t).lower() for t in (ns_targets or [])]
    if not targets:
        return "unknown"
    if any(any(p in t for p in NS_ENTERPRISE) for t in targets):
        return "enterprise"
    if any(any(p in t for p in NS_PARKING) for t in targets):
        return "parking"
    if any(any(p in t for p in NS_KNOWN) for t in targets):
        return "known"
    return "unknown"


def _band(score: float, bands) -> str:
    for threshold, label in bands:
        if score >= threshold:
            return label
    return "LOW"


def _age_days(created) -> int | None:
    """Whole days since an ISO ``YYYY-MM-DD`` creation date, or None if absent /
    unparseable. Never raises."""
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(str(created)[:10]).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return (datetime.now(timezone.utc) - dt).days


def calculate_risk_score(
    record: dict, target_created: str | None = None, is_apex: bool = False,
) -> tuple[float, str]:
    """Registration + DNS-posture risk for a lookalike record.

    Returns ``(score, level)`` where level is PRE-EXISTING / CRITICAL / HIGH /
    MEDIUM / LOW. PRE-EXISTING (score 0.0) short-circuits when the lookalike IS
    the apex or was registered before the target — a domain older than yours
    cannot be squatting on it.
    """
    created = record.get("created")

    # PRE-EXISTING — the dominant rule (competitor-domain timing analysis).
    if is_apex:
        return 0.0, "PRE-EXISTING"
    if created and target_created and str(created) < str(target_created):
        return 0.0, "PRE-EXISTING"

    score = 0.0

    # Registration recency — a freshly-registered lookalike is a stronger signal.
    days = _age_days(created)
    if days is not None:
        years = days / 365.25
        if days <= 90:
            score += 2.0
        elif days <= 365:
            score += 1.5
        elif years <= 3:
            score += 1.0
        else:
            score += 0.5
    else:
        score += 0.5  # unknown age = mild signal

    has_a = bool(record.get("has_a"))
    has_aaaa = bool(record.get("has_aaaa"))
    has_mx = bool(record.get("has_mx"))
    has_ns = bool(record.get("has_ns"))
    has_cname = bool(record.get("has_cname"))
    has_txt = bool(record.get("has_txt"))
    has_spf = bool(record.get("has_spf"))
    has_dmarc = bool(record.get("has_dmarc"))

    # Infrastructure presence.
    if has_a:
        score += 2.0
    if has_mx:
        score += 1.5
    if has_ns:
        score += 1.0

    # Suspicious record combinations — the phishing-setup fingerprints.
    if has_mx and not has_a and not has_aaaa:
        score += 3.0  # email-only domain = phishing setup
    if has_cname and not has_a:
        score += 1.5  # proxied content, possible impersonation
    if has_txt and not has_a and not has_mx:
        score += 1.0  # domain-verification abuse (claiming ownership)
    if has_spf and not has_a:
        score += 2.0  # SPF without website = email spoofing prep
    if has_dmarc and not has_a:
        score += 2.0  # DMARC without website = email legitimacy setup
    if has_spf and has_dmarc and has_mx and not has_a:
        score += 2.0  # full email infra, no website = active phishing

    # Security configurations.
    if has_spf:
        score += 1.0
    if has_dmarc:
        score += 1.0
    if record.get("has_caa"):
        score += 0.5
    if record.get("has_dnssec"):
        score += 1.0

    # Web presence.
    if has_cname:
        score += 0.5
    if has_txt:
        score += 0.5

    # HTTPS/SSL (from the homepage probe).
    if record.get("https_enabled"):
        score += 1.0
        if record.get("ssl_valid"):
            score += 0.5
        if record.get("https_redirect"):
            score += 0.5

    # NS reputation tier — enterprise NS is a legitimacy signal, parking a
    # squatter signal. Classified from the resolved NS targets (no network).
    ns_tier = record.get("ns_tier") or ns_tier_from_targets(record.get("ns_targets"))
    if ns_tier == "enterprise":
        score -= 1.0
    elif ns_tier == "parking":
        score += 2.0
    elif ns_tier == "unknown":
        score += 1.0

    score = max(0.0, score)
    return round(score, 2), _band(score, RISK_BANDS)


def calculate_threat_score(record: dict, risk_score: float) -> tuple[float, str]:
    """Unified threat score = risk score + live weaponization signals.

    Only the content signals OpenEASD actually gathers are wired (login form,
    brand mentions, parked); the reference's SSL / subdomain / IP-reputation
    branches have no data here and contribute 0 (graceful).
    """
    score = float(risk_score)

    if record.get("login_form"):
        score += 3.0  # login form = strong credential-phishing signal

    if record.get("brand_mentioned"):
        count = record.get("brand_mention_count", 0) or 0
        if count >= 5:
            score += 2.0  # heavy brand mention = impersonation
        elif count >= 1:
            score += 1.0  # some brand mention

    if record.get("parked"):
        score -= 1.0  # parked = less immediate threat

    score = max(0.0, score)
    return round(score, 2), _band(score, THREAT_BANDS)
