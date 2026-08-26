"""WAF / block / challenge detection over httpx probe results (spec C1).

Pure classification — no DB, no network. Operates only on fields httpx already
returns (status_code, title, web_server), so detection adds zero traffic.

We report what we *observed* (a probe received a block/challenge response) and a
hedged vendor *fingerprint guess*. We never claim to know the target's WAF
configuration. When interference is seen but the vendor can't be fingerprinted,
the vendor is "unidentified".
"""

# web_server (Server header) substring → vendor label
_WAF_SERVER = {
    "cloudflare": "cloudflare",
    "akamaighost": "akamai",
    "akamai": "akamai",
    "sucuri": "sucuri",
    "imperva": "imperva",
    "incapsula": "imperva",
    "awselb": "aws",
    "big-ip": "f5",
    "barracuda": "barracuda",
}

# lowercased title substrings that indicate an interstitial challenge page
_CHALLENGE_TITLES = (
    "just a moment",
    "attention required",
    "checking your browser",
    "access denied",
    "cf-chl",
    "ddos-guard",
    "one moment",
    "please wait",
)

# statuses that, *together with a WAF fingerprint*, indicate an edge block.
# A bare 403/503 with no WAF signal is a legitimate app response — left as reached.
_BLOCK_STATUSES = {403, 406, 503}

REACHED = "reached"
BLOCKED = "blocked"
CHALLENGED = "challenged"
RATE_LIMITED = "rate_limited"

# reachability values that mean the probe did not reach the application
INTERFERED = frozenset({BLOCKED, CHALLENGED, RATE_LIMITED})


def fingerprint_vendor(title: str, web_server: str) -> str | None:
    """Best-effort vendor guess from response signatures. None if no signal."""
    ws = (web_server or "").lower()
    for needle, name in _WAF_SERVER.items():
        if needle in ws:
            return name
    t = (title or "").lower()
    if "cloudflare" in t or "cf-chl" in t:
        return "cloudflare"
    if "incapsula" in t or "imperva" in t:
        return "imperva"
    if "ddos-guard" in t:
        return "ddos-guard"
    return None


def classify(status_code, title: str = "", web_server: str = "") -> tuple[str, str | None]:
    """Return (reachability, vendor) for one probe.

    reachability ∈ {reached, blocked, challenged, rate_limited}.
    vendor is a fingerprint guess (or "unidentified" when a probe is interfered
    with but no vendor matched; None when the probe reached the app cleanly).
    """
    vendor = fingerprint_vendor(title, web_server)
    t = (title or "").lower()
    is_challenge = any(sig in t for sig in _CHALLENGE_TITLES)

    if is_challenge:
        reach = CHALLENGED
    elif status_code == 429:
        reach = RATE_LIMITED
    elif status_code in _BLOCK_STATUSES and vendor is not None:
        reach = BLOCKED
    else:
        reach = REACHED

    if reach == REACHED:
        return reach, vendor  # vendor may be set (WAF fronting but let us through)
    return reach, vendor or "unidentified"
