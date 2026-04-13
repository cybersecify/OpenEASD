# Service Detection Confidence Scoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the binary pass/fail service detection cascade with a multi-signal confidence scoring system that eliminates `tcpwrapped` and `ssl/unknown` false positives.

**Architecture:** Each port accumulates a score from independent signals (banner grab, HTTP probing, nmap, port hint). A port is only classified as `is_web=True` when the score reaches ≥ 50. Banner grab runs first to short-circuit HTTP probing for clear non-web ports (SSH, FTP, SMTP), reducing requests from 4+ to 1 for those ports.

**Tech Stack:** Python stdlib `socket`, existing `requests`, existing `nmap` subprocess. All changes confined to `apps/core/service_detection/detector.py` and `tests/unit/test_service_detection.py`.

**Spec:** `docs/superpowers/specs/2026-04-13-service-detection-confidence-scoring-design.md`

---

## File Map

| File | Change |
|---|---|
| `apps/core/service_detection/detector.py` | Add `_grab_banner`, `_banner_score`, `_nmap_score`, `_port_hint_score`, `CLASSIFICATION_THRESHOLD`; rewrite `detect_services` |
| `tests/unit/test_service_detection.py` | Add tests for new helpers; update existing `detect_services` tests to mock `_grab_banner` and reflect new behavior |

---

## Task 1: Add `_grab_banner`

**Files:**
- Modify: `apps/core/service_detection/detector.py`
- Test: `tests/unit/test_service_detection.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_service_detection.py` after the `TestProbeHttp` class:

```python
# ---------------------------------------------------------------------------
# _grab_banner
# ---------------------------------------------------------------------------

class TestGrabBanner:
    def test_returns_banner_on_successful_connect(self):
        import socket
        from apps.core.service_detection.detector import _grab_banner
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            result = _grab_banner("1.2.3.4", 22)
        assert result == "SSH-2.0-OpenSSH_8.9\r\n"

    def test_returns_empty_on_connection_refused(self):
        import socket
        from apps.core.service_detection.detector import _grab_banner
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   side_effect=ConnectionRefusedError()):
            result = _grab_banner("1.2.3.4", 22)
        assert result == ""

    def test_returns_empty_on_timeout(self):
        import socket
        from apps.core.service_detection.detector import _grab_banner
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   side_effect=socket.timeout()):
            result = _grab_banner("1.2.3.4", 9999)
        assert result == ""

    def test_decodes_bytes_ignoring_errors(self):
        from apps.core.service_detection.detector import _grab_banner
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\xff\xfe HTTP/1.1 200 OK"
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("apps.core.service_detection.detector.socket.create_connection",
                   return_value=mock_sock):
            result = _grab_banner("1.2.3.4", 80)
        assert "HTTP/1.1 200 OK" in result
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_service_detection.py::TestGrabBanner -v
```

Expected: `ImportError` or `AttributeError` — `_grab_banner` does not exist yet.

- [ ] **Step 3: Add `_grab_banner` to `detector.py`**

Add `import socket` at the top of `apps/core/service_detection/detector.py` after the existing imports. Then add this function after the `_probe_http` function (before the `# nmap -sV fallback` section):

```python
# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

BANNER_TIMEOUT = 3
BANNER_READ_BYTES = 512


def _grab_banner(host: str, port: int) -> str:
    """
    Open a raw TCP connection and read the first bytes the server sends.

    Returns the decoded banner string, or "" on any failure (timeout,
    refused, no data). Used to detect SSH/FTP/SMTP before wasting HTTP
    probe attempts on them.
    """
    try:
        with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            data = sock.recv(BANNER_READ_BYTES)
            return data.decode("utf-8", errors="replace")
    except Exception:
        return ""
```

Also update the imports line in `tests/unit/test_service_detection.py` to include `_grab_banner`:

```python
from apps.core.service_detection.detector import (
    _probe_http, _parse_nmap_sv_xml, _nmap_sv, detect_services,
    WEB_SERVICES, _KNOWN_WEB_PORTS, _grab_banner,
)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/unit/test_service_detection.py::TestGrabBanner -v
```

Expected: 4 PASSED.

- [ ] **Step 5: Commit**

```bash
git add apps/core/service_detection/detector.py tests/unit/test_service_detection.py
git commit -m "feat(service_detection): add _grab_banner — raw TCP banner read"
```

---

## Task 2: Add Scoring Helpers

**Files:**
- Modify: `apps/core/service_detection/detector.py`
- Test: `tests/unit/test_service_detection.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_service_detection.py` after `TestGrabBanner`:

```python
# ---------------------------------------------------------------------------
# _banner_score
# ---------------------------------------------------------------------------

class TestBannerScore:
    def setup_method(self):
        from apps.core.service_detection.detector import _banner_score
        self.fn = _banner_score

    def test_ssh_banner_negative(self):
        assert self.fn("SSH-2.0-OpenSSH_8.9\r\n") == -70

    def test_ssh1_banner_negative(self):
        assert self.fn("SSH-1.99-OpenSSH_3.9\r\n") == -70

    def test_ftp_banner_negative(self):
        assert self.fn("220 ProFTPD 1.3.5 Server ready\r\n") == -70

    def test_smtp_ehlo_negative(self):
        assert self.fn("EHLO mail.example.com\r\n") == -70

    def test_esmtp_negative(self):
        assert self.fn("220 mail.example.com ESMTP\r\n") == -70

    def test_pop3_positive_ok_negative(self):
        assert self.fn("+OK POP3 server ready\r\n") == -70

    def test_imap_ok_negative(self):
        assert self.fn("* OK IMAP4rev1 ready\r\n") == -70

    def test_http_response_positive(self):
        assert self.fn("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n") == 70

    def test_html_doctype_positive(self):
        assert self.fn("<!DOCTYPE html><html>") == 70

    def test_html_tag_positive(self):
        assert self.fn("<html lang='en'>") == 70

    def test_empty_banner_zero(self):
        assert self.fn("") == 0

    def test_unknown_banner_zero(self):
        assert self.fn("some random binary garbage \x00\x01\x02") == 0


# ---------------------------------------------------------------------------
# _nmap_score
# ---------------------------------------------------------------------------

class TestNmapScore:
    def setup_method(self):
        from apps.core.service_detection.detector import _nmap_score
        self.fn = _nmap_score

    def test_http_positive(self):
        assert self.fn("http", 8080) == 70

    def test_https_positive(self):
        assert self.fn("https", 443) == 70

    def test_ssl_http_positive(self):
        assert self.fn("ssl/http", 8443) == 70

    def test_ssh_negative(self):
        assert self.fn("ssh", 22) == -80

    def test_ftp_negative(self):
        assert self.fn("ftp", 21) == -80

    def test_smtp_negative(self):
        assert self.fn("smtp", 25) == -80

    def test_tcpwrapped_zero(self):
        assert self.fn("tcpwrapped", 443) == 0

    def test_ssl_unknown_on_known_web_port(self):
        assert self.fn("ssl/unknown", 443) == 40

    def test_ssl_unknown_on_known_web_port_8443(self):
        assert self.fn("ssl/unknown", 8443) == 40

    def test_ssl_unknown_on_non_web_port(self):
        assert self.fn("ssl/unknown", 9200) == 10

    def test_empty_string_zero(self):
        assert self.fn("", 1234) == 0

    def test_unknown_service_zero(self):
        assert self.fn("unknown", 9999) == 0


# ---------------------------------------------------------------------------
# _port_hint_score
# ---------------------------------------------------------------------------

class TestPortHintScore:
    def setup_method(self):
        from apps.core.service_detection.detector import _port_hint_score
        self.fn = _port_hint_score

    def test_port_80(self):
        assert self.fn(80) == 20

    def test_port_443(self):
        assert self.fn(443) == 20

    def test_port_8080(self):
        assert self.fn(8080) == 20

    def test_port_8443(self):
        assert self.fn(8443) == 20

    def test_port_22_zero(self):
        assert self.fn(22) == 0

    def test_port_9200_zero(self):
        assert self.fn(9200) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_service_detection.py::TestBannerScore tests/unit/test_service_detection.py::TestNmapScore tests/unit/test_service_detection.py::TestPortHintScore -v
```

Expected: `ImportError` — `_banner_score`, `_nmap_score`, `_port_hint_score` do not exist yet.

- [ ] **Step 3: Add scoring constants and helpers to `detector.py`**

Add after the existing `_KNOWN_WEB_PORTS` dict (before the `# HTTP probing` section):

```python
CLASSIFICATION_THRESHOLD = 50

# nmap service names that identify clearly non-web services.
_NMAP_NON_WEB_SERVICES = frozenset({
    "ssh", "ftp", "ftps", "smtp", "smtps", "imap", "imaps",
    "pop3", "pop3s", "telnet", "rdp", "ms-wbt-server",
    "mysql", "postgresql", "ms-sql-s", "oracle", "mongodb",
    "redis", "memcached", "ldap", "ldaps", "snmp", "ntp",
    "sip", "sips", "dns", "domain", "rpcbind", "sunrpc",
    "netbios-ssn", "microsoft-ds",
})

# Banner prefixes/substrings that identify clearly non-web services.
_BANNER_NON_WEB_SIGNALS = ("SSH-2.0-", "SSH-1.", "220 ", "EHLO", "ESMTP", "+OK ", "* OK ", "* BYE")

# Banner substrings that identify web services.
_BANNER_WEB_SIGNALS = ("HTTP/", "<!DOCTYPE", "<html")
```

Then add these three functions after `_grab_banner` (before `_parse_nmap_sv_xml`):

```python
# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _banner_score(banner: str) -> int:
    """
    Score a raw TCP banner.

    Returns +70 for HTTP banners, -70 for SSH/FTP/SMTP banners, 0 otherwise.
    """
    if not banner:
        return 0
    for signal in _BANNER_WEB_SIGNALS:
        if signal in banner:
            return 70
    for signal in _BANNER_NON_WEB_SIGNALS:
        if signal in banner:
            return -70
    return 0


def _nmap_score(nmap_svc: str, port_num: int) -> int:
    """
    Score an nmap service name.

    ssl/unknown on a known web port scores higher to preserve CDN/CloudFront
    detection (those services block most probes but nmap still sees ssl/unknown).
    tcpwrapped contributes nothing — it carries no protocol information.
    """
    if not nmap_svc:
        return 0
    if nmap_svc in _NMAP_WEB_SERVICES:
        return 70
    if nmap_svc in _NMAP_NON_WEB_SERVICES:
        return -80
    if nmap_svc == "ssl/unknown":
        return 40 if port_num in _KNOWN_WEB_PORTS else 10
    if nmap_svc == "tcpwrapped":
        return 0
    return 0


def _port_hint_score(port_num: int) -> int:
    """
    Weak bonus for well-known web port numbers.

    Not enough alone to cross CLASSIFICATION_THRESHOLD — requires at least
    one other positive signal.
    """
    return 20 if port_num in _KNOWN_WEB_PORTS else 0
```

Also update the import line in `tests/unit/test_service_detection.py`:

```python
from apps.core.service_detection.detector import (
    _probe_http, _parse_nmap_sv_xml, _nmap_sv, detect_services,
    WEB_SERVICES, _KNOWN_WEB_PORTS, _grab_banner,
    _banner_score, _nmap_score, _port_hint_score, CLASSIFICATION_THRESHOLD,
)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/unit/test_service_detection.py::TestBannerScore tests/unit/test_service_detection.py::TestNmapScore tests/unit/test_service_detection.py::TestPortHintScore -v
```

Expected: all PASSED.

- [ ] **Step 5: Commit**

```bash
git add apps/core/service_detection/detector.py tests/unit/test_service_detection.py
git commit -m "feat(service_detection): add confidence scoring helpers — banner/nmap/port_hint scores"
```

---

## Task 3: Rewrite `detect_services` + Update Existing Tests

**Files:**
- Modify: `apps/core/service_detection/detector.py`
- Test: `tests/unit/test_service_detection.py`

### Background: what changes in behavior

The old code had a "well-known port fallback" as a last resort: if everything failed on port 80/443/8080/8443, it forced `is_web=True`. With confidence scoring, port 443 with zero signals scores only +20 (port hint) < 50 → `is_web=False`. This is intentional — a port that doesn't respond to anything is genuinely ambiguous. CloudFront/CDN cases are handled by nmap returning `ssl/unknown` on port 443 → +40+20=60 → web.

This means **three existing tests need updated assertions** (marked below).

- [ ] **Step 1: Write new `detect_services` tests**

Add to `tests/unit/test_service_detection.py`, in the `TestDetectServices` class, after the existing tests:

```python
    # -- Confidence scoring: tcpwrapped must NOT classify as web --------------

    def test_tcpwrapped_port_9200_is_not_web(self):
        """tcpwrapped contributes 0 — port 9200 stays non-web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=9200, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={9200: "tcpwrapped"}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=9200)
        assert p.is_web is False

    def test_ssl_unknown_on_port_443_is_web(self):
        """ssl/unknown on port 443 scores +40+20=60 >= 50 — classified web (CDN case)."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=443, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={443: "ssl/unknown"}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=443)
        assert p.is_web is True

    def test_ssl_unknown_on_port_9200_is_not_web(self):
        """ssl/unknown on non-web port scores +10 < 50 — stays non-web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=9200, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={9200: "ssl/unknown"}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=9200)
        assert p.is_web is False

    def test_ssh_banner_skips_http_probing(self):
        """SSH banner scores -70 — HTTP probing is skipped, port stays non-web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=22, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http") as mock_http, \
             patch("apps.core.service_detection.detector._grab_banner",
                   return_value="SSH-2.0-OpenSSH_8.9\r\n"), \
             patch("apps.core.service_detection.detector._nmap_sv",
                   return_value={22: "ssh"}):
            detect_services(sess)
            mock_http.assert_not_called()

        p = Port.objects.get(session=sess, port=22)
        assert p.is_web is False
        assert p.service == "ssh"

    def test_http_probe_success_classifies_as_web(self):
        """HTTP probe success scores +80 >= 50 — classified web."""
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                            port=8888, protocol="tcp", state="open", source="naabu")

        with patch("apps.core.service_detection.detector._probe_http",
                   side_effect=lambda host, port, scheme: scheme == "https"), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        p = Port.objects.get(session=sess, port=8888)
        assert p.is_web is True
        assert p.service == "https"
```

- [ ] **Step 2: Run new tests to verify they fail**

```bash
uv run pytest tests/unit/test_service_detection.py::TestDetectServices::test_tcpwrapped_port_9200_is_not_web tests/unit/test_service_detection.py::TestDetectServices::test_ssl_unknown_on_port_443_is_web tests/unit/test_service_detection.py::TestDetectServices::test_ssl_unknown_on_port_9200_is_not_web tests/unit/test_service_detection.py::TestDetectServices::test_ssh_banner_skips_http_probing tests/unit/test_service_detection.py::TestDetectServices::test_http_probe_success_classifies_as_web -v
```

Expected: FAIL (old logic still running).

- [ ] **Step 3: Replace `detect_services` in `detector.py`**

Replace the entire `detect_services` function (lines 171–277) with:

```python
def detect_services(session) -> int:
    """
    Classify all open ports as web or non-web using confidence scoring.

    Each port accumulates a score from independent signals:
      banner grab → +70 (HTTP) or −70 (SSH/FTP/SMTP)
      HTTP probe  → +80 (hostname) or +60 (IP fallback)
      nmap -sV    → +70 (web service) or −80 (non-web service)
      port hint   → +20 for 80/443/8080/8443

    score >= CLASSIFICATION_THRESHOLD (50) → is_web=True

    Returns the count of ports whose service or is_web changed.
    """
    from apps.core.assets.models import Port

    open_ports = list(
        Port.objects.filter(session=session, state="open")
        .select_related("ip_address__subdomain")
    )
    if not open_ports:
        logger.info(f"[service_detection:{session.id}] No open ports")
        return 0

    scores: dict[int, int] = {}         # port.id → accumulated score
    http_services: dict[int, str] = {}  # port.id → service name from HTTP probe
    nmap_results: dict[int, str] = {}   # port.id → service name from nmap
    needs_nmap: list = []

    # ── Steps 1+2: Banner grab then HTTP probing ──────────────────────────────
    for p in open_ports:
        ip       = p.address
        port_num = p.port
        hostname = ip
        if p.ip_address and p.ip_address.subdomain:
            hostname = p.ip_address.subdomain.subdomain

        # Step 1: banner grab — cheapest signal, runs first
        banner  = _grab_banner(hostname, port_num)
        b_score = _banner_score(banner)
        score   = b_score

        # Step 2: HTTP probing — skip when banner is clearly non-web (saves 4 probes)
        http_svc = ""
        if b_score >= -50:
            if _probe_http(hostname, port_num, "https"):
                score += 80
                http_svc = "https"
            elif _probe_http(hostname, port_num, "http"):
                score += 80
                http_svc = "http"
            elif hostname != ip:
                if _probe_http(ip, port_num, "https"):
                    score += 60
                    http_svc = "https"
                elif _probe_http(ip, port_num, "http"):
                    score += 60
                    http_svc = "http"

        # Step 4: port hint — always applied
        score += _port_hint_score(port_num)

        scores[p.id]        = score
        http_services[p.id] = http_svc

        logger.debug(
            f"[service_detection:{session.id}] {hostname}:{port_num} "
            f"banner_score={b_score} http_svc={http_svc!r} score_so_far={score}"
        )

        if not http_svc:
            needs_nmap.append(p)

    # ── Step 3: nmap -sV — only for ports not resolved by HTTP ───────────────
    if needs_nmap:
        by_target: dict[tuple[str, str], list] = {}
        for p in needs_nmap:
            hostname = p.address
            if p.ip_address and p.ip_address.subdomain:
                hostname = p.ip_address.subdomain.subdomain
            by_target.setdefault((p.address, hostname), []).append(p)

        for (ip, hostname), ports in by_target.items():
            nmap_services = _nmap_sv(ip, [p.port for p in ports], hostname=hostname)
            for p in ports:
                nmap_svc = nmap_services.get(p.port, "")
                nmap_results[p.id] = nmap_svc
                n_score = _nmap_score(nmap_svc, p.port)
                scores[p.id] += n_score
                logger.debug(
                    f"[service_detection:{session.id}] {hostname}:{p.port} "
                    f"nmap={nmap_svc!r} nmap_score={n_score} total={scores[p.id]}"
                )

    # ── Persist ───────────────────────────────────────────────────────────────
    updated = 0
    for p in open_ports:
        score  = scores[p.id]
        is_web = score >= CLASSIFICATION_THRESHOLD

        # Determine service name: HTTP probe wins, then nmap, then port default
        service = http_services.get(p.id, "") or nmap_results.get(p.id, "")
        # Sanitise ambiguous nmap names: if classified web but name is uninformative,
        # use the port-based default
        if is_web and service in {"ssl/unknown", "tcpwrapped", ""}:
            service = _KNOWN_WEB_PORTS.get(p.port, "https" if p.port in {443, 8443} else "http")

        logger.info(
            f"[service_detection:{session.id}] {p.address}:{p.port} "
            f"score={score} → {'web' if is_web else 'non-web'} service={service!r}"
        )

        if service != p.service or is_web != p.is_web:
            Port.objects.filter(id=p.id).update(service=service, is_web=is_web)
            updated += 1

    logger.info(
        f"[service_detection:{session.id}] {updated}/{len(open_ports)} ports classified"
    )
    return updated
```

- [ ] **Step 4: Update existing tests that break due to behavior change**

The following three tests in `TestDetectServices` need updated assertions. Replace their bodies:

**`test_port_443_fallback_when_all_probes_fail`** — old: asserts `is_web=True`. New behavior: port 443 with zero signals scores +20 < 50 → non-web.

```python
    def test_port_443_fallback_when_all_probes_fail(self):
        """Port 443 with no signals scores only port hint (20) — non-web under confidence scoring."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        p443 = Port.objects.get(session=sess, port=443)
        assert p443.is_web is False
        assert p443.service == ""
```

**`test_port_80_fallback_when_all_probes_fail`** — same: port 80 with zero signals → non-web.

```python
    def test_port_80_fallback_when_all_probes_fail(self):
        """Port 80 with no signals scores only port hint (20) — non-web under confidence scoring."""
        from apps.core.assets.models import Port
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={}):
            detect_services(sess)

        p80 = Port.objects.get(session=sess, port=80)
        assert p80.is_web is False
        assert p80.service == ""
```

**`test_returns_count_of_updated_ports`** — old: expected count=3. New behavior: port 80 and 443 get no service change (service stays ""), port 22 gets service="ssh". Count=1. (Note: this test appears twice in the file — update both.)

```python
    def test_returns_count_of_updated_ports(self):
        sess = self._make_session()

        with patch("apps.core.service_detection.detector._probe_http", return_value=False), \
             patch("apps.core.service_detection.detector._grab_banner", return_value=""), \
             patch("apps.core.service_detection.detector._nmap_sv", return_value={22: "ssh"}):
            count = detect_services(sess)

        # port 22 → service="ssh" (changed); ports 80 and 443 → no signal, no change
        assert count == 1
```

Also add `_grab_banner` mocks to the remaining existing `TestDetectServices` tests that don't have them yet — `test_port_443_probe_result_takes_priority_over_fallback`, `test_ssh_port_classified_as_non_web`, `test_nmap_fallback_non_standard_https`, `test_nmap_fallback_ssl_tunnel_non_standard`, `test_nmap_fallback_unknown_stays_non_web`, `test_undetectable_non_standard_port_stays_non_web`, `test_empty_session`. Add to each:

```python
patch("apps.core.service_detection.detector._grab_banner", return_value=""),
```

as a context manager alongside the existing `_probe_http` and `_nmap_sv` patches.

- [ ] **Step 5: Run the full service detection test suite**

```bash
uv run pytest tests/unit/test_service_detection.py -v
```

Expected: all PASSED. Count should be 16 existing + 5 new = approximately 30+ tests.

- [ ] **Step 6: Commit**

```bash
git add apps/core/service_detection/detector.py tests/unit/test_service_detection.py
git commit -m "feat(service_detection): replace binary cascade with confidence scoring

tcpwrapped no longer forces is_web=True. ssl/unknown on non-web ports
scores +10 only. Banner grab runs first to skip HTTP probes on SSH/FTP/SMTP.
"
```

---

## Task 4: Full Test Suite Verification

**Files:** none changed

- [ ] **Step 1: Run the full fast test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all PASSED. If any test outside `test_service_detection.py` fails, investigate — no other file should be affected by these changes.

- [ ] **Step 2: Commit final state (only if Step 1 passes)**

No new commit needed — all changes were committed in Tasks 1–3. This step is just verification.
