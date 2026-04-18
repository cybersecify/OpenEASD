# Pipeline Phase Reordering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorder scan pipeline phases so all non-web port scanning (nmap, tls_checker, ssh_checker, nuclei_network) runs at Phase 7 before httpx (Phase 8) discovers web URLs, then web scanning (nuclei, web_checker) runs at Phase 9.

**Architecture:** Change `phase` numbers in four `tool_meta` dicts, remove dead web-port code from `tls_checker` collector and analyzer, and add `is_web=False` filter to `ssh_checker`. No models, migrations, or new files.

**Tech Stack:** Django AppConfig tool_meta, Python, pytest

---

## File Map

| File | Change |
|---|---|
| `apps/httpx/apps.py` | phase 6 → 8 |
| `apps/nuclei_network/apps.py` | phase 9 → 7 |
| `apps/nuclei/apps.py` | phase 8 → 9 |
| `apps/web_checker/apps.py` | phase 8 → 9 |
| `apps/tls_checker/collector.py` | remove `url_by_port` + dead `if p.is_web:` branch + URL import + update docstring |
| `apps/tls_checker/analyzer.py` | remove `_hsts_finding()`, remove `is_web` branches, clean result extra dict |
| `apps/ssh_checker/collector.py` | add `is_web=False` to Port query |
| `tests/unit/test_tls_checker.py` | remove web-port and HSTS tests, update `_make_result` helper |
| `tests/unit/test_ssh_checker.py` | add test that `is_web=True` ports are excluded from collect |

---

## Task 1: Phase number updates

**Files:**
- Modify: `apps/httpx/apps.py`
- Modify: `apps/nuclei_network/apps.py`
- Modify: `apps/nuclei/apps.py`
- Modify: `apps/web_checker/apps.py`

The workflow runner uses `get_tool_phases()` which reads `tool_meta["phase"]` from each AppConfig. Changing only these four numbers is the entire phase reorder.

- [ ] **Step 1: Write a failing test that asserts the new phase numbers**

Create `tests/unit/test_pipeline_phases.py`:

```python
"""Tests that tool_meta phase numbers match the intended pipeline order."""
import pytest


def test_phase_order():
    """Non-web tools (7) must run before httpx (8) and web tools (9)."""
    from apps.core.workflows.registry import get_tool_phases
    phases = get_tool_phases()

    assert phases["httpx"] == 8,           f"httpx: expected 8, got {phases['httpx']}"
    assert phases["nuclei_network"] == 7,  f"nuclei_network: expected 7, got {phases['nuclei_network']}"
    assert phases["nuclei"] == 9,          f"nuclei: expected 9, got {phases['nuclei']}"
    assert phases["web_checker"] == 9,     f"web_checker: expected 9, got {phases['web_checker']}"

    # Non-web tools must all be before httpx
    assert phases["nmap"] < phases["httpx"],          "nmap must run before httpx"
    assert phases["tls_checker"] < phases["httpx"],   "tls_checker must run before httpx"
    assert phases["ssh_checker"] < phases["httpx"],   "ssh_checker must run before httpx"
    assert phases["nuclei_network"] < phases["httpx"],"nuclei_network must run before httpx"

    # Web tools must run after httpx
    assert phases["nuclei"] > phases["httpx"],        "nuclei must run after httpx"
    assert phases["web_checker"] > phases["httpx"],   "web_checker must run after httpx"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/unit/test_pipeline_phases.py -v
```

Expected: FAIL — `httpx: expected 8, got 6`

- [ ] **Step 3: Update phase numbers in all four apps.py files**

`apps/httpx/apps.py` — change `"phase": 6` to `"phase": 8`:

```python
from django.apps import AppConfig


class HttpxConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.httpx"
    label = "httpx"
    verbose_name = "HTTPx (Web Probe)"
    tool_meta = {
        "label": "HTTPx (Web Probe)",
        "runner": "apps.httpx.scanner.run_httpx",
        "phase": 8,
        "requires": ["naabu"],
        "produces_findings": False,
    }
```

`apps/nuclei_network/apps.py` — change `"phase": 9` to `"phase": 7`:

```python
from django.apps import AppConfig


class NucleiNetworkConfig(AppConfig):
    name = "apps.nuclei_network"
    label = "nuclei_network"
    verbose_name = "Nuclei Network"
    tool_meta = {
        "label": "Nuclei (Network Scan)",
        "runner": "apps.nuclei_network.scanner.run_nuclei_network",
        "phase": 7,
        "requires": ["naabu", "service_detection"],
        "produces_findings": True,
    }
```

`apps/nuclei/apps.py` — change `"phase": 8` to `"phase": 9`:

```python
from django.apps import AppConfig


class NucleiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.nuclei"
    label = "nuclei"
    verbose_name = "Nuclei (Web Vuln Scan)"
    tool_meta = {
        "label": "Nuclei (Web Vuln Scan)",
        "runner": "apps.nuclei.scanner.run_nuclei",
        "phase": 9,
        "requires": ["httpx"],
        "produces_findings": True,
    }
```

`apps/web_checker/apps.py` — change `"phase": 8` to `"phase": 9`:

```python
from django.apps import AppConfig


class WebCheckerConfig(AppConfig):
    name = "apps.web_checker"
    label = "web_checker"
    verbose_name = "Web Checker"
    tool_meta = {
        "label": "Web Checker",
        "runner": "apps.web_checker.scanner.run_web_check",
        "phase": 9,
        "requires": ["httpx"],
        "produces_findings": True,
    }
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/unit/test_pipeline_phases.py -v
```

Expected: PASS

- [ ] **Step 5: Run full suite to confirm no regressions**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add apps/httpx/apps.py apps/nuclei_network/apps.py apps/nuclei/apps.py apps/web_checker/apps.py tests/unit/test_pipeline_phases.py
git commit -m "feat: reorder pipeline phases — non-web (7) before httpx (8) before web (9)"
```

---

## Task 2: tls_checker collector dead code removal

**Files:**
- Modify: `apps/tls_checker/collector.py`
- Modify: `tests/unit/test_tls_checker.py`

The port query at line 420 already has `is_web=False`, so the `if p.is_web:` branch (lines 458–485) is unreachable. The `url_by_port` dict and `URL` import are only used by that dead branch.

- [ ] **Step 1: Write failing tests that assert web ports are excluded from collect results**

Add to `tests/unit/test_tls_checker.py` inside the existing `TestTlsCollector` class (search for it near line 670):

```python
def test_web_ports_excluded_from_collect(self):
    """Web ports (is_web=True) must never appear in collect() results."""
    sess = self._make_session()
    with patch("apps.tls_checker.collector._probe_tls", return_value=None):
        with patch("apps.tls_checker.collector._probe_tls_details", return_value=None):
            with patch("apps.tls_checker.collector._check_legacy_protocol_support", return_value={}):
                results = collect(sess)
    web_ports = {r["port"] for r in results if r.get("is_web")}
    assert web_ports == set(), f"Expected no web ports in results, got: {web_ports}"
    port_nums = {r["port"] for r in results}
    assert 443 not in port_nums, "Port 443 (is_web=True) must not appear in collect results"
    assert 80 not in port_nums, "Port 80 (is_web=True) must not appear in collect results"
```

- [ ] **Step 2: Run test to verify it passes (it should already — query is already correct)**

```bash
uv run pytest tests/unit/test_tls_checker.py::TestTlsCollector::test_web_ports_excluded_from_collect -v
```

Expected: PASS (confirming the filter is already working)

- [ ] **Step 3: Remove the dead `if p.is_web:` branch and `url_by_port` from collector**

In `apps/tls_checker/collector.py`, make these changes:

**a) Remove the URL import** (line 417) — find and remove:
```python
# Remove this line:
from apps.core.web_assets.models import URL
```

**b) Remove the `url_by_port` block** (lines 426–430) — find and remove:
```python
# Remove this entire block:
url_by_port: dict[int, object] = {}
for url in URL.objects.filter(session=session).select_related("port"):
    if url.port_id:
        url_by_port[url.port_id] = url
```

**c) Remove the hostname resolution that uses `url_by_port`** (lines 449–456) — replace:
```python
# Remove this block:
url_obj = url_by_port.get(p.id)
if url_obj and url_obj.host:
    host = url_obj.host
elif p.ip_address and p.ip_address.subdomain:
    host = p.ip_address.subdomain.subdomain
else:
    host = ip

# Replace with:
if p.ip_address and p.ip_address.subdomain:
    host = p.ip_address.subdomain.subdomain
else:
    host = ip
```

**d) Remove the entire `if p.is_web:` branch** (lines 458–485) — find and delete this block:
```python
if p.is_web:
    scheme = url_obj.scheme if url_obj else ""
    has_tls = scheme == "https"
    tls_detail: dict = _tls_empty.copy()
    details = None

    if has_tls or not scheme:
        details = _probe_tls_details(ip, port_num, hostname=host)
        if details and not scheme:
            has_tls = True
            scheme = "https"
        if details:
            legacy = _check_legacy_protocol_support(ip, port_num)
            tls_detail = {**details, **legacy}
        else:
            tls_detail = {**_tls_empty, "supports_tls10": False, "supports_tls11": False}
        tls_detail["hsts_header"] = _check_hsts(ip, port_num, host)
    else:
        tls_detail = {**_tls_empty}

    results.append({
        "ip": ip, "port": port_num, "service": service,
        "has_tls": has_tls, "is_web": True, "scheme": scheme,
        "inherently_insecure": False,
        "port_fk": p, "url_fk": url_obj,
        **tls_detail,
    })

elif service in INHERENTLY_INSECURE_SERVICES:
```

After deleting, the `elif` becomes `if`:
```python
if service in INHERENTLY_INSECURE_SERVICES:
```

**e) Update the collect() docstring** — change:
```python
def collect(session) -> list[dict]:
    """
    Probe all open ports for TLS status and configuration.

    Returns one result dict per port that requires TLS analysis:
      {
        ip, port, service,
        has_tls:           bool,
        is_web:            bool,
        scheme:            str | None,       # "http"/"https" for web ports
        inherently_insecure: bool,
        port_fk, url_fk,
        ...
        hsts_header:       str | None,       # Strict-Transport-Security value (HTTPS web ports only)
      }

    Ports with unknown services (not in TLS_CAPABLE or INHERENTLY_INSECURE)
    that are not web ports are omitted — no findings can be generated.
    """
```

To:
```python
def collect(session) -> list[dict]:
    """
    Probe all non-web open ports for TLS status and configuration.

    Returns one result dict per non-web port that requires TLS analysis:
      {
        ip, port, service,
        has_tls:             bool,
        inherently_insecure: bool,
        port_fk,
        tls_version, cipher_name, cipher_bits,
        cert_expiry_days, cert_self_signed, cert_key_type, cert_key_bits,
        cert_sig_algorithm, cert_sig_sha1, cert_san_list, cert_san_mismatch,
        cert_has_sct, cert_trusted,
        supports_tls10, supports_tls11,
      }

    Ports with unknown services (not in TLS_CAPABLE or INHERENTLY_INSECURE)
    are omitted — no findings can be generated.
    """
```

- [ ] **Step 4: Run tests to verify collector still works**

```bash
uv run pytest tests/unit/test_tls_checker.py -v
```

Expected: some tests fail — the web-port collector tests (`test_https_web_port_no_probe`, `test_http_web_port_has_tls_false`) will now fail because web ports no longer appear in results. That is correct — we remove those tests next.

- [ ] **Step 5: Remove dead web-port tests from test_tls_checker.py**

In `tests/unit/test_tls_checker.py`, delete the following test methods entirely:

- `test_https_web_port_no_probe` (tests that 443 with is_web=True appears in results with has_tls=True — no longer true)
- `test_http_web_port_has_tls_false` (tests that 80 with is_web=True appears — no longer true)

Also delete in `TestTlsAnalyzerUnencrypted`:
- `test_http_web_port_finding` (tests the `if is_web:` branch in analyzer — dead code after cleanup)
- `test_https_no_finding` (same dead branch)

Also delete in the HSTS test class (search for `TestTlsAnalyzerHSTS` or similar):
- `test_hsts_missing_https_web_high`
- `test_hsts_present_no_finding`
- `test_hsts_not_checked_for_non_web`
- `test_hsts_not_checked_when_no_tls`

And update `_make_result` helper — remove `is_web`, `scheme`, `hsts_header` parameters and dict keys:

```python
def _make_result(port_fk, ip="1.2.3.4", port=443, service="https",
                 has_tls=True,
                 inherently_insecure=False,
                 tls_version="TLSv1.3", cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
                 cipher_bits=256, cert_expiry_days=365, cert_self_signed=False,
                 cert_key_type="RSA", cert_key_bits=2048,
                 cert_sig_algorithm="sha256WithRSAEncryption", cert_sig_sha1=False,
                 cert_san_list=None, cert_san_mismatch=False, cert_has_sct=True,
                 cert_trusted=True,
                 supports_tls10=False, supports_tls11=False):
    return {
        "ip": ip, "port": port, "service": service,
        "has_tls": has_tls,
        "inherently_insecure": inherently_insecure,
        "port_fk": port_fk,
        "tls_version": tls_version, "cipher_name": cipher_name,
        "cipher_bits": cipher_bits, "cert_expiry_days": cert_expiry_days,
        "cert_self_signed": cert_self_signed,
        "cert_key_type": cert_key_type, "cert_key_bits": cert_key_bits,
        "cert_sig_algorithm": cert_sig_algorithm, "cert_sig_sha1": cert_sig_sha1,
        "cert_san_list": cert_san_list if cert_san_list is not None else [],
        "cert_san_mismatch": cert_san_mismatch, "cert_has_sct": cert_has_sct,
        "cert_trusted": cert_trusted,
        "supports_tls10": supports_tls10, "supports_tls11": supports_tls11,
    }
```

- [ ] **Step 6: Run tests to verify all pass**

```bash
uv run pytest tests/unit/test_tls_checker.py -v
```

Expected: all remaining tests pass

- [ ] **Step 7: Commit**

```bash
git add apps/tls_checker/collector.py tests/unit/test_tls_checker.py
git commit -m "refactor: remove dead web-port branch from tls_checker collector"
```

---

## Task 3: tls_checker analyzer cleanup

**Files:**
- Modify: `apps/tls_checker/analyzer.py`
- Modify: `tests/unit/test_tls_checker.py`

The analyzer reads `is_web` from result dicts to branch into an "Unencrypted HTTP" finding and to call `_hsts_finding()`. Since collector results never have `is_web=True` after Task 2, these branches are dead code.

- [ ] **Step 1: Write a failing test that confirms `hsts_missing` findings are never generated**

Add to `tests/unit/test_tls_checker.py`:

```python
@pytest.mark.django_db
class TestTlsAnalyzerNoHsts:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open",
                                service="https", is_web=False, source="naabu")
        return sess, p

    def test_hsts_finding_never_generated(self):
        """tls_checker no longer produces hsts_missing findings (web ports excluded)."""
        from apps.tls_checker.analyzer import analyze
        sess, port_fk = self._make_port()
        # Even if someone constructs a result with TLS — no HSTS finding
        result = _make_result(port_fk, port=443, service="https", has_tls=True)
        findings = analyze(sess, [result])
        assert not any(f.check_type == "hsts_missing" for f in findings), \
            "hsts_missing finding must not be generated after web-port removal"
```

- [ ] **Step 2: Run test to verify it passes already (HSTS guard is `is_web` which is absent)**

```bash
uv run pytest tests/unit/test_tls_checker.py::TestTlsAnalyzerNoHsts -v
```

Expected: PASS (since `_make_result` no longer has `is_web`, `result.get("is_web")` returns `None` which is falsy)

- [ ] **Step 3: Remove dead code from analyzer**

In `apps/tls_checker/analyzer.py`:

**a) Remove the entire `_hsts_finding()` function** (lines 620–662):
```python
# Delete this entire function:
def _hsts_finding(result: dict, session) -> list[Finding]:
    ...
```

**b) In `analyze()`, remove `is_web` and `url_fk` reads** (lines 688–691):
```python
# Remove these two lines:
is_web = r["is_web"]
...
url_fk = r.get("url_fk")
```

**c) In the `not has_tls` branch, remove the `if is_web:` arm** — change:
```python
if not has_tls:
    if is_web:
        title = f"Unencrypted HTTP service on {ip}:{port_num}"
        description = (
            f"The web service on {ip}:{port_num} is accessible over plain HTTP. "
            ...
        )
        remediation = _HTTP_REMEDIATION
    elif is_inherently_insecure:
        title = f"Insecure protocol {display_svc} on {ip}:{port_num}"
        ...
    else:
        title = f"Unencrypted {display_svc} on {ip}:{port_num}"
        ...
```

To:
```python
if not has_tls:
    if is_inherently_insecure:
        title = f"Insecure protocol {display_svc} on {ip}:{port_num}"
        description = (
            f"{display_svc} on {ip}:{port_num} is an inherently insecure protocol "
            f"with no TLS support. All data — including credentials — is transmitted "
            f"in plaintext and is trivially interceptable."
        )
        remediation = _TLS_REMEDIATION.get(service, _DEFAULT_TLS_REMEDIATION)
    else:
        title = f"Unencrypted {display_svc} on {ip}:{port_num}"
        description = (
            f"{display_svc} on {ip}:{port_num} is accepting connections without TLS. "
            f"Sensitive data exchanged over this service is exposed to interception "
            f"and man-in-the-middle attacks."
        )
        remediation = _TLS_REMEDIATION.get(service, _DEFAULT_TLS_REMEDIATION)
```

**d) Remove `url=url_fk` and `is_web`/`scheme` from the Finding extra dict**:
```python
# Change this:
findings.append(Finding(
    ...
    port=port_fk,
    url=url_fk,
    target=f"{ip}:{port_num}",
    extra={
        "service": service, "port_number": port_num, "address": ip,
        "is_web": is_web, "scheme": r.get("scheme"),
        "inherently_insecure": is_inherently_insecure,
    },
))

# To this:
findings.append(Finding(
    ...
    port=port_fk,
    target=f"{ip}:{port_num}",
    extra={
        "service": service, "port_number": port_num, "address": ip,
        "inherently_insecure": is_inherently_insecure,
    },
))
```

**e) Remove the `_hsts_finding` call** at the bottom of the `else` (has_tls) branch:
```python
# Remove this line:
findings.extend(_hsts_finding(r, session))
```

- [ ] **Step 4: Run full tls_checker test suite**

```bash
uv run pytest tests/unit/test_tls_checker.py -v
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add apps/tls_checker/analyzer.py tests/unit/test_tls_checker.py
git commit -m "refactor: remove HSTS and web-port branches from tls_checker analyzer"
```

---

## Task 4: ssh_checker — add is_web=False filter

**Files:**
- Modify: `apps/ssh_checker/collector.py`
- Modify: `tests/unit/test_ssh_checker.py`

- [ ] **Step 1: Write a failing test that confirms web ports are excluded**

Add to `tests/unit/test_ssh_checker.py` inside the existing `TestSshCollector` integration test class (find it by searching for `class TestSshCollector`):

```python
def test_web_ssh_port_excluded(self):
    """SSH ports classified as is_web=True must be excluded from collect()."""
    from apps.core.scans.models import ScanSession
    from apps.core.assets.models import IPAddress, Port
    sess = ScanSession.objects.create(domain="example.com", scan_type="full")
    ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
    # Create an SSH port that is somehow marked is_web=True (edge case defence)
    Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                        port=22, protocol="tcp", state="open",
                        service="ssh", is_web=True, source="naabu")
    with patch("apps.ssh_checker.collector._probe_ssh", return_value=None):
        results = collect(sess)
    assert results == [], "SSH port with is_web=True must be excluded from collect results"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/unit/test_ssh_checker.py::TestSshCollector::test_web_ssh_port_excluded -v
```

Expected: FAIL — the web SSH port currently appears in results (no `is_web=False` filter)

- [ ] **Step 3: Add is_web=False to the Port query in ssh_checker**

In `apps/ssh_checker/collector.py` around line 301, change:

```python
# Before:
ssh_ports = list(Port.objects.filter(
    session=session, state="open",
).filter(
    db_models.Q(service="ssh") | db_models.Q(port=22)
))

# After:
ssh_ports = list(Port.objects.filter(
    session=session, state="open", is_web=False,
).filter(
    db_models.Q(service="ssh") | db_models.Q(port=22)
))
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/unit/test_ssh_checker.py::TestSshCollector::test_web_ssh_port_excluded -v
```

Expected: PASS

- [ ] **Step 5: Run full ssh_checker suite**

```bash
uv run pytest tests/unit/test_ssh_checker.py -v
```

Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add apps/ssh_checker/collector.py tests/unit/test_ssh_checker.py
git commit -m "fix: exclude is_web=True ports from ssh_checker collect"
```

---

## Task 5: Final verification

- [ ] **Step 1: Run the full test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests pass

- [ ] **Step 2: Verify Django check passes**

```bash
uv run manage.py check
```

Expected: `System check identified no issues`

- [ ] **Step 3: Verify pipeline order in the registry**

```bash
uv run python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'openeasd.settings')
django.setup()
from apps.core.workflows.registry import get_tool_phases
phases = get_tool_phases()
for tool, phase in sorted(phases.items(), key=lambda x: x[1]):
    print(f'  Phase {phase}: {tool}')
"
```

Expected output (tools grouped by phase):
```
  Phase 1: domain_security
  Phase 2: subfinder
  Phase 3: dnsx
  Phase 4: naabu
  Phase 5: service_detection
  Phase 7: nmap
  Phase 7: tls_checker
  Phase 7: ssh_checker
  Phase 7: nuclei_network
  Phase 8: httpx
  Phase 9: nuclei
  Phase 9: web_checker
```

- [ ] **Step 4: Final commit if needed**

```bash
git add -A
git commit -m "chore: pipeline phase reorder — final verification passed"
```
