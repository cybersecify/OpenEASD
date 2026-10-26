# tldsquatting FP-Reduction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify each registered lookalike as `owned` / `parked` / `unrelated` / `pre_existing` / `threat`, collapse the benign classes into auditable `info` rollup findings, and keep only real threats as individual findings — shrinking large-brand tldsquatting output from hundreds of rows to a readable handful.

**Architecture:** A new pure `classify.py` decides the class from signals the collector already gathers plus a passively-fetched target baseline (`target_ns`, registrant). The analyzer groups by class: benign → one `info` rollup per class (full list in `extra`), `threat` → the existing per-domain scoring+cap path (unchanged). `scoring.py` is untouched.

**Tech Stack:** Django 5.2, pytest + pytest-django (real postgres service DB), `uv run` for everything.

**Spec:** `docs/specs/2026-09-30-tldsquatting-fp-reduction.md`

## Global Constraints

- Use `uv run python` / `uv run pytest` — never bare python/pytest.
- Branch `feat/tldsquatting-fp-reduction` (off main); never commit to `main`.
- Every commit message ends with EXACTLY these two trailer lines (no other Co-Authored-By):
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_018Dp8ybrePZ5NXcxrMSnnhY`
- Do NOT modify `justfile`, `frontend/dist/`, or files outside a task's list.
- **Passive contract:** any new lookup targets public DNS / RDAP only — never the org's own systems.
- **`scoring.py` is untouched.**
- **FN-safety (guarded by tests):** a candidate with `brand_mentioned`, or the email-only phishing-prep fingerprint (`has_mx and not has_a`, or SPF/DMARC without a website), is **always `threat`** (never collapsed) — except `pre_existing`; and `owned` requires a **positive** NS/registrant match.

---

### Task 1: Collector — gather the target ownership baseline + per-candidate registrant

**Files:**
- Modify: `apps/tldsquatting/collector.py`
- Test: `tests/unit/test_tldsquatting.py`

**Interfaces:**
- Produces on each record: `record["registrant"]` (str|None, the candidate's RDAP registrant), `record["target_ns"]` (list[str], the apex's authoritative NS hosts), `record["target_registrant"]` (str|None), `record["target_registrar"]` (str|None). `target_created`/`created`/`predates_target` remain as today.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/unit/test_tldsquatting.py
def test_rdap_info_parses_registrant_and_registrar():
    from apps.tldsquatting import collector
    payload = {
        "events": [{"eventAction": "registration", "eventDate": "2015-04-01T00:00:00Z"}],
        "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Zoho Corp"]]]}],
        "registrar": "MarkMonitor Inc.",
    }
    class _R:
        status_code = 200
        def json(self): return payload
    from unittest.mock import patch
    with patch("apps.tldsquatting.collector.requests.get", return_value=_R()):
        info = collector._rdap_info("zoho.com")
    assert info["created"] == "2015-04-01"
    assert info["registrant"] == "Zoho Corp"
    assert "MarkMonitor" in (info["registrar"] or "")


def test_resolve_target_ns_returns_host_list():
    from apps.tldsquatting import collector
    from unittest.mock import patch, MagicMock
    ans = [MagicMock(**{"to_text.return_value": "ns1.zoho.com."}),
           MagicMock(**{"to_text.return_value": "ns2.zoho.com."})]
    with patch("apps.tldsquatting.collector._thread_resolver") as mk:
        mk.return_value.resolve.return_value = ans
        ns = collector._resolve_target_ns("zoho.com")
    assert "ns1.zoho.com" in ns and "ns2.zoho.com" in ns
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_tldsquatting.py -k "rdap_info or resolve_target_ns" -v`
Expected: FAIL — `_rdap_info` / `_resolve_target_ns` not defined.

- [ ] **Step 3: Write minimal implementation**

In `collector.py`:
- Add `_rdap_info(domain, timeout=8) -> dict` that reuses the existing `_rdap_created` request logic but returns `{"created": <iso|None>, "registrant": <str|None>, "registrar": <str|None>}`. Parse `registrant` from the `entities` array (role `"registrant"`, take vCard `fn`, else the entity `handle`); `registrar` from top-level `"registrar"` or the `entities` role `"registrar"` fn. Never raises → return all-None on any failure. Keep `_rdap_created` as a thin wrapper: `return _rdap_info(domain, timeout)["created"]`.
- Add `_resolve_target_ns(apex, timeout=None) -> list[str]`: resolve the apex `NS` via `_thread_resolver()`, return normalized (`.rstrip(".").lower()`) NS host strings; never raises → `[]` on failure. Passive (public resolver).
- In `_enrich_registration_age` (rename its docstring to mention ownership, keep the function name to minimize churn OR rename to `_enrich_ownership` and update the one caller in `collect`): compute the target baseline ONCE — `_ti = _rdap_info(apex, timeout)`, `target_ns = _resolve_target_ns(apex, timeout)` — and in the per-record `_age` closure set `record["created"]`, `record["registrant"]` from `_rdap_info(candidate)` (replace the `_rdap_created` call with `_rdap_info`), plus `record["target_created"] = _ti["created"]`, `record["target_registrant"] = _ti["registrant"]`, `record["target_registrar"] = _ti["registrar"]`, `record["target_ns"] = target_ns`, and `record["predates_target"]` as today. Records beyond the RDAP cap still get `target_ns`/`target_registrant` (set them on ALL results, not just `to_age`, so classification works for every candidate — set the target baseline in a cheap loop over `results` even past the cap; only the per-candidate RDAP `created`/`registrant` is cap-bounded).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_tldsquatting.py -k "rdap_info or resolve_target_ns" -v` → PASS. Then `uv run pytest tests/unit/test_tldsquatting.py -q` → all still green (existing RDAP-age tests must still pass; adjust any that patched `_rdap_created` to patch `_rdap_info` if needed).

- [ ] **Step 5: Commit**

```bash
git add apps/tldsquatting/collector.py tests/unit/test_tldsquatting.py
git commit -m "feat: tldsquatting collector gathers target ownership baseline (NS + registrant)"
```

---

### Task 2: `classify.py` — pure lookalike classifier

**Files:**
- Create: `apps/tldsquatting/classify.py`
- Test: `tests/unit/test_tldsquatting_classify.py`

**Interfaces:**
- Consumes: a record dict + target baseline.
- Produces: `classify_lookalike(record, target_ns_ops, target_registrant, target_registrar) -> str` returning one of `"pre_existing" | "owned" | "parked" | "unrelated" | "threat"`; and `ns_operators(ns_targets) -> set[str]` (registrable-domain set of NS hosts).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_tldsquatting_classify.py
from apps.tldsquatting.classify import classify_lookalike, ns_operators


def _rec(**kw):
    base = dict(candidate="x.com", ns_targets=[], has_a=True, has_aaaa=False, has_mx=False,
                has_spf=False, has_dmarc=False, brand_mentioned=False, parked=False,
                content_checked=True, predates_target=False, registrant=None)
    base.update(kw); return base


def test_ns_operators_reduces_to_registrable():
    assert ns_operators(["ns1.zoho.com.", "ns2.zoho.com."]) == {"zoho.com"}


def test_pre_existing_wins():
    assert classify_lookalike(_rec(predates_target=True, brand_mentioned=True), {"zoho.com"}, None, None) == "pre_existing"


def test_owned_by_ns_match_even_with_brand():
    # a domain on YOUR nameservers is yours; brand mention is expected there.
    assert classify_lookalike(_rec(ns_targets=["ns1.zoho.com."], brand_mentioned=True),
                              {"zoho.com"}, None, None) == "owned"


def test_owned_by_registrant_match():
    assert classify_lookalike(_rec(registrant="Zoho Corp"), {"other.com"}, "zoho corp", None) == "owned"


def test_brand_mention_forces_threat_when_not_owned():
    assert classify_lookalike(_rec(ns_targets=["ns1.evil.com."], brand_mentioned=True),
                              {"zoho.com"}, None, None) == "threat"


def test_email_only_forces_threat():
    r = _rec(has_a=False, has_aaaa=False, has_mx=True, content_checked=False)
    assert classify_lookalike(r, {"zoho.com"}, None, None) == "threat"


def test_parked_when_no_brand_no_owned():
    assert classify_lookalike(_rec(ns_targets=["ns.parkingcrew.net."], parked=True),
                              {"zoho.com"}, None, None) == "parked"


def test_unrelated_diff_ns_no_brand_own_content():
    assert classify_lookalike(_rec(ns_targets=["ns1.somehost.com."], has_a=True, content_checked=True),
                              {"zoho.com"}, None, None) == "unrelated"


def test_unrelated_with_login_form_still_unrelated():
    # postman.catering: login form but no brand mention, different NS → unrelated.
    r = _rec(ns_targets=["ns1.gandi.net."], has_a=True, content_checked=True, brand_mentioned=False)
    assert classify_lookalike(r, {"postman.com"}, None, None) == "unrelated"


def test_resolving_no_content_check_is_threat():
    # has_a but homepage never fetched (content_checked False) and no other signal → threat (don't collapse blindly)
    assert classify_lookalike(_rec(ns_targets=["ns1.x.com."], content_checked=False),
                              {"zoho.com"}, None, None) == "threat"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_tldsquatting_classify.py -v` → FAIL (module missing).

- [ ] **Step 3: Write minimal implementation**

```python
# apps/tldsquatting/classify.py
"""Pure classification of a registered lookalike into owned / parked / unrelated /
pre_existing / threat, from signals the collector gathered + a passive target
baseline. No network, no side effects. See docs/specs/2026-09-30-tldsquatting-fp-reduction.md.
"""
from .collector import _split_apex

CLASSES = ("pre_existing", "owned", "parked", "unrelated", "threat")


def ns_operators(ns_targets) -> set:
    ops = set()
    for t in ns_targets or []:
        host = str(t).strip().rstrip(".").lower()
        if not host:
            continue
        name, tld = _split_apex(host)
        ops.add(f"{name}.{tld}" if tld else host)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_tldsquatting_classify.py -v` → PASS (10 passed).

- [ ] **Step 5: Commit**

```bash
git add apps/tldsquatting/classify.py tests/unit/test_tldsquatting_classify.py
git commit -m "feat: pure classify_lookalike (owned/parked/unrelated/pre_existing/threat)"
```

---

### Task 3: Analyzer — group by class, collapse benign into rollups, toggle

**Files:**
- Modify: `apps/tldsquatting/analyzer.py`
- Modify: `openeasd/settings/base.py`
- Test: `tests/unit/test_tldsquatting.py` (add cases)

**Interfaces:**
- Consumes: `classify_lookalike`/`ns_operators` (Task 2), target baseline on records (Task 1), `settings.TLDSQUATTING_COLLAPSE_BENIGN`.
- Produces: `analyze(session, results)` now emits per-`threat` individual findings (unchanged shape/severity/cap) PLUS one `info` rollup Finding per non-empty benign class (`check_type` `lookalike_owned`/`lookalike_parked`/`lookalike_unrelated`/`lookalike_pre_existing`, `extra["domains"]` = full member list). Toggle off ⇒ all classes individual (pre-feature behavior).

- [ ] **Step 1: Write the failing tests**

```python
# add to tests/unit/test_tldsquatting.py
def _analyze(session, recs):
    from apps.tldsquatting.analyzer import analyze
    return analyze(session, recs)

@pytest.mark.django_db
def test_owned_lookalikes_collapse_to_one_info_rollup(settings):
    settings.TLDSQUATTING_COLLAPSE_BENIGN = True
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="zoho.com", scan_type="full", status="completed")
    base = dict(has_a=True, content_checked=True, target_ns=["ns1.zoho.com"], target_created="2000-01-01")
    recs = [
        {**base, "candidate": "zoho.io", "ns_targets": ["ns1.zoho.com."], "technique": "tld_swap"},
        {**base, "candidate": "zoho.co", "ns_targets": ["ns2.zoho.com."], "technique": "tld_swap"},
    ]
    findings = _analyze(s, recs)
    owned = [f for f in findings if f.check_type == "lookalike_owned"]
    assert len(owned) == 1
    assert owned[0].severity == "info"
    assert len(owned[0].extra["domains"]) == 2
    assert not [f for f in findings if f.check_type == "lookalike_domain"]  # none individual

@pytest.mark.django_db
def test_threat_stays_individual(settings):
    settings.TLDSQUATTING_COLLAPSE_BENIGN = True
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="zoho.com", scan_type="full", status="completed")
    rec = {"candidate": "zoho-login.com", "ns_targets": ["ns1.evil.com."], "has_a": True,
           "content_checked": True, "brand_mentioned": True, "login_form": True,
           "target_ns": ["ns1.zoho.com"], "target_created": "2000-01-01", "technique": "combo"}
    findings = _analyze(s, [rec])
    ind = [f for f in findings if f.check_type == "lookalike_domain"]
    assert len(ind) == 1 and ind[0].target == "zoho-login.com"
    assert not [f for f in findings if f.check_type.startswith("lookalike_") and f.check_type != "lookalike_domain"]

@pytest.mark.django_db
def test_toggle_off_keeps_per_domain(settings):
    settings.TLDSQUATTING_COLLAPSE_BENIGN = False
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="zoho.com", scan_type="full", status="completed")
    rec = {"candidate": "zoho.io", "ns_targets": ["ns1.zoho.com."], "has_a": True,
           "content_checked": True, "target_ns": ["ns1.zoho.com"], "target_created": "2000-01-01", "technique": "x"}
    findings = _analyze(s, [rec])
    assert [f for f in findings if f.check_type == "lookalike_domain"]  # individual, not a rollup
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/test_tldsquatting.py -k "collapse or threat_stays or toggle_off" -v` → FAIL.

- [ ] **Step 3: Implement**

In `settings/base.py` (near the other `TLDSQUATTING_*`): `TLDSQUATTING_COLLAPSE_BENIGN = config("TLDSQUATTING_COLLAPSE_BENIGN", default=True, cast=bool)`.

In `analyzer.py`:
- Extract the current per-record Finding-building block (the whole loop body that computes scoring, cap, and appends the `lookalike_domain` Finding) into a helper `_individual_finding(session, apex, record) -> Finding` and have it `return` the Finding (unchanged logic).
- Add `_rollup_finding(session, apex, cls, records) -> Finding`:
  - `_TITLE = {"owned": "owned lookalike domains (share nameservers/registrant with {apex})", ...}` etc.; severity `"info"`; check_type `f"lookalike_{cls}"`.
  - Compute per-domain scores (call `calculate_risk_score`/`calculate_threat_score` for the extra list — pure, cheap), build `extra["domains"] = [{"domain", "technique", "reason", "risk_score", "threat_score", "threat_level", "created"}]`, and `extra["count"] = len(records)`, `extra["source_data"]="tldsquatting"`. `reason` is a short per-class string (e.g. owned → "same nameservers/registrant as target").
  - `target` = apex.
- Rewrite `analyze`: resolve target baseline once from the records (`target_ns_ops = ns_operators(_first(results,"target_ns"))`, `target_registrant = _first(results,"target_registrant")`, `target_registrar = _first(results,"target_registrar")`, where `_first` returns the first non-None value across records). Bucket each record via `classify_lookalike`. Emit `_individual_finding` for every `threat`. For benign classes: if `TLDSQUATTING_COLLAPSE_BENIGN`, emit one `_rollup_finding` per non-empty class; else emit `_individual_finding` for each (preserves per-domain info/low severity via the existing cap). Keep the existing `is_apex`/PRE-EXISTING handling inside `_individual_finding`.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/test_tldsquatting.py -q` → all green (existing per-domain tests still pass because they either hit `threat` or run with records lacking `target_ns` → classify falls through to `threat`/`unrelated`; adjust the few existing severity tests that now classify as benign to set a `threat` signal, e.g. `brand_mentioned=True`, OR assert against the rollup — keep each existing assertion meaningful).

- [ ] **Step 5: Commit**

```bash
git add apps/tldsquatting/analyzer.py openeasd/settings/base.py tests/unit/test_tldsquatting.py
git commit -m "feat: collapse benign lookalikes into info rollups; threats stay individual"
```

---

### Task 4: Report — render rollup domain lists

**Files:**
- Modify: `apps/core/console/reports/views.py` and/or `templates/reports/scan_report.html`
- Test: `tests/unit/test_reports.py`

**Interfaces:**
- Consumes: findings whose `check_type` starts `lookalike_` (not `lookalike_domain`) and carry `extra["domains"]`.
- Produces: the PDF renders each rollup as its title (with count) + the member domain list (domain + reason) from `extra["domains"]`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/unit/test_reports.py — reuse the file's existing _render_pdf HTML-capture pattern
    def test_report_renders_lookalike_rollup_list(self):
        html = self._render_report_html_with_finding(
            source="tldsquatting", check_type="lookalike_owned", severity="info",
            title="2 owned lookalike domains (share nameservers with zoho.com)",
            extra={"count": 2, "domains": [
                {"domain": "zoho.io", "reason": "same nameservers as target"},
                {"domain": "zoho.co", "reason": "same nameservers as target"}]},
        )
        assert "zoho.io" in html and "zoho.co" in html
        assert "owned lookalike domains" in html
```

- [ ] **Step 2–4:** run (fail) → in the report finding-rendering, when `extra["domains"]` is present render the list (domain + reason) beneath the finding title (guard on presence so all other findings are unchanged) → run (`uv run pytest tests/unit/test_reports.py -q`, all green, existing report tests unchanged).

- [ ] **Step 5: Commit**

```bash
git add apps/core/console/reports/views.py templates/reports/scan_report.html tests/unit/test_reports.py
git commit -m "feat: report renders tldsquatting rollup domain lists"
```

---

### Task 5: Docs + spec status flip

**Files:**
- Modify: `docs/03-system.md`, `CLAUDE.md`, `docs/specs/2026-09-30-tldsquatting-fp-reduction.md`
- Test: full fast suite

**Interfaces:** none new.

- [ ] **Step 1:** In `CLAUDE.md` update the `tldsquatting` tool-table row to note the classify + rollup behavior (owned/parked/unrelated/pre_existing collapse to `info` rollups; threats stay individual `lookalike_domain`; `TLDSQUATTING_COLLAPSE_BENIGN` toggle). Add `apps/tldsquatting/classify.py` + the new test file(s) to the test table with real `--collect-only` counts and bump Total. In `docs/03-system.md` note the classification/rollup step under the Brand Threat tool description. Flip the spec Status header from `📝 Proposed` to `✅ Implemented`.
- [ ] **Step 2:** Run `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py` → all green, coverage ≥ 80%.
- [ ] **Step 3: Commit**

```bash
git add docs/03-system.md CLAUDE.md docs/specs/2026-09-30-tldsquatting-fp-reduction.md
git commit -m "docs: document tldsquatting classification + rollups; spec -> Implemented"
```

---

## Self-Review

**Spec coverage:** §2 target baseline → Task 1; §3 classification + forcing rules → Task 2; §4 rollup collapse + threat-individual → Task 3; §5 toggle → Task 3; §6 report → Task 4; §7 files → Tasks 1–5; §8 invariants → tested in Tasks 2–3; §9 residual FN → documented, no code. `scoring.py` untouched (no task edits it). ✅

**Placeholder scan:** Task 4 Steps 2–4 are compressed (reuse the existing `test_reports.py` capture pattern) — acceptable because that pattern is already established in the file; no hidden logic. No TBD/TODO.

**Type/name consistency:** `classify_lookalike(record, target_ns_ops, target_registrant, target_registrar)` and `ns_operators(ns_targets)` are used identically in Tasks 2 and 3. Record keys (`ns_targets`, `target_ns`, `registrant`, `target_registrant`, `predates_target`, `has_a`, `content_checked`, `brand_mentioned`, `parked`) match between collector (Task 1) and classifier (Task 2). Rollup `check_type` values (`lookalike_owned`/`_parked`/`_unrelated`/`_pre_existing`) consistent between Tasks 3 and 4. `_individual_finding` = the refactored existing loop body (unchanged behavior).

**Integration points to confirm at execution (repo-specific):** `test_reports.py`'s exact HTML-capture helper name (Task 4); the precise existing per-domain severity tests in `test_tldsquatting.py` that need a `threat` signal added so they still assert what they mean (Task 3 Step 4); `_split_apex` import from `collector` into `classify` (same tool, allowed).
