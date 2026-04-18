# Pipeline Phase Reordering Design

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reorder scan pipeline phases so all non-web port scanning runs before web URL discovery, and clean up tls_checker dead code.

**Architecture:** Move nuclei_network from Phase 9 to Phase 7 (alongside existing non-web tools), move httpx from Phase 6 to Phase 8, move nuclei (web) and web_checker from Phase 8 to Phase 9. Remove dead web-port branch from tls_checker collector and add is_web=False filter to ssh_checker.

**Tech Stack:** Django AppConfig tool_meta, Python ssl/socket, nuclei binary

---

## Current Pipeline

```
Phase 1  — domain_security
Phase 2  — subfinder
Phase 3  — dnsx
Phase 4  — naabu
Phase 5  — service_detection   (classify Port.is_web + Port.service)
Phase 6  — httpx               (web URL discovery)  ← moves to 8
Phase 7  — nmap, tls_checker, ssh_checker           ← nuclei_network joins here
Phase 8  — nuclei (web), web_checker                ← moves to 9
Phase 9  — nuclei_network                           ← moves to 7
```

## Proposed Pipeline

```
Phase 1  — domain_security
Phase 2  — subfinder
Phase 3  — dnsx
Phase 4  — naabu
Phase 5  — service_detection        (classify Port.is_web + Port.service)
Phase 7  — nmap                     (is_web=False — CVE scan via NSE)
            tls_checker             (is_web=False — encryption analysis)
            ssh_checker             (is_web=False, service=ssh|port=22)
            nuclei_network          (is_web=False — network templates)
Phase 8  — httpx                    (web URL discovery via subdomain:port)
Phase 9  — nuclei (web)             (URL targets — HTTP templates)
            web_checker             (URL targets — headers/cookies/CORS)
```

Phase 6 is intentionally vacant — reserved for future tools between service classification and non-web scanning.

---

## Change 1: Phase number updates (apps.py only)

### httpx — phase 6 → 8

**File:** `apps/httpx/apps.py`

```python
tool_meta = {
    "label": "HTTPx (Web Probe)",
    "runner": "apps.httpx.scanner.run_httpx",
    "phase": 8,          # was 6
    "requires": ["naabu"],
    "produces_findings": False,
}
```

### nuclei_network — phase 9 → 7

**File:** `apps/nuclei_network/apps.py`

```python
tool_meta = {
    "label": "Nuclei (Network Scan)",
    "runner": "apps.nuclei_network.scanner.run_nuclei_network",
    "phase": 7,          # was 9
    "requires": ["naabu", "service_detection"],
    "produces_findings": True,
}
```

### nuclei (web) — phase 8 → 9

**File:** `apps/nuclei/apps.py`

```python
tool_meta = {
    "label": "Nuclei (Web Vuln Scan)",
    "runner": "apps.nuclei.scanner.run_nuclei",
    "phase": 9,          # was 8
    "requires": ["httpx"],
    "produces_findings": True,
}
```

### web_checker — phase 8 → 9

**File:** `apps/web_checker/apps.py`

```python
tool_meta = {
    "label": "Web Checker",
    "runner": "apps.web_checker.scanner.run_web_check",
    "phase": 9,          # was 8
    "requires": ["httpx"],
    "produces_findings": True,
}
```

---

## Change 2: tls_checker dead code cleanup

**File:** `apps/tls_checker/collector.py`

The port query at line 420 already has `is_web=False`, making the `if p.is_web:` branch (lines 458–485) unreachable dead code. The `url_by_port` dict (lines 426–429) is only consumed by that dead branch.

**Remove:**
1. `url_by_port` lookup block (lines 426–429)
2. The `if p.is_web:` branch and its entire body (lines 458–485)
3. `is_web` and `scheme` from the result dict docstring
4. `hsts_header` note in the docstring (HSTS only applied in the web branch)
5. `URL` import at line 417 (no longer needed)

**Update docstring** — change opening line from "Probe all open ports" to "Probe all non-web open ports", remove `is_web`, `scheme`, `hsts_header` from the return dict description.

The remaining branches (inherently insecure, TLS-capable, unknown service fallback) are all reachable and correct — no changes needed there.

---

## Change 3: ssh_checker — add is_web=False filter

**File:** `apps/ssh_checker/collector.py`

SSH ports are never classified as web, but the filter is inconsistent with the other Phase 7 tools. Add `is_web=False` for clarity and defence-in-depth.

```python
# Before
ssh_ports = list(Port.objects.filter(
    session=session, state="open",
).filter(
    db_models.Q(service="ssh") | db_models.Q(port=22)
))

# After
ssh_ports = list(Port.objects.filter(
    session=session, state="open", is_web=False,
).filter(
    db_models.Q(service="ssh") | db_models.Q(port=22)
))
```

---

## Dependency verification

| Tool | Needs | Available at phase |
|---|---|---|
| nmap (7) | Port.is_web=False | Phase 5 ✓ |
| tls_checker (7) | Port.is_web=False, Port.service | Phase 5 ✓ |
| ssh_checker (7) | Port.service="ssh" | Phase 5 ✓ |
| nuclei_network (7) | Port.is_web=False, Port.service | Phase 5 ✓ |
| httpx (8) | Port records, Subdomain records | Phase 4+3 ✓ |
| nuclei web (9) | URL records | Phase 8 ✓ |
| web_checker (9) | URL records | Phase 8 ✓ |

No circular dependencies. No tool reads data produced by a later phase.

---

## What does NOT change

- No model changes — `Port`, `URL`, `Finding`, `Subdomain`, `IPAddress` untouched
- No migrations
- No new files
- No changes to `service_detection` (Phase 5) — runs identically
- No changes to `nmap`, `nuclei (web)` scanner/collector/analyzer logic
- `nuclei_network` collector already filters `is_web=False` — no logic change needed
- `tls_checker` collector query already has `is_web=False` — no behaviour change, only dead code removal

---

## Testing

Existing test suites cover the tool logic independently. After this change, verify:

1. `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py` — all pass
2. Workflow runner orders tools by phase — confirm `get_tool_phases()` returns updated numbers
3. In a live scan, confirm httpx URL records are created before nuclei/web_checker run (check scan logs)
4. Confirm nuclei_network runs at Phase 7 (before httpx) and finds no URL records to depend on
