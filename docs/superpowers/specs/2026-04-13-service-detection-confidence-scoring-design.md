# Service Detection — Confidence Scoring Design

**Date:** 2026-04-13
**Status:** Approved
**Scope:** `apps/core/service_detection/detector.py` only

## Problem

The current service detection (`Phase 5`) uses a binary pass/fail cascade:

1. HTTP probe succeeds → `is_web=True`
2. nmap identifies a known web service → `is_web=True`
3. `tcpwrapped` → forced `is_web=True` ← **false positive source**
4. `ssl/unknown` → forced `is_web=True` ← **false positive source**
5. Well-known port fallback → `is_web=True`

If `is_web` is wrong, the entire downstream pipeline is wrong:
- A non-web port marked `is_web=True` is skipped by nmap's CVE scan.
- A web port marked `is_web=False` is never probed by httpx/nuclei.

The root cause: `tcpwrapped` and `ssl/unknown` provide no protocol information, but the current code treats them as web signals. This produces false positives that corrupt the attack strategy.

## Goal

Replace binary pass/fail with a **confidence score** built from multiple independent signals. A port is only classified as web if enough positive evidence accumulates above a threshold. No single ambiguous signal (`tcpwrapped`, `ssl/unknown`) can force a web classification.

## Scoring Model

Each port accumulates a score from all signals. Final classification: score ≥ 50 → `is_web=True`.

| Signal | Score | Notes |
|---|---|---|
| HTTP probe succeeded (hostname) | +80 | Strongest positive signal |
| HTTP probe succeeded (raw IP fallback) | +60 | Weaker — CDN may reject |
| Banner contains `HTTP/` or `<!DOCTYPE` | +70 | Raw TCP confirms HTTP |
| nmap reports known web service | +70 | `http`, `https`, `ssl/http`, etc. |
| Port in known web ports (80/443/8080/8443) | +20 | Weak hint, always applied |
| nmap reports known non-web service | −80 | `ssh`, `ftp`, `smtp`, `imap`, etc. |
| Banner contains SSH/FTP/SMTP signature | −70 | `SSH-2.0-`, `220 `, `EHLO` |
| `tcpwrapped` | 0 | No information — ignored |
| `ssl/unknown` on known web port (80/443/8080/8443) | +40 | CDN/TLS fronting likely |
| `ssl/unknown` on other port | +10 | Weak hint only |

**Threshold:** ≥ 50 → `is_web=True`, < 50 → `is_web=False`

A port needs at least one meaningful positive signal to be classified as web. `tcpwrapped` alone scores 0 — it can never force a web classification. A non-web banner (−70/−80) overrides a weak port-number hint (+20).

## Detection Order (per port)

Banner grab runs **first** to short-circuit expensive HTTP probing for non-web ports.

```
Step 1 — Banner grab (1 raw TCP connection, 3s timeout, 512 bytes)
  SSH/FTP/SMTP banner → score −70 → skip Steps 2–3 (saves 4 HTTP probes)
  HTTP banner (HTTP/ or <!DOCTYPE) → score +70 → run 1 HTTP probe to confirm
  Empty/unknown banner → proceed to Step 2

Step 2 — HTTP probing (up to 4 probes, only if banner gave no clear signal)
  HTTPS + hostname → score +80
  HTTP  + hostname → score +80
  HTTPS + raw IP   → score +60  (only if hostname ≠ IP)
  HTTP  + raw IP   → score +60  (only if hostname ≠ IP)
  Stop as soon as score ≥ 50

Step 3 — nmap -sV (batched per IP, only if score still ambiguous after Steps 1–2)
  Known web service name → score +70
  Known non-web service name → score −80
  tcpwrapped → score 0
  ssl/unknown on known web port → score +40
  ssl/unknown on other port → score +10

Step 4 — Port number hint (always applied)
  80 / 443 / 8080 / 8443 → score +20

Final: score ≥ 50 → is_web=True, else is_web=False
```

## Request Count

| Scenario | Requests | vs Today |
|---|---|---|
| SSH/FTP/SMTP (clear banner) | 1 TCP | was 4 HTTP + nmap |
| HTTP service (HTTP banner) | 1 TCP + 1 HTTP | was 4 HTTP |
| Ambiguous (no banner, not HTTP) | 1 TCP + up to 4 HTTP + nmap | same as today |

For typical non-web ports: **1 request instead of 4+.**

## Architecture

All changes are confined to `apps/core/service_detection/detector.py`. No other files change. No new models, no migrations, no schema changes.

**New internal functions:**

### `_grab_banner(host: str, port: int) -> str`
- Opens raw TCP socket to `host:port`
- Reads up to 512 bytes with 3-second timeout
- Returns decoded string (ignores decode errors)
- Returns `""` on any connection failure (timeout, refused, etc.)

### `_score_port(port, banner: str, http_result: tuple[str, int], nmap_svc: str) -> int`
- Pure function — no DB writes, no side effects
- Applies all signal weights, returns total score
- Parameters:
  - `banner`: raw bytes decoded from TCP banner grab
  - `http_result`: `(scheme, score_delta)` from HTTP probing, `("", 0)` if none
  - `nmap_svc`: nmap service name string, `""` if not run

### `detect_services(session) -> int`
- Orchestrates the 4-step flow
- Logs score breakdown per port at DEBUG level:
  ```
  [service_detection] api.example.com:9200 score=-10 → non-web
    signals: banner=elasticsearch(-70), nmap=elasticsearch(-80), port_hint=+20
  ```

## Non-Goals

- No changes to nmap batching logic — still grouped by `(ip, hostname)`.
- No changes to the well-known port list — stays as `_KNOWN_WEB_PORTS`.
- No UI changes — `Port.is_web` and `Port.service` fields are unchanged.
- No changes to how downstream tools consume `is_web`.
- No configurable thresholds — 50 is hardcoded; can be made configurable later.

## Testing

Update `tests/unit/test_service_detection.py`:

- Test `_grab_banner()`: mock socket, return SSH banner → negative score contribution
- Test `_score_port()`: unit test each signal in isolation
- Test `tcpwrapped` → score 0 → `is_web=False` (the key regression test)
- Test `ssl/unknown` on port 9200 → score +10 < 50 → `is_web=False`
- Test `ssl/unknown` on port 443 → score +40+20=60 ≥ 50 → `is_web=True` (CDN fronting preserved)
- Test HTTP probe success → score +80 ≥ 50 → `is_web=True`
- Test SSH banner → score −70 → skips HTTP probing → `is_web=False`
- Existing tests for `detect_services()` should continue to pass with mock adjustments
