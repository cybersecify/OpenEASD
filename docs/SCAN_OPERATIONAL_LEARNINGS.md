# Scan Operational Learnings

Problems hit running **real** scans, their root cause, the fix, and the
regression test that now guards each one. Rule: every operational failure we see
in production becomes a documented learning **and** a test, so it can't silently
recur. Add to this list whenever a scan misbehaves.

## nuclei (the biggest source of pain)

**Key correction (verified against ProjectDiscovery maintainers):** nuclei parses
**all** ~13,500 templates into RAM up front (~500 MB, fixed) and *then* applies
`-severity`/`-tags` filters. So severity scoping does **NOT** shrink the startup
parse — it only cuts the *executed* set. The startup parse (~500 MB) on top of
gunicorn + qcluster + Django is what tips a 1 GB box; runtime peak is
`concurrency × bulk-size × per-host buffer`. The levers that actually prevent the
**freeze** are `GOMEMLIMIT` + a small **`-bulk-size`**, not `-severity`.

| Symptom | Root cause | Fix | Guard |
|---|---|---|---|
| **Freeze** (box + web UI unresponsive for minutes) | ~500 MB startup template parse + runtime `c × bulk-size × per-host buffer` on a 1 GB host | `GOMEMLIMIT` soft heap cap **+** small `-bulk-size` per profile (low=5) — NOT `-severity` | `test_nuclei.py::test_go_memory_limit_applied_to_subprocess`, `::test_cmd_includes_memory_and_scope_flags`; `test_settings_security.py::test_bulk_size_scales_down_on_low_profile` |
| **Timeout** (2 h wall hit, run reported `partial`) | Template *execution*: targets × executed templates ÷ polite rate | Severity scoping (drop `info` ≈ 38%) + `-type http` (web run skips dns/tcp/ssl) + `-max-host-error` (abandon dead hosts) → far fewer requests | `test_nuclei.py::test_cmd_scopes_severity_and_drops_info`, `::test_cmd_includes_memory_and_scope_flags` |
| **Low value / noise** | `info` tech-detect templates are already covered by httpx `-tech-detect` + web_checker; they bury real findings | Scope to `critical,high,medium(,low)` per profile (`NUCLEI_SEVERITY`). NOTE: this also drops the unique `exposures` bucket (.git/.env/backups/tokens) — a value gap; re-including it needs a memory-safe second pass (`-include-tags` does NOT override `-severity` on v3.2.9, verified) — deferred | `test_settings_security.py::TestResourceProfile` |
| **Wedge / lost findings** | `nuclei_network` used plain `subprocess.run` (no process-group kill) → an escaped interactsh helper could hold the pipe and hang the worker | Both nuclei collectors now use the shared `run_capped` (temp-file redirect + `killpg`) | `test_nuclei.py::TestRunProcessGroupKill` |
| **Empty output** | The target **dropped the scanner's probes** → httpx returned 0 live URLs → nuclei had nothing to scan | Coverage/blocking problem, not nuclei — surfaced by the coverage-regression finding + `partial` status | `test_coverage_regression.py` |

**Template freshness:** templates are baked into the image and
`-disable-update-check` is set (a mid-scan template download once wedged a scan
for hours). Consequence: templates are frozen at image-build time and **rot** —
an old image misses new CVEs. A **weekly CI cron** now rebuilds `:latest` so
templates refresh on cadence (`.github/workflows/ci.yml`). Do **not** re-enable
runtime template updates.

**Deferred nuclei follow-ups:** (a) recover partial findings written before a
wall-timeout (`run_capped` now carries them on the exception's `.output`; the
scanner does not yet save them); (b) re-include the `exposures` template bucket
via a memory-safe mechanism; (c) store `info.tags` / `classification.cwe-id` for
richer report categorisation.

**What nuclei needs to work properly:** (1) reachable targets (not blocked —
run a Passive Scan or get the scanner IP allowlisted if coverage collapses),
(2) a template set scoped to the box (severity profile), (3) a memory cap on
small hosts, (4) reasonably fresh templates (image rebuild cadence).

## Other tools (guarded by the 2026-08 audit)

- **amass / nmap timeouts** used to be swallowed → scan read `completed` with a
  truncated surface. Now they raise `ToolTimeout` → scan `partial`. Guards:
  `test_amass.py`, `test_nmap.py::TestNmapCollectorFailureModes`.
- **takeover_check** silently dropped `vulnerable` records it couldn't
  fingerprint → subzy field drift hid real takeovers. Now reported. Guard:
  `test_takeover_check.py`.
- **Parsers crash on real (not curated) output**: nuclei/nuclei_network on
  `info: null`, katana on non-dict `request`, domain_security RDAP on missing
  `eventAction`. All guarded by adversarial parser tests.
- **Target blocking is silent**: a blocked scan returns fewer findings but read
  as clean. Now: `endpoints_probed` vs reached counting + a coverage-regression
  finding + `partial` status. Guards: `test_coverage_regression.py`.
