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
| **Timeout** (wall hit, findings discarded) | Template *execution*: targets × executed templates ÷ polite rate | Give nuclei TIME to finish (6h `NUCLEI_TIMEOUT`, 24h worker/watchdog) rather than capping its output; `-type http` + `-max-host-error` trim wasted work. AND if the wall still hits, **deliver the partial findings** nuclei already wrote (`run_capped` carries them on `TimeoutExpired.output`; both collectors parse + return them) instead of discarding them for a false 0 | `test_nuclei.py::test_timeout_delivers_partial_findings`, `test_nuclei_network.py::test_collect_timeout_delivers_partial_findings`, `::test_cmd_includes_memory_and_scope_flags` |
| **Low value / noise** | `info` tech-detect templates are already covered by httpx `-tech-detect` + web_checker; they bury real findings | Scope to `critical,high,medium(,low)` per profile (`NUCLEI_SEVERITY`). NOTE: this also drops the unique `exposures` bucket (.git/.env/backups/tokens) — a value gap; re-including it needs a memory-safe second pass (`-include-tags` does NOT override `-severity` on v3.2.9, verified) — deferred | `test_settings_security.py::TestResourceProfile` |
| **Wedge / lost findings** | `nuclei_network` used plain `subprocess.run` (no process-group kill) → an escaped interactsh helper could hold the pipe and hang the worker | Both nuclei collectors now use the shared `run_capped` (temp-file redirect + `killpg`) | `test_nuclei.py::TestRunProcessGroupKill` |
| **Empty output** | The target **dropped the scanner's probes** → httpx returned 0 live URLs → nuclei had nothing to scan | Coverage/blocking problem, not nuclei — surfaced by the coverage-regression finding + `partial` status | `test_coverage_regression.py` |

**Template freshness:** templates are baked into the image and
`-disable-update-check` is set (a mid-scan template download once wedged a scan
for hours). Consequence: templates are frozen at image-build time and **rot** —
an old image misses new CVEs. A **weekly CI cron** now rebuilds `:latest` so
templates refresh on cadence (`.github/workflows/ci.yml`). Do **not** re-enable
runtime template updates.

**Deferred nuclei follow-ups:** (a) re-include the `exposures` template bucket
via a memory-safe mechanism; (b) store `info.tags` / `classification.cwe-id` for
richer report categorisation. (Recovering partial findings on a wall-timeout —
formerly deferred — is now DONE: both collectors parse `TimeoutExpired.output`.)

**What nuclei needs to work properly:** (1) reachable targets (not blocked —
run a Passive Scan or get the scanner IP allowlisted if coverage collapses),
(2) a template set scoped to the box (severity profile), (3) a memory cap on
small hosts, (4) reasonably fresh templates (image rebuild cadence).

## Other tools (guarded by the 2026-08 audit)

- **amass / nmap timeouts** used to be swallowed → scan read `completed` with a
  truncated surface. Now handled honestly: enumeration/finding tools whose partial
  output is worthwhile **deliver it** on the wall (amass subdomains, nuclei +
  nuclei_network findings — a time-boxed run is a normal result); tools where a
  truncated run is not meaningfully partial raise `ToolTimeout` → scan `partial`
  (nmap). Guards: `test_amass.py::test_timeout_delivers_partial_results`,
  `test_nuclei.py::test_timeout_delivers_partial_findings`,
  `test_nmap.py::TestNmapCollectorFailureModes`.
- **takeover_check** silently dropped `vulnerable` records it couldn't
  fingerprint → subzy field drift hid real takeovers. Now reported. Guard:
  `test_takeover_check.py`.
- **Parsers crash on real (not curated) output**: nuclei/nuclei_network on
  `info: null`, katana on non-dict `request`, domain_security RDAP on missing
  `eventAction`. All guarded by adversarial parser tests.
- **Target blocking is silent**: a blocked scan returns fewer findings but read
  as clean. Now: `endpoints_probed` vs reached counting + a coverage-regression
  finding + `partial` status. Guards: `test_coverage_regression.py`.
