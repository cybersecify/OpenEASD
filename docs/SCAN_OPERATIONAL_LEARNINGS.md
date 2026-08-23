# Scan Operational Learnings

Problems hit running **real** scans, their root cause, the fix, and the
regression test that now guards each one. Rule: every operational failure we see
in production becomes a documented learning **and** a test, so it can't silently
recur. Add to this list whenever a scan misbehaves.

## nuclei (the biggest source of pain)

nuclei compiles its **entire template set (~13,500 templates) into RAM at
startup**, before it touches a single target. This one fact causes three of the
four symptoms:

| Symptom | Root cause | Fix | Guard |
|---|---|---|---|
| **Freeze** (box + web UI unresponsive for minutes) | Template *loading* swaps a small (1 GB) host | `GOMEMLIMIT` soft heap cap on the Go process (low profile) **+** severity scoping to load fewer templates | `test_nuclei.py::test_go_memory_limit_applied_to_subprocess`; `test_proc_env.py` |
| **Timeout** (2 h wall hit, run reported `partial`) | Template *execution*: targets × ~13.5k templates ÷ polite rate | Severity scoping (drop `info` ≈ 38%, `low` ≈ 4% on low profile) → far fewer requests | `test_nuclei.py::test_cmd_scopes_severity_and_drops_info` |
| **Low value / noise** | `info` templates are mostly recon (tech-detect), already covered by httpx `-tech-detect` + web_checker; they bury real findings | Scope to `critical,high,medium(,low)` per profile; overridable via `NUCLEI_SEVERITY` | `test_settings_security.py::TestResourceProfile` |
| **Empty output** | The target **dropped the scanner's probes** → httpx returned 0 live URLs → nuclei had nothing to scan | This is a coverage/blocking problem, not a nuclei problem — surfaced by the coverage-regression finding + `partial` status | `test_coverage_regression.py` |

**Template freshness caveat:** templates are baked into the image and
`-disable-update-check` is set (a mid-scan template download once wedged a scan
for hours). Consequence: templates are frozen at image-build time and **rot** —
an old image misses new CVEs. Rebuild the image on a cadence to refresh them;
do **not** re-enable runtime template updates.

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
