---
category: Q&A
title: What's the difference between OpenEASD and just running `subfinder | dnsx | naabu | nuclei` by hand?
action: post (no pin needed); answer your own question with the body below
---

Fair question — it's the first one people ask. Three things you get from OpenEASD that hand-rolled CLI pipelines don't:

### 1. Persistent findings lifecycle

Every finding tracks `open → acknowledged → in-progress → resolved → false positive`, with notes, across scans. When you re-scan next week, OpenEASD shows you the **delta** — new findings since last scan, resolved findings that came back. CLI pipelines emit fresh output every time and you re-do triage from scratch.

### 2. Asset graph, not flat output

OpenEASD persists the `Domain → Subdomain → IPAddress → Port → URL` relationships. Each tool in the pipeline reads from the same graph instead of re-parsing the previous tool's stdout. That means:

- The `nmap` stage knows which ports came from `naabu` *and* which subdomains those ports belong to
- Subscan ("re-run just Nuclei on the existing scan") works without repeating discovery
- Findings can be filtered by hostname / IP / port / source tool / severity — not just grep

### 3. The boring-but-load-bearing operational layer

- Schedule a daily scan or per-domain monitoring (6h/12h/24h/48h/weekly)
- Slack and Teams alerts at a severity threshold you set in the UI (no restart needed)
- CSV/PDF export of any scan (with optional minimum-severity filter)
- JWT-authenticated REST API at `/api/` with auto-generated OpenAPI docs
- Backport-aware CVE matching (since v0.5) — Ubuntu/Debian backports are recognised so already-patched CVEs aren't shown as live findings

### When the hand-rolled pipeline still wins

- Scanning one target once for a single output dump → CLI is faster, no install
- You don't want a long-running container
- You want exotic flag combinations that aren't exposed via the Workflows UI
- You're scripting against very specific raw tool output

OpenEASD's value compounds with **multiple targets over time**. For a single ad-hoc scan it's overkill.

---

Got a different angle on this comparison? Drop a comment — happy to refine the answer.
