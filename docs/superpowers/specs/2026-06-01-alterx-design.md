# alterx Subdomain Permutation Tool — Design

## Goal

Add `apps/alterx/` as a Phase 2 tool that generates subdomain permutations from already-discovered subdomains (subfinder/amass output) and writes them as `Subdomain` rows so dnsx (Phase 3) resolves them automatically.

## Architecture

**Phase:** 2 — same group as subfinder and amass. No renumbering needed.

**Contract:** `produces_findings: False`, `requires: ["subfinder"]`. Reads `Subdomain` rows already in the session, pipes them to the `alterx` binary via stdin, and bulk-creates new `Subdomain` rows for the generated permutations. dnsx (Phase 3) resolves all `Subdomain` rows in one pass.

**Data flow:**
```
run_alterx(session)
  → Subdomain.objects.filter(session=session) → list of subdomain strings
  → if empty: return [] without calling binary
  → collect(subdomains) → pipe to alterx stdin → list[str] raw permutations
  → analyze(session, raw) → normalize, dedup vs existing → list[Subdomain]
  → bulk_create(ignore_conflicts=True)
  → return saved rows
```

**Why stdin over `-list` flag:** avoids creating a temp file on disk. `alterx` reads one subdomain per line from stdin cleanly.

## File Structure

```
apps/alterx/
    __init__.py       — empty package marker
    apps.py           — AppConfig, phase=2, requires=["subfinder"], produces_findings=False
    models.py         — empty (writes to apps.core.assets.Subdomain)
    collector.py      — pipes subdomains to alterx, returns list[str]
    analyzer.py       — normalizes, deduplicates, builds Subdomain objects
    scanner.py        — orchestrator: read → collect → analyze → save

tests/unit/test_alterx.py
openeasd/settings.py   — TOOL_ALTERX = config("TOOL_ALTERX", default="alterx")
Dockerfile             — ARG ALTERX_VERSION, downloaded in tools-builder stage alongside subfinder
CLAUDE.md              — tool table (17 tools), scan pipeline, tests table
```

## Components

### `collector.py`

`collect(subdomains: list[str]) -> list[str]`

- Returns `[]` if `subdomains` is empty
- Checks binary with `shutil.which`; returns `[]` if missing
- Runs `alterx` with subdomains joined by newlines piped to stdin via `input=`
- Returns one permutation string per stdout line, blank lines stripped
- Handles: `FileNotFoundError`, `TimeoutExpired` (300s), non-zero exit → all return `[]`

### `analyzer.py`

`analyze(session, raw: list[str]) -> list[Subdomain]`

- Returns `[]` if `raw` is empty
- Lowercases and strips each line
- Validates hostname against RFC 1035 regex (same pattern as subfinder)
- Deduplicates against subdomains already saved in the session (`Subdomain.objects.filter(session=session).values_list("subdomain", flat=True)`)
- Returns `list[Subdomain]` with `source="alterx"`

### `scanner.py`

`run_alterx(session) -> list[Subdomain]`

- Reads `Subdomain.objects.filter(session=session).values_list("subdomain", flat=True).distinct()`
- Early return `[]` if no subdomains exist
- Calls `collect` → `analyze` → `bulk_create(ignore_conflicts=True)`
- Returns saved rows queried back from DB

### `apps.py`

```python
tool_meta = {
    "label": "Alterx (Subdomain Permutation)",
    "runner": "apps.alterx.scanner.run_alterx",
    "phase": 2,
    "requires": ["subfinder"],
    "produces_findings": False,
}
```

### Dockerfile

Add `ALTERX_VERSION` arg and download in the `tools-builder` stage alongside the other ProjectDiscovery tools:

```dockerfile
ARG ALTERX_VERSION=0.0.4
RUN curl -fsSL "https://github.com/projectdiscovery/alterx/releases/download/v${ALTERX_VERSION}/alterx_${ALTERX_VERSION}_linux_${TARGETARCH}.zip" \
    -o alterx.zip && unzip alterx.zip alterx && rm alterx.zip
```

## Tests

`tests/unit/test_alterx.py` — three test classes:

**TestCollect** (5 tests):
- Empty input returns `[]` without calling binary
- Binary not found returns `[]`
- Non-zero exit returns `[]`
- Timeout returns `[]`
- Happy path: returns permutation strings from stdout

**TestAnalyze** (6 tests, `@pytest.mark.django_db`):
- Empty input returns `[]`
- Invalid hostname filtered out
- Valid permutation builds correct `Subdomain` object with `source="alterx"`
- Deduplicates within raw list
- Deduplicates against existing session subdomains
- Lowercases input

**TestScanner** (4 tests, `@pytest.mark.django_db`):
- No subdomains returns `[]` without calling collect
- Passes existing subdomain names to collect
- Saves rows and returns them
- Returns `[]` when collect returns nothing

## Deduplication

Three layers:
1. Analyzer deduplicates within the raw list (seen set)
2. Analyzer deduplicates against existing Subdomain rows in the session
3. `bulk_create(ignore_conflicts=True)` handles any remaining dupes via `unique_together = [("session", "subdomain")]`

## Non-Goals

- alterx does not resolve subdomains — that is dnsx's job (Phase 3)
- No custom wordlist support in this implementation (alterx's built-in patterns are sufficient)
- No findings produced — this is a pure asset-discovery tool
