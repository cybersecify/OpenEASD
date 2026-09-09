# Credential Management — UI-managed BYOK keys — Design Spec

> **Status:** ✅ **Implemented (C1 + C3 + C5).** C1: `apps/core/console/credentials/`
> (`ToolCredentials` encrypted singleton + `get_credential()` resolver + write-only
> `/api/credentials/`). C3: the 5 tools read via `get_credential()` — `shodan`,
> `breach_check`, `github_recon`, `github_secrets`, `dns_history` — so a DB-stored
> key overrides the env with no redeploy. **C5: `CredentialsPage`** (`/credentials`,
> new nav item) — per-key password inputs + Save/Clear, presence/source pills
> (UI/env/not-set), write-only (values never shown). Cloudflare still defers to
> `AISettings` (Section 6); `github_secret` field kept but unconsumed. The feature
> is complete — manage BYOK keys from the console, no redeploy.

**Goal:** let the operator manage the tools' bring-your-own-key (BYOK) API keys
from a **single console page**, stored **encrypted in the DB**, instead of
env-vars-only that require a redeploy to change. Enter a key once in the UI → the
tool uses it on the next scan, no restart.

**Owner:** OpenEASD core. **Depends on:** existing `apps/core/crypto.py` +
`fields.py` (Fernet field encryption). **Single-user** — one operator owns one
credential store (no per-user credentials, no RBAC).

---

## 1. Motivation

BYOK keys are today **env-var only** for most tools (`SHODAN_API_KEY`,
`HIBP_API_KEY`, `GITHUB_TOKEN`, `GITHUB_SECRET`, `DNS_HISTORY_API_URL`,
`CLOUDFLARE_*`, plus the amass/subfinder provider keys). Changing any means
editing `.env` / compose / the k8s secret **and redeploying**. That's high
friction for a self-hosted single-user product where the operator just wants to
paste a Shodan key and scan.

The infrastructure to fix this **already exists**: `EncryptedCharField`/
`EncryptedTextField` (Fernet, transparent encrypt-on-write / decrypt-on-read) and
four models already store secrets in the DB this way (`ai` AISettings,
`notifications` NotificationConfig, `amass` AmassConfig, `subfinder`
SubfinderConfig). This feature **consolidates and extends** that pattern into one
credential surface, and wires the remaining env-only tools to read from it.

## 2. Design principles

1. **Reuse, don't reinvent.** Encrypted fields, the singleton-config pattern
   (`NotificationConfig` pk=1), the write-only API shape (`AISettings` returns
   presence booleans, never values), and the DB-wins-over-env precedence
   (`cfg.slack_webhook_url or getattr(settings, "SLACK_WEBHOOK_URL", "")`) all
   already exist — copy them.
2. **Write-only secrets.** The API never returns a stored key value — only
   `<name>_configured: true/false`. `None` on write = unchanged; `""` = clear
   (falls back to env).
3. **DB wins over env; env is the fallback.** A key set in the DB overrides the
   env var; cleared/absent DB key falls back to the env var; absent both = the
   tool runs in its keyless/degraded mode (all these tools are fail-graceful).
4. **Additive & safe.** With no DB credentials set, every tool behaves exactly as
   today (reads env). No scan behaviour changes until a key is entered.
5. **Single-user.** One `ToolCredentials` singleton; no ownership/RBAC.

## 3. Scope — which keys

**In scope (movable to the DB):**
`SHODAN_API_KEY`, `HIBP_API_KEY`, `GITHUB_TOKEN`, `GITHUB_SECRET`,
`DNS_HISTORY_API_URL`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, and the
amass/subfinder provider keys (Censys ID/secret, PassiveTotal, etc. — some already
in AmassConfig/SubfinderConfig; consolidate or leave in place, see Section 8).

**Explicitly OUT of scope — MUST stay env-only (hard rule):**
- **`FIELD_ENCRYPTION_KEY`** — it *decrypts* the DB secrets. Storing it in the
  encrypted DB is a chicken-and-egg impossibility.
- **`SECRET_KEY`** — Django bootstrap secret; also the fallback source for the
  Fernet key when `FIELD_ENCRYPTION_KEY` is unset.
- **`DB_*` / `DATABASE_URL`** — needed to reach the DB before any row can be read.

The credentials page must not expose these; document why.

## 4. Component C1 — the `ToolCredentials` model

New app **`apps/core/console/credentials/`** (label `credentials`), a peer of
`notifications` in the console layer. One singleton:

```python
class ToolCredentials(models.Model):   # pk=1 singleton, NotificationConfig pattern
    shodan_api_key       = EncryptedCharField(blank=True, default="")
    hibp_api_key         = EncryptedCharField(blank=True, default="")
    github_token         = EncryptedCharField(blank=True, default="")
    github_secret        = EncryptedCharField(blank=True, default="")
    cloudflare_account_id= EncryptedCharField(blank=True, default="")  # identifier, but keep uniform
    cloudflare_api_token = EncryptedCharField(blank=True, default="")
    dns_history_api_url   = EncryptedCharField(blank=True, default="")  # BYO endpoint
    updated_at            = DateTimeField(auto_now=True)

    @classmethod
    def get(cls): ...          # get_or_create(pk=1)
```

- Fernet fields → ciphertext at rest, plaintext via ORM attribute access
  (non-deterministic, so read via `.get()` + attribute, never `.filter()`).
- `blank`/`default=""` so an unset key is empty (→ env fallback via C2).

## 5. Component C2 — the `get_credential()` resolver (the core seam)

A single helper every tool calls instead of reading `settings` directly:

```python
# apps/core/console/credentials/resolver.py
def get_credential(name: str) -> str:
    """DB value (if set) wins; else the env/settings var; else ''.
    `name` is the settings key, e.g. "SHODAN_API_KEY"."""
    db_val = _db_value_for(name)          # ToolCredentials.get() attribute, mapped
    if db_val:
        return db_val
    return getattr(settings, name, "")
```

- One place owns the DB→env precedence (principle 3) and the name→field mapping.
- Fail-graceful: any DB error (no row / decrypt issue) → fall back to env, never
  raise (a scan must never die because the credential store hiccuped).
- Cheap: `ToolCredentials.get()` is a single indexed pk=1 fetch; fine per scan.

## 6. Component C3 — wire the tools

Replace each tool's `getattr(settings, "<KEY>", "")` /
`config("<KEY>")` with `get_credential("<KEY>")`. Affected collectors (from the
scope list): `shodan`, `breach_check` (HIBP), `github_secrets` + `github_recon`
(GITHUB_TOKEN/SECRET), `dns_history`, and the `ai` client (Cloudflare). This is
the **bulk of the work** — mechanical, one line per tool, but touches ~7 tools.

**Note on the AI layer:** `ai` already has `AISettings` with a DB Cloudflare token
+ env fallback. Either (a) leave `ai` as-is and have `get_credential` defer to
`AISettings` for the Cloudflare keys, or (b) migrate them into `ToolCredentials`.
Recommend **(a)** for v1 — don't disturb the working, consent-gated AI config;
`get_credential` can special-case Cloudflare to read `AISettings`.

## 7. Component C4 — API

`apps/core/console/credentials/api.py`, `Router(auth=JWTAuth())`, mounted at
`/api/credentials/`:

```
GET  /api/credentials/    → { shodan_configured: bool, hibp_configured: bool, ... ,
                              source: {shodan: "db"|"env"|"none", ...} }
                            values are NEVER returned — presence booleans only.
POST /api/credentials/    → write-only: for each field, None=unchanged, ""=clear
                            (→ env fallback), "value"=set. Returns the GET shape.
```

- Mirrors `apps/core/console/ai/api.py` (`available`/`configured` booleans, no
  credential leak). The `source` map lets the UI show "using env var" vs "set in
  UI" vs "not configured" per key — useful operator feedback.

## 8. Component C5 — Frontend

- **New `Credentials` nav item** (console; e.g. under a Settings group or next to
  Notifications).
- **`CredentialsPage`** — clone `AiPage`/`NotificationsPage`: one row per key with
  a password input, a "configured ✓ (db|env)" pill, a Save and a Clear. Helper
  text per tool ("Shodan — free InternetDB works keyless; a key unlocks the host
  API"). A banner noting `FIELD_ENCRYPTION_KEY`/`SECRET_KEY` remain env-only and why.
- react-query + `apiGet`/`apiPost`, write-only (never render a returned value).

## 9. Suggested sequencing (each independently shippable)

1. **C1 + C2 + C4** — the `credentials` app: model + `get_credential` resolver +
   write-only API (+ tests: encryption at rest, DB-wins-over-env, write-only never
   leaks, clear→env fallback). No tool touched yet → zero behaviour change.
2. **C3** — wire the ~7 tools to `get_credential` (+ per-tool tests: DB key used
   when set, env fallback when not). This is where DB keys start taking effect.
3. **C5** — `CredentialsPage` + nav (+ Vitest for the presence pills).
4. **Docs** — CLAUDE.md (new app + `/api/credentials/` + Secrets-at-rest note),
   DESIGN.md (console app count 5→6), CHANGELOG, README (BYOK-via-UI mention).

## 10. Non-goals / out of scope

- **No env-only bootstrap secrets in the DB** (`FIELD_ENCRYPTION_KEY`,
  `SECRET_KEY`, `DB_*`) — hard rule (Section 3).
- **No per-user credentials / RBAC / sharing** (single-user).
- **No key rotation scheduler / vault integration** — a later idea, not v1.
- **No change to the AI consent gate** — AI keys keep their existing consent flow;
  `get_credential` defers to `AISettings` for Cloudflare (Section 6).
- **No secret values ever returned by the API or logged** — write-only, presence
  booleans only.

## 11. Open decisions for the team

1. **Consolidate amass/subfinder provider keys into `ToolCredentials`, or leave
   them in AmassConfig/SubfinderConfig?** (Proposal: leave for v1 — they're
   per-provider and already DB-backed; `get_credential` need not cover them yet.)
2. **Cloudflare keys — defer to `AISettings` (recommended) or migrate?**
   (Proposal: defer; don't disturb the consent-gated AI config.)
3. **`source` map in the API** — worth the extra field for "db vs env" UI feedback?
   (Proposal: yes — it's the main operability win over blind env vars.)
4. **Nav placement** — standalone `Credentials` item, or a `Settings` group that
   also folds in Notifications/AI config?
