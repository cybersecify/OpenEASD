# Security Policy

OpenEASD is a security tool, so we take vulnerabilities in it seriously.
This document explains how to report them and what to expect after.

## Supported versions

We patch security issues against the `main` branch and the most recent
tagged release. There is no extended LTS — if you're running an older
release, the fix is to upgrade.

| Version | Security fixes |
|---|---|
| `main` (and latest `vX.Y` tag) | ✅ |
| Older tags | ❌ — upgrade |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**
Use one of the private channels below.

### Preferred: GitHub Private Vulnerability Reporting

Open a private report at
[github.com/cybersecify/OpenEASD/security/advisories/new](https://github.com/cybersecify/OpenEASD/security/advisories/new).
This routes through GitHub's built-in advisory workflow, keeps the
discussion private until we publish, and gives you a CVE if one is
warranted.

### Fallback: email

If you'd rather email, send to **contact@cybersecify.com** with
`[OpenEASD security]` in the subject line. We'll route it internally
to the maintainers.

## What to include

The more of these we get up-front, the faster we can confirm and fix:

- **Affected version** — git SHA or release tag, plus how you're running
  it (Docker image tag, Kubernetes manifest, standalone, dev mode)
- **A description of the issue** — what's vulnerable, why it matters
- **Steps to reproduce** — minimal repro, ideally with the exact HTTP
  request, payload, or scan input that triggers it
- **Impact** — what an attacker can do (auth bypass? RCE? info disclosure?
  privilege escalation against the host running OpenEASD?)
- **Your suggested fix or mitigation**, if you have one

A proof-of-concept exploit is welcome but not required.

## What's in scope

Vulnerabilities in **OpenEASD itself** — the Django app, the React SPA,
the REST API, the workflow runner, the Docker image, the Kubernetes
manifests, the auth flow, the way we shell out to external tools, etc.

Examples of what we'd treat as security issues:
- Authentication bypass on the API or web UI
- Command/SQL/template injection
- Server-side request forgery in scan target handling
- Cross-site scripting in the dashboard
- Privilege escalation against the host (especially around `NET_RAW` or
  the way collector subprocesses are invoked)
- Hard-coded credentials, secrets, or insecure defaults that survive
  the first-login password change
- Container escape vectors in the Docker image
- Denial-of-service that takes the scanner offline with a small input

## What's out of scope

- **Vulnerabilities in the wrapped scanners themselves** (`subfinder`,
  `dnsx`, `naabu`, `httpx`, `nuclei`, `nmap`, `amass`) — please report
  those to their upstream projects. We'll happily bump the version once
  upstream ships a fix.
- **Findings produced by OpenEASD against a target** — those are
  *output*, not vulnerabilities in OpenEASD.
- **Best-practice/hardening suggestions that aren't a security issue**
  (e.g. "you should set X env var by default") — open a regular GitHub
  issue instead.
- **Self-XSS / clickjacking on routes that require authenticated admin** —
  not impactful in the single-admin model OpenEASD ships.
- **Findings that require physical access** or compromise of the host the
  user chose to run OpenEASD on.
- **Reports from automated scanners with no reproducible impact.**

## What to expect after reporting

We're a small team. Honest timelines:

- **Acknowledgement:** within 3 business days
- **Initial triage** (severity assessment + reproducibility check):
  within 7 business days
- **Fix or mitigation plan for high/critical:** within 30 days. Some
  issues will be faster — auth bypass and RCE we drop everything for.
- **Public disclosure:** coordinated. We aim to publish the advisory
  (with credit to you, if you want it) once a fix is released. We
  default to coordinated disclosure on a 90-day clock from initial
  report, sooner if a fix is out earlier.

We do **not** currently run a bug bounty program. If you find something
genuinely serious in OpenEASD itself, get in touch — we'd rather hear
about it before someone else does.

## Credit

Researchers who report a confirmed vulnerability will be credited in
the release notes and GitHub advisory unless they ask to remain
anonymous. If you've reported via PVR, you can opt in to credit during
the advisory workflow.

## A note for users running OpenEASD

OpenEASD is designed to **scan your own infrastructure** (or
infrastructure you have written authorisation to test). Running active
scans against domains you don't own may violate laws in your
jurisdiction and the acceptable-use policy of your hosting provider.
You are responsible for your scan targets — see the [MIT
LICENSE](LICENSE) for the no-warranty clause.

For deployment hardening, see the **Production note** in the
[Deployment section of the README](README.md#deployment) — primarily
narrowing `ALLOWED_HOSTS`, setting a real `SECRET_KEY`, and changing
the default `admin/admin` password (forced on first login).
