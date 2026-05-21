# Changelog

All notable changes to OpenEASD are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with a short
**Why** note on non-obvious changes so reviewers don't have to dig through
commits to recover the reasoning.

## [Unreleased]

### Pre-launch hardening (May 2026)

Audience-and-positioning pass: OpenEASD targets the security community
specifically — in-house security/IT teams, small security consultancies,
security learners. The pre-launch work below tightens the load-bearing
"one `docker run` and it works" promise before any public announcement.

#### Fixed
- **Docker image now serves gunicorn, not Django's dev server.**
  The default `CMD` invoked `python main.py`, which under the hood runs
  `manage.py runserver` — Django's development server, which is single-threaded
  and explicitly *not* for production use. The published `:latest` image
  was therefore unsuitable for production despite the README framing it
  that way. The K8s manifests already used gunicorn (via a command override),
  so this change brings single-container Docker into line with K8s.
  **Why:** the security community will spot a dev server in a "production"
  image immediately, and the credibility cost is large. `main.py` is unchanged
  and remains the local-dev entry point with autoreload.

#### Changed
- **README docker run example now sets `ALLOWED_HOSTS`.**
  Without it, a user accessing via the server's IP from a remote machine
  hits Django's `DisallowedHost` 400 response with no obvious explanation,
  and bounces. The env var was documented further down the README, but
  the example command is what users actually copy.
  **Why:** the load-bearing promise is "copy this one command and it works."
  Friction in the first three minutes is what kills tool adoption in
  this niche.

### Verified (no code change required)
- `ghcr.io/cybersecify/openeasd:latest` is publicly pullable — anonymous
  manifest fetch returns 200. (Some packages default to private on GHCR;
  worth re-checking after each new repo's first publish.)
- `gunicorn>=21.2` is in the `[prod]` extras and is installed in the
  Docker image (`pyproject.toml:42`, `Dockerfile:105`).
