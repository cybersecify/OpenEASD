---
category: Show and tell
title: 🔭 Found something interesting with OpenEASD? Share the story.
action: post; this is a prompt, not a question — replies come from the community
---

What surfaced that you wouldn't have caught otherwise?

- A forgotten staging subdomain still serving an admin panel?
- An expired cert nobody was watching?
- A `DMARC p=none` on a domain you assumed was locked down?
- A subdomain takeover candidate via dangling DNS?
- A Postfix SMTP open relay because someone misread a config?
- An undocumented service on a port you didn't know was open?

Drop a short writeup — what you found, how it surfaced (which tool / which scan stage), what fixing it looked like. We love hearing these and they help other folks decide whether OpenEASD fits their workflow.

### A request

**Please redact anything identifying** — real IPs, organisation names, specific CVE-on-real-host attributions if the host is identifiable. Sanitised pattern descriptions are what's useful and what's safe.

Example of a good redacted writeup:

> Ran OpenEASD against a small-ish corp domain (~40 subdomains). `httpx` flagged a 200 on `https://internal.<redacted>.com` which I didn't recognise. `tls_checker` confirmed valid LetsEncrypt cert. Turned out to be a developer-staging copy of the customer portal that someone had spun up 18 months earlier and forgotten — full source map exposed in the JS bundle and the auth was disabled "for testing." Took it down same day. Wouldn't have noticed without the subdomain enum + httpx combo.

That's the level of useful. Concrete enough to learn from, redacted enough that the original target isn't identifiable.

— Look forward to reading what you find 🫡
