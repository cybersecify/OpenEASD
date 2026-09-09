# Third-Party Notices

OpenEASD is distributed under the MIT License (see `LICENSE`). It orchestrates a
number of independent third-party tools and public data sources. The OpenEASD
Docker image **bundles** several of these binaries; this file provides the
attribution and license notices their licenses require when redistributed.

OpenEASD does not modify these tools — it invokes them as separate processes and
reads their output. Each remains under its own license, reproduced/attributed
below.

---

## Bundled binaries (redistributed in the Docker image)

### MIT-licensed

The following are used under the MIT License. Copyright remains with their
respective authors; the MIT permission notice is preserved by reference to each
project's `LICENSE`.

| Tool | Project | Copyright |
|---|---|---|
| subfinder | github.com/projectdiscovery/subfinder | © ProjectDiscovery, Inc. |
| dnsx | github.com/projectdiscovery/dnsx | © ProjectDiscovery, Inc. |
| naabu | github.com/projectdiscovery/naabu | © ProjectDiscovery, Inc. |
| httpx | github.com/projectdiscovery/httpx | © ProjectDiscovery, Inc. |
| katana | github.com/projectdiscovery/katana | © ProjectDiscovery, Inc. |
| nuclei | github.com/projectdiscovery/nuclei | © ProjectDiscovery, Inc. |
| alterx | github.com/projectdiscovery/alterx | © ProjectDiscovery, Inc. |
| nuclei-templates | github.com/projectdiscovery/nuclei-templates | © ProjectDiscovery, Inc. |
| gitleaks | github.com/gitleaks/gitleaks | © Zachary Rice |
| gau | github.com/lc/gau | © Corben Leo |
| cloud_enum | github.com/initstring/cloud_enum | © initstring |

> The MIT License permits use, copying, modification, and redistribution provided
> the copyright notice and permission notice are retained. Full text:
> https://opensource.org/license/mit — and in each project's `LICENSE` file.

### Apache License 2.0

**amass** — github.com/owasp-amass/amass — © OWASP Amass Project / contributors.

Used under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0).
Per Apache-2.0 §4, the project's `NOTICE` is preserved: this product includes
software developed by the OWASP Amass Project and its contributors. No changes are
made to the amass source; it is invoked as a separate binary.

### GPL-2.0

**subzy** — github.com/PentestPad/subzy — © PentestPad / Emenalo Chibuzo Alexander.

Licensed under the GNU General Public License, version 2 (GPL-2.0). subzy is
invoked as a **separate process** (subprocess); OpenEASD's own MIT-licensed code
is not a derivative of subzy (mere aggregation). Because the compiled subzy binary
is **redistributed** in the Docker image, per GPL-2.0 §3:

> **Written offer for source.** The complete corresponding source code for the
> subzy binary distributed in this image is available at
> https://github.com/PentestPad/subzy . On request, the OpenEASD maintainers will
> provide the corresponding source (or a pointer to it) for the exact version
> shipped. GPL-2.0 full text: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html

### Nmap Public Source License (NPSL)

**nmap** — nmap.org — © Nmap Software LLC / Gordon Lyon.

Used under the Nmap Public Source License (https://nmap.org/npsl/). nmap is
installed from the OS package repository and invoked as a separate binary by the
`nmap`, `tls_checker`, and `service_detection` tools.

> **This product uses the Nmap Security Scanner (https://nmap.org).**
>
> Note for downstream redistributors: the NPSL restricts embedding nmap in
> **commercial products/services sold for a fee**. Such use may require an Nmap OEM
> license (https://nmap.org/oem/). OpenEASD's own use is free/non-commercial; if
> you build a paid product on top of it, review the NPSL and OEM terms yourself.

---

## Third-party data sources / APIs queried at scan time (not bundled)

| Source | Used by | License / terms | Note |
|---|---|---|---|
| EPSS (Exploit Prediction Scoring System) | cve_intel | Free, openly published by FIRST.org | See citation below |
| CISA KEV (Known Exploited Vulnerabilities) | cve_intel | Public domain (U.S. Government work) | No restriction |
| Certificate Transparency logs / crt.sh | subfinder feeds | Public data | Read-only |
| Wayback Machine / AlienVault OTX / Common Crawl | historical_urls (via gau) | Each source's own public terms | Read-only, low volume |
| Cloud storage APIs (AWS S3 / Azure / GCP) | cloud_assets (cloud_enum) | Public provider endpoints | Unauthenticated existence checks |
| Shodan InternetDB + host API | shodan | See note below | Passive |
| Hudson Rock Cavalier API | hudson_rock | Free OSINT API, attribution requested | Counts-only; attributed in report |

**EPSS citation:** Exploit Prediction Scoring System (EPSS), FIRST.org —
https://www.first.org/epss/ . Jacobs, J., Romanosky, S., et al. EPSS data is used
to prioritize CVE findings.

**Shodan note:** The `shodan` tool defaults to Shodan's **free InternetDB** API,
which Shodan makes available for **non-commercial use** ("you can use it at a
company but you can't use it to build commercial products that you charge money
for"). Operators building a **paid** product on OpenEASD must instead supply their
own paid Shodan plan via `SHODAN_API_KEY` (which switches to the licensed host
API) or disable the tool. See https://www.shodan.io/ .

**Hudson Rock:** infostealer-exposure data is provided by Hudson Rock's Cavalier
API (https://www.hudsonrock.com/), used with attribution and limited to aggregate
counts (no plaintext credentials are stored).
