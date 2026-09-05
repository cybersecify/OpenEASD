"""GitHub Org Recon analyzer — turns public-repo metadata/config into Findings.

Two Finding shapes (aggregate, low-noise — this complements github_secrets, which
finds actual secrets; this one finds *infra exposure*):

  * ``github_public_repos`` (info): one summary per scan — "N public repos discovered
    for org X". Establishes the source-code attack surface.
  * ``github_infra_exposure`` (low): one per unique infrastructure reference found in
    that public code/config — an internal hostname/subdomain of the target domain, a
    cloud-bucket URL (S3/Azure/GCP), or an API endpoint. Says WHICH repo and file it
    came from so the operator can verify and remediate.

We store the reference itself (a hostname / bucket name / URL) — NOT any secret. If a
secret is what's exposed, github_secrets is the tool that reports it.
"""

import logging
import re

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

_MAX_FINDINGS = 200  # hard cap so a huge org can't flood the report

# Cloud-storage bucket references. In an org's OWN public code these are very likely
# the org's own buckets, so we surface all providers (not just target-domain matches).
_BUCKET_RES = (
    re.compile(r"s3://[a-z0-9][a-z0-9.\-]{1,254}", re.I),
    re.compile(r"[a-z0-9][a-z0-9.\-]{1,254}\.s3(?:[.\-][a-z0-9\-]+)*\.amazonaws\.com", re.I),
    re.compile(r"[a-z0-9][a-z0-9\-]{1,62}\.blob\.core\.windows\.net", re.I),
    re.compile(r"storage\.googleapis\.com/[a-z0-9._\-]+", re.I),
    re.compile(r"[a-z0-9][a-z0-9._\-]{1,254}\.storage\.googleapis\.com", re.I),
)


# A URL whose PATH exposes an API surface (avoids a bare `"/api" in url` substring
# check, which static analysis flags as an incomplete-URL-sanitization pattern).
_API_PATH_RE = re.compile(r"/(?:api|graphql)(?:[/.?]|$)", re.I)


def _host_re(domain: str):
    # A hostname that is a SUBDOMAIN of the target domain (>=1 label before it).
    return re.compile(rf"\b((?:[a-z0-9_-]+\.)+{re.escape(domain)})\b", re.I)


def _url_re(domain: str):
    # A URL pointing at the target domain (used to catch /api paths on the apex).
    return re.compile(rf"https?://[a-z0-9_.\-]*{re.escape(domain)}[^\s\"'<>()]*", re.I)


def _looks_like_api(host: str) -> bool:
    parts = host.split(".")
    return parts[0] in ("api", "apis", "graphql", "gateway") or "api" in parts


def extract_infra_refs(text: str, domain: str) -> set:
    """Return a set of ``(ref_type, value)`` infra references found in ``text``.

    ref_type is one of ``hostname``, ``api_endpoint``, ``cloud_bucket``. Pure /
    side-effect-free so it is unit-testable in isolation.
    """
    refs: set = set()
    if not text or not domain:
        return refs
    domain = domain.lower()

    for host in _host_re(domain).findall(text):
        host = host.lower().rstrip(".")
        if host == domain:
            continue
        refs.add(("api_endpoint" if _looks_like_api(host) else "hostname", host))

    for url in _url_re(domain).findall(text):
        clean = url.rstrip("/").lower()
        if _API_PATH_RE.search(clean):
            refs.add(("api_endpoint", clean))

    for rx in _BUCKET_RES:
        for match in rx.findall(text):
            refs.add(("cloud_bucket", match.lower().rstrip("/")))

    return refs


_TITLE_BY_TYPE = {
    "hostname": "Internal hostname exposed in public GitHub repo",
    "api_endpoint": "API endpoint exposed in public GitHub repo",
    "cloud_bucket": "Cloud storage reference exposed in public GitHub repo",
}


def _infra_finding(session, domain, org, ref_type, value, repo, repo_url, location) -> Finding:
    title = _TITLE_BY_TYPE.get(ref_type, "Infrastructure reference exposed in public GitHub repo")
    return Finding(
        session=session,
        source="github_recon",
        check_type="github_infra_exposure",
        severity="low",
        target=value,
        title=f"{title}: {value}",
        description=(
            f"The {ref_type.replace('_', ' ')} '{value}' appears in the public GitHub "
            f"repository '{repo}' ({location}). Public source code and configuration "
            f"can leak internal infrastructure references — hostnames, storage buckets, "
            f"and API endpoints — that widen your external attack surface even though "
            f"the target itself was never scanned.\nRepository: {repo_url}"
        ),
        remediation=(
            "Confirm whether this reference should be public. Remove internal hostnames, "
            "bucket names, and API endpoints from public repositories (and their git "
            "history), rotate anything sensitive, and ensure the referenced "
            "infrastructure is firewalled / access-controlled and not implicitly trusted."
        ),
        extra={
            "ref_type": ref_type,
            "value": value,
            "repo": repo,
            "repo_url": repo_url,
            "location": location,
            "org": org,
            "source_data": "github_recon",
        },
    )


def analyze(session, domain, data) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(data, dict):
        return findings

    org = data.get("org")
    repos = data.get("repos") or []

    if data.get("org_confirmed") and org and repos:
        findings.append(Finding(
            session=session,
            source="github_recon",
            check_type="github_public_repos",
            severity="info",
            target=str(org),
            title=f"{len(repos)} public GitHub repositor{'y' if len(repos) == 1 else 'ies'} discovered for '{org}'",
            description=(
                f"{len(repos)} public repositor{'y' if len(repos) == 1 else 'ies'} were "
                f"found under the GitHub {data.get('kind') or 'account'} '{org}' "
                f"({data.get('org_url') or ''}). Public source code is part of your "
                f"external attack surface — the individual findings below flag specific "
                f"infrastructure references leaked in that code/config."
            ),
            remediation=(
                "Review which repositories should be public. Audit them for internal "
                "hostnames, credentials, and infrastructure details, and move private "
                "work into private repositories."
            ),
            extra={
                "org": org,
                "kind": data.get("kind"),
                "org_url": data.get("org_url"),
                "repo_count": len(repos),
                "source_data": "github_recon",
            },
        ))

    seen: set = set()
    for repo in repos:
        if not isinstance(repo, dict):
            continue
        name = repo.get("name") or ""
        repo_url = repo.get("html_url") or ""
        sources = [
            ("description", repo.get("description") or ""),
            ("homepage", repo.get("homepage") or ""),
            ("topics", " ".join(repo.get("topics") or [])),
        ]
        for f in repo.get("files") or []:
            if isinstance(f, dict):
                sources.append((f"file:{f.get('path')}", f.get("content") or ""))

        for location, text in sources:
            for ref_type, value in extract_infra_refs(text, domain):
                key = (ref_type, value)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    _infra_finding(session, domain, org, ref_type, value, name, repo_url, location)
                )
                if len(findings) >= _MAX_FINDINGS:
                    logger.info("github_recon: hit finding cap (%d) — truncating", _MAX_FINDINGS)
                    return findings

    return findings
