import logging
import re

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

_AWS_VIRTUAL = re.compile(r"https?://([^.]+)\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com")
_AWS_PATH = re.compile(r"https?://s3(?:\.[a-z0-9-]+)?\.amazonaws\.com/([^/\s]+)")
_AZURE = re.compile(r"https?://([^.]+)\.blob\.core\.windows\.net")
_GCP = re.compile(r"https?://storage\.googleapis\.com/([^/\s]+)")

_PROVIDER_SHORT = {"AWS S3": "aws", "Azure Blob": "azure", "GCP Storage": "gcp"}


def _parse_url(url: str) -> tuple[str, str] | None:
    m = _AWS_VIRTUAL.search(url)
    if m:
        return "AWS S3", m.group(1)

    m = _AWS_PATH.search(url)
    if m:
        return "AWS S3", m.group(1)

    m = _AZURE.search(url)
    if m:
        return "Azure Blob", m.group(1)

    m = _GCP.search(url)
    if m:
        return "GCP Storage", m.group(1)

    return None


def analyze(session, urls: list[str]) -> list[Finding]:
    if not urls:
        return []

    seen: set[str] = set()
    findings: list[Finding] = []

    for url in urls:
        url = url.strip()
        if not url or url in seen:
            continue
        seen.add(url)

        parsed = _parse_url(url)
        if parsed is None:
            logger.warning("cloud_assets: unrecognized bucket URL %r — skipping", url)
            continue

        provider, bucket_name = parsed
        short = _PROVIDER_SHORT[provider]

        findings.append(
            Finding(
                session=session,
                source="cloud_assets",
                check_type="open_cloud_bucket",
                severity="high",
                title=f"Public {provider} bucket: {bucket_name}",
                description=(
                    f"The {provider} bucket at {url} is publicly accessible. "
                    f"An unauthenticated attacker can list or read its contents."
                ),
                remediation=(
                    f"Set the bucket ACL to private and disable public access. "
                    f"For AWS: enable Block Public Access on {bucket_name}. "
                    f"Verify with: curl -I {url}"
                ),
                target=url,
                extra={"provider": short, "bucket_name": bucket_name, "url": url},
            )
        )

    return findings
