import logging

from apps.core.assets.models import Subdomain
from apps.core.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)

_MIN_KEYWORD_LEN = 3


def _derive_keywords(domain: str, subdomains: list[str]) -> list[str]:
    apex_label = domain.split(".")[0].lower()
    seen: set[str] = set()
    keywords: list[str] = []

    for label in [apex_label] + [s.split(".")[0].lower() for s in subdomains]:
        if len(label) >= _MIN_KEYWORD_LEN and label not in seen:
            seen.add(label)
            keywords.append(label)

    return keywords


def run_cloud_assets(session) -> list[Finding]:
    domain = session.domain  # CharField: "example.com"
    subdomain_values = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not subdomain_values:
        logger.info(f"[cloud_assets:{session.id}] no subdomains — skipping")
        return []

    keywords = _derive_keywords(domain, subdomain_values)

    if not keywords:
        logger.info(f"[cloud_assets:{session.id}] no keywords derived — skipping")
        return []

    urls = collect(keywords)
    findings = analyze(session, urls)

    if findings:
        Finding.objects.bulk_create(findings, ignore_conflicts=True)

    saved = list(Finding.objects.filter(session=session, source="cloud_assets"))
    logger.info(f"[cloud_assets:{session.id}] saved {len(saved)} open bucket findings")
    return saved
