"""S3 bucket analyzer — parse results and create Finding records."""

import logging

from apps.core.assets.models import Subdomain
from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

# Severity mapping for S3 findings
SEVERITY_MAP = {
    "public-list": "high",
    "public-read": "medium",
}


def analyze(session, records: list[dict]) -> list[Finding]:
    """
    Parse S3 bucket results and create Finding records.

    Args:
        session: The scan session object
        records: List of S3 bucket records

    Returns:
        List of Finding model instances
    """
    if not records:
        return []

    objs = []

    for record in records:
        try:
            bucket_name = record.get("bucket", "")
            url = record.get("url", "")
            access = record.get("access", "unknown")
            contents = record.get("contents", "")

            # Determine severity
            severity = SEVERITY_MAP.get(access, "low")

            # Create Finding
            obj = Finding(
                session=session,
                source="s3_enum",
                check_type="s3_bucket",
                severity=severity,
                title=f"Publicly accessible S3 bucket: {bucket_name}",
                description=(
                    f"S3 bucket {bucket_name} is publicly accessible.\n\n"
                    f"Access Level: {access}\n"
                    f"URL: {url}\n\n"
                    f"{f'Contents preview: {contents[:200]}...' if contents else ''}\n\n"
                    f"{'Anyone can list bucket contents.' if access == 'public-list' else 'Bucket exists and is publicly accessible.'}"
                ),
                extras={
                    "bucket": bucket_name,
                    "url": url,
                    "access": access,
                    "contents_preview": contents[:200] if contents else "",
                },
            )
            objs.append(obj)

        except Exception as e:
            logger.warning(f"Failed to process S3 record: {e}")
            continue

    logger.info(
        f"[s3_enum:{session.id}] "
        f"Analyzed {len(records)} records → {len(objs)} findings"
    )

    return objs
