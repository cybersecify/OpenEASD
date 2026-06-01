"""S3 bucket discovery — guess bucket names and probe for public access."""

import logging
import subprocess
import shutil
import json

from django.conf import settings

logger = logging.getLogger(__name__)

# Common S3 bucket name patterns
BUCKET_PATTERNS = [
    "{domain}",
    "{domain}-prod",
    "{domain}-production",
    "{domain}-staging",
    "{domain}-dev",
    "{domain}-test",
    "{domain}-backup",
    "{domain}-backups",
    "{domain}-assets",
    "{domain}-static",
    "{domain}-media",
    "{domain}-uploads",
    "{domain}-data",
    "{domain}-logs",
    "{domain}-archive",
    "{name}",
    "{name}-prod",
    "{name}-production",
    "{name}-staging",
    "{name}-dev",
    "{name}-test",
    "{name}-backup",
    "{name}-backups",
    "{name}-assets",
    "{name}-static",
    "{name}-media",
    "{name}-uploads",
    "{name}-data",
    "{name}-logs",
    "{name}-archive",
]


def _generate_bucket_names(domain: str) -> list[str]:
    """Generate potential bucket names from a domain."""
    names = set()

    # Extract name parts
    parts = domain.split(".")
    name = parts[0] if parts else domain

    for pattern in BUCKET_PATTERNS:
        try:
            names.add(pattern.format(domain=domain, name=name))
        except (KeyError, IndexError):
            continue

    return list(names)


def _probe_bucket(bucket_name: str) -> dict | None:
    """
    Probe an S3 bucket for public access.

    Returns dict with bucket info if publicly accessible, None otherwise.
    """
    try:
        # Try to list bucket contents (public list)
        result = subprocess.run(
            ["aws", "s3", "ls", f"s3://{bucket_name}", "--no-sign-request"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            # Bucket is publicly listable
            return {
                "bucket": bucket_name,
                "url": f"https://{bucket_name}.s3.amazonaws.com",
                "access": "public-list",
                "contents": result.stdout[:500],
            }

        # Try to head bucket (public read)
        result = subprocess.run(
            ["aws", "s3api", "head-bucket", "--bucket", bucket_name, "--no-sign-request"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            # Bucket exists and is publicly accessible
            return {
                "bucket": bucket_name,
                "url": f"https://{bucket_name}.s3.amazonaws.com",
                "access": "public-read",
                "contents": "",
            }

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return None


def collect(session, domains: list[str]) -> list[dict]:
    """
    Discover publicly accessible S3 buckets for given domains.

    Args:
        session: The scan session object
        domains: List of domain names to check

    Returns:
        List of publicly accessible S3 bucket records
    """
    if not domains:
        return []

    # Check if AWS CLI is available
    if not shutil.which("aws"):
        logger.warning("AWS CLI not found, skipping S3 enumeration")
        return []

    # Generate bucket names for all domains
    all_bucket_names = set()
    for domain in domains:
        all_bucket_names.update(_generate_bucket_names(domain))

    logger.info(
        f"[s3_enum:{session.id}] "
        f"Generated {len(all_bucket_names)} potential bucket names "
        f"from {len(domains)} domains"
    )

    # Probe each bucket
    records = []
    for bucket_name in all_bucket_names:
        result = _probe_bucket(bucket_name)
        if result:
            records.append(result)

    logger.info(
        f"[s3_enum:{session.id}] "
        f"Found {len(records)} publicly accessible S3 buckets "
        f"(from {len(all_bucket_names)} probed)"
    )

    return records
