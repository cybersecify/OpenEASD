from django.apps import AppConfig


class GithubReconConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.github_recon"
    label = "github_recon"
    verbose_name = "GitHub Org Recon"
    tool_meta = {
        "label": "GitHub Org Recon",
        "runner": "apps.github_recon.scanner.run_github_recon",
        "phase": 2,
        "phase_group": "Surface Enumeration",
        "requires": [],
        "produces_findings": True,
        # Passive: queries GitHub's PUBLIC REST API for the org's public repos and
        # the infra references (internal hostnames/subdomains, cloud-bucket URLs,
        # API endpoints) exposed in that public code/config. Sends ZERO packets to
        # the target's own systems — this is third-party (GitHub) data, so it needs
        # NO DomainAuthorization. BYO-token is OPTIONAL: unauthenticated works at
        # GitHub's 60 req/hr public limit (we cap requests to stay well under it);
        # a GITHUB_TOKEN raises the ceiling to 5000 req/hr for richer coverage.
        "active": False,
    }
