from django.apps import AppConfig


class GithubSecretsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.github_secrets"
    label = "github_secrets"
    verbose_name = "GitHub Secret Exposure (gitleaks)"
    tool_meta = {
        "label": "GitHub Secret Exposure (gitleaks)",
        "runner": "apps.github_secrets.scanner.run_github_secrets",
        "phase": 1,
        "phase_group": "Domain Intelligence",
        "requires": ["gitleaks"],
        "produces_findings": True,
        # Passive: queries GitHub's OWN public code-search API (a third party),
        # never the target's systems. Sends ZERO packets to the target — no
        # DomainAuthorization needed. BYOK is mandatory for this tool: GitHub's
        # code-search API requires auth, so with no GITHUB_TOKEN it is a logged
        # no-op that never breaks a keyless Full Scan.
        "active": False,
    }
