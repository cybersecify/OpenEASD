from django.apps import AppConfig


class TldsquattingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.tldsquatting"
    label = "tldsquatting"
    verbose_name = "TLD Squatting / Lookalike Domains"
    tool_meta = {
        "label": "TLD Squatting / Lookalike Domains",
        "runner": "apps.tldsquatting.scanner.run_tldsquatting",
        "phase": 1,
        "phase_group": "Brand Threat",
        "requires": [],
        "produces_findings": True,
        # Passive: generates lookalike candidates algorithmically from the apex
        # domain — TLD permutation across a broad set of registrable TLDs plus
        # character-level typos (homoglyph/omission/insertion/repetition/
        # transposition/hyphenation/adjacent-key) — then queries the CANDIDATE
        # domains' PUBLIC DNS (A/MX/NS) to see which are registered / weaponizable,
        # and fetches the web-serving ones' homepages for a login form / brand
        # impersonation. Sends ZERO packets to the target's own systems — the
        # target is never contacted. No DomainAuthorization, no API key needed.
        # Supersedes the former `typosquat` tool (broader TLD coverage).
        "active": False,
    }
