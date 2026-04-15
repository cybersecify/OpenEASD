"""AmassConfig — singleton model for amass settings and API keys, editable via Django admin."""

from django.db import models


class AmassConfig(models.Model):
    # Kill switch — checked before running the binary
    enabled = models.BooleanField(
        default=True,
        help_text="Uncheck to disable amass entirely without removing it from workflows.",
    )
    wordlist_file = models.FileField(
        upload_to="wordlists/",
        blank=True,
        null=True,
        help_text=(
            "Upload a DNS wordlist for brute-force subdomain discovery "
            "(e.g. subdomains-top1million-5000.txt from SecLists). "
            "Leave blank to skip brute force."
        ),
        verbose_name="Wordlist file",
    )
    scan_timeout = models.PositiveIntegerField(
        default=30,
        help_text="Maximum scan duration in minutes before amass is killed. Default: 30.",
        verbose_name="Timeout (minutes)",
    )

    # --- API Keys ---
    # ProjectDiscovery Chaos
    chaos_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="ProjectDiscovery Chaos API key.",
        verbose_name="Chaos Key",
    )
    # Shodan
    shodan_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="Shodan API key.",
        verbose_name="Shodan Key",
    )
    # Censys
    censys_id = models.CharField(
        max_length=200, blank=True, default="",
        help_text="Censys API ID.",
        verbose_name="Censys API ID",
    )
    censys_secret = models.CharField(
        max_length=200, blank=True, default="",
        help_text="Censys API Secret.",
        verbose_name="Censys API Secret",
    )
    # SecurityTrails
    securitytrails_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="SecurityTrails API key.",
        verbose_name="SecurityTrails Key",
    )
    # VirusTotal
    virustotal_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="VirusTotal API key.",
        verbose_name="VirusTotal Key",
    )
    # PassiveTotal (RiskIQ) — unique to amass
    passivetotal_username = models.CharField(
        max_length=200, blank=True, default="",
        help_text="PassiveTotal (RiskIQ) account username.",
        verbose_name="PassiveTotal Username",
    )
    passivetotal_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="PassiveTotal (RiskIQ) API key.",
        verbose_name="PassiveTotal Key",
    )
    # WhoisXMLAPI — unique to amass
    whoisxmlapi_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="WhoisXMLAPI key.",
        verbose_name="WhoisXMLAPI Key",
    )
    # GitHub
    github_token = models.CharField(
        max_length=200, blank=True, default="",
        help_text="GitHub personal access token (improves cert transparency results).",
        verbose_name="GitHub Token",
    )

    class Meta:
        verbose_name = "Amass Configuration"
        verbose_name_plural = "Amass Configuration"

    def __str__(self):
        if not self.enabled:
            return "Amass Config (disabled)"
        active_keys = [
            name for name, val in [
                ("Chaos", self.chaos_key),
                ("Shodan", self.shodan_key),
                ("Censys", self.censys_id and self.censys_secret),
                ("SecurityTrails", self.securitytrails_key),
                ("VirusTotal", self.virustotal_key),
                ("PassiveTotal", self.passivetotal_username and self.passivetotal_key),
                ("WhoisXMLAPI", self.whoisxmlapi_key),
                ("GitHub", self.github_token),
            ] if val
        ]
        keys_str = f", keys: {', '.join(active_keys)}" if active_keys else ""
        return f"Amass Config (active{keys_str})"

    @classmethod
    def get(cls):
        """Return the singleton config, creating defaults if none exists."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def build_datasource_config(self) -> list[dict]:
        """
        Build the datasources list for amass YAML config format.
        Only includes providers with keys set.
        """
        sources = []
        if self.chaos_key:
            sources.append({"name": "Chaos", "creds": {"apikey": self.chaos_key}})
        if self.shodan_key:
            sources.append({"name": "Shodan", "creds": {"apikey": self.shodan_key}})
        if self.censys_id and self.censys_secret:
            sources.append({
                "name": "Censys",
                "creds": {"username": self.censys_id, "password": self.censys_secret},
            })
        if self.securitytrails_key:
            sources.append({"name": "SecurityTrails", "creds": {"apikey": self.securitytrails_key}})
        if self.virustotal_key:
            sources.append({"name": "VirusTotal", "creds": {"apikey": self.virustotal_key}})
        if self.passivetotal_username and self.passivetotal_key:
            sources.append({
                "name": "PassiveTotal",
                "creds": {"username": self.passivetotal_username, "apikey": self.passivetotal_key},
            })
        if self.whoisxmlapi_key:
            sources.append({"name": "WhoisXMLAPI", "creds": {"apikey": self.whoisxmlapi_key}})
        if self.github_token:
            sources.append({"name": "GitHub", "creds": {"apikey": self.github_token}})
        return sources
