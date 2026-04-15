"""SubfinderConfig — singleton model for subfinder API keys, editable via Django admin."""

from django.db import models


class SubfinderConfig(models.Model):
    # ProjectDiscovery
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
    # Censys (needs both ID and Secret)
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
    # GitHub (improves certificate transparency results)
    github_token = models.CharField(
        max_length=200, blank=True, default="",
        help_text="GitHub personal access token (improves cert transparency results).",
        verbose_name="GitHub Token",
    )
    # BeVigil
    bevigil_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="BeVigil API key.",
        verbose_name="BeVigil Key",
    )
    # BinaryEdge
    binaryedge_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="BinaryEdge API key.",
        verbose_name="BinaryEdge Key",
    )
    # FullHunt
    fullhunt_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="FullHunt API key.",
        verbose_name="FullHunt Key",
    )
    # Hunter.io
    hunter_key = models.CharField(
        max_length=200, blank=True, default="",
        help_text="Hunter.io API key.",
        verbose_name="Hunter Key",
    )

    class Meta:
        verbose_name = "Subfinder Configuration"
        verbose_name_plural = "Subfinder Configuration"

    def __str__(self):
        active = [
            name for name, val in [
                ("Chaos", self.chaos_key),
                ("Shodan", self.shodan_key),
                ("Censys", self.censys_id and self.censys_secret),
                ("SecurityTrails", self.securitytrails_key),
                ("VirusTotal", self.virustotal_key),
                ("GitHub", self.github_token),
                ("BeVigil", self.bevigil_key),
                ("BinaryEdge", self.binaryedge_key),
                ("FullHunt", self.fullhunt_key),
                ("Hunter", self.hunter_key),
            ] if val
        ]
        if active:
            return f"Subfinder Config ({', '.join(active)})"
        return "Subfinder Config (no API keys)"

    @classmethod
    def get(cls):
        """Return the singleton config, creating defaults if none exists."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def build_provider_config(self) -> dict:
        """
        Build the provider config dict for subfinder's YAML format.
        Only includes providers with keys set.
        """
        config = {}
        if self.chaos_key:
            config["chaos"] = [self.chaos_key]
        if self.shodan_key:
            config["shodan"] = [self.shodan_key]
        if self.censys_id and self.censys_secret:
            config["censys"] = [self.censys_id, self.censys_secret]
        if self.securitytrails_key:
            config["securitytrails"] = [self.securitytrails_key]
        if self.virustotal_key:
            config["virustotal"] = [self.virustotal_key]
        if self.github_token:
            config["github"] = [self.github_token]
        if self.bevigil_key:
            config["bevigil"] = [self.bevigil_key]
        if self.binaryedge_key:
            config["binaryedge"] = [self.binaryedge_key]
        if self.fullhunt_key:
            config["fullhunt"] = [self.fullhunt_key]
        if self.hunter_key:
            config["hunter"] = [self.hunter_key]
        return config
