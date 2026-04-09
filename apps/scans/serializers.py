"""DRF serializers for OpenEASD scan models."""

from rest_framework import serializers
from .models import ScanSession, Subdomain, Service, Vulnerability, Alert, ScanDelta


class SubdomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subdomain
        fields = ["id", "subdomain", "ip_address", "discovered_at", "is_active"]


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ["id", "host", "port", "service_name", "version", "protocol", "state", "risk_level", "discovered_at"]


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = [
            "id", "host", "port", "vulnerability_type", "severity",
            "title", "description", "remediation", "cvss_score",
            "cve_id", "mitre_technique", "confidence", "discovered_at", "is_new",
        ]


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ["id", "alert_type", "severity_threshold", "status", "sent_at", "retry_count"]


class ScanDeltaSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanDelta
        fields = ["id", "change_type", "change_category", "item_identifier", "change_details", "created_at"]


class ScanSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanSession
        fields = [
            "id", "domain", "scan_type", "start_time", "end_time",
            "status", "total_findings", "created_at",
        ]


class ScanSessionDetailSerializer(serializers.ModelSerializer):
    subdomains = SubdomainSerializer(many=True, read_only=True)
    services = ServiceSerializer(many=True, read_only=True)
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    deltas = ScanDeltaSerializer(many=True, read_only=True)

    class Meta:
        model = ScanSession
        fields = [
            "id", "domain", "scan_type", "start_time", "end_time",
            "status", "total_findings", "created_at",
            "subdomains", "services", "vulnerabilities", "deltas",
        ]


class StartScanSerializer(serializers.Serializer):
    domain = serializers.CharField(max_length=255)
    scan_type = serializers.ChoiceField(choices=["full", "incremental"], default="full")
