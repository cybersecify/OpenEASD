from django.apps import AppConfig


class ServiceDetectionConfig(AppConfig):
    name = "apps.core.service_detection"
    label = "service_detection"
    verbose_name = "Service Detection"
    tool_meta = {
        "label": "Service Detection",
        "runner": "apps.core.service_detection.detector.detect_services",
        "phase": 5,
        "requires": ["naabu"],
        "produces_findings": False,
        "core": True,  # always runs, hidden from workflow UI
    }
