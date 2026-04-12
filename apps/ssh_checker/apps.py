from django.apps import AppConfig


class SshCheckerConfig(AppConfig):
    name = "apps.ssh_checker"
    label = "ssh_checker"
    verbose_name = "SSH Checker"
    tool_meta = {
        "label": "SSH Checker",
        "runner": "apps.ssh_checker.scanner.run_ssh_check",
        "phase": 7,
        "requires": ["naabu", "service_detection"],
        "produces_findings": True,
    }
