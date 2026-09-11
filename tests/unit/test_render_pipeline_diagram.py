"""Tests for the render_pipeline_diagram management command.

The command's whole purpose is to stay in sync with the tool registry, so the
key test is a drift guard: every registered tool must appear in the output.
"""

import json
from io import StringIO

import pytest
from django.core.management import call_command

from apps.core.engine.workflows.registry import get_registry
from apps.core.engine.workflows.management.commands.render_pipeline_diagram import (
    build_structure,
    render_html,
    render_text,
)


def _all_tool_keys():
    return set(get_registry().keys())


class TestBuildStructure:
    def test_includes_every_registered_tool(self):
        data = build_structure()
        seen = {t["key"] for g in data["groups"] for t in g["tools"]}
        assert seen == _all_tool_keys()

    def test_counts_are_consistent(self):
        data = build_structure()
        c = data["counts"]
        assert c["tools"] == len(_all_tool_keys())
        assert c["active"] + c["passive"] == c["tools"]
        assert c["groups"] == len(data["groups"])

    def test_groups_ordered_by_min_phase(self):
        data = build_structure()
        phases = [g["min_phase"] for g in data["groups"]]
        assert phases == sorted(phases)

    def test_active_flag_matches_registry(self):
        data = build_structure()
        reg = get_registry()
        for g in data["groups"]:
            for t in g["tools"]:
                assert t["active"] == bool(reg[t["key"]].get("active", True))

    def test_domain_security_passive_domain_probe_active(self):
        # Guards the split done in this line of work.
        data = build_structure()
        flags = {t["key"]: t["active"] for g in data["groups"] for t in g["tools"]}
        assert flags["domain_security"] is False
        assert flags["domain_probe"] is True


class TestRenderers:
    def test_html_contains_every_tool_and_stamp(self):
        html = render_html(build_structure())
        for key in _all_tool_keys():
            assert key in html, f"{key} missing from HTML"
        assert "DomainAuthorization" in html
        assert "<!doctype html>" in html
        assert "render_pipeline_diagram" in html  # self-documents its source

    def test_text_contains_every_tool(self):
        text = render_text(build_structure())
        for key in _all_tool_keys():
            assert key in text


class TestCommand:
    def test_html_to_stdout(self):
        out = StringIO()
        call_command("render_pipeline_diagram", stdout=out)
        assert "<!doctype html>" in out.getvalue()

    def test_text_format(self):
        out = StringIO()
        call_command("render_pipeline_diagram", "--format", "text", stdout=out)
        val = out.getvalue()
        assert "OpenEASD scan pipeline" in val
        assert "domain_probe" in val

    def test_json_format_parses(self):
        out = StringIO()
        call_command("render_pipeline_diagram", "--format", "json", stdout=out)
        data = json.loads(out.getvalue())
        assert data["counts"]["tools"] == len(_all_tool_keys())
        assert isinstance(data["groups"], list)

    def test_output_writes_file(self, tmp_path):
        target = tmp_path / "pipeline.html"
        call_command("render_pipeline_diagram", "--output", str(target))
        content = target.read_text(encoding="utf-8")
        assert "<!doctype html>" in content
        assert "domain_probe" in content

    def test_output_bad_path_errors(self):
        from django.core.management.base import CommandError
        with pytest.raises(CommandError):
            call_command("render_pipeline_diagram", "--output", "/no/such/dir/x.html")
