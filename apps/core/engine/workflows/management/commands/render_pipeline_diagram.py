"""Management command: render_pipeline_diagram.

Renders the scan pipeline as a self-contained HTML diagram (or a text/JSON
summary) **straight from the tool registry**, so it can never drift from the
code the way a hand-drawn diagram does. Every tool, phase, phase group, and
passive/active classification is read live from ``AppConfig.tool_meta`` via the
registry — add or move a tool and the next render reflects it automatically.

The passive/active colouring maps to the DomainAuthorization boundary: green =
passive (public/third-party data, no auth), amber = active (touches the target,
requires authorization). The output is stamped with the build version, git sha,
and render time so a reader can tell how current it is.

Usage:
    manage.py render_pipeline_diagram                       # HTML to stdout
    manage.py render_pipeline_diagram -o docs/pipeline.html # HTML to a file
    manage.py render_pipeline_diagram --format text         # terminal tree
    manage.py render_pipeline_diagram --format json         # machine-readable
"""

import html
import json
from string import Template

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.core.engine.workflows.registry import get_registry


def build_structure() -> dict:
    """Registry → ordered structure the renderers consume. Pure (no I/O)."""
    registry = get_registry()

    groups: dict[str, dict] = {}
    for name, info in registry.items():
        group = info.get("phase_group") or "Uncategorised"
        g = groups.setdefault(group, {"name": group, "min_phase": info["phase"], "tools": []})
        g["min_phase"] = min(g["min_phase"], info["phase"])
        g["tools"].append({
            "key": name,
            "label": info.get("label", name),
            "phase": info["phase"],
            "active": bool(info.get("active", True)),
            "produces_findings": bool(info.get("produces_findings", False)),
            "requires": list(info.get("requires", [])),
            "core": bool(info.get("core", False)),
        })

    ordered = sorted(groups.values(), key=lambda g: (g["min_phase"], g["name"]))
    for g in ordered:
        g["tools"].sort(key=lambda t: (t["phase"], t["key"]))
        g["max_phase"] = max(t["phase"] for t in g["tools"])

    tools = [t for g in ordered for t in g["tools"]]
    return {
        "groups": ordered,
        "counts": {
            "tools": len(tools),
            "groups": len(ordered),
            "active": sum(1 for t in tools if t["active"]),
            "passive": sum(1 for t in tools if not t["active"]),
            "phases": len({t["phase"] for t in tools}),
        },
        "provenance": {
            "version": getattr(settings, "OPENEASD_VERSION", "dev"),
            "git_sha": getattr(settings, "OPENEASD_GIT_SHA", "unknown"),
            "generated_at": timezone.now().strftime("%Y-%m-%d %H:%M UTC"),
        },
    }


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

_PAGE = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenEASD Scan Pipeline</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
:root{
  --bg:#f6f8fa;--surface:#fff;--surface-2:#eef1f5;--border:#d5dce4;--border-strong:#b8c2cd;
  --text:#1c2128;--muted:#5b6672;--accent:#1a7f4b;--accent-soft:rgba(26,127,75,.10);--accent-line:rgba(26,127,75,.45);
  --active:#9a6700;--active-soft:rgba(154,103,0,.10);--active-line:rgba(154,103,0,.45);--spine:#c2cbd5;
  --shadow:0 1px 2px rgba(27,33,40,.06),0 6px 20px rgba(27,33,40,.05);
  --sans:"IBM Plex Sans",ui-sans-serif,system-ui,-apple-system,sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,"SF Mono",Menlo,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0d1117;--surface:#161b22;--surface-2:#1b222c;--border:#2c333d;--border-strong:#3d4652;
  --text:#e6edf3;--muted:#8b949e;--accent:#30c074;--accent-soft:rgba(48,192,116,.13);--accent-line:rgba(48,192,116,.42);
  --active:#e3a53d;--active-soft:rgba(227,165,61,.13);--active-line:rgba(227,165,61,.42);--spine:#30363d;
  --shadow:0 1px 2px rgba(1,4,9,.4),0 8px 24px rgba(1,4,9,.3);
}}
:root[data-theme="dark"]{
  --bg:#0d1117;--surface:#161b22;--surface-2:#1b222c;--border:#2c333d;--border-strong:#3d4652;
  --text:#e6edf3;--muted:#8b949e;--accent:#30c074;--accent-soft:rgba(48,192,116,.13);--accent-line:rgba(48,192,116,.42);
  --active:#e3a53d;--active-soft:rgba(227,165,61,.13);--active-line:rgba(227,165,61,.42);--spine:#30363d;
  --shadow:0 1px 2px rgba(1,4,9,.4),0 8px 24px rgba(1,4,9,.3);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.5;-webkit-font-smoothing:antialiased;padding:clamp(20px,4vw,56px) clamp(16px,4vw,40px) 72px}
.wrap{max-width:1120px;margin:0 auto}
.eyebrow{font-family:var(--mono);font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin:0 0 10px;font-weight:600}
h1{font-size:clamp(28px,5vw,42px);line-height:1.08;letter-spacing:-.02em;margin:0 0 12px;text-wrap:balance;font-weight:700}
.lede{font-size:16px;color:var(--muted);max-width:64ch;margin:0 0 20px}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:10px 16px;box-shadow:var(--shadow)}
.stat .n{font-family:var(--mono);font-size:22px;font-weight:600;line-height:1}
.stat .l{font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:4px}
.stat.active .n{color:var(--active)}
.stat.passive .n{color:var(--accent)}
.legend{display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:10px;font-size:13px;margin-bottom:14px}
.legend .item{display:inline-flex;align-items:center;gap:8px;color:var(--muted)}
.sw{width:13px;height:13px;border-radius:4px;flex:none}
.sw.passive{background:var(--accent)}.sw.active{background:var(--active)}
.flowstrip{display:flex;flex-wrap:wrap;align-items:center;gap:8px;font-family:var(--mono);font-size:12.5px;color:var(--muted);background:var(--surface-2);border:1px solid var(--border);border-radius:10px;padding:12px 16px;margin-bottom:26px}
.flowstrip b{color:var(--text);font-weight:600}
.flowstrip .arw{color:var(--accent)}
.band{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:18px 20px;box-shadow:var(--shadow)}
.band-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.band-head .phase{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--muted);letter-spacing:.04em}
.band-head h2{font-size:19px;margin:0;letter-spacing:-.01em}
.lanes{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.lane{border:1px solid var(--border);border-radius:12px;padding:13px 15px 14px;background:var(--surface-2);display:flex;flex-direction:column;gap:7px}
.lane.passive{border-top:3px solid var(--accent)}
.lane.active{border-top:3px solid var(--active)}
.lane-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.lane-name{font-family:var(--mono);font-weight:600;font-size:14.5px}
.pill{font-family:var(--mono);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;padding:3px 8px;border-radius:999px;white-space:nowrap}
.pill.passive{color:var(--accent);background:var(--accent-soft);border:1px solid var(--accent-line)}
.pill.active{color:var(--active);background:var(--active-soft);border:1px solid var(--active-line)}
.lane-label{font-size:13px;color:var(--text)}
.lane-meta{display:flex;flex-wrap:wrap;gap:5px;margin-top:2px}
.chip{font-family:var(--mono);font-size:10.5px;padding:2px 7px;border-radius:5px;background:var(--surface);border:1px solid var(--border);color:var(--muted)}
.chip.find{color:var(--accent);border-color:var(--accent-line)}
.chip.core{color:var(--active);border-color:var(--active-line)}
.spine{display:flex;justify-content:center;height:26px}
.spine::before{content:"";width:2px;height:100%;background:var(--spine)}
footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--border);font-size:12.5px;color:var(--muted);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
.mono{font-family:var(--mono)}
</style>
</head>
<body>
<div class="wrap">
  <p class="eyebrow">OpenEASD · generated from the tool registry</p>
  <h1>Scan Pipeline</h1>
  <p class="lede">Every tool, phase, and passive/active classification below is read live from <span class="mono">AppConfig.tool_meta</span> — this diagram is generated by <span class="mono">manage.py render_pipeline_diagram</span>, so it cannot drift from the code.</p>
  <div class="stats">
    <div class="stat"><div class="n">$c_tools</div><div class="l">tools</div></div>
    <div class="stat"><div class="n">$c_groups</div><div class="l">phase groups</div></div>
    <div class="stat"><div class="n">$c_phases</div><div class="l">phases</div></div>
    <div class="stat passive"><div class="n">$c_passive</div><div class="l">passive</div></div>
    <div class="stat active"><div class="n">$c_active</div><div class="l">active · need auth</div></div>
  </div>
  <div class="legend">
    <span class="item"><span class="sw passive"></span> Passive — public / third-party data, no authorization</span>
    <span class="item"><span class="sw active"></span> Active — probes the target, requires <span class="mono">DomainAuthorization</span></span>
  </div>
  <div class="flowstrip">
    <b>create_scan_session</b> <span class="arw">→</span> <b>run_scan</b> (DBOS) <span class="arw">→</span> auth gate <span class="arw">→</span> <b>run_workflow</b> loops tools by phase <span class="arw">→</span> <b>Finding</b> <span class="arw">→</span> <b>_finalize_session</b> (deltas · report · alerts · AI)
  </div>
$bands
  <footer>
    <span>OpenEASD scan pipeline — $c_tools tools across $c_groups phase groups</span>
    <span class="mono">$version @ $git_sha · generated $generated_at</span>
  </footer>
</div>
</body>
</html>
""")


def render_html(data: dict) -> str:
    bands = []
    for i, g in enumerate(data["groups"]):
        if i:
            bands.append('  <div class="spine"></div>')
        pr = f"phase {g['min_phase']}" if g["min_phase"] == g["max_phase"] else f"phases {g['min_phase']}–{g['max_phase']}"
        lanes = []
        for t in g["tools"]:
            cls = "active" if t["active"] else "passive"
            pill = "active · needs auth" if t["active"] else "passive"
            meta = [f'<span class="chip">phase {t["phase"]}</span>']
            if t["produces_findings"]:
                meta.append('<span class="chip find">→ Finding</span>')
            else:
                meta.append('<span class="chip">→ assets / enrich</span>')
            if t["core"]:
                meta.append('<span class="chip core">core · auto-injected</span>')
            if t["requires"]:
                meta.append('<span class="chip">needs: ' + html.escape(", ".join(t["requires"])) + "</span>")
            lanes.append(
                f'      <div class="lane {cls}">\n'
                f'        <div class="lane-top"><span class="lane-name">{html.escape(t["key"])}</span>'
                f'<span class="pill {cls}">{pill}</span></div>\n'
                f'        <div class="lane-label">{html.escape(t["label"])}</div>\n'
                f'        <div class="lane-meta">{"".join(meta)}</div>\n'
                f'      </div>'
            )
        bands.append(
            f'  <div class="band">\n'
            f'    <div class="band-head"><span class="phase">{pr.upper()}</span>'
            f'<h2>{html.escape(g["name"])}</h2></div>\n'
            f'    <div class="lanes">\n' + "\n".join(lanes) + "\n    </div>\n  </div>"
        )
    c = data["counts"]
    p = data["provenance"]
    return _PAGE.substitute(
        c_tools=c["tools"], c_groups=c["groups"], c_phases=c["phases"],
        c_active=c["active"], c_passive=c["passive"],
        version=html.escape(p["version"]), git_sha=html.escape(p["git_sha"][:8]),
        generated_at=html.escape(p["generated_at"]),
        bands="\n".join(bands),
    )


def render_text(data: dict) -> str:
    c, p = data["counts"], data["provenance"]
    out = [
        f"OpenEASD scan pipeline — {c['tools']} tools, {c['groups']} phase groups, "
        f"{c['passive']} passive / {c['active']} active   ({p['version']} @ {p['git_sha'][:8]})",
        "",
    ]
    for g in data["groups"]:
        pr = f"phase {g['min_phase']}" if g["min_phase"] == g["max_phase"] else f"phases {g['min_phase']}-{g['max_phase']}"
        out.append(f"{g['name']}  ({pr})")
        for t in g["tools"]:
            flag = "ACTIVE " if t["active"] else "passive"
            emits = "Finding" if t["produces_findings"] else "assets/enrich"
            extras = []
            if t["core"]:
                extras.append("core")
            if t["requires"]:
                extras.append("needs " + ",".join(t["requires"]))
            tail = ("  [" + "; ".join(extras) + "]") if extras else ""
            out.append(f"  [{flag}] p{t['phase']}  {t['key']:<20} -> {emits}{tail}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


class Command(BaseCommand):
    help = "Render the scan pipeline diagram from the tool registry (HTML/text/JSON)."

    def add_arguments(self, parser):
        parser.add_argument(
            "-f", "--format", choices=["html", "text", "json"], default="html",
            help="Output format (default: html).",
        )
        parser.add_argument(
            "-o", "--output", default=None,
            help="Write to this file instead of stdout.",
        )

    def handle(self, *args, **options):
        data = build_structure()
        fmt = options["format"]
        if fmt == "html":
            content = render_html(data)
        elif fmt == "json":
            content = json.dumps(data, indent=2) + "\n"
        else:
            content = render_text(data)

        out_path = options["output"]
        if out_path:
            try:
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
            except OSError as e:
                raise CommandError(f"Could not write {out_path}: {e}")
            self.stderr.write(self.style.SUCCESS(
                f"Wrote {fmt} pipeline diagram ({data['counts']['tools']} tools) to {out_path}"
            ))
        else:
            self.stdout.write(content)
