# Dark Mode UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply a full dark mode redesign across all templates, aligned to the cybersecify.com brand palette (`#0a1a0f` body, `#0d2614` cards, `#30c074` accent, Inter font).

**Architecture:** Template-only changes — no views, models, or JS logic touched. All colors replaced using Tailwind CDN arbitrary-value syntax (`bg-[#hex]`, `text-[#hex]`, `border-[rgba(...)]`). Tailwind `shadow` utilities replaced with explicit dark borders since shadows are invisible on dark backgrounds. A global CSS block in `base.html` covers Django widget-rendered form inputs.

**Tech Stack:** Django 5 templates, Tailwind CSS CDN (arbitrary value syntax), Google Fonts (Inter)

---

## Color Reference (use throughout all tasks)

| Role | Value |
|---|---|
| Body bg | `#0a1a0f` |
| Sidebar bg | `#050e08` |
| Card bg | `#0d2614` |
| Table thead bg | `rgba(0,0,0,0.35)` |
| Border default | `rgba(48,192,116,0.12)` |
| Border medium | `rgba(48,192,116,0.22)` |
| Accent | `#30c074` |
| Accent bg tint | `rgba(48,192,116,0.10)` |
| Text primary | `#e8f5ef` |
| Text secondary | `#6b9e7e` |
| Text muted | `#3d6b4f` |
| Text inactive | `#1e3d2a` |

## File Map

| File | Change |
|---|---|
| `templates/base.html` | Font, body/sidebar/nav/messages, global input CSS |
| `templates/partials/severity_badge.html` | Dark-adapted severity colors |
| `templates/partials/status_badge.html` | Dark-adapted status colors |
| `templates/partials/scan_status.html` | Dark card, severity mini-cards, pipeline steps, asset cards |
| `templates/partials/pagination.html` | Dark page links |
| `templates/dashboard.html` | Stat cards, domain table badges, urgent findings |
| `templates/domains/list.html` | Form card, domain table |
| `templates/findings/list.html` | Severity cards, filter bar, findings table |
| `templates/scans/list.html` | Status cards, scan table |
| `templates/scans/scheduled.html` | Table, job type badges, confirm row |
| `templates/scans/detail.html` | Back link, export buttons, section cards |
| `templates/scans/start.html` | Form card, schedule type cards, recurring toggle |
| `templates/insights.html` | KPI cards, section accent, empty state |
| `templates/workflow/list.html` | Workflow cards, step badges, confirm row |
| `templates/workflow/create.html` | Form card |
| `templates/workflow/detail.html` | Detail cards, step badges |
| `templates/registration/login.html` | Standalone dark page |

---

## Task 1: base.html — Font, body, sidebar, nav, messages

**Files:**
- Modify: `templates/base.html`

- [ ] **Step 1: Replace `base.html` with the dark version**

Replace the entire file with:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{% block title %}OpenEASD{% endblock %} — Attack Surface Detection</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="https://unpkg.com/htmx.org@2.0.4" integrity="sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/alpinejs@3.14.1/dist/cdn.min.js" defer></script>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    [x-cloak] { display: none !important; }
    body { font-family: 'Inter', system-ui, sans-serif; }
    /* Dark mode global form input overrides (for Django widget-rendered inputs) */
    input[type="text"], input[type="password"], input[type="date"],
    input[type="email"], input[type="number"], input[type="search"],
    select, textarea {
      background-color: rgba(0,0,0,0.3) !important;
      border-color: rgba(48,192,116,0.20) !important;
      color: #e8f5ef !important;
      font-family: 'Inter', system-ui, sans-serif !important;
    }
    input[type="text"]::placeholder, input[type="password"]::placeholder,
    input[type="search"]::placeholder { color: #3d6b4f !important; }
    input[type="text"]:focus, input[type="password"]:focus,
    input[type="date"]:focus, select:focus, textarea:focus {
      outline: none !important;
      border-color: #30c074 !important;
      box-shadow: 0 0 0 2px rgba(48,192,116,0.15) !important;
    }
    select option { background-color: #0d2614; color: #e8f5ef; }
    input[type="checkbox"] { accent-color: #30c074; }
  </style>
</head>
<body class="bg-[#0a1a0f] text-[#e8f5ef] min-h-screen flex"
      style="background-image: radial-gradient(ellipse at 70% -10%, rgba(48,192,116,0.06) 0%, transparent 55%);">

  <!-- Sidebar -->
  <aside class="w-56 bg-[#050e08] flex flex-col min-h-screen flex-shrink-0 border-r border-[rgba(48,192,116,0.12)]">

    <!-- Logo -->
    <div class="px-4 py-4 border-b border-[rgba(48,192,116,0.12)]">
      <a href="{% url 'dashboard' %}" class="font-extrabold text-[#e8f5ef] text-sm tracking-tight flex items-center gap-2">
        <span class="text-[#30c074]">⬡</span> OpenEASD
      </a>
    </div>

    <!-- Nav links -->
    {% with n=request.resolver_match.url_name %}
    <nav class="flex-1 py-2">

      <a href="{% url 'dashboard' %}"
         class="flex items-center gap-2 px-4 py-2 text-sm border-l-2
           {% if n == 'dashboard' %}bg-[rgba(48,192,116,0.08)] text-[#e8f5ef] border-[#30c074]
           {% else %}text-[#1e3d2a] hover:text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.04)] border-transparent{% endif %}">
        Dashboard
      </a>

      <a href="{% url 'domain-list' %}"
         class="flex items-center gap-2 px-4 py-2 text-sm border-l-2
           {% if n == 'domain-list' or n == 'domain-toggle' or n == 'domain-delete' %}bg-[rgba(48,192,116,0.08)] text-[#e8f5ef] border-[#30c074]
           {% else %}text-[#1e3d2a] hover:text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.04)] border-transparent{% endif %}">
        Domains
      </a>

      <a href="{% url 'scan-list' %}"
         class="flex items-center justify-between px-4 py-2 text-sm border-l-2
           {% if n == 'scan-list' or n == 'scan-detail' or n == 'scan-start' or n == 'scan-status-fragment' or n == 'scan-stop' or n == 'scan-delete' or n == 'scheduled-jobs' %}bg-[rgba(48,192,116,0.08)] text-[#e8f5ef] border-[#30c074]
           {% else %}text-[#1e3d2a] hover:text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.04)] border-transparent{% endif %}">
        <span>Scans</span>
        {% if sidebar_running_count > 0 %}
        <span class="flex items-center gap-1 text-xs text-blue-400">
          <span class="w-1.5 h-1.5 bg-blue-500 rounded-full animate-pulse inline-block"></span>{{ sidebar_running_count }}
        </span>
        {% endif %}
      </a>

      <a href="{% url 'finding-list' %}"
         class="flex items-center justify-between px-4 py-2 text-sm border-l-2
           {% if n == 'finding-list' or n == 'finding-update-status' %}bg-[rgba(48,192,116,0.08)] text-[#e8f5ef] border-[#30c074]
           {% else %}text-[#1e3d2a] hover:text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.04)] border-transparent{% endif %}">
        <span>Findings</span>
        {% if sidebar_finding_badge > 0 %}
        <span class="bg-red-600 text-white text-xs font-bold px-1.5 py-0.5 rounded-full leading-none">{{ sidebar_finding_badge }}</span>
        {% endif %}
      </a>

      <a href="{% url 'insights' %}"
         class="flex items-center gap-2 px-4 py-2 text-sm border-l-2
           {% if n == 'insights' %}bg-[rgba(48,192,116,0.08)] text-[#e8f5ef] border-[#30c074]
           {% else %}text-[#1e3d2a] hover:text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.04)] border-transparent{% endif %}">
        Insights
      </a>

      <a href="{% url 'workflow-list' %}"
         class="flex items-center gap-2 px-4 py-2 text-sm border-l-2
           {% if n == 'workflow-list' or n == 'workflow-create' or n == 'workflow-detail' or n == 'workflow-delete' or n == 'workflow-toggle-step' %}bg-[rgba(48,192,116,0.08)] text-[#e8f5ef] border-[#30c074]
           {% else %}text-[#1e3d2a] hover:text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.04)] border-transparent{% endif %}">
        Workflows
      </a>

    </nav>
    {% endwith %}

    <!-- Logout -->
    <div class="px-4 py-3 border-t border-[rgba(48,192,116,0.12)]">
      <form method="post" action="{% url 'logout' %}">
        {% csrf_token %}
        <button type="submit" class="text-[#1e3d2a] hover:text-[#6b9e7e] text-xs font-medium">Logout</button>
      </form>
    </div>

  </aside>

  <!-- Main content -->
  <div class="flex-1 flex flex-col min-h-screen">
    <main class="flex-1 px-8 py-8">
      <div class="max-w-7xl mx-auto">

        {% if messages %}
        <div class="mb-6 space-y-2">
          {% for message in messages %}
          <div x-data="{ show: true }" x-show="show" x-init="setTimeout(() => show = false, 5000)"
               class="px-4 py-3 rounded-lg text-sm flex items-center justify-between
                 {% if message.tags == 'success' %}bg-[rgba(48,192,116,0.10)] border border-[rgba(48,192,116,0.25)] text-[#6ee7b7]
                 {% elif message.tags == 'error' %}bg-[rgba(239,68,68,0.10)] border border-[rgba(239,68,68,0.25)] text-[#fca5a5]
                 {% elif message.tags == 'warning' %}bg-[rgba(234,179,8,0.10)] border border-[rgba(234,179,8,0.25)] text-[#fde047]
                 {% else %}bg-[rgba(59,130,246,0.10)] border border-[rgba(59,130,246,0.25)] text-[#93c5fd]{% endif %}">
            <span>{{ message }}</span>
            <button @click="show = false" class="text-[#3d6b4f] hover:text-[#6b9e7e] ml-4">&times;</button>
          </div>
          {% endfor %}
        </div>
        {% endif %}

        {% block content %}{% endblock %}

      </div>
    </main>
  </div>

</body>
</html>
```

- [ ] **Step 2: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add templates/base.html
git commit -m "style: dark mode base — Inter font, brand palette, sidebar, nav, messages"
```

---

## Task 2: Partials — severity_badge, status_badge, scan_status, pagination

**Files:**
- Modify: `templates/partials/severity_badge.html`
- Modify: `templates/partials/status_badge.html`
- Modify: `templates/partials/scan_status.html`
- Modify: `templates/partials/pagination.html`

- [ ] **Step 1: Replace `severity_badge.html`**

```html
{% if severity == "critical" %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(239,68,68,0.14)] text-[#fca5a5]">Critical</span>
{% elif severity == "high" %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(249,115,22,0.14)] text-[#fdba74]">High</span>
{% elif severity == "medium" %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(234,179,8,0.10)] text-[#fde047]">Medium</span>
{% elif severity == "low" %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(48,192,116,0.12)] text-[#6ee7b7]">Low</span>
{% else %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(148,163,184,0.10)] text-[#94a3b8]">{{ severity }}</span>
{% endif %}
```

- [ ] **Step 2: Replace `status_badge.html`**

```html
{% if status == "pending" %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(255,255,255,0.06)] text-[#6b9e7e]">Pending</span>
{% elif status == "running" %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(59,130,246,0.12)] text-[#93c5fd]">Running</span>
{% elif status == "completed" %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(48,192,116,0.12)] text-[#6ee7b7]">Completed</span>
{% elif status == "failed" %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(239,68,68,0.12)] text-[#fca5a5]">Failed</span>
{% else %}
  <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[rgba(255,255,255,0.06)] text-[#6b9e7e]">{{ status }}</span>
{% endif %}
```

- [ ] **Step 3: Replace `scan_status.html`**

```html
<div id="scan-status-panel"
     {% if session.status == "running" or session.status == "pending" %}
     hx-get="{% url 'scan-status-fragment' session.uuid %}"
     hx-trigger="every 3s"
     hx-swap="outerHTML"
     {% endif %}>

  <div class="bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] p-6">
    <div class="flex items-center justify-between mb-4">
      <div class="flex items-center gap-3">
        {% include "partials/status_badge.html" with status=session.status large=True %}
        {% if session.status == "running" %}
        <span class="text-[#6b9e7e] text-sm animate-pulse">Scanning in progress...</span>
        {% elif session.status == "cancelled" %}
        <span class="text-[#6b9e7e] text-sm">Scan cancelled</span>
        {% endif %}
      </div>
      {% if session.status == "running" or session.status == "pending" %}
      <div x-data="{ confirmStop: false }">
        <button @click="confirmStop = true" x-show="!confirmStop"
                class="px-3 py-1.5 text-xs font-medium text-[#fca5a5] border border-[rgba(239,68,68,0.30)] rounded-md hover:bg-[rgba(239,68,68,0.08)] transition-colors">
          Stop Scan
        </button>
        <div x-show="confirmStop" x-cloak class="flex items-center gap-2">
          <button @click="confirmStop = false" class="text-xs text-[#6b9e7e] hover:text-[#e8f5ef]">Cancel</button>
          <form method="post" action="{% url 'scan-stop' session.uuid %}">
            {% csrf_token %}
            <button type="submit" class="px-3 py-1.5 text-xs font-medium text-[#022c22] bg-[#30c074] rounded-md hover:bg-[#28a863]">
              Yes, stop
            </button>
          </form>
        </div>
      </div>
      {% elif session.end_time %}
      <span class="text-[#3d6b4f] text-sm">{{ session.end_time|date:"M d, Y H:i" }}</span>
      {% endif %}
    </div>

    <div class="grid grid-cols-4 gap-4">
      {% for sev, count in vuln_counts.items %}
      <div class="rounded-md p-4 text-center
        {% if sev == 'critical' %}bg-[rgba(239,68,68,0.10)] border border-[rgba(239,68,68,0.20)]
        {% elif sev == 'high' %}bg-[rgba(249,115,22,0.10)] border border-[rgba(249,115,22,0.20)]
        {% elif sev == 'medium' %}bg-[rgba(234,179,8,0.08)] border border-[rgba(234,179,8,0.20)]
        {% else %}bg-[rgba(48,192,116,0.08)] border border-[rgba(48,192,116,0.20)]{% endif %}">
        <p class="text-2xl font-bold
          {% if sev == 'critical' %}text-[#fca5a5]
          {% elif sev == 'high' %}text-[#fdba74]
          {% elif sev == 'medium' %}text-[#fde047]
          {% else %}text-[#6ee7b7]{% endif %}">{{ count }}</p>
        <p class="text-xs font-semibold uppercase mt-1
          {% if sev == 'critical' %}text-[#f87171]
          {% elif sev == 'high' %}text-[#fb923c]
          {% elif sev == 'medium' %}text-[#ca8a04]
          {% else %}text-[#30c074]{% endif %}">{{ sev }}</p>
      </div>
      {% endfor %}
    </div>

    <p class="mt-4 text-sm text-[#6b9e7e]">
      Total findings: <span class="font-semibold text-[#e8f5ef]">{{ live_total }}</span>
      {% if session.status == "running" %}
      <span class="text-xs text-[#3d6b4f] ml-2">(updating live)</span>
      {% endif %}
    </p>

    {% if step_results %}
    <div class="mt-4 border-t border-[rgba(48,192,116,0.12)] pt-4">
      <p class="text-xs font-semibold text-[#3d6b4f] uppercase mb-2">Pipeline Progress</p>
      <div class="flex flex-wrap gap-2">
        {% for step in step_results %}
        <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium
          {% if step.status == 'completed' %}bg-[rgba(48,192,116,0.12)] text-[#6ee7b7]
          {% elif step.status == 'running' %}bg-[rgba(59,130,246,0.12)] text-[#93c5fd] animate-pulse
          {% elif step.status == 'failed' %}bg-[rgba(239,68,68,0.12)] text-[#fca5a5]
          {% else %}bg-[rgba(255,255,255,0.05)] text-[#3d6b4f]{% endif %}">
          {% if step.status == 'completed' %}&#10003;
          {% elif step.status == 'running' %}&#9679;
          {% elif step.status == 'failed' %}&#10007;
          {% else %}&#9675;{% endif %}
          {{ step.tool }}
        </div>
        {% endfor %}
      </div>
    </div>
    {% endif %}

  </div>

  <!-- Discovery summary cards -->
  <div class="mt-6 grid grid-cols-2 md:grid-cols-5 gap-3">
    <a href="#subdomains" class="bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] px-4 py-3 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
      <div class="text-xs text-[#3d6b4f] uppercase font-medium">Subdomains</div>
      <div class="text-2xl font-bold text-[#e8f5ef]">{{ asset_counts.subdomains_total }}</div>
      <div class="text-xs text-[#30c074]">{{ asset_counts.subdomains_active }} active</div>
    </a>
    <a href="#ports" class="bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] px-4 py-3 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
      <div class="text-xs text-[#3d6b4f] uppercase font-medium">Public IPs</div>
      <div class="text-2xl font-bold text-[#e8f5ef]">{{ asset_counts.ips }}</div>
    </a>
    <a href="#ports" class="bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] px-4 py-3 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
      <div class="text-xs text-[#3d6b4f] uppercase font-medium">Open Ports</div>
      <div class="text-2xl font-bold text-[#e8f5ef]">{{ asset_counts.ports }}</div>
    </a>
    <a href="#urls" class="bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] px-4 py-3 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
      <div class="text-xs text-[#3d6b4f] uppercase font-medium">Web URLs</div>
      <div class="text-2xl font-bold text-[#e8f5ef]">{{ asset_counts.urls }}</div>
    </a>
    <a href="#cves" class="bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] px-4 py-3 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
      <div class="text-xs text-[#3d6b4f] uppercase font-medium">CVE Findings</div>
      <div class="text-2xl font-bold text-[#fca5a5]">{{ asset_counts.nmap_findings }}</div>
    </a>
  </div>

</div>
```

- [ ] **Step 4: Replace `pagination.html`**

```html
{% if page_obj.has_other_pages %}
<div class="flex items-center justify-between px-6 py-3 border-t border-[rgba(48,192,116,0.12)] bg-[#0d2614]">
  <p class="text-sm text-[#6b9e7e]">
    Showing {{ page_obj.start_index }}–{{ page_obj.end_index }} of {{ page_obj.paginator.count }}
  </p>
  <div class="flex gap-1">
    {% if page_obj.has_previous %}
    <a href="?{% if request.GET.urlencode %}{{ request.GET.urlencode }}&{% endif %}page={{ page_obj.previous_page_number }}"
       class="px-3 py-1 text-sm border border-[rgba(48,192,116,0.15)] rounded text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.05)]">Prev</a>
    {% endif %}
    {% for num in page_obj.paginator.page_range %}
      {% if page_obj.number == num %}
        <span class="px-3 py-1 text-sm bg-[#30c074] text-[#022c22] font-bold rounded">{{ num }}</span>
      {% elif num > page_obj.number|add:"-3" and num < page_obj.number|add:"3" %}
        <a href="?{% if request.GET.urlencode %}{{ request.GET.urlencode }}&{% endif %}page={{ num }}"
           class="px-3 py-1 text-sm border border-[rgba(48,192,116,0.15)] rounded text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.05)]">{{ num }}</a>
      {% endif %}
    {% endfor %}
    {% if page_obj.has_next %}
    <a href="?{% if request.GET.urlencode %}{{ request.GET.urlencode }}&{% endif %}page={{ page_obj.next_page_number }}"
       class="px-3 py-1 text-sm border border-[rgba(48,192,116,0.15)] rounded text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.05)]">Next</a>
    {% endif %}
  </div>
</div>
{% endif %}
```

- [ ] **Step 5: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add templates/partials/severity_badge.html templates/partials/status_badge.html templates/partials/scan_status.html templates/partials/pagination.html
git commit -m "style: dark mode partials — severity/status badges, scan status panel, pagination"
```

---

## Task 3: dashboard.html

**Files:**
- Modify: `templates/dashboard.html`

- [ ] **Step 1: Update page header, stat cards, and asset cards**

Find and replace the `<div class="mb-8">` header block and both grid sections (lines 7–93). Replace with:

```html
<div class="mb-8">
  <h1 class="text-2xl font-extrabold text-[#e8f5ef] tracking-tight">Dashboard</h1>
  <p class="text-[#3d6b4f] text-sm mt-1">Current state of your external attack surface</p>
</div>

<!-- Current State Cards -->
<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
  <a href="{% url 'finding-list' %}?severity=critical"
     class="bg-[#0d2614] border border-[rgba(239,68,68,0.20)] rounded-lg px-5 py-4 hover:border-[rgba(239,68,68,0.40)] transition-colors block">
    <p class="text-xs font-semibold text-[#f87171] uppercase tracking-wide">Critical Now</p>
    <p class="text-3xl font-extrabold text-[#fca5a5] mt-1 tracking-tight">{{ current_critical }}</p>
    <p class="text-xs text-[#3d6b4f] mt-1">active findings</p>
  </a>
  <a href="{% url 'finding-list' %}?severity=high"
     class="bg-[#0d2614] border border-[rgba(249,115,22,0.20)] rounded-lg px-5 py-4 hover:border-[rgba(249,115,22,0.40)] transition-colors block">
    <p class="text-xs font-semibold text-[#fb923c] uppercase tracking-wide">High Now</p>
    <p class="text-3xl font-extrabold text-[#fdba74] mt-1 tracking-tight">{{ current_high }}</p>
    <p class="text-xs text-[#3d6b4f] mt-1">active findings</p>
  </a>
  <a href="{% url 'domain-list' %}"
     class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
    <p class="text-xs font-semibold text-[#6b9e7e] uppercase tracking-wide">Domains</p>
    <p class="text-3xl font-extrabold text-[#e8f5ef] mt-1 tracking-tight">{{ active_domain_count }}</p>
    <p class="text-xs text-[#3d6b4f] mt-1">monitored</p>
  </a>
  <a href="{% url 'scan-list' %}?status=running"
     class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
    <p class="text-xs font-semibold text-[#6b9e7e] uppercase tracking-wide">Scans Running</p>
    <p class="text-3xl font-extrabold text-[#e8f5ef] mt-1 tracking-tight">{{ running_count }}</p>
    <p class="text-xs text-[#3d6b4f] mt-1">
      {% if running_count > 0 %}
      <span class="inline-flex items-center gap-1">
        <span class="w-1.5 h-1.5 bg-blue-500 rounded-full animate-pulse inline-block"></span>in progress
      </span>
      {% else %}
      idle
      {% endif %}
    </p>
  </a>
</div>

<!-- Discovery Summary -->
<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
  {% if latest_scan_uuid %}
  <a href="{% url 'scan-detail' latest_scan_uuid %}#subdomains"
     class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
  {% else %}
  <div class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4">
  {% endif %}
    <p class="text-xs font-semibold text-[#6b9e7e] uppercase tracking-wide">Active Subdomains</p>
    <p class="text-3xl font-extrabold text-[#e8f5ef] mt-1 tracking-tight">{{ asset_counts.subdomains }}</p>
    <p class="text-xs text-[#3d6b4f] mt-1">discovered</p>
  {% if latest_scan_uuid %}</a>{% else %}</div>{% endif %}

  {% if latest_scan_uuid %}
  <a href="{% url 'scan-detail' latest_scan_uuid %}#ips"
     class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
  {% else %}
  <div class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4">
  {% endif %}
    <p class="text-xs font-semibold text-[#6b9e7e] uppercase tracking-wide">Public IPs</p>
    <p class="text-3xl font-extrabold text-[#e8f5ef] mt-1 tracking-tight">{{ asset_counts.ips }}</p>
    <p class="text-xs text-[#3d6b4f] mt-1">resolved</p>
  {% if latest_scan_uuid %}</a>{% else %}</div>{% endif %}

  {% if latest_scan_uuid %}
  <a href="{% url 'scan-detail' latest_scan_uuid %}#ports"
     class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
  {% else %}
  <div class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4">
  {% endif %}
    <p class="text-xs font-semibold text-[#6b9e7e] uppercase tracking-wide">Open Ports</p>
    <p class="text-3xl font-extrabold text-[#e8f5ef] mt-1 tracking-tight">{{ asset_counts.ports }}</p>
    <p class="text-xs text-[#3d6b4f] mt-1">across all hosts</p>
  {% if latest_scan_uuid %}</a>{% else %}</div>{% endif %}

  {% if latest_scan_uuid %}
  <a href="{% url 'scan-detail' latest_scan_uuid %}#urls"
     class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4 hover:border-[rgba(48,192,116,0.25)] transition-colors block">
  {% else %}
  <div class="bg-[#0d2614] border border-[rgba(48,192,116,0.12)] rounded-lg px-5 py-4">
  {% endif %}
    <p class="text-xs font-semibold text-[#6b9e7e] uppercase tracking-wide">Web URLs</p>
    <p class="text-3xl font-extrabold text-[#e8f5ef] mt-1 tracking-tight">{{ asset_counts.urls }}</p>
    <p class="text-xs text-[#3d6b4f] mt-1">live HTTP/HTTPS</p>
  {% if latest_scan_uuid %}</a>{% else %}</div>{% endif %}
</div>
```

- [ ] **Step 2: Update Domain Status table**

Find the Domain Status `<div class="bg-white rounded-lg shadow mb-6">` section and replace with:

```html
<!-- Domain Status -->
<div class="bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] mb-6">
  <div class="px-6 py-4 border-b border-[rgba(48,192,116,0.12)] flex items-center justify-between">
    <div>
      <h2 class="font-semibold text-[#e8f5ef]">Domain Status</h2>
      <p class="text-xs text-[#3d6b4f] mt-0.5">Latest scan results per domain</p>
    </div>
    <a href="{% url 'domain-list' %}" class="text-[#30c074] text-sm hover:underline">Manage domains</a>
  </div>

  {% if domain_status %}
  <table class="min-w-full">
    <thead class="bg-[rgba(0,0,0,0.35)]">
      <tr>
        <th class="px-6 py-3 text-left text-xs font-semibold text-[#3d6b4f] uppercase">Domain</th>
        <th class="px-6 py-3 text-left text-xs font-semibold text-[#3d6b4f] uppercase">Last Scan</th>
        <th class="px-6 py-3 text-left text-xs font-semibold text-[#3d6b4f] uppercase">Findings</th>
        <th class="px-6 py-3 text-center text-xs font-semibold text-[#ca8a04] uppercase">&#916; New</th>
        <th class="px-6 py-3 text-left text-xs font-semibold text-[#3d6b4f] uppercase">Status</th>
        <th class="px-6 py-3"></th>
      </tr>
    </thead>
    <tbody>
      {% for item in domain_status %}
      <tr class="border-t border-[rgba(48,192,116,0.05)] hover:bg-[rgba(48,192,116,0.025)]">
        <td class="px-6 py-3 text-sm font-medium text-[#e8f5ef] font-mono">{{ item.domain.name }}</td>
        <td class="px-6 py-3 text-xs text-[#6b9e7e]">
          {% if item.summary %}
            {{ item.summary.scan_date|date:"M d, H:i" }}
          {% else %}
            <span class="text-[#1e3d2a]">Never scanned</span>
          {% endif %}
        </td>
        <td class="px-6 py-4 text-sm">
          {% if item.summary %}
          <div class="flex flex-wrap gap-1">
            {% if item.summary.critical_count %}
            <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=critical"
               class="bg-[rgba(239,68,68,0.12)] text-[#fca5a5] text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">{{ item.summary.critical_count }} crit</a>
            {% endif %}
            {% if item.summary.high_count %}
            <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=high"
               class="bg-[rgba(249,115,22,0.12)] text-[#fdba74] text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">{{ item.summary.high_count }} high</a>
            {% endif %}
            {% if item.summary.medium_count %}
            <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=medium"
               class="bg-[rgba(234,179,8,0.08)] text-[#fde047] text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">{{ item.summary.medium_count }} med</a>
            {% endif %}
            {% if item.summary.low_count %}
            <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=low"
               class="bg-[rgba(48,192,116,0.10)] text-[#6ee7b7] text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">{{ item.summary.low_count }} low</a>
            {% endif %}
          </div>
          {% else %}
          <span class="text-[#1e3d2a]">—</span>
          {% endif %}
        </td>
        <td class="px-6 py-4 text-center">
          {% if item.summary.new_exposures %}
          <span class="bg-[rgba(234,179,8,0.15)] text-[#fde047] text-xs font-semibold px-2 py-0.5 rounded-full">+{{ item.summary.new_exposures }}</span>
          {% else %}
          <span class="text-[#1e3d2a] text-sm">—</span>
          {% endif %}
        </td>
        <td class="px-6 py-3 text-sm">
          {% if item.latest_session %}
            {% include "partials/status_badge.html" with status=item.latest_session.status %}
          {% else %}
            <span class="text-[#1e3d2a] text-xs">—</span>
          {% endif %}
        </td>
        <td class="px-6 py-3 text-right">
          <a href="{% url 'scan-start' %}?domain={{ item.domain.name }}"
             class="text-xs bg-[#30c074] text-[#022c22] font-bold px-3 py-1 rounded hover:bg-[#28a863]">
            Scan
          </a>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="px-6 py-12 text-center text-[#3d6b4f]">
    <p class="text-lg">No domains added yet.</p>
    <a href="{% url 'domain-list' %}" class="mt-3 inline-block text-[#30c074] hover:underline text-sm">Add a domain →</a>
  </div>
  {% endif %}
</div>
```

- [ ] **Step 3: Update Urgent Findings table**

Find the Urgent Findings section (`<!-- Urgent Findings -->`) and replace all `bg-white`, `border-gray-*`, `text-gray-*` classes using the same pattern. The section wrapper becomes:

```html
<!-- Urgent Findings (critical and high — all sources) -->
{% if urgent_findings %}
<div class="bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] mb-6">
  <div class="px-6 py-4 border-b border-[rgba(48,192,116,0.12)] flex items-center justify-between">
    <div>
      <h2 class="font-semibold text-[#e8f5ef]">Urgent Findings</h2>
      <p class="text-xs text-[#3d6b4f] mt-0.5">Critical and high — all sources</p>
    </div>
    <a href="{% url 'finding-list' %}?severity=critical" class="text-[#30c074] text-sm hover:underline">View all findings →</a>
  </div>
  <table class="min-w-full">
    <thead class="bg-[rgba(0,0,0,0.35)]">
      <tr>
        <th class="px-6 py-3 text-left text-xs font-semibold text-[#3d6b4f] uppercase">Finding</th>
        <th class="px-6 py-3 text-left text-xs font-semibold text-[#3d6b4f] uppercase">Domain</th>
        <th class="px-6 py-3 text-left text-xs font-semibold text-[#3d6b4f] uppercase">Source</th>
        <th class="px-6 py-3 text-left text-xs font-semibold text-[#3d6b4f] uppercase">Severity</th>
        <th class="px-6 py-3 text-left text-xs font-semibold text-[#3d6b4f] uppercase">Detected</th>
      </tr>
    </thead>
    <tbody>
      {% for f in urgent_findings %}
      <tr class="border-t border-[rgba(48,192,116,0.05)] hover:bg-[rgba(48,192,116,0.025)]">
        <td class="px-6 py-3 text-sm text-[#e8f5ef] max-w-xs truncate">{{ f.title }}</td>
        <td class="px-6 py-3 text-sm font-mono text-[#6b9e7e]">{{ f.session.domain }}</td>
        <td class="px-6 py-3 text-xs text-[#6b9e7e] uppercase">{{ f.source }}</td>
        <td class="px-6 py-3">{% include "partials/severity_badge.html" with severity=f.severity %}</td>
        <td class="px-6 py-3 text-sm text-[#3d6b4f]">{{ f.discovered_at|date:"M d, H:i" }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add templates/dashboard.html
git commit -m "style: dark mode dashboard — stat cards, domain table, urgent findings"
```

---

## Task 4: domains/list.html

**Files:**
- Modify: `templates/domains/list.html`

- [ ] **Step 1: Update page header, form card, and domain list**

Replace the full file content. Key class mappings:
- `text-gray-900` → `text-[#e8f5ef]`
- `text-gray-500` → `text-[#6b9e7e]`
- `text-gray-700` → `text-[#e8f5ef]`
- `text-gray-400` → `text-[#3d6b4f]`
- `bg-white rounded-lg shadow` → `bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)]`
- `border-gray-200` → `border-[rgba(48,192,116,0.12)]`
- `bg-red-50 border border-red-200 text-red-700` (delete error) → `bg-[rgba(239,68,68,0.10)] border border-[rgba(239,68,68,0.25)] text-[#fca5a5]`
- `bg-indigo-600 hover:bg-indigo-700 text-white` (Add Domain button) → `bg-[#30c074] hover:bg-[#28a863] text-[#022c22] font-bold`
- Table `divide-y divide-gray-200` → remove (use row border instead)
- Table `bg-gray-50` thead → `bg-[rgba(0,0,0,0.35)]`
- `th text-gray-500` → `text-[#3d6b4f]`
- `td text-gray-900` → `text-[#e8f5ef]`
- `td text-gray-500` → `text-[#6b9e7e]`
- `hover:bg-gray-50` row → `hover:bg-[rgba(48,192,116,0.025)]`
- Active toggle: `text-green-600` → `text-[#30c074]`
- Inactive toggle: `text-gray-400` → `text-[#3d6b4f]`
- Scan button: `bg-indigo-600 text-white` → `bg-[#30c074] text-[#022c22] font-bold`
- Delete button: `text-red-600 hover:text-red-800` stays (red is semantic and fine)
- Inline confirmation: `bg-red-50 border border-red-200` → `bg-[rgba(239,68,68,0.08)] border border-[rgba(239,68,68,0.20)]`
- `text-red-700` confirm text → `text-[#fca5a5]`
- `bg-red-600 text-white hover:bg-red-700` confirm button → stays (danger red is fine)
- Primary domain badge: `text-xs bg-indigo-100 text-indigo-700` → `text-xs bg-[rgba(48,192,116,0.10)] text-[#30c074]`
- `text-gray-600` label → `text-[#6b9e7e]`

Apply these replacements throughout `templates/domains/list.html`. The structure is unchanged — only classes change.

- [ ] **Step 2: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add templates/domains/list.html
git commit -m "style: dark mode domains page"
```

---

## Task 5: findings/list.html

**Files:**
- Modify: `templates/findings/list.html`

- [ ] **Step 1: Update severity cards at the top**

Find the 4 severity filter cards (`bg-white border border-red-200`, etc.) and replace:

```html
<div class="grid grid-cols-4 gap-4 mb-4">
  <a href="?severity=critical{% if domain %}&domain={{ domain|urlencode }}{% endif %}{% if status_filter %}&status={{ status_filter|urlencode }}{% endif %}{% if session_id %}&session_id={{ session_id }}{% endif %}"
     class="bg-[#0d2614] border border-[rgba(239,68,68,0.20)] rounded-lg p-4 cursor-pointer hover:border-[rgba(239,68,68,0.40)] transition-colors {% if severity == 'critical' %}ring-2 ring-[rgba(239,68,68,0.50)]{% endif %}">
    <div class="text-xs font-semibold text-[#f87171] uppercase tracking-wide">Critical</div>
    <div class="text-3xl font-extrabold text-[#fca5a5] my-1 tracking-tight">{{ count_open_critical }}</div>
    <div class="text-xs text-[#3d6b4f]">open findings</div>
  </a>
  <a href="?severity=high{% if domain %}&domain={{ domain|urlencode }}{% endif %}{% if status_filter %}&status={{ status_filter|urlencode }}{% endif %}{% if session_id %}&session_id={{ session_id }}{% endif %}"
     class="bg-[#0d2614] border border-[rgba(249,115,22,0.20)] rounded-lg p-4 cursor-pointer hover:border-[rgba(249,115,22,0.40)] transition-colors {% if severity == 'high' %}ring-2 ring-[rgba(249,115,22,0.50)]{% endif %}">
    <div class="text-xs font-semibold text-[#fb923c] uppercase tracking-wide">High</div>
    <div class="text-3xl font-extrabold text-[#fdba74] my-1 tracking-tight">{{ count_open_high }}</div>
    <div class="text-xs text-[#3d6b4f]">open findings</div>
  </a>
  <a href="?severity=medium{% if domain %}&domain={{ domain|urlencode }}{% endif %}{% if status_filter %}&status={{ status_filter|urlencode }}{% endif %}{% if session_id %}&session_id={{ session_id }}{% endif %}"
     class="bg-[#0d2614] border border-[rgba(234,179,8,0.20)] rounded-lg p-4 cursor-pointer hover:border-[rgba(234,179,8,0.40)] transition-colors {% if severity == 'medium' %}ring-2 ring-[rgba(234,179,8,0.50)]{% endif %}">
    <div class="text-xs font-semibold text-[#ca8a04] uppercase tracking-wide">Medium</div>
    <div class="text-3xl font-extrabold text-[#fde047] my-1 tracking-tight">{{ count_open_medium }}</div>
    <div class="text-xs text-[#3d6b4f]">open findings</div>
  </a>
  <a href="?severity=low{% if domain %}&domain={{ domain|urlencode }}{% endif %}{% if status_filter %}&status={{ status_filter|urlencode }}{% endif %}{% if session_id %}&session_id={{ session_id }}{% endif %}"
     class="bg-[#0d2614] border border-[rgba(48,192,116,0.20)] rounded-lg p-4 cursor-pointer hover:border-[rgba(48,192,116,0.40)] transition-colors {% if severity == 'low' %}ring-2 ring-[rgba(48,192,116,0.50)]{% endif %}">
    <div class="text-xs font-semibold text-[#30c074] uppercase tracking-wide">Low</div>
    <div class="text-3xl font-extrabold text-[#6ee7b7] my-1 tracking-tight">{{ count_open_low }}</div>
    <div class="text-xs text-[#3d6b4f]">open findings</div>
  </a>
</div>
```

- [ ] **Step 2: Update filter bar and findings table**

Apply these class replacements throughout the rest of `findings/list.html`:
- `bg-white rounded-lg shadow` → `bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)]`
- `border-gray-200` / `border-gray-300` → `border-[rgba(48,192,116,0.12)]`
- `text-gray-500` → `text-[#6b9e7e]`
- `text-gray-900` / `text-gray-800` → `text-[#e8f5ef]`
- `text-gray-400` → `text-[#3d6b4f]`
- `focus:ring-indigo-500` → `focus:ring-[#30c074]`
- `bg-gray-50` thead → `bg-[rgba(0,0,0,0.35)]`
- `th text-gray-500` → `text-[#3d6b4f]`
- `divide-y divide-gray-200` → remove from table/tbody (rows get `border-t border-[rgba(48,192,116,0.05)]`)
- `hover:bg-gray-50` → `hover:bg-[rgba(48,192,116,0.025)]`
- `td text-gray-900` → `text-[#e8f5ef]`
- `td text-gray-500` → `text-[#6b9e7e]`
- `h1 text-gray-900` → `text-[#e8f5ef] font-extrabold tracking-tight`

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add templates/findings/list.html
git commit -m "style: dark mode findings page"
```

---

## Task 6: scans/list.html and scans/scheduled.html

**Files:**
- Modify: `templates/scans/list.html`
- Modify: `templates/scans/scheduled.html`

- [ ] **Step 1: Update `scans/list.html` status cards**

Find the 3 status cards at the top and replace:

```html
<div class="grid grid-cols-3 gap-4 mb-4">
  <a href="?status=running{% if domain %}&domain={{ domain|urlencode }}{% endif %}"
     class="bg-[#0d2614] border border-[rgba(59,130,246,0.20)] rounded-lg p-4 cursor-pointer hover:border-[rgba(59,130,246,0.40)] transition-colors {% if status_filter == 'running' %}ring-2 ring-[rgba(59,130,246,0.50)]{% endif %}">
    <div class="text-xs font-semibold text-blue-400 uppercase tracking-wide">Running</div>
    <div class="text-3xl font-extrabold text-[#93c5fd] my-1 tracking-tight">{{ count_running }}</div>
    <div class="text-xs text-[#3d6b4f]">active scans</div>
  </a>
  <a href="?status=completed{% if domain %}&domain={{ domain|urlencode }}{% endif %}"
     class="bg-[#0d2614] border border-[rgba(48,192,116,0.20)] rounded-lg p-4 cursor-pointer hover:border-[rgba(48,192,116,0.40)] transition-colors {% if status_filter == 'completed' %}ring-2 ring-[rgba(48,192,116,0.50)]{% endif %}">
    <div class="text-xs font-semibold text-[#30c074] uppercase tracking-wide">Completed</div>
    <div class="text-3xl font-extrabold text-[#6ee7b7] my-1 tracking-tight">{{ count_completed }}</div>
    <div class="text-xs text-[#3d6b4f]">finished scans</div>
  </a>
  <a href="?status=failed{% if domain %}&domain={{ domain|urlencode }}{% endif %}"
     class="bg-[#0d2614] border border-[rgba(239,68,68,0.20)] rounded-lg p-4 cursor-pointer hover:border-[rgba(239,68,68,0.40)] transition-colors {% if status_filter == 'failed' %}ring-2 ring-[rgba(239,68,68,0.50)]{% endif %}">
    <div class="text-xs font-semibold text-[#f87171] uppercase tracking-wide">Failed</div>
    <div class="text-3xl font-extrabold text-[#fca5a5] my-1 tracking-tight">{{ count_failed }}</div>
    <div class="text-xs text-[#3d6b4f]">errored scans</div>
  </a>
</div>
```

- [ ] **Step 2: Update `scans/list.html` scheduled jobs section and scan history table**

Apply the standard class replacements:
- `bg-white rounded-lg shadow` → `bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)]`
- `border-gray-200` → `border-[rgba(48,192,116,0.12)]`
- `bg-gray-50` thead → `bg-[rgba(0,0,0,0.35)]`
- `text-gray-*` → appropriate dark equivalents (primary → `#e8f5ef`, secondary → `#6b9e7e`, muted → `#3d6b4f`)
- `divide-y divide-gray-*` → remove; add `border-t border-[rgba(48,192,116,0.05)]` to `<tr>`
- `hover:bg-gray-50` → `hover:bg-[rgba(48,192,116,0.025)]`
- `text-indigo-600` links → `text-[#30c074]`
- `bg-indigo-600 text-white` buttons → `bg-[#30c074] text-[#022c22] font-bold`
- `border-gray-300 text-gray-700` ghost buttons → `border-[rgba(48,192,116,0.22)] text-[#30c074]`
- Page `h1 text-gray-900` → `text-[#e8f5ef] font-extrabold tracking-tight`
- `text-gray-500` subtitle → `text-[#3d6b4f]`
- Scheduled job type badges: `bg-indigo-100 text-indigo-700` → `bg-[rgba(48,192,116,0.10)] text-[#30c074]`; `bg-amber-100 text-amber-700` → `bg-[rgba(234,179,8,0.10)] text-[#fde047]`

- [ ] **Step 3: Update `scans/scheduled.html`**

Apply the same standard replacements as above:
- `bg-white rounded-lg shadow` → `bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)]`
- `bg-gray-50` thead → `bg-[rgba(0,0,0,0.35)]`
- `divide-y divide-gray-100` → remove
- `tr hover:bg-gray-50` → `hover:bg-[rgba(48,192,116,0.025)]`
- `text-gray-900` → `text-[#e8f5ef]`; `text-gray-500` → `text-[#6b9e7e]`; `text-gray-300 italic` → `text-[#1e3d2a] italic`
- `bg-indigo-600 text-white hover:bg-indigo-700` (+ New Scan button) → `bg-[#30c074] text-[#022c22] font-bold hover:bg-[#28a863]`
- Job type badges: same as step 2
- Inline confirm row: `bg-red-50` → `bg-[rgba(239,68,68,0.08)]`; `text-red-700` → `text-[#fca5a5]`; `text-gray-600` → `text-[#6b9e7e]`
- Empty state: `text-gray-400` → `text-[#3d6b4f]`; `text-indigo-600` link → `text-[#30c074]`

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add templates/scans/list.html templates/scans/scheduled.html
git commit -m "style: dark mode scans list and scheduled pages"
```

---

## Task 7: scans/detail.html

**Files:**
- Modify: `templates/scans/detail.html`

- [ ] **Step 1: Update back link, header, export buttons, and all section cards**

Apply these replacements throughout `templates/scans/detail.html`:
- `text-indigo-600 text-sm hover:underline` (back link) → `text-[#30c074] text-sm hover:underline`
- `h1 text-gray-900` → `text-[#e8f5ef] font-extrabold tracking-tight`
- `text-gray-500` subtitle → `text-[#3d6b4f]`
- Export buttons: `border border-gray-300 text-gray-700 bg-white hover:bg-gray-50` → `border border-[rgba(48,192,116,0.22)] text-[#30c074] bg-transparent hover:bg-[rgba(48,192,116,0.05)]`
- All section cards: `bg-white rounded-lg shadow overflow-hidden` → `bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] overflow-hidden`
- `border-gray-200` → `border-[rgba(48,192,116,0.12)]`
- `h2 text-gray-700 font-semibold` → `text-[#e8f5ef] font-semibold`
- `text-indigo-600 text-sm hover:underline` section links → `text-[#30c074] text-sm hover:underline`
- Table `bg-gray-50` thead → `bg-[rgba(0,0,0,0.35)]`
- `th text-gray-500` → `text-[#3d6b4f]`
- `divide-y divide-gray-200` → remove; add row `border-t border-[rgba(48,192,116,0.05)]`
- `td text-gray-900` → `text-[#e8f5ef]`; `td text-gray-500` → `text-[#6b9e7e]`
- `hover:bg-gray-50` → `hover:bg-[rgba(48,192,116,0.025)]`
- Asset section headers (e.g. Subdomains): `text-sm font-semibold text-gray-700` → `text-[#e8f5ef]`
- Empty state text: `text-gray-400` → `text-[#3d6b4f]`
- `text-green-600` (active count) → `text-[#30c074]`
- Port service badge: `bg-blue-100 text-blue-700` → `bg-[rgba(59,130,246,0.12)] text-[#93c5fd]`
- Port is_web badge: `bg-green-100 text-green-700` → `bg-[rgba(48,192,116,0.12)] text-[#6ee7b7]`
- `bg-indigo-600 text-white` action buttons → `bg-[#30c074] text-[#022c22] font-bold hover:bg-[#28a863]`

- [ ] **Step 2: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add templates/scans/detail.html
git commit -m "style: dark mode scan detail page"
```

---

## Task 8: scans/start.html

**Files:**
- Modify: `templates/scans/start.html`

- [ ] **Step 1: Update the form card and all form elements**

Apply these replacements throughout `templates/scans/start.html`:
- `text-indigo-600 text-sm hover:underline` (back link) → `text-[#30c074] text-sm hover:underline`
- `h1 text-gray-900` → `text-[#e8f5ef] font-extrabold tracking-tight`
- `text-gray-500` subtitle → `text-[#3d6b4f]`
- Empty state card: `bg-white rounded-xl shadow-sm border border-gray-200` → `bg-[#0d2614] rounded-xl border border-[rgba(48,192,116,0.12)]`
- `text-gray-900` (no domains heading) → `text-[#e8f5ef]`
- `bg-indigo-600 hover:bg-indigo-700 text-white` (Go to Domains button) → `bg-[#30c074] hover:bg-[#28a863] text-[#022c22] font-bold`
- Main form card: `bg-white rounded-xl shadow-sm border border-gray-200` → `bg-[#0d2614] rounded-xl border border-[rgba(48,192,116,0.12)]`
- Error banner: `bg-red-50 border border-red-200 text-red-700` → `bg-[rgba(239,68,68,0.10)] border border-[rgba(239,68,68,0.25)] text-[#fca5a5]`
- Form labels: `text-sm font-semibold text-gray-700` → `text-sm font-semibold text-[#e8f5ef]`
- Helper text: `text-gray-400` → `text-[#3d6b4f]`; `text-indigo-500` links → `text-[#30c074]`
- Schedule type card Alpine `:class` — **find:**
  ```
  :class="schedule === 'now' ? 'border-indigo-500 bg-indigo-50' : 'border-gray-200 bg-white hover:border-gray-300'"
  ```
  **replace with:**
  ```
  :class="schedule === 'now' ? 'border-[#30c074] bg-[rgba(48,192,116,0.08)]' : 'border-[rgba(48,192,116,0.15)] bg-[#0d2614] hover:border-[rgba(48,192,116,0.30)]'"
  ```
  Apply the same pattern for `'once'` and `'recurring'` schedule cards.
- Card inner text: `text-xs font-semibold text-gray-800` → `text-xs font-semibold text-[#e8f5ef]`; `text-xs text-gray-400` → `text-xs text-[#3d6b4f]`
- Schedule once/recurring container: `rounded-lg border border-gray-200 bg-gray-50 p-4` → `rounded-lg border border-[rgba(48,192,116,0.12)] bg-[rgba(0,0,0,0.25)] p-4`
- Schedule label: `text-sm font-semibold text-gray-700` → `text-sm font-semibold text-[#e8f5ef]`; `text-xs font-normal text-gray-400` → `text-xs font-normal text-[#3d6b4f]`
- Frequency toggle wrapper: `flex rounded-lg border border-gray-300 overflow-hidden bg-white` → `flex rounded-lg border border-[rgba(48,192,116,0.20)] overflow-hidden bg-[rgba(0,0,0,0.2)]`
- Frequency button Alpine `:class`:
  ```
  :class="recurrence === 'daily' ? 'bg-indigo-600 text-white' : 'text-gray-600 hover:bg-gray-50'"
  ```
  **replace with:**
  ```
  :class="recurrence === 'daily' ? 'bg-[#30c074] text-[#022c22] font-bold' : 'text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.08)]'"
  ```
  Apply same for `'weekly'`.
- `text-gray-400 font-bold` (colon separator) → `text-[#3d6b4f] font-bold`
- Submit button: `bg-indigo-600 text-white hover:bg-indigo-700 font-semibold` → `bg-[#30c074] text-[#022c22] font-bold hover:bg-[#28a863]`

- [ ] **Step 2: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add templates/scans/start.html
git commit -m "style: dark mode scan start form — schedule cards, inputs, frequency toggle"
```

---

## Task 9: insights.html

**Files:**
- Modify: `templates/insights.html`

- [ ] **Step 1: Update empty state, KPI cards, and section headers**

Apply these replacements throughout `templates/insights.html`:
- `h1 text-gray-900` → `text-[#e8f5ef] font-extrabold tracking-tight`
- `text-gray-500` subtitle → `text-[#3d6b4f]`
- Empty state card: `bg-white rounded-lg shadow` → `bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)]`
- `text-gray-400` empty state text → `text-[#3d6b4f]`
- `bg-indigo-600 text-white hover:bg-indigo-700` Start Scan button → `bg-[#30c074] text-[#022c22] font-bold hover:bg-[#28a863]`
- KPI cards `bg-white rounded-lg border border-red-200` → `bg-[#0d2614] rounded-lg border border-[rgba(239,68,68,0.20)]`
- KPI `border-orange-200` → `border-[rgba(249,115,22,0.20)]`; `border-green-200` → `border-[rgba(48,192,116,0.20)]`; `border-blue-200` → `border-[rgba(59,130,246,0.20)]`
- KPI label/value colors: `text-red-500` → `text-[#f87171]`; `text-red-600` → `text-[#fca5a5]`; same pattern for orange/green/blue
- `text-gray-400` KPI sub → `text-[#3d6b4f]`
- Section accent bar: `bg-indigo-500` → `bg-[#30c074]`
- `text-slate-900` section heading → `text-[#e8f5ef]`; `text-slate-400` → `text-[#3d6b4f]`
- Chart cards: `bg-white rounded-lg shadow` → `bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)]`
- Chart padding `p-4 border-b border-gray-200` → `border-b border-[rgba(48,192,116,0.12)]`
- `text-sm font-semibold text-gray-700` chart titles → `text-[#e8f5ef]`
- Tool breakdown table: same standard replacements as other tables

- [ ] **Step 2: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add templates/insights.html
git commit -m "style: dark mode insights page"
```

---

## Task 10: workflow templates

**Files:**
- Modify: `templates/workflow/list.html`
- Modify: `templates/workflow/create.html`
- Modify: `templates/workflow/detail.html`

- [ ] **Step 1: Update `workflow/list.html`**

Apply standard replacements:
- `h1 text-gray-900` → `text-[#e8f5ef] font-extrabold tracking-tight`
- `bg-indigo-600 text-white hover:bg-indigo-700` (+ New Workflow) → `bg-[#30c074] text-[#022c22] font-bold hover:bg-[#28a863]`
- Workflow cards: `bg-white rounded-lg shadow` → `bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)]`
- `font-semibold text-gray-900 hover:text-indigo-600` workflow name → `text-[#e8f5ef] hover:text-[#30c074]`
- Default badge: `text-xs bg-indigo-100 text-indigo-700` → `text-xs bg-[rgba(48,192,116,0.10)] text-[#30c074]`
- `text-gray-500` description → `text-[#6b9e7e]`
- Step badges: `bg-green-100 text-green-700` (enabled) → `bg-[rgba(48,192,116,0.12)] text-[#6ee7b7]`; `bg-gray-100 text-gray-400 line-through` (disabled) → `bg-[rgba(255,255,255,0.05)] text-[#1e3d2a] line-through`
- `text-gray-400` run count → `text-[#3d6b4f]`
- `text-xs text-red-500 hover:text-red-700` Delete → stays
- Confirm row: `bg-red-50 border border-red-200` → `bg-[rgba(239,68,68,0.08)] border border-[rgba(239,68,68,0.20)]`; `text-red-700` → `text-[#fca5a5]`; `text-gray-500` cancel → `text-[#6b9e7e]`
- `bg-red-600 text-white hover:bg-red-700` confirm delete → stays
- Empty state: `bg-white rounded-lg shadow` → `bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)]`; `text-gray-400` → `text-[#3d6b4f]`; `text-indigo-600` links → `text-[#30c074]`

- [ ] **Step 2: Update `workflow/create.html` and `workflow/detail.html`**

Apply the same standard replacements:
- All `bg-white` → `bg-[#0d2614]`; `shadow` → `border border-[rgba(48,192,116,0.12)]`
- All `border-gray-*` → `border-[rgba(48,192,116,0.12)]`
- All `text-gray-900` → `text-[#e8f5ef]`; `text-gray-500/600/700` → `text-[#6b9e7e]`; `text-gray-400/300` → `text-[#3d6b4f]`
- `bg-indigo-600 text-white` buttons → `bg-[#30c074] text-[#022c22] font-bold`
- `text-indigo-600` links → `text-[#30c074]`
- Step enabled badge: `bg-green-100 text-green-700` → `bg-[rgba(48,192,116,0.12)] text-[#6ee7b7]`
- Step disabled badge: `bg-gray-100 text-gray-400` → `bg-[rgba(255,255,255,0.05)] text-[#1e3d2a]`
- Table heads: `bg-gray-50` → `bg-[rgba(0,0,0,0.35)]`

- [ ] **Step 3: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add templates/workflow/list.html templates/workflow/create.html templates/workflow/detail.html
git commit -m "style: dark mode workflow pages"
```

---

## Task 11: registration/login.html

**Files:**
- Modify: `templates/registration/login.html`

- [ ] **Step 1: Replace the full login page**

This file does not extend `base.html` so it needs its own font link and full dark styling:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login — OpenEASD</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { font-family: 'Inter', system-ui, sans-serif; }
    input:focus { outline: none !important; border-color: #30c074 !important; box-shadow: 0 0 0 2px rgba(48,192,116,0.15) !important; }
  </style>
</head>
<body class="bg-[#0a1a0f] min-h-screen flex items-center justify-center"
      style="background-image: radial-gradient(ellipse at 50% 0%, rgba(48,192,116,0.08) 0%, transparent 60%);">

  <div class="w-full max-w-sm">
    <div class="text-center mb-8">
      <div class="text-[#30c074] text-3xl mb-2">⬡</div>
      <h1 class="text-2xl font-extrabold text-[#e8f5ef] tracking-tight">OpenEASD</h1>
      <p class="text-[#3d6b4f] text-sm mt-1">Automated External Attack Surface Detection</p>
    </div>

    <div class="bg-[#0d2614] rounded-lg border border-[rgba(48,192,116,0.12)] p-8">
      <h2 class="text-lg font-semibold text-[#e8f5ef] mb-6">Sign in</h2>

      {% if form.errors %}
      <div class="mb-4 bg-[rgba(239,68,68,0.10)] border border-[rgba(239,68,68,0.25)] text-[#fca5a5] text-sm rounded-md px-4 py-3">
        Invalid username or password.
      </div>
      {% endif %}

      <form method="post">
        {% csrf_token %}
        <div class="mb-4">
          <label class="block text-sm font-medium text-[#6b9e7e] mb-1">Username</label>
          <input type="text" name="username" autofocus autocomplete="username"
                 class="w-full border border-[rgba(48,192,116,0.20)] rounded-md px-3 py-2 text-sm bg-[rgba(0,0,0,0.3)] text-[#e8f5ef] placeholder-[#3d6b4f]">
        </div>
        <div class="mb-6">
          <label class="block text-sm font-medium text-[#6b9e7e] mb-1">Password</label>
          <input type="password" name="password" autocomplete="current-password"
                 class="w-full border border-[rgba(48,192,116,0.20)] rounded-md px-3 py-2 text-sm bg-[rgba(0,0,0,0.3)] text-[#e8f5ef]">
        </div>
        <input type="hidden" name="next" value="{{ next }}">
        <button type="submit"
                class="w-full bg-[#30c074] text-[#022c22] py-2 px-4 rounded-md hover:bg-[#28a863] font-bold text-sm transition-colors">
          Sign in
        </button>
      </form>
    </div>
  </div>

</body>
</html>
```

- [ ] **Step 2: Run tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add templates/registration/login.html
git commit -m "style: dark mode login page"
```

---

## Final step: run full suite

- [ ] **Run full test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.
