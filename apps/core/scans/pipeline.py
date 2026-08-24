"""
Scan orchestration for OpenEASD.

All scans run through the workflow system — tools are defined as WorkflowSteps
in the database and executed dynamically by apps.core.workflows.runner.

The default "Full Scan" workflow runs all tools in order:
  1. Domain security (DNS, email, RDAP)
  2. Subfinder (passive subdomain enumeration)
  3. DNSx (DNS resolution, public IP filtering)
  4. Naabu (port scanning)
  5. HTTPx (web probe, URL discovery)
  6. Nmap (NSE vulners on non-web ports)
  7. TLS checker (all open ports)
  8. SSH checker (SSH ports)
  9. Nuclei (web vulnerability scanning on URLs)
  10. Web checker (security headers, cookies, CORS, disclosure)

After tools complete: finalise session, delta detection, insights, alerts.
"""

import logging

from django.db import transaction, DatabaseError
from django.utils import timezone as django_tz

from .models import ScanSession, ScanDelta

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Delta detection
# ---------------------------------------------------------------------------

def _detect_deltas(session):
    # Exclude subscans: they only run a subset of tools, so using one as the
    # baseline would produce spurious "new finding" deltas on the next full scan.
    # Filter on scan_type (immutable) rather than parent_session, which is
    # SET_NULL and would promote a subscan to a baseline once its parent is
    # deleted.
    previous = (
        ScanSession.objects.filter(
            domain=session.domain, status__in=["completed", "partial"]
        )
        .exclude(id=session.id)
        .exclude(scan_type="subscan")
        .order_by("-start_time")
        .first()
    )
    if not previous:
        return

    from apps.core.findings.models import Finding

    current_keys = {
        f"{f.source}:{f.check_type}:{f.title}"
        for f in Finding.objects.filter(session=session)
    }
    prev_keys = {
        f"{f.source}:{f.check_type}:{f.title}"
        for f in Finding.objects.filter(session=previous)
    }
    deltas = []
    for key in current_keys - prev_keys:
        deltas.append(ScanDelta(session=session, previous_session=previous,
                                change_type="new", change_category="finding",
                                item_identifier=key))
    for key in prev_keys - current_keys:
        deltas.append(ScanDelta(session=session, previous_session=previous,
                                change_type="removed", change_category="finding",
                                item_identifier=key))
    if deltas:
        ScanDelta.objects.bulk_create(deltas)


def _check_coverage_regression(session):
    """Emit a loud, in-report warning when this scan's coverage collapsed vs the
    previous one — the tell for the scanner's IP being blocked/rate-limited.

    Catches what a human otherwise only notices by manually comparing two
    reports: findings or live web endpoints dropping sharply, or most probes
    coming back unreachable. Written as a Finding so it shows in the report and
    flows through the normal alert path.
    """
    from apps.core.web_assets.models import URL
    from apps.core.findings.models import Finding

    def _httpx_urls(s):
        return URL.objects.filter(session=s, source="httpx").count()

    reasons = []

    # 1. Most probes unreachable this run (silent drops / WAF) — needs no baseline.
    probed = session.endpoints_probed or 0
    blocked = session.endpoints_blocked or 0
    if probed >= 5 and blocked / probed >= 0.8:
        reasons.append(
            f"{blocked} of {probed} web endpoints probed were unreachable "
            f"({round(100 * blocked / probed)}%)"
            + (f", consistent with {session.waf_vendor}" if session.waf_vendor else "")
        )

    # 2. Sharp drop vs the previous scan of the SAME workflow for this domain.
    # Must be same-workflow: a Passive Scan runs far fewer tools than a Full Scan,
    # so diffing a passive run against a prior active baseline always looks like a
    # collapse and fires a spurious "results incomplete" finding (found live on a
    # cybersecify.com passive run). Same class as excluding subscans from deltas.
    previous = (
        ScanSession.objects.filter(
            domain=session.domain, status__in=["completed", "partial"],
            workflow_id=session.workflow_id,
        )
        .exclude(id=session.id)
        .exclude(scan_type="subscan")
        .order_by("-start_time")
        .first()
    )
    if previous:
        pf, cf = previous.total_findings or 0, session.total_findings or 0
        if pf >= 5 and cf <= 0.5 * pf:
            reasons.append(f"findings fell from {pf} to {cf} vs the previous scan")
        pu, cu = _httpx_urls(previous), _httpx_urls(session)
        if pu >= 3 and cu <= 0.5 * pu:
            reasons.append(f"live web endpoints fell from {pu} to {cu} vs the previous scan")

    if not reasons:
        return

    Finding.objects.create(
        session=session,
        source="scan_coverage",
        check_type="coverage_regression",
        severity="medium",
        title="Scan coverage dropped sharply — results may be incomplete",
        description=(
            "This scan surfaced far less than expected, which usually means the "
            "scanner could not reach the target rather than that the target is "
            "clean. Observed: " + "; ".join(reasons) + "."
        ),
        remediation=(
            "Treat these results as a lower bound, not a clean bill of health. "
            "The target may be blocking or rate-limiting this scanner's IP (WAF), "
            "or its hosting/DNS changed. Re-run from a different vantage point or "
            "an allowlisted IP, run a passive scan (public sources, no direct "
            "probing) to compare, and confirm the host is actually reachable."
        ),
        target=session.domain,
    )
    logger.warning(
        f"[scan:{session.id}] Coverage regression flagged: {'; '.join(reasons)}"
    )


def _count_all_findings(session) -> int:
    try:
        from apps.core.findings.models import Finding
        return Finding.objects.filter(session=session).count()
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Post-scan finalisation
# ---------------------------------------------------------------------------

def _compute_coverage(session):
    """Aggregate httpx probe reachability into per-session coverage counts (C2).

    Sets endpoints_probed / endpoints_blocked and a dominant waf_vendor guess.
    Only httpx-sourced URLs carry a reachability value; other sources are ignored.
    """
    from collections import Counter
    from apps.core.web_assets.models import URL
    from apps.httpx.waf import INTERFERED, fingerprint_vendor

    # `endpoints_probed` is the number of targets httpx was ASKED to probe (set by
    # the httpx scanner). Hosts that responded become URL rows; hosts that were
    # silently dropped leave nothing. So "blocked/unreachable" = everything we
    # probed that did NOT come back as a cleanly reachable URL. This makes a
    # silent block (0 URLs from N probes) visible instead of reading as "clean".
    live = list(
        URL.objects.filter(session=session, source="httpx")
        .values_list("reachability", "title", "web_server")
    )
    interfered = [(r, t, w) for r, t, w in live if r in INTERFERED]
    reached_ok = sum(1 for r, _, _ in live if r not in INTERFERED)  # "" counts as reached
    # The httpx scanner persisted the probe count; re-read it (this may be a
    # different in-memory instance) rather than trust the in-memory field.
    session.refresh_from_db(fields=["endpoints_probed"])
    probed = session.endpoints_probed or len(live)
    session.endpoints_probed = probed
    session.endpoints_blocked = max(0, probed - reached_ok)

    # Dominant vendor among interfered probes; "" when nothing identifiable blocked.
    vendors = Counter(
        fingerprint_vendor(title, ws) or "unidentified"
        for _, title, ws in interfered
    )
    session.waf_vendor = vendors.most_common(1)[0][0] if vendors else ""


def _finalize_session(session):
    """Post-scan: count findings, mark completed, detect deltas, build insights, dispatch alerts."""
    session_id = session.id
    total = _count_all_findings(session)
    session.total_findings = total
    _compute_coverage(session)
    # Reflect the workflow run's outcome instead of always claiming "completed":
    # if any tool failed or timed out, the run is "partial" and the scan must say
    # so, or the top-line status hides a half-finished scan (a tool that didn't
    # run produces zero findings, which reads as "clean").
    from apps.core.workflows.models import WorkflowRun
    run = WorkflowRun.objects.filter(session=session).order_by("-id").first()
    session.status = "partial" if run and run.status in ("partial", "failed") else "completed"
    session.end_time = django_tz.now()
    session.save(update_fields=[
        "total_findings", "status", "end_time",
        "waf_vendor", "endpoints_probed", "endpoints_blocked",
    ])
    logger.info(
        f"[scan:{session_id}] Completed — {total} findings, "
        f"{session.endpoints_blocked}/{session.endpoints_probed} endpoints blocked"
    )

    # Subscans run only a subset of tools against copied parent assets. Delta
    # detection, insights, and alerts all assume a full scan's finding set — a
    # subscan's subset would diff against the last full scan (spurious "removed"
    # deltas) and re-fire alerts the parent already sent. Skip them for subscans.
    if session.scan_type == "subscan":
        logger.info(f"[scan:{session_id}] Subscan — skipping deltas, insights, and alerts")
        return

    _detect_deltas(session)

    # After deltas (so this meta-warning isn't itself a "new finding" delta) and
    # before insights (so it's included in the report's finding set).
    _check_coverage_regression(session)

    from apps.core.insights.builder import build_insights
    build_insights(session)

    _dispatch_alerts(session)


# ---------------------------------------------------------------------------
# Concurrency guard
# ---------------------------------------------------------------------------

def _is_scan_active(domain: str) -> bool:
    """Return True if a pending or running scan already exists for this domain."""
    return ScanSession.objects.filter(
        domain=domain, status__in=["pending", "running"]
    ).exists()


def create_scan_session(domain: str, triggered_by: str = "manual", workflow=None) -> "ScanSession | None":
    """
    Atomically create a scan session if no active scan exists for the domain.
    Returns the new ScanSession or None if a scan is already active.

    If no workflow is specified, the default workflow is auto-assigned so all
    scans run through the dynamic workflow runner.
    """
    if workflow is None:
        from apps.core.workflows.models import Workflow
        workflow = Workflow.objects.filter(is_default=True).first()

    try:
        with transaction.atomic():
            # NOTE: select_for_update(nowait=True) is a no-op on SQLite — Django silently
            # ignores it. Real duplicate-session protection comes from workers=1 in
            # Q_CLUSTER and the if-active check below, not from DB-level locking.
            active = (
                ScanSession.objects
                .select_for_update(nowait=True)
                .filter(domain=domain, status__in=["pending", "running"])
                .exists()
            )
            if active:
                return None
            return ScanSession.objects.create(
                domain=domain, scan_type="full", status="pending",
                triggered_by=triggered_by, workflow=workflow,
            )
    except DatabaseError:
        if _is_scan_active(domain):
            logger.info(f"[create_scan_session] Scan already active for {domain} (confirmed via fallback read)")
            return None
        logger.warning(f"[create_scan_session] Transient lock contention for {domain} — retrying once")
        try:
            with transaction.atomic():
                active = (
                    ScanSession.objects
                    .select_for_update(nowait=True)
                    .filter(domain=domain, status__in=["pending", "running"])
                    .exists()
                )
                if active:
                    return None
                return ScanSession.objects.create(
                    domain=domain, scan_type="full", status="pending",
                    triggered_by=triggered_by, workflow=workflow,
                )
        except DatabaseError:
            logger.error(f"[create_scan_session] Retry failed for {domain} — skipping scan")
            return None


# ---------------------------------------------------------------------------
# Apex domain seed — guarantees the downstream pipeline has work to do even
# when subfinder/amass find no children (leaf hosts, new domains, etc.).
# ---------------------------------------------------------------------------

def _seed_apex_into_assets(session) -> None:
    """Insert the scan's input domain as a Subdomain + resolve its public IPs.

    The Subdomain insert alone isn't enough — dnsx has been observed silently
    returning 0 records for a single-host input list when invoked from the
    Django-Q worker (works fine in a bare subprocess). Resolving here with
    dnspython sidesteps that and guarantees the apex flows downstream into
    naabu / service_detection / nmap / tls / ssh / nuclei_network.
    """
    import ipaddress
    import dns.resolver

    from apps.core.assets.models import IPAddress, Subdomain
    from django.utils import timezone as django_tz

    sub, _ = Subdomain.objects.get_or_create(
        session=session,
        subdomain=session.domain,
        defaults={"domain": session.domain, "source": "seed"},
    )

    public_ips: list[tuple[str, int]] = []
    for rdtype in ("A", "AAAA"):
        try:
            for rdata in dns.resolver.resolve(session.domain, rdtype, lifetime=10):
                ip_str = rdata.to_text()
                try:
                    ip = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                    continue
                public_ips.append((ip_str, ip.version))
        except Exception:
            # NXDOMAIN, no answer, timeout — all benign; just leave IPs unresolved.
            continue

    if not public_ips:
        logger.info(f"[scan:{session.id}] Apex {session.domain} has no public IPs to seed")
        return

    IPAddress.objects.bulk_create(
        [IPAddress(session=session, subdomain=sub, address=addr, version=ver, source="seed")
         for addr, ver in public_ips],
        ignore_conflicts=True,
    )
    if not sub.is_active:
        sub.is_active = True
        sub.resolved_at = django_tz.now()
        sub.save(update_fields=["is_active", "resolved_at"])
    logger.info(f"[scan:{session.id}] Seeded apex {session.domain} → {len(public_ips)} public IP(s)")


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def _copy_assets_from_parent(session) -> None:
    """Copy Subdomain/IPAddress/Port/URL records from parent session into this subscan session."""
    from apps.core.assets.models import IPAddress, Port, Subdomain
    from apps.core.web_assets.models import URL

    parent = session.parent_session
    logger.info(f"[scan:{session.id}] Copying assets from parent session {parent.id}")

    # --- Subdomains ---
    sub_map = {}  # old_id -> new Subdomain
    for old in Subdomain.objects.filter(session=parent):
        new_sub = Subdomain.objects.create(
            session=session,
            domain=old.domain,
            subdomain=old.subdomain,
            source=old.source,
            is_active=old.is_active,
            resolved_at=old.resolved_at,
        )
        sub_map[old.id] = new_sub

    # --- IP Addresses ---
    ip_map = {}  # old_id -> new IPAddress
    for old in IPAddress.objects.filter(session=parent):
        new_ip = IPAddress.objects.create(
            session=session,
            subdomain=sub_map.get(old.subdomain_id),
            address=old.address,
            version=old.version,
            source=old.source,
        )
        ip_map[old.id] = new_ip

    # --- Ports ---
    port_map = {}  # old_id -> new Port
    for old in Port.objects.filter(session=parent):
        new_port = Port.objects.create(
            session=session,
            ip_address=ip_map.get(old.ip_address_id),
            address=old.address,
            port=old.port,
            protocol=old.protocol,
            state=old.state,
            service=old.service,
            version=old.version,
            is_web=old.is_web,
            source=old.source,
        )
        port_map[old.id] = new_port

    # --- URLs ---
    for old in URL.objects.filter(session=parent):
        URL.objects.create(
            session=session,
            port=port_map.get(old.port_id),
            subdomain=sub_map.get(old.subdomain_id),
            url=old.url,
            scheme=old.scheme,
            host=old.host,
            port_number=old.port_number,
            status_code=old.status_code,
            title=old.title,
            web_server=old.web_server,
            content_length=old.content_length,
            source=old.source,
        )

    logger.info(
        f"[scan:{session.id}] Copied {len(sub_map)} subdomains, {len(ip_map)} IPs, "
        f"{len(port_map)} ports from parent {parent.id}"
    )


def create_subscan_session(parent_uuid: str, tools: list[str], triggered_by: str = "subscan") -> "ScanSession | None":
    """Create a subscan session that reuses parent assets and runs only the specified tools."""
    try:
        parent = ScanSession.objects.get(uuid=parent_uuid, status="completed")
    except ScanSession.DoesNotExist:
        return None

    workflow = parent.workflow
    if workflow is None:
        from apps.core.workflows.models import Workflow
        workflow = Workflow.objects.filter(is_default=True).first()
    if workflow is None:
        logger.error(f"[subscan] Cannot create subscan for {parent_uuid} — no workflow available")
        return None

    return ScanSession.objects.create(
        domain=parent.domain,
        scan_type="subscan",
        triggered_by=triggered_by,
        workflow=workflow,
        parent_session=parent,
        subscan_tools=tools,
        status="pending",
    )


def run_scan(session_id: int):
    """Execute a scan session via its attached workflow, then finalise."""
    session = ScanSession.objects.select_related("workflow", "parent_session").get(id=session_id)
    # A queued task may be picked up after the session was already cancelled
    # (stop issued while pending) or reaped by the watchdog (marked failed while
    # sitting in a deep queue). Flipping such a session back to "running" would
    # resurrect it — re-executing a cancelled scan, or running a second copy
    # alongside the replacement the reap allowed to start. Only pending sessions
    # are meant to run.
    if session.status != "pending":
        logger.info(f"[scan:{session_id}] Session status is '{session.status}', not 'pending' — skipping run")
        return
    session.status = "running"
    session.save(update_fields=["status"])
    logger.info(f"[scan:{session_id}] Starting {'subscan' if session.parent_session_id else 'scan'} for {session.domain}")

    if session.parent_session_id:
        _copy_assets_from_parent(session)
    else:
        _seed_apex_into_assets(session)

    try:
        _run_via_workflow(session)
        session.refresh_from_db(fields=["status"])
        if session.status == "cancelled":
            logger.info(f"[scan:{session_id}] Scan was cancelled — skipping finalization")
            return
        _finalize_session(session)
    except Exception as exc:
        logger.error(f"[scan:{session_id}] Scan failed: {exc}", exc_info=True)
        session.status = "failed"
        session.end_time = django_tz.now()
        session.save(update_fields=["status", "end_time"])


def _run_via_workflow(session):
    """Run scan using the session's Workflow definition."""
    from apps.core.workflows.models import WorkflowRun
    from apps.core.workflows.runner import run_workflow

    if not session.workflow_id:
        raise RuntimeError(
            f"Session {session.id} has no workflow assigned. "
            f"Ensure a default workflow exists (run migrations)."
        )

    run = WorkflowRun.objects.create(workflow=session.workflow, session=session)
    run_workflow(run.id, only_tools=session.subscan_tools)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def _dispatch_alerts(session):
    """Fire alerts to all configured channels after a scan completes."""
    from django.conf import settings
    from apps.core.notifications.models import NotificationConfig

    cfg = NotificationConfig.get()
    # DB config takes precedence; fall back to env vars for Docker/K8s deployments
    slack_url  = cfg.slack_webhook_url  or getattr(settings, "SLACK_WEBHOOK_URL", "")
    teams_url  = cfg.teams_webhook_url  or getattr(settings, "MS_TEAMS_WEBHOOK_URL", "")
    threshold  = cfg.severity_threshold or getattr(settings, "ALERT_SEVERITY_THRESHOLD", "high")

    if not slack_url and not teams_url:
        return

    try:
        from apps.core.notifications.dispatcher import dispatch_alerts
        dispatch_alerts(session.id, severity_threshold=threshold)
    except Exception as e:
        logger.error(f"[scan:{session.id}] Alert dispatch failed: {e}", exc_info=True)
