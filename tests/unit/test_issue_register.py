"""Persistent Issue register rollup (PR2) — cross-scan finding identity so triage
status survives a re-scan. Spec: docs/specs/2026-09-12-finding-centric-ui-direction.md."""

import pytest
from django.utils import timezone


@pytest.mark.django_db
class TestIssueRollup:
    def _domain_and_session(self, name="example.com", status="completed", scan_type="full"):
        from apps.core.data.domains.models import Domain
        from apps.core.engine.scans.models import ScanSession
        dom, _ = Domain.objects.get_or_create(name=name)
        sess = ScanSession.objects.create(domain=name, scan_type=scan_type, status=status)
        return dom, sess

    def _finding(self, sess, **kw):
        from apps.core.data.findings.models import Finding
        defaults = dict(
            session=sess, source="web_checker", check_type="missing_header",
            severity="medium", title="Missing CSP", target="example.com",
            description="d", remediation="r",
        )
        defaults.update(kw)
        # Mirror the finalize backfill: a finding has a check_id by the time the
        # rollup runs. Default to "{source}:{check_type}" unless the test sets one.
        defaults.setdefault("check_id", f"{defaults['source']}:{defaults['check_type']}")
        return Finding.objects.create(**defaults)

    def _rollup(self, sess):
        from apps.core.data.issues.rollup import rollup_session_issues
        rollup_session_issues(sess)

    def _full_session(self, name="example.com", status="completed", subscan_tools=None):
        """A *comprehensive* scan: default full workflow, no tool subset — the only
        shape that auto-resolves unseen Issues (item 4)."""
        from apps.core.data.domains.models import Domain
        from apps.core.engine.scans.models import ScanSession
        from apps.core.engine.workflows.models import Workflow
        Domain.objects.get_or_create(name=name)
        wf = (Workflow.objects.filter(is_default=True).first()
              or Workflow.objects.create(name="Full Scan", is_default=True))
        sess = ScanSession.objects.create(
            domain=name, scan_type="full", status=status,
            workflow=wf, subscan_tools=subscan_tools,
        )
        return Domain.objects.get(name=name), sess

    # ---- item 4: close Issues not seen in the latest full scan ----

    def test_unseen_issue_auto_resolved_after_full_scan(self):
        from apps.core.data.issues.models import Issue
        dom, s1 = self._full_session()
        self._finding(s1, check_id="web_checker:missing_hsts", title="Missing HSTS")
        self._rollup(s1)
        assert Issue.objects.get(domain=dom).status == "open"
        # A later comprehensive scan no longer sees it (a different check is present).
        _, s2 = self._full_session()
        self._finding(s2, check_id="web_checker:missing_csp", title="Missing CSP")
        self._rollup(s2)
        gone = Issue.objects.get(domain=dom, check_id="web_checker:missing_hsts")
        assert gone.status == "resolved" and gone.resolved_at is not None

    def test_subset_scan_does_not_auto_resolve(self):
        # subscan_tools set → not comprehensive → an unseen Issue must stay open.
        from apps.core.data.issues.models import Issue
        dom, s1 = self._full_session()
        self._finding(s1, check_id="web_checker:missing_hsts")
        self._rollup(s1)
        _, s2 = self._full_session(subscan_tools=["tls_checker"])
        self._finding(s2, check_id="tls_checker:weak_cipher", source="tls_checker",
                      check_type="weak_cipher")
        self._rollup(s2)
        assert Issue.objects.get(domain=dom, check_id="web_checker:missing_hsts").status == "open"

    def test_partial_scan_does_not_auto_resolve(self):
        from apps.core.data.issues.models import Issue
        dom, s1 = self._full_session()
        self._finding(s1, check_id="web_checker:missing_hsts")
        self._rollup(s1)
        _, s2 = self._full_session(status="partial")  # a tool failed → not authoritative
        self._finding(s2, check_id="tls_checker:weak_cipher", source="tls_checker",
                      check_type="weak_cipher")
        self._rollup(s2)
        assert Issue.objects.get(domain=dom, check_id="web_checker:missing_hsts").status == "open"

    def test_false_positive_not_auto_resolved(self):
        from apps.core.data.issues.models import Issue
        dom, s1 = self._full_session()
        self._finding(s1, check_id="web_checker:missing_hsts")
        self._rollup(s1)
        Issue.objects.filter(domain=dom).update(status="false_positive")
        _, s2 = self._full_session()
        self._finding(s2, check_id="tls_checker:weak_cipher", source="tls_checker",
                      check_type="weak_cipher")
        self._rollup(s2)
        # A dismissed false positive is a triage decision — not auto-resolved.
        assert Issue.objects.get(domain=dom, check_id="web_checker:missing_hsts").status == "false_positive"

    def test_reopen_clears_resolved_at(self):
        from apps.core.data.issues.models import Issue
        dom, s1 = self._full_session()
        self._finding(s1, check_id="web_checker:missing_hsts")
        self._rollup(s1)
        _, s2 = self._full_session()  # not seen → resolved
        self._finding(s2, check_id="tls_checker:weak_cipher", source="tls_checker",
                      check_type="weak_cipher")
        self._rollup(s2)
        assert Issue.objects.get(domain=dom, check_id="web_checker:missing_hsts").resolved_at is not None
        _, s3 = self._full_session()  # reappears → reopened, resolved_at cleared
        self._finding(s3, check_id="web_checker:missing_hsts")
        self._rollup(s3)
        reopened = Issue.objects.get(domain=dom, check_id="web_checker:missing_hsts")
        assert reopened.status == "open" and reopened.resolved_at is None

    def test_creates_one_issue_per_identity_key(self):
        from apps.core.data.issues.models import Issue
        dom, sess = self._domain_and_session()
        self._finding(sess, title="Missing CSP")
        self._finding(sess, source="tls_checker", check_type="weak_cipher",
                      title="Weak TLS cipher", severity="high")
        self._rollup(sess)
        assert Issue.objects.filter(domain=dom).count() == 2
        i = Issue.objects.get(domain=dom, title="Missing CSP")
        assert i.status == "open" and i.severity == "medium"
        assert i.first_seen is not None and i.last_seen is not None

    def test_title_reword_keeps_same_issue(self):
        # Item 2: the key is (check_id, target), NOT the title. Rewording the title
        # (same check_id + target) must map to the SAME Issue — not orphan its triage
        # and create a duplicate — while the displayed title refreshes to the reword.
        from apps.core.data.issues.models import Issue
        dom, s1 = self._domain_and_session()
        self._finding(s1, check_id="domain_security:dkim_unconfirmed",
                      title="DKIM not found", target="example.com")
        self._rollup(s1)
        assert Issue.objects.filter(domain=dom).count() == 1

        _, s2 = self._domain_and_session(status="completed")
        self._finding(s2, check_id="domain_security:dkim_unconfirmed",
                      title="DKIM could not be confirmed", target="example.com")
        self._rollup(s2)
        assert Issue.objects.filter(domain=dom).count() == 1  # same Issue, not a dup
        assert Issue.objects.get(domain=dom).title == "DKIM could not be confirmed"

    def test_false_positive_persists_across_scans(self):
        # The whole point of PR2: dismissing a false positive sticks on re-scan.
        from apps.core.data.issues.models import Issue
        from apps.core.engine.scans.models import ScanSession
        dom, s1 = self._domain_and_session()
        self._finding(s1)
        self._rollup(s1)
        issue = Issue.objects.get(domain=dom)
        issue.status = "false_positive"
        issue.save(update_fields=["status"])

        s2 = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        self._finding(s2)  # same identity → same Issue
        self._rollup(s2)

        issue.refresh_from_db()
        assert issue.status == "false_positive"          # dismissal survived
        assert Issue.objects.filter(domain=dom).count() == 1  # not duplicated

    def test_acknowledged_persists_across_scans(self):
        from apps.core.data.issues.models import Issue
        from apps.core.engine.scans.models import ScanSession
        dom, s1 = self._domain_and_session()
        self._finding(s1); self._rollup(s1)
        Issue.objects.filter(domain=dom).update(status="acknowledged")
        s2 = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        self._finding(s2); self._rollup(s2)
        assert Issue.objects.get(domain=dom).status == "acknowledged"

    def test_resolved_reopens_on_regression(self):
        from apps.core.data.issues.models import Issue
        from apps.core.engine.scans.models import ScanSession
        dom, s1 = self._domain_and_session()
        self._finding(s1); self._rollup(s1)
        Issue.objects.filter(domain=dom).update(status="resolved")
        # It comes back in the next scan → regressed → re-open.
        s2 = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        self._finding(s2); self._rollup(s2)
        assert Issue.objects.get(domain=dom).status == "open"

    def test_severity_refreshes_from_latest_occurrence(self):
        from apps.core.data.issues.models import Issue
        from apps.core.engine.scans.models import ScanSession
        dom, s1 = self._domain_and_session()
        self._finding(s1, severity="medium"); self._rollup(s1)
        s2 = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        self._finding(s2, severity="high"); self._rollup(s2)  # same key, higher sev
        assert Issue.objects.get(domain=dom).severity == "high"

    def test_subscan_does_not_roll_up(self):
        from apps.core.data.issues.models import Issue
        _, sess = self._domain_and_session(scan_type="subscan")
        self._finding(sess); self._rollup(sess)
        assert Issue.objects.count() == 0

    def test_no_domain_row_skips_without_error(self):
        from apps.core.data.issues.models import Issue
        from apps.core.engine.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="orphan.example", scan_type="full", status="completed")
        self._finding(sess, target="orphan.example")
        self._rollup(sess)  # must not raise
        assert Issue.objects.count() == 0

    def test_scan_coverage_meta_excluded(self):
        from apps.core.data.issues.models import Issue
        _, sess = self._domain_and_session()
        self._finding(sess, source="scan_coverage", check_type="coverage_regression",
                      title="Scan coverage dropped")
        self._rollup(sess)
        assert Issue.objects.count() == 0

    def test_idempotent_on_replay(self):
        from apps.core.data.issues.models import Issue
        dom, sess = self._domain_and_session()
        self._finding(sess)
        self._rollup(sess)
        self._rollup(sess)  # finalize replay
        assert Issue.objects.filter(domain=dom).count() == 1

    def test_asset_grounding(self):
        from apps.core.data.asset_inventory.models import Asset
        from apps.core.data.issues.models import Issue
        dom, sess = self._domain_and_session()
        asset = Asset.objects.create(
            domain=dom, kind="subdomain", key="example.com",
            first_seen=timezone.now(), last_seen=timezone.now(),
        )
        self._finding(sess, asset=asset)
        self._rollup(sess)
        assert Issue.objects.get(domain=dom).asset_id == asset.id
