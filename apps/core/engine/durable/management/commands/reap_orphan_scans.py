"""Cancel phantom `run_scan` DBOS workflows holding `scans`-queue slots (H8).

A phantom is a workflow still ENQUEUED/PENDING while its ScanSession is terminal
(or gone) — it occupies a scarce concurrency slot with no live work behind it.
A couple of phantoms can permanently jam the (concurrency=2) queue so no new scan
dequeues. This is the operator-invoked form of the periodic reaper the watchdog
runs; use it to clear a jam immediately after a worker rollout.

    uv run manage.py reap_orphan_scans            # cancel phantoms now
    uv run manage.py reap_orphan_scans --dry-run  # list them, cancel nothing
"""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Cancel phantom run_scan workflows holding scans-queue slots (terminal/missing session)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="List the phantom workflows that would be cancelled, but cancel nothing.",
        )

    def handle(self, *args, **options):
        from apps.core.engine.scheduler.scheduler import reap_orphaned_scan_workflows

        apply = not options["dry_run"]
        reaped = reap_orphaned_scan_workflows(apply=apply)

        if not reaped:
            self.stdout.write(self.style.SUCCESS("No phantom run_scan workflows found — queue is clean."))
            return

        verb = "Cancelled" if apply else "Would cancel (dry-run)"
        self.stdout.write(self.style.WARNING(f"{verb} {len(reaped)} phantom workflow(s):"))
        for workflow_id, dedup, status in reaped:
            self.stdout.write(f"  {dedup:<14} session={status:<10} {workflow_id}")
        if not apply:
            self.stdout.write("Re-run without --dry-run to cancel them.")
