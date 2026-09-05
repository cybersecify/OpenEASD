"""Leaf constants for the durable subsystem.

Kept in their own module (importing nothing else in the package) so that
dbos_app and workflows can share them without importing each other at module
load time — which would form an import cycle.
"""

QUEUE_NAME = "scans"
SYSTEM_SCHEMA = "dbos"
