"""Fully offline synthetic send queue (Python 3.12, standard library only).

Implements a two-phase (precheck / commit) send queue persisted in SQLite with:

* pinned identity/connection generations established at connect time,
* lease-based resume that may only extend before the old lease expires,
* identity-generation bump on deactivate->reactivate and
  connection-generation bump on connection-id reuse,
* per-tenant policy limiting permissions and per-connection actions,
* idempotent send entries keyed by (tenant, request_id) with receipts,
* a monotonic per-tenant clock,
* named synchronization points for deterministic concurrency/crash tests.

No network access is used anywhere.
"""

__version__ = "1.0.0"
