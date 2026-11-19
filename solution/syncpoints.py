"""Named synchronization points.

The service fires named sync points at well-defined places (e.g. right
before the commit transaction begins, after the send entry is written but
before COMMIT, after COMMIT but before returning).  Tests register handlers
to:

* fix the relative order of concurrent operations (threading.Events), or
* really terminate the process at an exact spot (``os._exit`` in a child
  process started by the test).

In production runs no handlers are registered and firing is a no-op.
"""

from __future__ import annotations

from typing import Callable, Dict, List


class SyncPoints:
    def __init__(self) -> None:
        self._handlers: Dict[str, List[Callable[..., None]]] = {}

    def register(self, name: str, handler: Callable[..., None]) -> None:
        """Register ``handler(**ctx)`` to run when sync point ``name`` fires."""
        self._handlers.setdefault(name, []).append(handler)

    def clear(self, name: str | None = None) -> None:
        if name is None:
            self._handlers.clear()
        else:
            self._handlers.pop(name, None)

    def fire(self, name: str, **ctx) -> None:
        for handler in list(self._handlers.get(name, ())):
            handler(**ctx)


# Well-known sync point names (fired by SendQueueService):
#
#   precheck.done          -- after a (non-persistent) precheck completed
#   commit.before_begin    -- inside send_commit, just before BEGIN IMMEDIATE
#   commit.tx_begin        -- just after BEGIN IMMEDIATE
#   commit.state_read      -- after clock/lease/identity/connection/policy read
#   commit.validated       -- after authorization validation, before INSERT
#   commit.entry_written   -- after INSERT of send entry + receipt, before COMMIT
#   commit.committed       -- after COMMIT, before returning to the caller
#   commit.replayed        -- idempotent replay of an already-persisted entry
SP_PRECHECK_DONE = "precheck.done"
SP_COMMIT_BEFORE_BEGIN = "commit.before_begin"
SP_COMMIT_TX_BEGIN = "commit.tx_begin"
SP_COMMIT_STATE_READ = "commit.state_read"
SP_COMMIT_VALIDATED = "commit.validated"
SP_COMMIT_ENTRY_WRITTEN = "commit.entry_written"
SP_COMMIT_COMMITTED = "commit.committed"
SP_COMMIT_REPLAYED = "commit.replayed"
