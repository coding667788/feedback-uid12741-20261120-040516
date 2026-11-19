"""Core send-queue service.

Persistence: a single SQLite database file.  Every mutating operation runs
inside a ``BEGIN IMMEDIATE`` transaction so concurrent writers serialize.
Each thread gets its own SQLite connection (``threading.local``) so the
concurrency tests can genuinely interleave operations from two threads.

Send is split into two phases:

* :meth:`SendQueueService.send_precheck` -- non-persistent: runs the full
  authorization validation but writes nothing (no send entry, no audit row).
* :meth:`SendQueueService.send_commit` -- the real authorization result:
  inside one transaction it reads the monotonic tenant clock, the lease,
  the identity, the connection and the policy, re-validates everything,
  and records the non-repeatable send entry plus its receipt.  If a
  disable / close / policy-revoke committed after the precheck, the commit
  still rejects, because validation happens inside the commit transaction.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from . import syncpoints as sp
from .errors import (
    E_ACTION_NOT_PERMITTED,
    E_CONNECTION_CLOSED,
    E_CONNECTION_EXISTS,
    E_CONNECTION_NOT_FOUND,
    E_IDENTITY_INACTIVE,
    E_IDENTITY_NOT_FOUND,
    E_INVALID_ARGUMENT,
    E_LEASE_EXPIRED,
    E_PERMISSION_DENIED,
    E_POLICY_NOT_FOUND,
    E_POLICY_REVOKED,
    E_RECEIPT_NOT_FOUND,
    E_REQUEST_ID_CONFLICT,
    E_STALE_CONNECTION_GENERATION,
    E_STALE_IDENTITY_GENERATION,
    E_TENANT_DISABLED,
    E_TENANT_EXISTS,
    E_TENANT_NOT_FOUND,
    QueueError,
)
from .syncpoints import SyncPoints

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   TEXT PRIMARY KEY,
    disabled    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clocks (
    tenant_id   TEXT PRIMARY KEY,
    now         INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
    tenant_id   TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    generation  INTEGER NOT NULL,
    active      INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, identity_id)
);
CREATE TABLE IF NOT EXISTS connections (
    tenant_id             TEXT NOT NULL,
    connection_id         TEXT NOT NULL,
    identity_id           TEXT NOT NULL,
    identity_generation   INTEGER NOT NULL,
    connection_generation INTEGER NOT NULL,
    lease_expiry          INTEGER NOT NULL,
    closed                INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, connection_id)
);
CREATE TABLE IF NOT EXISTS policies (
    tenant_id        TEXT PRIMARY KEY,
    version          INTEGER NOT NULL,
    revoked          INTEGER NOT NULL,
    permissions_json TEXT NOT NULL,
    actions_json     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sends (
    tenant_id     TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    action        TEXT NOT NULL,
    params_hash   TEXT NOT NULL,
    status        TEXT NOT NULL,
    receipt_json  TEXT NOT NULL,
    created_clock INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    clock       INTEGER NOT NULL,
    op          TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
"""

STATUS_SUCCEEDED = "SUCCEEDED"
STATUS_BUSINESS_FAILED = "BUSINESS_FAILED"


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _params_hash(connection_id: str, action: str, payload: dict) -> str:
    """Canonical hash of the *business parameters* of a send.

    Generations are version tokens, not parameters, so they are excluded.
    """
    blob = _canonical(
        {"connection_id": connection_id, "action": action, "payload": payload}
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class SendQueueService:
    """The send-queue service bound to one SQLite database file."""

    def __init__(self, db_path, syncpoints: SyncPoints | None = None):
        self.db_path = str(db_path)
        self.sp = syncpoints or SyncPoints()
        self._local = threading.local()
        init = self._new_conn()
        try:
            init.executescript(SCHEMA)
        finally:
            init.close()

    # ------------------------------------------------------------------ db
    def _new_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            isolation_level=None,  # explicit BEGIN/COMMIT
            timeout=5.0,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    @property
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._new_conn()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    @contextmanager
    def _tx(self):
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------- helpers
    def _clock_now(self, conn, tenant_id: str) -> int:
        row = conn.execute(
            "SELECT now FROM clocks WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        if row is None:
            raise QueueError(E_TENANT_NOT_FOUND, f"unknown tenant {tenant_id!r}")
        return row["now"]

    def _require_tenant(self, conn, tenant_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        if row is None:
            raise QueueError(E_TENANT_NOT_FOUND, f"unknown tenant {tenant_id!r}")
        return row

    def _require_tenant_active(self, conn, tenant_id: str) -> sqlite3.Row:
        row = self._require_tenant(conn, tenant_id)
        if row["disabled"]:
            raise QueueError(E_TENANT_DISABLED, f"tenant {tenant_id!r} is disabled")
        return row

    def _audit(self, conn, tenant_id: str, clock: int, op: str, detail: dict) -> None:
        conn.execute(
            "INSERT INTO audit_log (tenant_id, clock, op, detail_json) VALUES (?,?,?,?)",
            (tenant_id, clock, op, _canonical(detail)),
        )

    def _load_send_state(self, conn, tenant_id: str, connection_id: str) -> dict:
        tenant = conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        clock_row = conn.execute(
            "SELECT now FROM clocks WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        connection = conn.execute(
            "SELECT * FROM connections WHERE tenant_id = ? AND connection_id = ?",
            (tenant_id, connection_id),
        ).fetchone()
        identity = None
        if connection is not None:
            identity = conn.execute(
                "SELECT * FROM identities WHERE tenant_id = ? AND identity_id = ?",
                (tenant_id, connection["identity_id"]),
            ).fetchone()
        policy = conn.execute(
            "SELECT * FROM policies WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        return {
            "tenant": tenant,
            "clock": clock_row["now"] if clock_row else None,
            "connection": connection,
            "identity": identity,
            "policy": policy,
        }

    # ------------------------------------------------------- tenant/clock
    def create_tenant(self, tenant_id: str) -> dict:
        with self._tx() as conn:
            existing = conn.execute(
                "SELECT tenant_id FROM tenants WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
            if existing is not None:
                raise QueueError(E_TENANT_EXISTS, f"tenant {tenant_id!r} already exists")
            conn.execute("INSERT INTO tenants (tenant_id, disabled) VALUES (?, 0)", (tenant_id,))
            conn.execute("INSERT INTO clocks (tenant_id, now) VALUES (?, 0)", (tenant_id,))
            self._audit(conn, tenant_id, 0, "create_tenant", {"tenant_id": tenant_id})
        return {"tenant_id": tenant_id}

    def disable_tenant(self, tenant_id: str) -> dict:
        with self._tx() as conn:
            self._require_tenant(conn, tenant_id)
            now = self._clock_now(conn, tenant_id)
            conn.execute("UPDATE tenants SET disabled = 1 WHERE tenant_id = ?", (tenant_id,))
            self._audit(conn, tenant_id, now, "disable_tenant", {})
        return {"tenant_id": tenant_id, "disabled": True}

    def enable_tenant(self, tenant_id: str) -> dict:
        with self._tx() as conn:
            self._require_tenant(conn, tenant_id)
            now = self._clock_now(conn, tenant_id)
            conn.execute("UPDATE tenants SET disabled = 0 WHERE tenant_id = ?", (tenant_id,))
            self._audit(conn, tenant_id, now, "enable_tenant", {})
        return {"tenant_id": tenant_id, "disabled": False}

    def tick(self, tenant_id: str, by: int = 1) -> dict:
        """Advance the monotonic tenant clock.  ``by`` must be >= 0."""
        if not isinstance(by, int) or by < 0:
            raise QueueError(E_INVALID_ARGUMENT, "tick amount must be a non-negative integer")
        with self._tx() as conn:
            self._require_tenant(conn, tenant_id)
            conn.execute("UPDATE clocks SET now = now + ? WHERE tenant_id = ?", (by, tenant_id))
            now = self._clock_now(conn, tenant_id)
            self._audit(conn, tenant_id, now, "tick", {"by": by})
        return {"tenant_id": tenant_id, "now": now}

    def now(self, tenant_id: str) -> int:
        return self._clock_now(self._conn, tenant_id)

    # -------------------------------------------------------------- policy
    def set_policy(self, tenant_id: str, permissions: list, actions: dict) -> dict:
        """Install/replace the tenant policy.

        ``permissions``: list of granted permission names (sending requires
        ``"send"``).  ``actions``: mapping ``connection_id -> [action, ...]``
        of per-connection allowed actions.
        """
        with self._tx() as conn:
            self._require_tenant_active(conn, tenant_id)
            now = self._clock_now(conn, tenant_id)
            row = conn.execute(
                "SELECT version FROM policies WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
            version = (row["version"] + 1) if row else 1
            conn.execute(
                "INSERT INTO policies (tenant_id, version, revoked, permissions_json, actions_json)"
                " VALUES (?,?,0,?,?)"
                " ON CONFLICT(tenant_id) DO UPDATE SET"
                " version = excluded.version, revoked = 0,"
                " permissions_json = excluded.permissions_json,"
                " actions_json = excluded.actions_json",
                (tenant_id, version, _canonical(list(permissions)), _canonical(dict(actions))),
            )
            self._audit(conn, tenant_id, now, "set_policy", {"version": version})
        return {"tenant_id": tenant_id, "version": version}

    def revoke_policy(self, tenant_id: str) -> dict:
        with self._tx() as conn:
            self._require_tenant_active(conn, tenant_id)
            now = self._clock_now(conn, tenant_id)
            row = conn.execute(
                "SELECT version FROM policies WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
            if row is None:
                raise QueueError(E_POLICY_NOT_FOUND, f"tenant {tenant_id!r} has no policy")
            conn.execute("UPDATE policies SET revoked = 1 WHERE tenant_id = ?", (tenant_id,))
            self._audit(conn, tenant_id, now, "revoke_policy", {"version": row["version"]})
        return {"tenant_id": tenant_id, "revoked": True}

    # ------------------------------------------------- identity/connection
    def connect(self, tenant_id: str, identity_id: str, connection_id: str,
                lease_ttl: int) -> dict:
        """Establish a connection, pinning the current identity generation and
        assigning a connection generation.

        Reusing a ``connection_id`` whose previous incarnation is closed (or
        bound to a stale identity generation) bumps the connection generation.
        """
        if lease_ttl <= 0:
            raise QueueError(E_INVALID_ARGUMENT, "lease_ttl must be positive")
        with self._tx() as conn:
            self._require_tenant_active(conn, tenant_id)
            now = self._clock_now(conn, tenant_id)
            ident = conn.execute(
                "SELECT * FROM identities WHERE tenant_id = ? AND identity_id = ?",
                (tenant_id, identity_id),
            ).fetchone()
            if ident is None:
                conn.execute(
                    "INSERT INTO identities (tenant_id, identity_id, generation, active)"
                    " VALUES (?,?,1,1)",
                    (tenant_id, identity_id),
                )
                ident = conn.execute(
                    "SELECT * FROM identities WHERE tenant_id = ? AND identity_id = ?",
                    (tenant_id, identity_id),
                ).fetchone()
            elif not ident["active"]:
                raise QueueError(
                    E_IDENTITY_INACTIVE,
                    f"identity {identity_id!r} is deactivated; reactivate before connecting",
                )
            ig = ident["generation"]
            row = conn.execute(
                "SELECT * FROM connections WHERE tenant_id = ? AND connection_id = ?",
                (tenant_id, connection_id),
            ).fetchone()
            if row is not None and not row["closed"] and row["identity_generation"] == ig:
                raise QueueError(
                    E_CONNECTION_EXISTS,
                    f"connection {connection_id!r} is already established",
                )
            cg = (row["connection_generation"] + 1) if row is not None else 1
            expiry = now + lease_ttl
            conn.execute(
                "INSERT INTO connections (tenant_id, connection_id, identity_id,"
                " identity_generation, connection_generation, lease_expiry, closed)"
                " VALUES (?,?,?,?,?,?,0)"
                " ON CONFLICT(tenant_id, connection_id) DO UPDATE SET"
                " identity_id = excluded.identity_id,"
                " identity_generation = excluded.identity_generation,"
                " connection_generation = excluded.connection_generation,"
                " lease_expiry = excluded.lease_expiry, closed = 0",
                (tenant_id, connection_id, identity_id, ig, cg, expiry),
            )
            self._audit(conn, tenant_id, now, "connect", {
                "identity_id": identity_id, "connection_id": connection_id,
                "identity_generation": ig, "connection_generation": cg,
                "lease_expiry": expiry,
            })
        return {
            "tenant_id": tenant_id,
            "identity_id": identity_id,
            "connection_id": connection_id,
            "identity_generation": ig,
            "connection_generation": cg,
            "lease_expiry": expiry,
        }

    def resume(self, tenant_id: str, connection_id: str, identity_generation: int,
               connection_generation: int, extend_by: int) -> dict:
        """Extend the lease of a live connection.

        Bound to the current version: both generations must match.  The old
        lease must not have expired yet (``now < lease_expiry``); the new
        expiry is ``old_expiry + extend_by``.
        """
        if extend_by <= 0:
            raise QueueError(E_INVALID_ARGUMENT, "extend_by must be positive")
        with self._tx() as conn:
            self._require_tenant_active(conn, tenant_id)
            now = self._clock_now(conn, tenant_id)
            row = conn.execute(
                "SELECT * FROM connections WHERE tenant_id = ? AND connection_id = ?",
                (tenant_id, connection_id),
            ).fetchone()
            if row is None:
                raise QueueError(E_CONNECTION_NOT_FOUND, f"unknown connection {connection_id!r}")
            if row["closed"]:
                raise QueueError(E_CONNECTION_CLOSED, f"connection {connection_id!r} is closed")
            ident = conn.execute(
                "SELECT * FROM identities WHERE tenant_id = ? AND identity_id = ?",
                (tenant_id, row["identity_id"]),
            ).fetchone()
            if ident is None or not ident["active"]:
                raise QueueError(E_IDENTITY_INACTIVE, "identity is deactivated")
            if ident["generation"] != identity_generation or row["identity_generation"] != identity_generation:
                raise QueueError(
                    E_STALE_IDENTITY_GENERATION,
                    f"identity generation {identity_generation} is stale (current {ident['generation']})",
                )
            if row["connection_generation"] != connection_generation:
                raise QueueError(
                    E_STALE_CONNECTION_GENERATION,
                    f"connection generation {connection_generation} is stale"
                    f" (current {row['connection_generation']})",
                )
            if now >= row["lease_expiry"]:
                raise QueueError(
                    E_LEASE_EXPIRED,
                    f"lease expired at {row['lease_expiry']} (now {now}); cannot resume",
                )
            new_expiry = row["lease_expiry"] + extend_by
            conn.execute(
                "UPDATE connections SET lease_expiry = ?"
                " WHERE tenant_id = ? AND connection_id = ?",
                (new_expiry, tenant_id, connection_id),
            )
            self._audit(conn, tenant_id, now, "resume", {
                "connection_id": connection_id, "extend_by": extend_by,
                "lease_expiry": new_expiry,
            })
        return {
            "tenant_id": tenant_id,
            "connection_id": connection_id,
            "lease_expiry": new_expiry,
        }

    def deactivate_identity(self, tenant_id: str, identity_id: str) -> dict:
        with self._tx() as conn:
            self._require_tenant_active(conn, tenant_id)
            now = self._clock_now(conn, tenant_id)
            row = conn.execute(
                "SELECT * FROM identities WHERE tenant_id = ? AND identity_id = ?",
                (tenant_id, identity_id),
            ).fetchone()
            if row is None:
                raise QueueError(E_IDENTITY_NOT_FOUND, f"unknown identity {identity_id!r}")
            conn.execute(
                "UPDATE identities SET active = 0 WHERE tenant_id = ? AND identity_id = ?",
                (tenant_id, identity_id),
            )
            self._audit(conn, tenant_id, now, "deactivate_identity", {"identity_id": identity_id})
        return {"tenant_id": tenant_id, "identity_id": identity_id, "active": False}

    def reactivate_identity(self, tenant_id: str, identity_id: str) -> dict:
        """Reactivate a deactivated identity, bumping its identity generation."""
        with self._tx() as conn:
            self._require_tenant_active(conn, tenant_id)
            now = self._clock_now(conn, tenant_id)
            row = conn.execute(
                "SELECT * FROM identities WHERE tenant_id = ? AND identity_id = ?",
                (tenant_id, identity_id),
            ).fetchone()
            if row is None:
                raise QueueError(E_IDENTITY_NOT_FOUND, f"unknown identity {identity_id!r}")
            if row["active"]:
                raise QueueError(E_INVALID_ARGUMENT, f"identity {identity_id!r} is already active")
            new_gen = row["generation"] + 1
            conn.execute(
                "UPDATE identities SET active = 1, generation = ?"
                " WHERE tenant_id = ? AND identity_id = ?",
                (new_gen, tenant_id, identity_id),
            )
            self._audit(conn, tenant_id, now, "reactivate_identity", {
                "identity_id": identity_id, "identity_generation": new_gen,
            })
        return {
            "tenant_id": tenant_id,
            "identity_id": identity_id,
            "identity_generation": new_gen,
        }

    def close_connection(self, tenant_id: str, connection_id: str) -> dict:
        with self._tx() as conn:
            self._require_tenant_active(conn, tenant_id)
            now = self._clock_now(conn, tenant_id)
            row = conn.execute(
                "SELECT * FROM connections WHERE tenant_id = ? AND connection_id = ?",
                (tenant_id, connection_id),
            ).fetchone()
            if row is None:
                raise QueueError(E_CONNECTION_NOT_FOUND, f"unknown connection {connection_id!r}")
            if row["closed"]:
                raise QueueError(E_CONNECTION_CLOSED, f"connection {connection_id!r} already closed")
            conn.execute(
                "UPDATE connections SET closed = 1 WHERE tenant_id = ? AND connection_id = ?",
                (tenant_id, connection_id),
            )
            self._audit(conn, tenant_id, now, "close_connection", {"connection_id": connection_id})
        return {"tenant_id": tenant_id, "connection_id": connection_id, "closed": True}

    # ----------------------------------------------------------------- send
    def _validate_send_state(self, state: dict, connection_id: str,
                             identity_generation: int, connection_generation: int,
                             action: str) -> None:
        """Authorization validation shared by precheck and commit.

        Check order (documented in README.md): tenant -> connection ->
        identity -> generations -> lease -> policy.
        """
        tenant = state["tenant"]
        if tenant is None:
            raise QueueError(E_TENANT_NOT_FOUND, "unknown tenant")
        if tenant["disabled"]:
            raise QueueError(E_TENANT_DISABLED, "tenant is disabled")
        conn_row = state["connection"]
        if conn_row is None:
            raise QueueError(E_CONNECTION_NOT_FOUND, f"unknown connection {connection_id!r}")
        if conn_row["closed"]:
            raise QueueError(E_CONNECTION_CLOSED, f"connection {connection_id!r} is closed")
        ident = state["identity"]
        if ident is None or not ident["active"]:
            raise QueueError(E_IDENTITY_INACTIVE, "identity is deactivated")
        if ident["generation"] != identity_generation or conn_row["identity_generation"] != identity_generation:
            raise QueueError(
                E_STALE_IDENTITY_GENERATION,
                f"identity generation {identity_generation} is stale (current {ident['generation']})",
            )
        if conn_row["connection_generation"] != connection_generation:
            raise QueueError(
                E_STALE_CONNECTION_GENERATION,
                f"connection generation {connection_generation} is stale"
                f" (current {conn_row['connection_generation']})",
            )
        if state["clock"] >= conn_row["lease_expiry"]:
            raise QueueError(
                E_LEASE_EXPIRED,
                f"lease expired at {conn_row['lease_expiry']} (now {state['clock']})",
            )
        policy = state["policy"]
        if policy is None:
            raise QueueError(E_POLICY_NOT_FOUND, "tenant has no policy")
        if policy["revoked"]:
            raise QueueError(E_POLICY_REVOKED, "tenant policy has been revoked")
        permissions = json.loads(policy["permissions_json"])
        if "send" not in permissions:
            raise QueueError(E_PERMISSION_DENIED, "policy does not grant the 'send' permission")
        actions = json.loads(policy["actions_json"])
        if action not in actions.get(connection_id, []):
            raise QueueError(
                E_ACTION_NOT_PERMITTED,
                f"action {action!r} is not permitted on connection {connection_id!r}",
            )

    def send_precheck(self, tenant_id: str, connection_id: str,
                      identity_generation: int, connection_generation: int,
                      request_id: str, action: str, payload: dict) -> dict:
        """Non-persistent precheck: full validation, zero writes."""
        conn = self._conn
        state = self._load_send_state(conn, tenant_id, connection_id)
        self._validate_send_state(
            state, connection_id, identity_generation, connection_generation, action
        )
        ph = _params_hash(connection_id, action, payload)
        row = conn.execute(
            "SELECT params_hash FROM sends WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        would_replay = False
        if row is not None:
            if row["params_hash"] != ph:
                raise QueueError(
                    E_REQUEST_ID_CONFLICT,
                    f"request_id {request_id!r} already used with different parameters",
                )
            would_replay = True
        result = {
            "tenant_id": tenant_id,
            "request_id": request_id,
            "would_replay": would_replay,
            "clock": state["clock"],
            "lease_expiry": state["connection"]["lease_expiry"],
        }
        self.sp.fire(sp.SP_PRECHECK_DONE, tenant=tenant_id, request_id=request_id)
        return result

    def send_commit(self, tenant_id: str, connection_id: str,
                    identity_generation: int, connection_generation: int,
                    request_id: str, action: str, payload: dict) -> dict:
        """The real, persistent authorization result.

        One transaction: read clock/lease/identity/connection/policy,
        validate, write the non-repeatable send entry and its receipt.
        Idempotent on (tenant, request_id): same parameters return the
        persisted first result; different parameters are rejected.
        """
        conn = self._conn
        self.sp.fire(sp.SP_COMMIT_BEFORE_BEGIN, tenant=tenant_id, request_id=request_id)
        conn.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            self.sp.fire(sp.SP_COMMIT_TX_BEGIN, tenant=tenant_id, request_id=request_id)
            state = self._load_send_state(conn, tenant_id, connection_id)
            self.sp.fire(sp.SP_COMMIT_STATE_READ, tenant=tenant_id, request_id=request_id)

            ph = _params_hash(connection_id, action, payload)
            row = conn.execute(
                "SELECT * FROM sends WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
            if row is not None:
                if row["params_hash"] != ph:
                    raise QueueError(
                        E_REQUEST_ID_CONFLICT,
                        f"request_id {request_id!r} already used with different parameters",
                    )
                receipt = json.loads(row["receipt_json"])
                conn.execute("COMMIT")
                committed = True
                self.sp.fire(sp.SP_COMMIT_REPLAYED, tenant=tenant_id, request_id=request_id)
                return receipt

            self._validate_send_state(
                state, connection_id, identity_generation, connection_generation, action
            )
            self.sp.fire(sp.SP_COMMIT_VALIDATED, tenant=tenant_id, request_id=request_id)

            now = state["clock"]
            if payload.get("simulate_business_failure"):
                status, reason = STATUS_BUSINESS_FAILED, "synthetic business rule rejected payload"
            else:
                status, reason = STATUS_SUCCEEDED, "accepted"
            receipt = {
                "tenant_id": tenant_id,
                "request_id": request_id,
                "connection_id": connection_id,
                "action": action,
                "status": status,
                "reason": reason,
                "clock": now,
                "identity_generation": identity_generation,
                "connection_generation": connection_generation,
            }
            conn.execute(
                "INSERT INTO sends (tenant_id, request_id, connection_id, action,"
                " params_hash, status, receipt_json, created_clock)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (tenant_id, request_id, connection_id, action, ph, status,
                 _canonical(receipt), now),
            )
            self._audit(conn, tenant_id, now, "send_commit", {
                "request_id": request_id, "connection_id": connection_id,
                "action": action, "status": status,
            })
            self.sp.fire(sp.SP_COMMIT_ENTRY_WRITTEN, tenant=tenant_id, request_id=request_id)
            conn.execute("COMMIT")
            committed = True
        finally:
            if not committed and conn.in_transaction:
                conn.execute("ROLLBACK")
        self.sp.fire(sp.SP_COMMIT_COMMITTED, tenant=tenant_id, request_id=request_id)
        return receipt

    # --------------------------------------------------------------- query
    def get_receipt(self, tenant_id: str, request_id: str) -> dict:
        row = self._conn.execute(
            "SELECT receipt_json FROM sends WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if row is None:
            raise QueueError(
                E_RECEIPT_NOT_FOUND,
                f"no receipt for request_id {request_id!r} in tenant {tenant_id!r}",
            )
        return json.loads(row["receipt_json"])

    def list_log(self, tenant_id: str) -> dict:
        rows = self._conn.execute(
            "SELECT seq, clock, op, detail_json FROM audit_log"
            " WHERE tenant_id = ? ORDER BY seq",
            (tenant_id,),
        ).fetchall()
        entries = [
            {"seq": r["seq"], "clock": r["clock"], "op": r["op"],
             "detail": json.loads(r["detail_json"])}
            for r in rows
        ]
        return {"tenant_id": tenant_id, "count": len(entries), "entries": entries}

    def count_sends(self, tenant_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM sends WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        return row["n"]

    def send_entries(self, tenant_id: str) -> list:
        rows = self._conn.execute(
            "SELECT request_id, connection_id, action, status, created_clock"
            " FROM sends WHERE tenant_id = ? ORDER BY request_id",
            (tenant_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def state(self, tenant_id: str) -> dict:
        conn = self._conn
        self._require_tenant(conn, tenant_id)
        identities = [dict(r) for r in conn.execute(
            "SELECT identity_id, generation, active FROM identities WHERE tenant_id = ?"
            " ORDER BY identity_id", (tenant_id,)).fetchall()]
        connections = [dict(r) for r in conn.execute(
            "SELECT connection_id, identity_id, identity_generation,"
            " connection_generation, lease_expiry, closed FROM connections"
            " WHERE tenant_id = ? ORDER BY connection_id", (tenant_id,)).fetchall()]
        policy_row = conn.execute(
            "SELECT version, revoked, permissions_json, actions_json FROM policies"
            " WHERE tenant_id = ?", (tenant_id,)).fetchone()
        policy = None
        if policy_row is not None:
            policy = {
                "version": policy_row["version"],
                "revoked": bool(policy_row["revoked"]),
                "permissions": json.loads(policy_row["permissions_json"]),
                "actions": json.loads(policy_row["actions_json"]),
            }
        tenant = conn.execute(
            "SELECT disabled FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return {
            "tenant_id": tenant_id,
            "disabled": bool(tenant["disabled"]),
            "clock": self._clock_now(conn, tenant_id),
            "identities": identities,
            "connections": connections,
            "policy": policy,
            "sends": self.count_sends(tenant_id),
        }


class ReadOnlyGateway:
    """Read-only entry point: receipt lookup by request id and the audit log.

    Opens the database with SQLite's ``mode=ro`` so no write is possible
    through this object at all.
    """

    def __init__(self, db_path):
        uri = Path(str(db_path)).absolute().as_uri() + "?mode=ro"
        self._conn = sqlite3.connect(uri, uri=True)
        self._conn.row_factory = sqlite3.Row

    def get_receipt(self, tenant_id: str, request_id: str) -> dict:
        row = self._conn.execute(
            "SELECT receipt_json FROM sends WHERE tenant_id = ? AND request_id = ?",
            (tenant_id, request_id),
        ).fetchone()
        if row is None:
            raise QueueError(
                E_RECEIPT_NOT_FOUND,
                f"no receipt for request_id {request_id!r} in tenant {tenant_id!r}",
            )
        return json.loads(row["receipt_json"])

    def list_log(self, tenant_id: str) -> dict:
        rows = self._conn.execute(
            "SELECT seq, clock, op, detail_json FROM audit_log"
            " WHERE tenant_id = ? ORDER BY seq",
            (tenant_id,),
        ).fetchall()
        entries = [
            {"seq": r["seq"], "clock": r["clock"], "op": r["op"],
             "detail": json.loads(r["detail_json"])}
            for r in rows
        ]
        return {"tenant_id": tenant_id, "count": len(entries), "entries": entries}

    def count_sends(self, tenant_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM sends WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        return row["n"]

    def close(self) -> None:
        self._conn.close()
