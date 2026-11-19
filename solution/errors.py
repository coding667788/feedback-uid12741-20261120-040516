"""Error codes raised by the send-queue service.

Every business/authorization failure is raised as :class:`QueueError`
carrying a stable machine-readable ``code``.  These codes are part of the
public contract (documented in README.md) and are what ``cases.json``
expectations and the unit tests assert against.
"""

# --- tenant / clock -------------------------------------------------------
E_TENANT_NOT_FOUND = "E_TENANT_NOT_FOUND"
E_TENANT_DISABLED = "E_TENANT_DISABLED"
E_TENANT_EXISTS = "E_TENANT_EXISTS"

# --- identity -------------------------------------------------------------
E_IDENTITY_NOT_FOUND = "E_IDENTITY_NOT_FOUND"
E_IDENTITY_INACTIVE = "E_IDENTITY_INACTIVE"
E_STALE_IDENTITY_GENERATION = "E_STALE_IDENTITY_GENERATION"

# --- connection / lease ---------------------------------------------------
E_CONNECTION_NOT_FOUND = "E_CONNECTION_NOT_FOUND"
E_CONNECTION_CLOSED = "E_CONNECTION_CLOSED"
E_CONNECTION_EXISTS = "E_CONNECTION_EXISTS"
E_STALE_CONNECTION_GENERATION = "E_STALE_CONNECTION_GENERATION"
E_LEASE_EXPIRED = "E_LEASE_EXPIRED"

# --- policy ---------------------------------------------------------------
E_POLICY_NOT_FOUND = "E_POLICY_NOT_FOUND"
E_POLICY_REVOKED = "E_POLICY_REVOKED"
E_PERMISSION_DENIED = "E_PERMISSION_DENIED"
E_ACTION_NOT_PERMITTED = "E_ACTION_NOT_PERMITTED"

# --- send / idempotency ---------------------------------------------------
E_REQUEST_ID_CONFLICT = "E_REQUEST_ID_CONFLICT"
E_RECEIPT_NOT_FOUND = "E_RECEIPT_NOT_FOUND"

# --- generic --------------------------------------------------------------
E_INVALID_ARGUMENT = "E_INVALID_ARGUMENT"


class QueueError(Exception):
    """Business/authorization failure with a stable error ``code``."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message}
