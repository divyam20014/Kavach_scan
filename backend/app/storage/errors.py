"""Storage-layer errors. Each maps to a stable API error code via AppError."""

from __future__ import annotations

from app.core.errors import AppError


class StorageError(AppError):
    status_code = 500
    code = "storage_error"


class DataRootError(StorageError):
    status_code = 503
    code = "data_root_unavailable"


class StorageVersionError(StorageError):
    status_code = 503
    code = "storage_version_unsupported"


class UnsafePathError(StorageError):
    status_code = 400
    code = "unsafe_path"


class InvalidIdError(StorageError):
    status_code = 400
    code = "invalid_id"


class RecordNotFoundError(StorageError):
    status_code = 404
    code = "not_found"


class AlreadyExistsError(StorageError):
    status_code = 409
    code = "already_exists"


class RevisionConflictError(StorageError):
    status_code = 409
    code = "revision_conflict"


class CorruptRecordError(StorageError):
    """File exists but is not parseable JSON (or is not a JSON object)."""

    status_code = 500
    code = "record_corrupt"


class InvalidRecordError(StorageError):
    """File parses but fails schema validation, or a write was rejected by validation."""

    status_code = 422
    code = "record_invalid"


class UnsupportedSchemaVersionError(StorageError):
    status_code = 500
    code = "schema_version_unsupported"


class RecordTooLargeError(StorageError):
    status_code = 413
    code = "record_too_large"


class LockTimeoutError(StorageError):
    status_code = 503
    code = "lock_timeout"


class InstanceLockedError(StorageError):
    status_code = 503
    code = "instance_locked"
