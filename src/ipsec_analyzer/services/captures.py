"""Capture ingestion and lifecycle service.

The API never parses captures. Ingestion streams the upload to a temp file in
bounded chunks, computing SHA-256, enforcing the byte limit, and checking magic
bytes while reading. Object storage is written first, then the DB row + audit
event commit together; a failed commit deletes the stored object, and a failed
storage write leaves no DB row. Temp files are always removed. Logs carry IDs
and sizes only — never packet contents or object keys.
"""

import hashlib
import logging
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO

from sqlalchemy.orm import Session

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.models import Capture, CaptureState, User
from ipsec_analyzer.parsing.magic import detect_format
from ipsec_analyzer.services.audit import record_event
from ipsec_analyzer.storage.base import ObjectStorage, StorageError
from ipsec_analyzer.storage.keys import random_capture_object_key, sanitize_display_name

logger = logging.getLogger(__name__)
_CHUNK = 1024 * 1024


class UploadRejected(Exception):
    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code


def _spool_upload(fileobj: BinaryIO, max_bytes: int) -> tuple[Path, str, object]:
    """Stream to a temp file; returns (path, sha256_hex, detected_format)."""
    digest = hashlib.sha256()
    total = 0
    header = b""
    fmt = None
    tmp = tempfile.NamedTemporaryFile(prefix="ipsec-upload-", delete=False)  # noqa: SIM115
    path = Path(tmp.name)
    try:
        while True:
            try:
                chunk = fileobj.read(_CHUNK)
            except Exception as exc:  # client disconnect / interrupted stream
                raise UploadRejected(400, "upload_interrupted") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise UploadRejected(413, "file_too_large")
            if not header:
                header = chunk[:4]
                fmt = detect_format(header)
                if fmt is None:
                    raise UploadRejected(422, "invalid_capture_format")
            digest.update(chunk)
            tmp.write(chunk)
        tmp.close()
        if total == 0:
            raise UploadRejected(422, "empty_file")
        if fmt is None:  # fewer than 4 bytes read
            raise UploadRejected(422, "invalid_capture_format")
        return path, digest.hexdigest(), fmt
    except BaseException:
        tmp.close()
        path.unlink(missing_ok=True)
        raise


def ingest_capture(
    db: Session,
    storage: ObjectStorage,
    user: User,
    fileobj: BinaryIO,
    filename: str | None,
    settings: Settings,
) -> Capture:
    path, sha256, fmt = _spool_upload(fileobj, settings.max_upload_bytes)
    capture_id = uuid.uuid4()
    object_key = random_capture_object_key(user.organization_id, capture_id)
    try:
        try:
            storage.put_file(object_key, path)
        except StorageError as exc:
            logger.warning("capture ingest: storage write failed user_id=%s", user.id)
            raise UploadRejected(503, "storage_unavailable") from exc

        now = datetime.now(UTC)
        capture = Capture(
            id=capture_id,
            organization_id=user.organization_id,
            uploader_id=user.id,
            display_name=sanitize_display_name(filename),
            object_key=object_key,
            sha256=sha256,
            size_bytes=path.stat().st_size,
            format=fmt,
            state=CaptureState.READY,
            uploaded_at=now,
            retention_until=(
                now + timedelta(days=settings.capture_retention_days)
                if settings.capture_retention_days
                else None
            ),
        )
        db.add(capture)
        record_event(
            db,
            action="capture.uploaded",
            resource_type="capture",
            resource_id=capture_id,
            actor_user_id=user.id,
            organization_id=user.organization_id,
            metadata={"size_bytes": capture.size_bytes, "format": str(fmt), "sha256": sha256},
        )
        try:
            db.commit()
        except Exception as exc:
            db.rollback()
            # Compensating cleanup: never leave an orphaned object behind.
            try:
                storage.delete(object_key)
            except StorageError:
                logger.error("capture ingest: orphan cleanup failed capture_id=%s", capture_id)
            raise UploadRejected(500, "ingest_failed") from exc
        db.refresh(capture)
        logger.info(
            "capture ingested capture_id=%s organization_id=%s size=%s format=%s",
            capture_id,
            user.organization_id,
            capture.size_bytes,
            fmt,
        )
        return capture
    finally:
        path.unlink(missing_ok=True)


def delete_capture(db: Session, storage: ObjectStorage, user: User, capture: Capture) -> None:
    """Delete object then row+audit. On storage failure the row is tombstoned so
    the deletion can be retried and the capture is no longer usable."""
    try:
        storage.delete(capture.object_key)
    except StorageError as exc:
        capture.state = CaptureState.DELETION_PENDING
        db.commit()
        logger.warning("capture delete: storage delete failed capture_id=%s", capture.id)
        raise UploadRejected(503, "storage_unavailable") from exc
    record_event(
        db,
        action="capture.deleted",
        resource_type="capture",
        resource_id=capture.id,
        actor_user_id=user.id,
        organization_id=user.organization_id,
        metadata={"size_bytes": capture.size_bytes},
    )
    db.delete(capture)
    db.commit()
    logger.info(
        "capture deleted capture_id=%s organization_id=%s", capture.id, user.organization_id
    )
