import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.storage.base import StorageError, StorageNotFound
from ipsec_analyzer.storage.client import make_s3_client

logger = logging.getLogger(__name__)


class S3Storage:
    """Private S3-compatible storage (MinIO in development).

    Server-side encryption is requested only when explicitly configured
    (`s3_sse_algorithm`); nothing here claims encryption that was not set.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: Any = None

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = make_s3_client(self._settings)
        return self._client

    @property
    def bucket(self) -> str:
        return self._settings.s3_bucket

    def put_file(self, key: str, path: Path) -> None:
        extra: dict[str, Any] = {"ContentType": "application/octet-stream"}
        sse = self._settings.s3_sse_algorithm
        if sse:
            extra["ServerSideEncryption"] = sse
            if self._settings.s3_sse_kms_key_id:
                extra["SSEKMSKeyId"] = self._settings.s3_sse_kms_key_id
        try:
            with path.open("rb") as fh:
                self.client.upload_fileobj(fh, self.bucket, key, ExtraArgs=extra)
        except (BotoCoreError, ClientError, OSError) as exc:
            logger.warning("storage put failed (bucket configured=%s)", bool(self.bucket))
            raise StorageError("object storage write failed") from exc

    def stream(self, key: str) -> Iterator[bytes]:
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                raise StorageNotFound("object not found") from exc
            raise StorageError("object storage read failed") from exc
        except BotoCoreError as exc:
            raise StorageError("object storage read failed") from exc
        body = obj["Body"]
        try:
            yield from body.iter_chunks(chunk_size=1024 * 1024)
        finally:
            body.close()

    def delete(self, key: str) -> None:
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
        except (BotoCoreError, ClientError) as exc:
            raise StorageError("object storage delete failed") from exc
