"""Storage abstraction. Implementations must never expose credentials or
internal details in errors surfaced to clients."""

from collections.abc import Iterator
from pathlib import Path
from typing import Protocol


class StorageError(Exception):
    """Object-storage operation failed (details stay in server logs)."""


class StorageNotFound(StorageError):
    pass


class ObjectStorage(Protocol):
    def put_file(self, key: str, path: Path) -> None: ...

    def stream(self, key: str) -> Iterator[bytes]: ...

    def delete(self, key: str) -> None: ...
