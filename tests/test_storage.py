from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.storage.s3 import S3Storage


class _FakeBody:
    def __init__(self, data=b"x"):
        self._data = data

    def iter_chunks(self, chunk_size=1024):
        yield self._data

    def close(self):
        pass


class _FakeClient:
    def __init__(self):
        self.calls = []

    def upload_fileobj(self, fh, bucket, key, ExtraArgs=None):
        self.calls.append(("put", bucket, key, ExtraArgs, fh.read()))

    def get_object(self, Bucket, Key):
        self.calls.append(("get", Bucket, Key))
        return {"Body": _FakeBody()}

    def delete_object(self, Bucket, Key):
        self.calls.append(("delete", Bucket, Key))


def _storage(tmp_path, **kw):
    s = Settings(environment="test", **kw)
    storage = S3Storage(s)
    storage._client = _FakeClient()
    f = tmp_path / "f.bin"
    f.write_bytes(b"data")
    return storage, f


def test_sse_requested_only_when_configured(tmp_path):
    storage, f = _storage(tmp_path)
    storage.put_file("k", f)
    assert "ServerSideEncryption" not in storage._client.calls[0][3]
    assert storage._settings.storage_encryption_configured is False

    storage2, f2 = _storage(tmp_path, s3_sse_algorithm="aws:kms", s3_sse_kms_key_id="key-1")
    storage2.put_file("k", f2)
    extra = storage2._client.calls[0][3]
    assert extra["ServerSideEncryption"] == "aws:kms"
    assert extra["SSEKMSKeyId"] == "key-1"
    assert storage2._settings.storage_encryption_configured is True


def test_stream_and_delete(tmp_path):
    storage, _f = _storage(tmp_path)
    assert b"".join(storage.stream("k")) == b"x"
    storage.delete("k")
    assert storage._client.calls[-1][0] == "delete"
