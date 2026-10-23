import boto3
from botocore.config import Config

from ipsec_analyzer.core.config import Settings


def make_s3_client(settings: Settings):  # noqa: ANN202 - boto3 has no typed client export
    """Private S3-compatible client (MinIO locally). No public ACLs are ever set here."""
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        use_ssl=settings.s3_use_tls,
        verify=settings.s3_verify_tls,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        region_name=settings.s3_region,
        config=Config(signature_version="s3v4", retries={"max_attempts": 3}),
    )
