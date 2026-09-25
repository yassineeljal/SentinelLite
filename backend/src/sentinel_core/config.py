from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables prefixed with SENTINEL_."""

    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    # No default: credentials must always come from the environment.
    database_url: str
    redis_url: str = "redis://redis:6379/0"
    responder_mode: str = Field(default="dry_run", pattern="^(dry_run|enforce)$")

    # Ingestion limits. A full batch is 500 lines of up to 8192 chars; JSON escaping can
    # multiply that, so 8 MiB leaves room while still bounding what one request may cost.
    ingest_max_body_bytes: int = Field(default=8 * 1024 * 1024, gt=0)
    raw_stream_high_watermark: int = Field(default=100_000, gt=0)

    # Normalizer worker: entries per batch, and how long a delivered-but-unacknowledged entry
    # may sit before another worker takes it over (must exceed the slowest batch).
    normalizer_batch_size: int = Field(default=100, gt=0)
    normalizer_claim_idle_ms: int = Field(default=60_000, ge=0)
    # The normalizer stops reading raw lines while this many events wait for the detector.
    normalized_stream_high_watermark: int = Field(default=100_000, gt=0)

    # Detector worker: same knobs as above, and where the rule files are read at startup.
    detector_batch_size: int = Field(default=100, gt=0)
    detector_claim_idle_ms: int = Field(default=60_000, ge=0)
    rules_dir: Path = Path("rules")


@lru_cache
def get_settings() -> Settings:
    return Settings()
