from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
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

    # Enrichment (GeoIP now, reputation later). Off by default: it needs a database file, see
    # docs/OPERATIONS.md. When on, the detector announces new alerts on `alerts.new` and the
    # enricher worker (which refuses to start without a database) adds context to them.
    enrichment_enabled: bool = False
    geoip_city_db: Path | None = None  # MaxMind format: GeoLite2-City or DB-IP City Lite
    geoip_asn_db: Path | None = None  # MaxMind format: GeoLite2-ASN or DB-IP ASN Lite
    enricher_batch_size: int = Field(default=100, gt=0)
    enricher_claim_idle_ms: int = Field(default=60_000, ge=0)
    alerts_stream_maxlen: int = Field(default=100_000, gt=0)
    # AbuseIPDB reputation. Off without a key. UNLIKE GeoIP it sends the source address of an alert
    # (public addresses only) to a third party. The key comes from the environment only, is never
    # logged, and the free plan allows 1000 requests a day: the default budget stays below that.
    abuseipdb_api_key: SecretStr | None = None
    abuseipdb_daily_limit: int = Field(default=900, gt=0)
    abuseipdb_max_age_days: int = Field(default=90, ge=1, le=365)
    reputation_cache_ttl_seconds: int = Field(default=24 * 3600, gt=0)

    # Dashboard sessions. Cookies are HttpOnly and SameSite=Strict always; `Secure` (HTTPS only)
    # is on by default and MUST be turned off for a plain-HTTP lab (deploy/.env), never for a
    # deployment reachable over the network: see docs/OPERATIONS.md.
    session_ttl_hours: int = Field(default=8, gt=0)
    session_cookie_secure: bool = True

    # Built frontend (frontend/dist) to serve, if any: None means API-only (tests, local dev
    # against `npm run dev`'s own server). The Docker image sets this; docker-compose.yml does not
    # need to, since the image default already matches where the build stage puts it.
    static_dir: Path | None = None

    @field_validator("abuseipdb_api_key", mode="before")
    @classmethod
    def _empty_key_means_off(cls, value: object) -> object:
        # docker compose passes `${SENTINEL_ABUSEIPDB_API_KEY:-}` as an empty string when unset.
        return None if isinstance(value, str) and not value.strip() else value


@lru_cache
def get_settings() -> Settings:
    return Settings()
