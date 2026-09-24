from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables prefixed with SENTINEL_."""

    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    # No default: credentials must always come from the environment.
    database_url: str
    redis_url: str = "redis://redis:6379/0"
    responder_mode: str = Field(default="dry_run", pattern="^(dry_run|enforce)$")


@lru_cache
def get_settings() -> Settings:
    return Settings()
