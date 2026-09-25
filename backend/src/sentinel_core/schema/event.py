"""Common event schema (ECS-inspired). Every normalizer produces `Event`."""

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from pydantic.networks import IPvAnyAddress


class Source(StrEnum):
    LINUX_AUTH = "linux.auth"
    NGINX_ACCESS = "nginx.access"
    WINDOWS_SECURITY = "windows.security"
    WINDOWS_SYSMON = "windows.sysmon"


class Category(StrEnum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    WEB = "web"
    IAM = "iam"
    FILE = "file"


class Action(StrEnum):
    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCESS = "login_success"
    INVALID_USER = "invalid_user"
    SUDO_COMMAND = "sudo_command"
    SUDO_FAILED = "sudo_failed"
    ACCOUNT_CREATED = "account_created"
    GROUP_MEMBER_ADDED = "group_member_added"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Event(BaseModel):
    """A normalized security event. Immutable once built."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(min_length=64, max_length=64, description="sha256 hex, idempotency key")
    ts: AwareDatetime = Field(description="When the event happened (UTC)")
    received_at: AwareDatetime
    agent_id: UUID
    host: str = Field(max_length=255)
    source: Source
    category: Category
    action: Action
    outcome: Outcome
    severity: int = Field(ge=0, le=100, description="Raw event severity, not the alert score")
    src_ip: IPvAnyAddress | None = None
    dst_ip: IPvAnyAddress | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    user_name: str | None = Field(default=None, max_length=256)
    raw: str
    extra: dict[str, Any] = Field(default_factory=dict)
