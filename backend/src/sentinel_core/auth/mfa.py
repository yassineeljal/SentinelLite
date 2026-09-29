"""Enrollment and factor management. Every mutation reauthenticates and locks the user row."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pyotp
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.auth.passwords import verify_password_async
from sentinel_core.auth.sessions import hash_session_token
from sentinel_core.auth.totp import SecretBox, consume_factor, match_counter, new_recovery_codes
from sentinel_core.auth.user_registry import add_session
from sentinel_core.db.models import User, UserSession


class InvalidMFACredentials(Exception):
    """Wrong password, factor, expired enrollment or no longer valid session."""


class MFAStateConflict(Exception):
    """The account already enabled 2FA, or it is not enabled for a management action."""


@dataclass(frozen=True)
class MFAStatus:
    enabled: bool
    setup_available: bool
    recovery_codes_remaining: int


@dataclass(frozen=True)
class MFASetup:
    secret: str
    provisioning_uri: str
    expires_at: datetime


def clear_pending(user: User) -> None:
    user.totp_pending_secret = None
    user.totp_pending_expires_at = None
    user.totp_pending_session_hash = None


class MFAManager:
    def __init__(self, sessions: async_sessionmaker[AsyncSession], box: SecretBox) -> None:
        self._sessions = sessions
        self._box = box

    async def status(self, user_id: UUID) -> MFAStatus:
        async with self._sessions() as session:
            user = await session.get(User, user_id)
            if user is None or user.revoked_at is not None:
                raise InvalidMFACredentials
            return MFAStatus(
                enabled=user.totp_secret is not None,
                setup_available=self._box.available,
                recovery_codes_remaining=len(user.recovery_code_hashes or []),
            )

    async def _verified_user(
        self,
        session: AsyncSession,
        user_id: UUID,
        token: str,
        password: str,
    ) -> User:
        user = await session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None or user.revoked_at is not None:
            raise InvalidMFACredentials
        # Recheck AFTER locking: another request may have revoked this session while we waited.
        login_session = await session.get(UserSession, hash_session_token(token))
        if (
            login_session is None
            or login_session.user_id != user_id
            or login_session.expires_at <= datetime.now(UTC)
        ):
            raise InvalidMFACredentials
        if not await verify_password_async(password, user.password_hash):
            raise InvalidMFACredentials
        return user

    async def start(self, user_id: UUID, token: str, password: str) -> MFASetup:
        async with self._sessions.begin() as session:
            user = await self._verified_user(session, user_id, token, password)
            if user.totp_secret is not None:
                raise MFAStateConflict("Two-factor authentication is already enabled")
            secret = pyotp.random_base32()
            user.totp_pending_secret = self._box.encrypt(secret, user.id)
            user.totp_pending_expires_at = datetime.now(UTC) + timedelta(minutes=10)
            user.totp_pending_session_hash = hash_session_token(token)
            return MFASetup(
                secret=secret,
                provisioning_uri=pyotp.TOTP(secret).provisioning_uri(
                    name=user.email,
                    issuer_name="SentinelLite",
                ),
                expires_at=user.totp_pending_expires_at,
            )

    async def _rotate_sessions(self, session: AsyncSession, user: User, ttl: timedelta) -> str:
        await session.execute(delete(UserSession).where(UserSession.user_id == user.id))
        return add_session(session, user.id, ttl)

    async def confirm(
        self,
        user_id: UUID,
        token: str,
        password: str,
        code: str,
        ttl: timedelta,
    ) -> tuple[list[str], str]:
        async with self._sessions.begin() as session:
            user = await self._verified_user(session, user_id, token, password)
            if user.totp_secret is not None:
                raise MFAStateConflict("Two-factor authentication is already enabled")
            if (
                user.totp_pending_secret is None
                or user.totp_pending_expires_at is None
                or user.totp_pending_expires_at <= datetime.now(UTC)
                or user.totp_pending_session_hash != hash_session_token(token)
            ):
                raise InvalidMFACredentials
            secret = self._box.decrypt(user.totp_pending_secret, user.id)
            counter = match_counter(secret, code.strip(), datetime.now(UTC), None)
            if counter is None:
                raise InvalidMFACredentials
            user.totp_secret = user.totp_pending_secret
            user.totp_last_counter = counter
            clear_pending(user)
            codes, user.recovery_code_hashes = new_recovery_codes()
            new_token = await self._rotate_sessions(session, user, ttl)
            return codes, new_token

    async def change(
        self,
        user_id: UUID,
        token: str,
        password: str,
        code: str,
        ttl: timedelta,
        *,
        disable: bool,
    ) -> tuple[list[str], str]:
        async with self._sessions.begin() as session:
            user = await self._verified_user(session, user_id, token, password)
            if user.totp_secret is None:
                raise MFAStateConflict("Two-factor authentication is not enabled")
            if not consume_factor(user, code, self._box, datetime.now(UTC)):
                raise InvalidMFACredentials
            if disable:
                codes: list[str] = []
                user.totp_secret = None
                user.totp_last_counter = None
                user.recovery_code_hashes = None
            else:
                codes, user.recovery_code_hashes = new_recovery_codes()
            clear_pending(user)
            new_token = await self._rotate_sessions(session, user, ttl)
            return codes, new_token
