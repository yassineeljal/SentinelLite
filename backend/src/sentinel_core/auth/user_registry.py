"""Postgres-backed dashboard users and sessions: authentication (used by the API) and
administration (the CLI). No self-registration: `sentinel users create` is the only way in."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core.auth.passwords import hash_password, verify_password_async
from sentinel_core.auth.sessions import generate_session_token, hash_session_token
from sentinel_core.auth.totp import SecretBox, consume_factor
from sentinel_core.db.models import User, UserSession

VALID_ROLES = ("admin", "analyst")
MAX_EMAIL_LENGTH = 255
# A login identifier, not a deliverable address: no DNS/MX lookups and no rejection of reserved
# TLDs (.local, .test, .internal...), which a self-hosted lab legitimately uses. Just shape:
# one '@', no whitespace or control characters, a dot somewhere after the '@'.
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
# Verified against this on an unknown email, so a login attempt costs the same work either way
# and cannot be used to test which emails have an account (see ingest.py's _DUMMY_HASH for the
# same reasoning with agent keys).
_DUMMY_HASH = hash_password("not a real password, only ever compared against, never matched")


class EmailTaken(Exception):
    """A user with this email already exists."""


@dataclass(frozen=True)
class UserInfo:
    """Public view of a user. Deliberately carries no password hash."""

    id: UUID
    email: str
    role: str
    created_at: datetime
    revoked_at: datetime | None


def _info(row: User) -> UserInfo:
    return UserInfo(
        id=row.id,
        email=row.email,
        role=row.role,
        created_at=row.created_at,
        revoked_at=row.revoked_at,
    )


def add_session(session: AsyncSession, user_id: UUID, ttl: timedelta) -> str:
    """Issue a token inside the caller's transaction, after all authentication checks."""
    token = generate_session_token()
    session.add(
        UserSession(
            id=hash_session_token(token),
            user_id=user_id,
            expires_at=datetime.now(UTC) + ttl,
        )
    )
    return token


class PostgresUserRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def create_user(self, email: str, password: str, role: str) -> UserInfo:
        email = email.strip().lower()
        if len(email) > MAX_EMAIL_LENGTH or not EMAIL_PATTERN.match(email):
            raise ValueError("not a valid email address")
        if role not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        row = User(id=uuid4(), email=email, password_hash=hash_password(password), role=role)
        async with self._sessions() as session:
            session.add(row)
            try:
                await session.commit()
            except IntegrityError as exc:
                raise EmailTaken(email) from exc
            await session.refresh(row)
            return _info(row)

    async def revoke_user(self, user_id: UUID) -> bool:
        """Revoke an active user AND every one of their sessions (an admin locking out a
        colleague, or offboarding, must not leave a live session behind). False if the user does
        not exist or is already revoked."""
        async with self._sessions() as session:
            revoked = await session.scalar(
                update(User)
                .where(User.id == user_id, User.revoked_at.is_(None))
                .values(revoked_at=func.now())
                .returning(User.id)
            )
            if revoked is not None:
                await session.execute(delete(UserSession).where(UserSession.user_id == user_id))
            await session.commit()
            return revoked is not None

    async def list_users(self) -> list[UserInfo]:
        async with self._sessions() as session:
            rows = await session.scalars(select(User).order_by(User.email))
            return [_info(row) for row in rows]

    async def authenticate(self, email: str, password: str) -> UserInfo | None:
        """Legacy password-only check. Refuses MFA accounts; HTTP login uses `login`."""
        async with self._sessions() as session:
            row = await session.scalar(
                select(User).where(User.email == email.strip().lower(), User.revoked_at.is_(None))
            )
            candidate_hash = row.password_hash if row is not None else _DUMMY_HASH
            if not await verify_password_async(password, candidate_hash):
                return None
            return _info(row) if row is not None and row.totp_secret is None else None

    async def login(
        self,
        email: str,
        password: str,
        code: str,
        ttl: timedelta,
        box: SecretBox,
    ) -> tuple[UserInfo, str] | None:
        # Serialize factor consumption, revocation and session creation on the same user row.
        async with self._sessions.begin() as session:
            row = await session.scalar(
                select(User)
                .where(
                    User.email == email.strip().lower(),
                    User.revoked_at.is_(None),
                )
                .with_for_update()
            )
            candidate_hash = row.password_hash if row is not None else _DUMMY_HASH
            if not await verify_password_async(password, candidate_hash):
                return None
            if row is None:
                return None
            if row.totp_secret is not None and not consume_factor(
                row, code, box, datetime.now(UTC)
            ):
                return None
            return _info(row), add_session(session, row.id, ttl)

    async def create_session(self, user_id: UUID, ttl: timedelta) -> str:
        """Internal session issuance for trusted callers; HTTP login uses `login` atomically."""
        async with self._sessions.begin() as session:
            return add_session(session, user_id, ttl)

    async def resolve_session(self, token: str) -> UserInfo | None:
        """The session's user, or None if the token is unknown, expired, or the user was
        revoked since. An expired session is deleted here (lazily; there is no background sweep,
        see auth/CLEANUP note in the CLI)."""
        async with self._sessions() as session:
            row = await session.scalar(
                select(UserSession).where(UserSession.id == hash_session_token(token))
            )
            if row is None:
                return None
            if row.expires_at <= datetime.now(UTC):
                await session.delete(row)
                await session.commit()
                return None
            user = await session.scalar(
                select(User).where(User.id == row.user_id, User.revoked_at.is_(None))
            )
            return _info(user) if user is not None else None

    async def revoke_session(self, token: str) -> None:
        async with self._sessions() as session:
            await session.execute(
                delete(UserSession).where(UserSession.id == hash_session_token(token))
            )
            await session.commit()
