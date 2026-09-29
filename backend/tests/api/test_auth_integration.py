"""`/v1/auth/*` and `/v1/alerts` against a real Postgres. See
tests/db/test_agent_registry_integration.py for how to run these locally."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.api.auth import COOKIE_NAME
from sentinel_core.api.main import create_app
from sentinel_core.auth.agent_keys import DenyAllAgentRepository
from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.config import Settings
from sentinel_core.db.alerts import insert_alerts, set_enrichment
from sentinel_core.db.events import insert_events
from sentinel_core.detection.alerts import Alert
from sentinel_core.enrichment.abuseipdb import Reputation
from sentinel_core.enrichment.enricher import Enrichment
from sentinel_core.enrichment.risk import assess
from sentinel_core.schema.event import Action, Category, Event, Outcome, Source
from tests.support import DATABASE_URL, InMemoryPublisher

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

PASSWORD = "correct horse battery staple"  # noqa: S105
T0 = datetime(2026, 9, 24, 15, 0, tzinfo=UTC)


def alert(alert_id: str, rule_id: str = "ssh-bruteforce") -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        title="SSH brute force",
        mitre=["T1110"],
        severity=60,
        ts=T0,
        group={"src_ip": "203.0.113.7"},
        src_ip="203.0.113.7",
        event_ids=["00" * 32],
        match_count=5,
    )


@pytest.fixture
def users(engine: AsyncEngine) -> PostgresUserRepository:
    return PostgresUserRepository(async_sessionmaker(engine, expire_on_commit=False))


@pytest.fixture
async def client(engine: AsyncEngine, users: PostgresUserRepository) -> AsyncGenerator[AsyncClient]:
    app = create_app(
        settings=Settings(
            database_url=str(engine.url), session_cookie_secure=False
        ),  # httpx enforces Secure like a real browser: http://test needs it off
        agent_repo=DenyAllAgentRepository(),
        publisher=InMemoryPublisher(),
        user_repo=users,
        db_sessions=async_sessionmaker(engine, expire_on_commit=False),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def test_login_sets_a_cookie_and_returns_the_user(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    await users.create_user("alice@example.com", PASSWORD, "analyst")

    response = await client.post(
        "/v1/auth/login", json={"email": "alice@example.com", "password": PASSWORD}
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": response.json()["id"],
        "email": "alice@example.com",
        "role": "analyst",
    }
    assert UUID(response.json()["id"])
    cookie = response.cookies.get(COOKIE_NAME)
    assert cookie is not None
    assert response.headers["set-cookie"].lower().count("httponly") == 1
    assert "samesite=strict" in response.headers["set-cookie"].lower()


async def test_the_cookie_authenticates_subsequent_requests(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    await users.create_user("bob@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "bob@example.com", "password": PASSWORD})

    me = await client.get("/v1/auth/me")

    assert me.status_code == 200 and me.json()["email"] == "bob@example.com"


async def test_a_wrong_password_is_rejected_with_a_generic_message(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    await users.create_user("carol@example.com", PASSWORD, "analyst")

    wrong_password = await client.post(
        "/v1/auth/login", json={"email": "carol@example.com", "password": "the wrong one"}
    )
    unknown_email = await client.post(
        "/v1/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}
    )

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json()["detail"] == unknown_email.json()["detail"]
    assert COOKIE_NAME not in wrong_password.cookies


async def test_me_without_a_session_is_rejected(client: AsyncClient) -> None:
    response = await client.get("/v1/auth/me")

    assert response.status_code == 401


async def test_a_malformed_cookie_is_rejected_not_trusted(client: AsyncClient) -> None:
    client.cookies.set(COOKIE_NAME, "not-a-real-session-token")

    response = await client.get("/v1/auth/me")

    assert response.status_code == 401


async def test_logout_ends_the_session(client: AsyncClient, users: PostgresUserRepository) -> None:
    await users.create_user("dave@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "dave@example.com", "password": PASSWORD})

    logout = await client.post("/v1/auth/logout")
    after = await client.get("/v1/auth/me")

    assert logout.status_code == 204
    assert after.status_code == 401


async def test_alerts_requires_authentication(client: AsyncClient) -> None:
    response = await client.get("/v1/alerts")

    assert response.status_code == 401


async def test_alerts_lists_the_stored_alerts_once_logged_in(
    client: AsyncClient, users: PostgresUserRepository, engine: AsyncEngine
) -> None:
    async with async_sessionmaker(engine, expire_on_commit=False).begin() as session:
        await insert_alerts(session, [alert("ab" * 32), alert("cd" * 32, "ssh-root-login")])
    await users.create_user("erin@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "erin@example.com", "password": PASSWORD})

    listed = await client.get("/v1/alerts")
    filtered = await client.get("/v1/alerts", params={"rule": "ssh-root-login"})

    assert listed.status_code == 200 and len(listed.json()) == 2
    assert [a["rule_id"] for a in filtered.json()] == ["ssh-root-login"]
    assert listed.json()[0]["src_ip"] == "203.0.113.7"


async def test_a_revoked_users_session_stops_working(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    created = await users.create_user("frank@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "frank@example.com", "password": PASSWORD})

    await users.revoke_user(created.id)
    response = await client.get("/v1/auth/me")

    assert response.status_code == 401


async def test_an_unknown_field_in_the_login_body_is_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/login",
        json={"email": "x@example.com", "password": PASSWORD, "remember_me": True},
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "body", [{"email": "not-an-email", "password": PASSWORD}, {"email": "x@example.com"}]
)
async def test_a_malformed_login_body_is_rejected(
    client: AsyncClient, body: dict[str, str]
) -> None:
    response = await client.post("/v1/auth/login", json=body)

    assert response.status_code == 422


async def test_the_secure_flag_is_set_by_default(
    engine: AsyncEngine, users: PostgresUserRepository
) -> None:
    """`session_cookie_secure` defaults to True: the cookie must carry `Secure` unless the
    operator explicitly turns it off (for a plain-HTTP lab; see docs/OPERATIONS.md)."""
    app = create_app(
        settings=Settings(database_url=str(engine.url)),  # default: session_cookie_secure=True
        agent_repo=DenyAllAgentRepository(),
        publisher=InMemoryPublisher(),
        user_repo=users,
        db_sessions=async_sessionmaker(engine, expire_on_commit=False),
    )
    await users.create_user("grace@example.com", PASSWORD, "analyst")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/auth/login", json={"email": "grace@example.com", "password": PASSWORD}
        )

    assert "secure" in response.headers["set-cookie"].lower()


async def test_a_local_lab_domain_is_accepted_not_just_real_ones(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    """This is a login identifier, not a deliverable address: a self-hosted lab may use
    reserved/internal TLDs (.local, .internal, .test...) that a real email validator would
    refuse as "special-use"."""
    await users.create_user("admin@sentinellite.local", PASSWORD, "admin")

    response = await client.post(
        "/v1/auth/login", json={"email": "admin@sentinellite.local", "password": PASSWORD}
    )

    assert response.status_code == 200 and response.json()["email"] == "admin@sentinellite.local"


# --- GET /v1/alerts/{id}: full detail (evidence, enrichment, risk) ------------------------------


def evidence_event(n: int) -> Event:
    return Event(
        event_id=f"{n:064x}",
        ts=T0 + timedelta(seconds=n),
        received_at=T0 + timedelta(seconds=n, milliseconds=200),
        agent_id=UUID(int=1),
        host="ubuntu-01",
        source=Source.LINUX_AUTH,
        category=Category.AUTHENTICATION,
        action=Action.LOGIN_FAILED,
        outcome=Outcome.FAILURE,
        severity=20,
        src_ip="203.0.113.7",
        user_name="root",
        raw=f"failed password attempt number {n}",
    )


async def test_alert_detail_includes_evidence_enrichment_and_risk(
    client: AsyncClient, users: PostgresUserRepository, engine: AsyncEngine
) -> None:
    detail_id = "ef" * 32
    events = [evidence_event(i) for i in range(4)]
    detailed_alert = Alert(
        alert_id=detail_id,
        rule_id="ssh-bruteforce",
        title="SSH brute force",
        mitre=["T1110"],
        severity=60,
        ts=T0 + timedelta(seconds=3),
        group={"src_ip": "203.0.113.7"},
        src_ip="203.0.113.7",
        event_ids=[e.event_id for e in reversed(events)],  # newest first
        match_count=4,
    )
    reputation = Reputation(
        score=90, total_reports=200, distinct_reporters=50, is_tor=True, checked_at=T0
    )
    async with async_sessionmaker(engine, expire_on_commit=False).begin() as session:
        await insert_events(session, events)
        await insert_alerts(session, [detailed_alert])
        await set_enrichment(
            session,
            detail_id,
            Enrichment(ip_scope="public", reputation=reputation),
            assess(60, Enrichment(ip_scope="public", reputation=reputation)),
        )
    await users.create_user("show@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "show@example.com", "password": PASSWORD})

    response = await client.get(f"/v1/alerts/{detail_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["alert"]["alert_id"] == detail_id
    assert body["mitre"] == ["T1110"]
    assert body["group"] == {"src_ip": "203.0.113.7"}
    assert [e["raw"] for e in body["evidence"]] == [e.raw for e in events]  # oldest first
    assert body["detection_latency_ms"] is not None and body["detection_latency_ms"] > 0
    assert body["enrichment"]["reputation"]["score"] == 90
    assert body["risk"]["score"] == 87  # 60 + 90//4 (22) + 5 (tor)


async def test_alert_detail_requires_authentication(client: AsyncClient) -> None:
    response = await client.get(f"/v1/alerts/{'a' * 64}")

    assert response.status_code == 401


async def test_alert_detail_of_an_unknown_id_is_404(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    await users.create_user("notfound@example.com", PASSWORD, "analyst")
    await client.post(
        "/v1/auth/login", json={"email": "notfound@example.com", "password": PASSWORD}
    )

    response = await client.get(f"/v1/alerts/{'ef' * 32}")

    assert response.status_code == 404


async def test_alert_detail_of_a_malformed_id_is_400(
    client: AsyncClient, users: PostgresUserRepository
) -> None:
    await users.create_user("badid@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "badid@example.com", "password": PASSWORD})

    too_short = await client.get("/v1/alerts/abcde")
    not_hex = await client.get("/v1/alerts/not-hexadecimal-at-all")

    assert too_short.status_code == 400 and not_hex.status_code == 400


async def test_alert_detail_of_an_ambiguous_prefix_is_400(
    client: AsyncClient, users: PostgresUserRepository, engine: AsyncEngine
) -> None:
    async with async_sessionmaker(engine, expire_on_commit=False).begin() as session:
        await insert_alerts(session, [alert("abcdef" + "01" * 29), alert("abcdef" + "02" * 29)])
    await users.create_user("ambiguous@example.com", PASSWORD, "analyst")
    await client.post(
        "/v1/auth/login", json={"email": "ambiguous@example.com", "password": PASSWORD}
    )

    response = await client.get("/v1/alerts/abcdef")

    assert response.status_code == 400


async def test_alert_without_enrichment_has_null_enrichment_and_risk(
    client: AsyncClient, users: PostgresUserRepository, engine: AsyncEngine
) -> None:
    bare_id = "12" * 32
    async with async_sessionmaker(engine, expire_on_commit=False).begin() as session:
        await insert_alerts(session, [alert(bare_id)])
    await users.create_user("bare@example.com", PASSWORD, "analyst")
    await client.post("/v1/auth/login", json={"email": "bare@example.com", "password": PASSWORD})

    response = await client.get(f"/v1/alerts/{bare_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["enrichment"] is None and body["risk"] is None
    assert body["detection_latency_ms"] is None  # no evidence event was ever inserted
