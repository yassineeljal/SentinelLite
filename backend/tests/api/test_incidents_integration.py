"""Exercise triage through the real authenticated API and migrated Postgres database."""

from collections.abc import AsyncGenerator
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core.api.main import create_app
from sentinel_core.auth.agent_keys import DenyAllAgentRepository
from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.config import Settings
from sentinel_core.db.alerts import insert_alerts
from tests.db.test_incidents_integration import alert
from tests.support import DATABASE_URL, InMemoryPublisher

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]
PASSWORD = "correct horse battery staple"  # noqa: S105


@pytest.fixture
async def client(engine: AsyncEngine) -> AsyncGenerator[AsyncClient]:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    users = PostgresUserRepository(sessions)
    await users.create_user("analyst@example.com", PASSWORD, "analyst")
    await users.create_user("admin@example.com", PASSWORD, "admin")
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("a" * 64), alert("b" * 64)])
    app = create_app(
        settings=Settings(database_url=str(engine.url), session_cookie_secure=False),
        agent_repo=DenyAllAgentRepository(),
        publisher=InMemoryPublisher(),
        user_repo=users,
        db_sessions=sessions,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client


async def login(client: AsyncClient, role: str = "analyst") -> None:
    result = await client.post(
        "/v1/auth/login",
        json={
            "email": f"{role}@example.com",
            "password": PASSWORD,
        },
    )
    assert result.status_code == 200


@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [
        ("GET", "", None),
        ("POST", "", {"title": "x"}),
        ("GET", "/{id}", None),
        ("PATCH", "/{id}", {"status": "closed"}),
        ("POST", "/{id}/claim", None),
        ("DELETE", "/{id}/assignee", None),
        ("POST", "/{id}/notes", {"body": "x"}),
        ("POST", "/{id}/alerts", {"alert_ids": ["a" * 64]}),
        ("DELETE", "/{id}/alerts/" + "a" * 64, None),
    ],
)
async def test_every_route_requires_a_session(
    client: AsyncClient,
    method: str,
    suffix: str,
    body: dict[str, object] | None,
) -> None:
    result = await client.request(method, "/v1/incidents" + suffix.format(id=uuid4()), json=body)
    assert result.status_code == 401


@pytest.mark.parametrize("role", ["analyst", "admin"])
async def test_full_triage_workflow(client: AsyncClient, role: str) -> None:
    await login(client, role)
    created = await client.post(
        "/v1/incidents", json={"title": "  SSH spike  ", "alert_ids": ["a" * 64]}
    )
    assert created.status_code == 201
    assert created.json()["title"] == "SSH spike"
    assert created.json()["alert_count"] == 1
    alert_detail = (await client.get("/v1/alerts/" + "a" * 64)).json()
    assert alert_detail["incident_id"] == created.json()["id"]
    path = f"/v1/incidents/{created.json()['id']}"
    assert (await client.post(path + "/claim")).status_code == 204
    assert (await client.patch(path, json={"status": "investigating"})).status_code == 204
    assert (
        await client.post(path + "/notes", json={"body": "  Checked SSH logs\nInvestigating.  "})
    ).status_code == 204
    assert (await client.post(path + "/alerts", json={"alert_ids": ["b" * 64]})).status_code == 204
    detail = (await client.get(path)).json()
    assert detail["summary"]["status"] == "investigating"
    assert detail["summary"]["assignee_email"] == f"{role}@example.com"
    assert detail["summary"]["alert_count"] == 2
    assert {a["alert_id"] for a in detail["alerts"]} == {"a" * 64, "b" * 64}
    assert detail["notes"][0]["body"] == "Checked SSH logs\nInvestigating."
    assert detail["notes"][0]["author_email"] == f"{role}@example.com"
    assert (await client.patch(path, json={"status": "closed"})).status_code == 204
    closed_at = (await client.get(path)).json()["summary"]["closed_at"]
    assert closed_at is not None
    # Retrying a close request must not rewrite history.
    await client.patch(path, json={"status": "closed"})
    assert (await client.get(path)).json()["summary"]["closed_at"] == closed_at
    assert len((await client.get("/v1/incidents?status=closed")).json()) == 1
    assert (await client.get("/v1/incidents?status=new")).json() == []
    assert (await client.patch(path, json={"status": "new"})).status_code == 204
    assert (await client.delete(path + "/assignee")).status_code == 204
    assert (await client.delete(path + "/alerts/" + "a" * 64)).status_code == 204
    detail = (await client.get(path)).json()
    assert detail["summary"]["closed_at"] is None
    assert detail["summary"]["assignee_email"] is None
    assert detail["summary"]["alert_count"] == 1
    assert (await client.get("/v1/alerts/" + "a" * 64)).json()["incident_id"] is None


@pytest.mark.parametrize(
    ("suffix", "body"),
    [
        ("", {"title": "   "}),
        ("", {"title": "a" * 201}),
        ("", {"title": "bad\x00title"}),
        ("", {"title": "x", "alert_ids": ["bad"]}),
        ("", {"title": "x", "alert_ids": ["a" * 64] * 201}),
        ("/{id}/notes", {"body": "  \n "}),
        ("/{id}/notes", {"body": "a" * 4001}),
        ("/{id}/notes", {"body": "bad\x00note"}),
        ("/{id}/notes", {"body": "note", "author_id": str(uuid4())}),
        ("/{id}/alerts", {"alert_ids": []}),
    ],
)
async def test_invalid_mutations_are_rejected(
    client: AsyncClient,
    suffix: str,
    body: dict[str, object],
) -> None:
    await login(client)
    result = await client.post("/v1/incidents" + suffix.format(id=uuid4()), json=body)
    assert result.status_code == 422


async def test_invalid_status_id_and_list_bounds(client: AsyncClient) -> None:
    await login(client)
    assert (
        await client.patch(f"/v1/incidents/{uuid4()}", json={"status": "archived"})
    ).status_code == 422
    for suffix in ("/invalid-id", "?status=archived", "?limit=0", "?limit=201"):
        assert (await client.get("/v1/incidents" + suffix)).status_code == 422


@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [
        ("GET", "", None),
        ("PATCH", "", {"status": "closed"}),
        ("POST", "/claim", None),
        ("DELETE", "/assignee", None),
        ("POST", "/notes", {"body": "note"}),
        ("POST", "/alerts", {"alert_ids": ["a" * 64]}),
        ("DELETE", "/alerts/" + "a" * 64, None),
    ],
)
async def test_unknown_incidents_return_404(
    client: AsyncClient,
    method: str,
    suffix: str,
    body: dict[str, object] | None,
) -> None:
    await login(client)
    result = await client.request(method, f"/v1/incidents/{uuid4()}" + suffix, json=body)
    assert result.status_code == 404


async def test_link_conflicts_are_atomic_and_do_not_move_alerts(client: AsyncClient) -> None:
    await login(client)
    first = (
        await client.post("/v1/incidents", json={"title": "first", "alert_ids": ["a" * 64]})
    ).json()
    for ids in (["b" * 64, "a" * 64], ["b" * 64, "f" * 64]):
        failed = await client.post("/v1/incidents", json={"title": "failed", "alert_ids": ids})
        assert failed.status_code == 409
    assert len((await client.get("/v1/incidents")).json()) == 1
    second = (await client.post("/v1/incidents", json={"title": "second"})).json()
    path = f"/v1/incidents/{second['id']}"
    failed = await client.post(path + "/alerts", json={"alert_ids": ["b" * 64, "a" * 64]})
    assert failed.status_code == 409
    assert (await client.get(path)).json()["alerts"] == []
    # A stale unlink naming the wrong incident cannot affect the first incident.
    assert (await client.delete(path + "/alerts/" + "a" * 64)).status_code == 204
    first_path = f"/v1/incidents/{first['id']}"
    assert (await client.get(first_path)).json()["summary"]["alert_count"] == 1
    # Explicitly unlinking then linking elsewhere works; linking twice is idempotent.
    await client.delete(first_path + "/alerts/" + "a" * 64)
    for _ in range(2):
        assert (
            await client.post(path + "/alerts", json={"alert_ids": ["a" * 64]})
        ).status_code == 204
    assert (await client.get(path)).json()["summary"]["alert_count"] == 1
