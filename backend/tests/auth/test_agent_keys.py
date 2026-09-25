from uuid import UUID, uuid4

import pytest

from sentinel_core.auth.agent_keys import (
    DenyAllAgentRepository,
    InMemoryAgentRepository,
    generate_agent_key,
    hash_secret,
    parse_bearer_token,
)


def test_generated_key_round_trips_through_the_parser() -> None:
    agent_id = uuid4()

    key = generate_agent_key(agent_id)
    credentials = parse_bearer_token(f"Bearer {key.token}")

    assert credentials is not None
    assert credentials.agent_id == agent_id
    assert hash_secret(credentials.secret) == key.secret_hash


def test_keys_are_unique_and_the_hash_never_contains_the_secret() -> None:
    agent_id = uuid4()

    first, second = generate_agent_key(agent_id), generate_agent_key(agent_id)

    assert first.token != second.token
    assert first.secret_hash != second.secret_hash
    secret = first.token.split(".", 1)[1]
    assert secret not in first.secret_hash
    assert len(secret) >= 43  # 256 bits, url-safe base64


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer",
        "Bearer ",
        "Basic abc",
        "bearer-without-space",
        "Bearer not-a-uuid.secretsecretsecretsecretsecret",
        "Bearer 11111111-1111-1111-1111-111111111111",  # no secret
        "Bearer 11111111-1111-1111-1111-111111111111.short",
        "Bearer 11111111-1111-1111-1111-111111111111." + "a" * 129,
        "Bearer 11111111-1111-1111-1111-111111111111.has space in secret!!!!!!!",
    ],
)
def test_malformed_authorization_headers_are_rejected(header: str | None) -> None:
    assert parse_bearer_token(header) is None


def test_scheme_is_case_insensitive() -> None:
    key = generate_agent_key(UUID(int=1))

    assert parse_bearer_token(f"bearer {key.token}") is not None


async def test_in_memory_repository_returns_hash_and_hides_revoked_agents() -> None:
    agent_id = uuid4()
    key = generate_agent_key(agent_id)
    repo = InMemoryAgentRepository()
    repo.add(agent_id, key.secret_hash)

    assert await repo.get_key_hash(agent_id) == key.secret_hash
    assert await repo.get_key_hash(uuid4()) is None

    repo.revoke(agent_id)
    assert await repo.get_key_hash(agent_id) is None


async def test_deny_all_repository_fails_closed() -> None:
    assert await DenyAllAgentRepository().get_key_hash(uuid4()) is None
