"""Every shipped rule must detect its attacks and stay silent on benign traffic.

The convention and the replay logic live in `sentinel_core.detection.scenarios` (also used by
`sentinel bench`); see its docstring for the dataset format. A rule without at least one attack and
one benign scenario, or a malformed dataset file, fails here.
"""

from pathlib import Path
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from sentinel_core.detection.rules import load_rules
from sentinel_core.detection.scenarios import SHARED, Scenario, discover_scenarios, run_scenario
from sentinel_core.detection.store import RedisWindowStore
from tests.support import REDIS_URL

REPO_ROOT = Path(__file__).resolve().parents[3]
RULES = load_rules(REPO_ROOT / "rules")
# A disabled rule needs no scenario coverage: it can never fire (see bench.py).
SCENARIOS = discover_scenarios(REPO_ROOT / "datasets", [rule.id for rule in RULES if rule.enabled])


def test_every_rule_has_attack_and_benign_scenarios() -> None:
    assert {s.rule_id for s in SCENARIOS} - {SHARED} == {rule.id for rule in RULES if rule.enabled}


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: f"{s.rule_id}/{s.name}")
async def test_scenario_produces_exactly_the_expected_alerts(scenario: Scenario) -> None:
    result = await run_scenario(scenario, RULES)

    assert result.passed, "; ".join(result.problems)


@pytest.mark.integration
@pytest.mark.skipif(REDIS_URL is None, reason="SENTINEL_TEST_REDIS_URL not set")
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: f"{s.rule_id}/{s.name}")
async def test_scenarios_give_the_same_result_on_the_redis_store_the_detector_uses(
    scenario: Scenario,
) -> None:
    """Same alerts on the Redis store (Lua scripts) as on the in-memory reference, on every
    scenario including the 2000-line normal day."""
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        store = RedisWindowStore(client, key_prefix=f"test:{uuid4()}:")

        on_redis = await run_scenario(scenario, RULES, store=store)
        on_memory = await run_scenario(scenario, RULES)

        assert on_redis.alerts == on_memory.alerts
        assert on_redis.passed, "; ".join(on_redis.problems)
    finally:
        await client.aclose()
