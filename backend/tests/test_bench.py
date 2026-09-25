from pathlib import Path

import pytest

from sentinel_core import cli
from sentinel_core.bench import measure_throughput, render_report, run_benchmark
from sentinel_core.detection.rules import load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]

FAILED = (
    "2026-09-24T15:00:0{i}+00:00 host sshd[1]: "
    "Failed password for root from 203.0.113.7 port {i} ssh2"
)
ROOT_OK = (
    "2026-09-24T15:00:09+00:00 host sshd[2]: "
    "Accepted password for root from 203.0.113.7 port 9 ssh2"
)


def write(directory: Path, rule: str, name: str, body: str) -> None:
    (directory / rule).mkdir(parents=True, exist_ok=True)
    (directory / rule / name).write_text(body)


@pytest.fixture
def datasets(tmp_path: Path) -> Path:
    data = tmp_path / "datasets"
    for rule, attack, benign in [
        (
            "ssh-root-login",
            ROOT_OK,
            ROOT_OK.replace("root from", "rootkit from").replace("for root", "for rootkit"),
        ),
        ("ssh-bruteforce", "\n".join(FAILED.format(i=i) for i in range(5)), FAILED.format(i=1)),
    ]:
        write(data, rule, "attack.log", f"# expect: 1\n# description: the attack\n{attack}\n")
        write(data, rule, "benign.log", f"# expect: 0\n# description: nothing to see\n{benign}\n")
    write(data, "_shared", "benign-day.log", f"# expect: 0\n{FAILED.format(i=1)}\n")
    return data


async def test_the_report_counts_detections_and_false_alerts(datasets: Path) -> None:
    rules = load_rules(REPO_ROOT / "rules")

    run = await run_benchmark(rules, datasets)
    report = render_report(run)

    assert run.ok
    assert "| Attack scenarios | 2 |" in report
    assert "| Attack scenarios detected | 2/2 (100%) |" in report
    assert "| Benign scenarios | 3 (1 shared across all rules) |" in report
    assert "| Benign scenarios with a false alert | 0/3 |" in report
    assert "| False alerts on benign traffic | 0 |" in report
    assert "| ssh-bruteforce | T1110 | 1/1 | 2/2 | 0 |" in report
    assert "| ssh-root-login | T1078 | 1/1 | 2/2 | 0 |" in report
    assert "the attack" in report  # descriptions are shown in the scenario table


async def test_the_report_is_deterministic(datasets: Path) -> None:
    rules = load_rules(REPO_ROOT / "rules")

    first = render_report(await run_benchmark(rules, datasets))
    second = render_report(await run_benchmark(rules, datasets))

    assert first == second


async def test_a_false_positive_and_a_miss_make_the_run_fail_and_are_visible(
    datasets: Path,
) -> None:
    rules = load_rules(REPO_ROOT / "rules")
    write(datasets, "ssh-root-login", "benign-oops.log", f"# expect: 0\n{ROOT_OK}\n")  # rule fires
    write(
        datasets, "ssh-bruteforce", "attack-oops.log", f"# expect: 1\n{FAILED.format(i=1)}\n"
    )  # misses

    run = await run_benchmark(rules, datasets)
    report = render_report(run)

    assert not run.ok
    assert "| Benign scenarios with a false alert | 1/" in report
    assert "| Attack scenarios detected | 2/3 (67%) |" in report
    assert "false positive" in report and "expected 1 alert(s), got 0" in report
    assert "❌" in report


def test_the_committed_benchmark_report_is_up_to_date() -> None:
    """The same check CI runs: `sentinel bench --check docs/BENCHMARK.md`."""
    code = cli.main(
        [
            "bench",
            "--rules",
            str(REPO_ROOT / "rules"),
            "--datasets",
            str(REPO_ROOT / "datasets"),
            "--check",
            str(REPO_ROOT / "docs" / "BENCHMARK.md"),
        ]
    )

    assert code == 0, (
        "docs/BENCHMARK.md is stale: run `uv run sentinel bench --output ../docs/BENCHMARK.md`"
    )


def test_cli_writes_and_checks_a_report(
    tmp_path: Path, datasets: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.md"
    common = ["bench", "--rules", str(REPO_ROOT / "rules"), "--datasets", str(datasets)]

    assert cli.main([*common, "--output", str(out)]) == 0
    assert "# Detection benchmark" in out.read_text()
    assert cli.main([*common, "--check", str(out)]) == 0

    out.write_text(out.read_text() + "tampered\n")
    assert cli.main([*common, "--check", str(out)]) == 1
    assert "out of date" in capsys.readouterr().err
    assert cli.main([*common, "--check", str(tmp_path / "missing.md")]) == 1


def test_cli_prints_the_report_and_exits_1_when_a_scenario_fails(
    tmp_path: Path, datasets: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(datasets, "ssh-bruteforce", "attack-oops.log", f"# expect: 1\n{FAILED.format(i=1)}\n")

    code = cli.main(["bench", "--rules", str(REPO_ROOT / "rules"), "--datasets", str(datasets)])

    assert code == 1
    assert "❌" in capsys.readouterr().out


def test_cli_reports_a_broken_dataset_layout_as_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "datasets"
    empty.mkdir()

    code = cli.main(["bench", "--rules", str(REPO_ROOT / "rules"), "--datasets", str(empty)])

    assert code == 2
    assert "needs at least one attack" in capsys.readouterr().err


async def test_throughput_is_measured_without_end_to_end_claims(datasets: Path) -> None:
    rules = load_rules(REPO_ROOT / "rules")

    result = await measure_throughput(rules, datasets, repeat=3)

    assert result.events > 0 and result.seconds > 0 and result.events_per_second > 0
