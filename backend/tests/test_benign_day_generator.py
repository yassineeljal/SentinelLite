import importlib.util
import ipaddress
import re
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "datasets" / "tools" / "generate_benign_day.py"
COMMITTED = REPO_ROOT / "datasets" / "_shared" / "benign-normal-day.log"


def load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_benign_day", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_benign_day_is_exactly_what_the_generator_produces() -> None:
    """The file is generated (fixed seed): editing it by hand, or changing the generator without
    regenerating, must fail here."""
    assert load_generator().generate() == COMMITTED.read_text(), (
        "regenerate with: python3 datasets/tools/generate_benign_day.py "
        "> datasets/_shared/benign-normal-day.log"
    )


def test_the_generator_is_deterministic() -> None:
    module = load_generator()

    assert module.generate() == module.generate()


def test_the_benign_day_is_large_and_time_ordered() -> None:
    lines = [x for x in COMMITTED.read_text().splitlines() if not x.startswith("#")]

    assert len(lines) > 1900
    stamps = [x.split(" ", 1)[0] for x in lines]
    assert stamps == sorted(stamps)


def test_only_documentation_or_private_addresses_appear_in_the_datasets() -> None:
    """Datasets are committed: no real Internet address may leak into them (RFC 5737 and
    RFC 3849 documentation ranges, private ranges)."""
    allowed = [
        ipaddress.ip_network(net)
        for net in (
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "10.0.0.0/8",
            "2001:db8::/32",
        )
    ]
    pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f:]*::[0-9a-f:]*\b")
    offenders = set()
    for path in (REPO_ROOT / "datasets").rglob("*.log"):
        for line in path.read_text().splitlines():
            if line.startswith("#"):
                continue
            for text in pattern.findall(line):
                try:
                    address = ipaddress.ip_address(text)
                except ValueError:
                    continue
                if not any(address in net for net in allowed):
                    offenders.add((path.name, text))

    assert not offenders, offenders
