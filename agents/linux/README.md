# sentinel-agent

Linux log agent for SentinelLite: follows log files and ships their lines to the ingestion API.
Standard library only, Python >= 3.11. Full documentation: [`docs/AGENT.md`](../../docs/AGENT.md).

```bash
uv sync                                   # development
uv run pytest -q && uv run ruff check . && uv run mypy src tests
uv run sentinel-agent --config deploy/agent.toml.example --once   # after editing paths and key
uv build                                  # wheel to copy to a host
```
