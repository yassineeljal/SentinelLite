from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class Alert(BaseModel):
    """A detection. `alert_id` is deterministic, so replaying events never duplicates alerts."""

    model_config = ConfigDict(frozen=True)

    alert_id: str = Field(min_length=64, max_length=64)
    rule_id: str
    title: str
    mitre: list[str]
    severity: int = Field(ge=0, le=100)
    ts: AwareDatetime = Field(description="Time of the triggering event (clamped, see engine)")
    group: dict[str, str] = Field(description="Values of the rule's group_by fields")
    src_ip: str | None = None
    host: str | None = None
    user_name: str | None = None
    event_ids: list[str] = Field(description="Evidence, newest first (capped)")
    match_count: int = Field(ge=1, description="Events counted, which may exceed the evidence list")
