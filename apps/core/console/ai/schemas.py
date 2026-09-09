"""Structured-output contracts for every LLM call (pure module, no DB).

Each pydantic model doubles as the ``response_format`` json_schema sent to
Cloudflare Workers AI and as the validator for what comes back. The agent's
action space is a closed union — anything outside it fails validation and is
handled by the client's single corrective retry.
"""

from typing import Literal, Union

from pydantic import BaseModel, Field


# --- Triage ---------------------------------------------------------------

class TriageItemOut(BaseModel):
    finding_id: int
    priority: Literal["fix_now", "plan", "monitor", "likely_noise"]
    rationale: str = Field(max_length=1000)


class TriageOut(BaseModel):
    overview: str = Field(max_length=3000)
    items: list[TriageItemOut] = Field(max_length=50)


# --- Summaries ------------------------------------------------------------

class SummaryOut(BaseModel):
    text: str = Field(max_length=2000)


# --- Orchestration (closed action space) ----------------------------------

class RunSubscan(BaseModel):
    action: Literal["run_subscan"]
    tools: list[str] = Field(max_length=10)
    reason: str = Field(max_length=500)


class FlagFinding(BaseModel):
    action: Literal["flag_finding"]
    finding_id: int
    note: str = Field(max_length=500)


class Done(BaseModel):
    action: Literal["done"]
    summary: str = Field(max_length=1000)


class AgentDecision(BaseModel):
    actions: list[Union[RunSubscan, FlagFinding, Done]] = Field(max_length=5)


def json_schema_for(model_cls: type[BaseModel]) -> dict:
    """JSON schema dict for Workers AI's response_format json_schema mode."""
    return model_cls.model_json_schema()
