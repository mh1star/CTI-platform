"""مخطّطات الطلبات والاستجابات لواجهة المنصة."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TextRequest(BaseModel):
    text: str = Field(min_length=1, max_length=2_000_000)
    enrich: bool = True
    provider_mode: str | None = Field(default=None, description="auto|offline|all")


class ReputationRequest(BaseModel):
    value: str = Field(min_length=1)
    type: str = Field(default="IP")


class ReputationResponse(BaseModel):
    value: str
    type: str
    providers: list[dict[str, Any]] = Field(default_factory=list)


class AnalysisSummary(BaseModel):
    total_entities: int
    by_type: dict[str, int] = Field(default_factory=dict)
    risk_level: str
    mitre_techniques: list[dict[str, Any]] = Field(default_factory=list)
    high_confidence: int


class AnalysisResponse(BaseModel):
    request_id: str
    text_len: int
    engine: str
    summary: AnalysisSummary
    entities: list[dict[str, Any]] = Field(default_factory=list)
    graph: dict[str, Any] = Field(default_factory=dict)
    stix: dict[str, Any] | None = None


class EvalResponse(BaseModel):
    model: dict[str, Any]
    dataset: dict[str, Any]
    token_level: dict[str, Any]
    span_level: dict[str, Any]
    pipeline: dict[str, Any] = Field(default_factory=dict)
    n_test_records: int
    n_tokens: int
    training_seconds: float = 0.0
    train_records: int = 0
    trained_at: str