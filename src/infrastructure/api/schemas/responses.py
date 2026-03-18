from pydantic import BaseModel


class MetricBreakdownResponse(BaseModel):
    metric_name: str
    abbreviation: str
    value_name: str
    value_abbreviation: str
    numeric_weight: float
    description: str


class AnalysisResponse(BaseModel):
    vector_string: str
    base_score: float
    severity: str
    impact_score: float
    exploitability_score: float
    metrics: list[MetricBreakdownResponse]
    risk_description: str
    mitigations: list[str]
