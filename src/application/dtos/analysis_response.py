from dataclasses import dataclass


@dataclass(frozen=True)
class MetricBreakdownDTO:
    metric_name: str
    abbreviation: str
    value_name: str
    value_abbreviation: str
    numeric_weight: float
    description: str


@dataclass(frozen=True)
class AnalysisResponseDTO:
    vector_string: str
    base_score: float
    severity: str
    impact_score: float
    exploitability_score: float
    metrics: list[MetricBreakdownDTO]
    risk_description: str
    mitigations: list[str]
