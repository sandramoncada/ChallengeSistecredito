from dataclasses import dataclass

from src.domain.value_objects.severity import Severity


@dataclass(frozen=True)
class ScoreBreakdown:
    base_score: float
    impact_sub_score: float
    impact_score: float
    exploitability_score: float


@dataclass(frozen=True)
class MetricDetail:
    metric_name: str
    abbreviation: str
    value_name: str
    value_abbreviation: str
    numeric_weight: float
    description: str


@dataclass(frozen=True)
class CvssResult:
    vector_string: str
    base_score: float
    severity: Severity
    impact_score: float
    exploitability_score: float
    metrics: list[MetricDetail]
    risk_description: str
    mitigations: list[str]
