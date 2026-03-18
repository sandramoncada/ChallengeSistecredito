from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisRequest:
    vector: str
