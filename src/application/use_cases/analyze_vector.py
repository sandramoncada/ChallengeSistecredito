from src.application.dtos.analysis_response import AnalysisResponseDTO, MetricBreakdownDTO
from src.application.services.description_service import DescriptionService
from src.application.services.mitigation_service import MitigationService
from src.domain.entities.cvss_vector import CvssVector
from src.domain.services import cvss_calculator
from src.domain.value_objects.severity import Severity


class AnalyzeVectorUseCase:
    def __init__(
        self,
        description_service: DescriptionService,
        mitigation_service: MitigationService,
    ) -> None:
        self._description_service = description_service
        self._mitigation_service = mitigation_service

    def execute(self, vector_string: str) -> AnalysisResponseDTO:
        vector = CvssVector.from_vector_string(vector_string)
        score_breakdown = cvss_calculator.calculate(vector)
        severity = Severity.from_score(score_breakdown.base_score)

        metric_details = self._description_service.get_metric_details(vector)
        risk_description = self._description_service.get_risk_description(
            vector, severity, score_breakdown.base_score
        )
        mitigations = self._mitigation_service.get_mitigations(vector, severity)

        return AnalysisResponseDTO(
            vector_string=vector_string,
            base_score=score_breakdown.base_score,
            severity=severity.value,
            impact_score=score_breakdown.impact_score,
            exploitability_score=score_breakdown.exploitability_score,
            metrics=[
                MetricBreakdownDTO(
                    metric_name=m.metric_name,
                    abbreviation=m.abbreviation,
                    value_name=m.value_name,
                    value_abbreviation=m.value_abbreviation,
                    numeric_weight=m.numeric_weight,
                    description=m.description,
                )
                for m in metric_details
            ],
            risk_description=risk_description,
            mitigations=mitigations,
        )
