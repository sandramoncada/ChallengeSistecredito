from fastapi import APIRouter, Depends, Query

from src.application.use_cases.analyze_vector import AnalyzeVectorUseCase
from src.infrastructure.api.dependencies import get_analyze_use_case
from src.infrastructure.api.schemas.requests import AnalyzeRequest
from src.infrastructure.api.schemas.responses import AnalysisResponse

router = APIRouter(prefix="/api/v1", tags=["CVSS Analysis"])


@router.post("/analyze", response_model=AnalysisResponse)
def analyze_vector_post(
    request: AnalyzeRequest,
    use_case: AnalyzeVectorUseCase = Depends(get_analyze_use_case),
) -> AnalysisResponse:
    result = use_case.execute(request.vector)
    return AnalysisResponse(
        vector_string=result.vector_string,
        base_score=result.base_score,
        severity=result.severity,
        impact_score=result.impact_score,
        exploitability_score=result.exploitability_score,
        metrics=[m.__dict__ for m in result.metrics],  # type: ignore[arg-type]
        risk_description=result.risk_description,
        mitigations=result.mitigations,
    )


@router.get("/analyze", response_model=AnalysisResponse)
def analyze_vector_get(
    vector: str = Query(..., description="CVSS v3.1 vector string"),
    use_case: AnalyzeVectorUseCase = Depends(get_analyze_use_case),
) -> AnalysisResponse:
    result = use_case.execute(vector)
    return AnalysisResponse(
        vector_string=result.vector_string,
        base_score=result.base_score,
        severity=result.severity,
        impact_score=result.impact_score,
        exploitability_score=result.exploitability_score,
        metrics=[m.__dict__ for m in result.metrics],  # type: ignore[arg-type]
        risk_description=result.risk_description,
        mitigations=result.mitigations,
    )
