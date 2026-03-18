from functools import lru_cache

from src.application.services.description_service import DescriptionService
from src.application.services.mitigation_service import MitigationService
from src.application.use_cases.analyze_vector import AnalyzeVectorUseCase


@lru_cache(maxsize=1)
def get_analyze_use_case() -> AnalyzeVectorUseCase:
    return AnalyzeVectorUseCase(
        description_service=DescriptionService(),
        mitigation_service=MitigationService(),
    )
