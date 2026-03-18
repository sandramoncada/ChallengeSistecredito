import math

from src.domain.entities.cvss_result import ScoreBreakdown
from src.domain.entities.cvss_vector import CvssVector


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup function as defined in FIRST specification Appendix A.
    Uses integer arithmetic to avoid floating-point rounding issues.
    """
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def calculate(vector: CvssVector) -> ScoreBreakdown:
    """Calculate CVSS v3.1 base score following the FIRST specification."""
    scope_changed = vector.scope.is_changed

    # Impact Sub-Score (ISS)
    iss = 1.0 - (
        (1.0 - vector.confidentiality.weight)
        * (1.0 - vector.integrity.weight)
        * (1.0 - vector.availability.weight)
    )

    # Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    # Exploitability
    pr_weight = vector.privileges_required.get_weight(scope_changed)
    exploitability = (
        8.22
        * vector.attack_vector.weight
        * vector.attack_complexity.weight
        * pr_weight
        * vector.user_interaction.weight
    )

    # Base Score
    if impact <= 0:
        base_score = 0.0
    elif scope_changed:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base_score = _roundup(min(impact + exploitability, 10.0))

    return ScoreBreakdown(
        base_score=base_score,
        impact_sub_score=round(iss, 1),
        impact_score=round(impact, 1),
        exploitability_score=round(exploitability, 1),
    )
