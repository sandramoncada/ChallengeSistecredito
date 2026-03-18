from dataclasses import dataclass

from src.domain.exceptions import InvalidMetricError, InvalidMetricValueError, InvalidVectorError
from src.domain.value_objects.metrics import (
    METRIC_CLASSES,
    REQUIRED_METRICS,
    AttackComplexity,
    AttackVector,
    Impact,
    PrivilegesRequired,
    Scope,
    UserInteraction,
)

VECTOR_PREFIX = "CVSS:3.1/"


@dataclass(frozen=True)
class CvssVector:
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: Impact
    integrity: Impact
    availability: Impact

    @classmethod
    def from_vector_string(cls, vector: str) -> "CvssVector":
        if not vector.startswith(VECTOR_PREFIX):
            raise InvalidVectorError(
                f"Vector must start with '{VECTOR_PREFIX}'. Got: '{vector}'"
            )

        metrics_str = vector[len(VECTOR_PREFIX):]
        parts = metrics_str.split("/")

        if len(parts) != len(REQUIRED_METRICS):
            raise InvalidVectorError(
                f"Expected {len(REQUIRED_METRICS)} metrics, got {len(parts)}"
            )

        parsed: dict[str, object] = {}

        for part in parts:
            if ":" not in part:
                raise InvalidVectorError(f"Invalid metric format: '{part}'")

            key, value = part.split(":", 1)

            if key not in METRIC_CLASSES:
                raise InvalidMetricError(key)

            if key in parsed:
                raise InvalidVectorError(f"Duplicate metric: '{key}'")

            metric_class = METRIC_CLASSES[key]
            try:
                parsed[key] = metric_class.from_abbreviation(value)
            except ValueError:
                raise InvalidMetricValueError(key, value)

        missing = set(REQUIRED_METRICS) - set(parsed.keys())
        if missing:
            raise InvalidVectorError(f"Missing required metrics: {', '.join(sorted(missing))}")

        return cls(
            attack_vector=parsed["AV"],  # type: ignore[arg-type]
            attack_complexity=parsed["AC"],  # type: ignore[arg-type]
            privileges_required=parsed["PR"],  # type: ignore[arg-type]
            user_interaction=parsed["UI"],  # type: ignore[arg-type]
            scope=parsed["S"],  # type: ignore[arg-type]
            confidentiality=parsed["C"],  # type: ignore[arg-type]
            integrity=parsed["I"],  # type: ignore[arg-type]
            availability=parsed["A"],  # type: ignore[arg-type]
        )
