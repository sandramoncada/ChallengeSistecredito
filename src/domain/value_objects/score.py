from dataclasses import dataclass


@dataclass(frozen=True)
class Score:
    value: float

    def __post_init__(self) -> None:
        if not (0.0 <= self.value <= 10.0):
            raise ValueError(f"Score must be between 0.0 and 10.0, got {self.value}")
