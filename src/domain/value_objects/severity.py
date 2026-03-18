from enum import Enum


class Severity(Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score == 0.0:
            return cls.NONE
        if score <= 3.9:
            return cls.LOW
        if score <= 6.9:
            return cls.MEDIUM
        if score <= 8.9:
            return cls.HIGH
        return cls.CRITICAL
