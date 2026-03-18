from enum import Enum


class AttackVector(Enum):
    NETWORK = ("N", 0.85)
    ADJACENT_NETWORK = ("A", 0.62)
    LOCAL = ("L", 0.55)
    PHYSICAL = ("P", 0.20)

    def __init__(self, abbreviation: str, weight: float) -> None:
        self.abbreviation = abbreviation
        self.weight = weight

    @classmethod
    def from_abbreviation(cls, abbrev: str) -> "AttackVector":
        for member in cls:
            if member.abbreviation == abbrev:
                return member
        raise ValueError(f"Invalid Attack Vector abbreviation: '{abbrev}'")


class AttackComplexity(Enum):
    LOW = ("L", 0.77)
    HIGH = ("H", 0.44)

    def __init__(self, abbreviation: str, weight: float) -> None:
        self.abbreviation = abbreviation
        self.weight = weight

    @classmethod
    def from_abbreviation(cls, abbrev: str) -> "AttackComplexity":
        for member in cls:
            if member.abbreviation == abbrev:
                return member
        raise ValueError(f"Invalid Attack Complexity abbreviation: '{abbrev}'")


class PrivilegesRequired(Enum):
    NONE = ("N", 0.85, 0.85)
    LOW = ("L", 0.62, 0.68)
    HIGH = ("H", 0.27, 0.50)

    def __init__(self, abbreviation: str, weight_unchanged: float, weight_changed: float) -> None:
        self.abbreviation = abbreviation
        self.weight_unchanged = weight_unchanged
        self.weight_changed = weight_changed

    def get_weight(self, scope_changed: bool) -> float:
        return self.weight_changed if scope_changed else self.weight_unchanged

    @classmethod
    def from_abbreviation(cls, abbrev: str) -> "PrivilegesRequired":
        for member in cls:
            if member.abbreviation == abbrev:
                return member
        raise ValueError(f"Invalid Privileges Required abbreviation: '{abbrev}'")


class UserInteraction(Enum):
    NONE = ("N", 0.85)
    REQUIRED = ("R", 0.62)

    def __init__(self, abbreviation: str, weight: float) -> None:
        self.abbreviation = abbreviation
        self.weight = weight

    @classmethod
    def from_abbreviation(cls, abbrev: str) -> "UserInteraction":
        for member in cls:
            if member.abbreviation == abbrev:
                return member
        raise ValueError(f"Invalid User Interaction abbreviation: '{abbrev}'")


class Scope(Enum):
    UNCHANGED = ("U",)
    CHANGED = ("C",)

    def __init__(self, abbreviation: str) -> None:
        self.abbreviation = abbreviation

    @property
    def is_changed(self) -> bool:
        return self == Scope.CHANGED

    @classmethod
    def from_abbreviation(cls, abbrev: str) -> "Scope":
        for member in cls:
            if member.abbreviation == abbrev:
                return member
        raise ValueError(f"Invalid Scope abbreviation: '{abbrev}'")


class Impact(Enum):
    """Shared enum for Confidentiality, Integrity, and Availability impact metrics."""
    HIGH = ("H", 0.56)
    LOW = ("L", 0.22)
    NONE = ("N", 0.0)

    def __init__(self, abbreviation: str, weight: float) -> None:
        self.abbreviation = abbreviation
        self.weight = weight

    @classmethod
    def from_abbreviation(cls, abbrev: str) -> "Impact":
        for member in cls:
            if member.abbreviation == abbrev:
                return member
        raise ValueError(f"Invalid Impact abbreviation: '{abbrev}'")


METRIC_CLASSES = {
    "AV": AttackVector,
    "AC": AttackComplexity,
    "PR": PrivilegesRequired,
    "UI": UserInteraction,
    "S": Scope,
    "C": Impact,
    "I": Impact,
    "A": Impact,
}

REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
