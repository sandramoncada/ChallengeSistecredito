class CvssDomainError(Exception):
    pass


class InvalidVectorError(CvssDomainError):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class InvalidMetricError(CvssDomainError):
    def __init__(self, metric: str) -> None:
        self.metric = metric
        self.message = f"Unknown metric: '{metric}'"
        super().__init__(self.message)


class InvalidMetricValueError(CvssDomainError):
    def __init__(self, metric: str, value: str) -> None:
        self.metric = metric
        self.value = value
        self.message = f"Invalid value '{value}' for metric '{metric}'"
        super().__init__(self.message)
