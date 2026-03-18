from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.domain.exceptions import (
    CvssDomainError,
    InvalidMetricError,
    InvalidMetricValueError,
    InvalidVectorError,
)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(InvalidVectorError)
    async def invalid_vector_handler(_request: Request, exc: InvalidVectorError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_vector",
                "message": exc.message,
            },
        )

    @app.exception_handler(InvalidMetricError)
    async def invalid_metric_handler(_request: Request, exc: InvalidMetricError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_metric",
                "message": exc.message,
                "metric": exc.metric,
            },
        )

    @app.exception_handler(InvalidMetricValueError)
    async def invalid_metric_value_handler(
        _request: Request, exc: InvalidMetricValueError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_metric_value",
                "message": exc.message,
                "metric": exc.metric,
                "value": exc.value,
            },
        )

    @app.exception_handler(CvssDomainError)
    async def domain_error_handler(_request: Request, exc: CvssDomainError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "domain_error",
                "message": str(exc),
            },
        )
