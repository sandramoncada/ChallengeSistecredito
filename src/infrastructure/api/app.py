from fastapi import FastAPI

from src.infrastructure.api.middleware.error_handler import register_error_handlers
from src.infrastructure.api.routes import cvss, health


def create_app() -> FastAPI:
    app = FastAPI(
        title="CVSS v3.1 Analyzer API",
        description="API para analizar vectores CVSS v3.1 y obtener el score, severidad, desglose de metricas, descripcion de riesgos y recomendaciones de mitigacion.",
        version="1.0.0",
    )

    register_error_handlers(app)

    app.include_router(health.router)
    app.include_router(cvss.router)

    return app
