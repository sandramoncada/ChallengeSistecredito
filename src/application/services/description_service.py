from src.domain.entities.cvss_result import MetricDetail
from src.domain.entities.cvss_vector import CvssVector
from src.domain.value_objects.metrics import (
    AttackComplexity,
    AttackVector,
    Impact,
    PrivilegesRequired,
    Scope,
    UserInteraction,
)
from src.domain.value_objects.severity import Severity

_METRIC_NAMES = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality Impact",
    "I": "Integrity Impact",
    "A": "Availability Impact",
}

_VALUE_NAMES: dict[str, dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent Network", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}

_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "AV": {
        "N": "La vulnerabilidad es explotable a través de la red sin requerir acceso físico o local. Esto incrementa significativamente el número de potenciales atacantes.",
        "A": "La vulnerabilidad requiere acceso a la red adyacente (mismo segmento de red). El atacante debe estar en la misma red lógica o física.",
        "L": "La vulnerabilidad requiere acceso local al sistema. El atacante necesita acceso previo al sistema objetivo o interacción con un usuario local.",
        "P": "La vulnerabilidad requiere acceso físico al dispositivo. El atacante debe poder interactuar físicamente con el componente vulnerable.",
    },
    "AC": {
        "L": "La explotación no requiere condiciones especiales. El atacante puede explotar la vulnerabilidad de forma fiable en la mayoría de los intentos.",
        "H": "La explotación requiere condiciones específicas fuera del control del atacante, como una configuración particular o una condición de carrera.",
    },
    "PR": {
        "N": "El atacante no necesita autenticación ni privilegios previos para explotar la vulnerabilidad.",
        "L": "El atacante necesita privilegios básicos de usuario (cuenta con permisos limitados) para explotar la vulnerabilidad.",
        "H": "El atacante necesita privilegios administrativos o de alto nivel para explotar la vulnerabilidad.",
    },
    "UI": {
        "N": "La explotación no requiere ninguna interacción por parte del usuario. El ataque puede ejecutarse de forma completamente autónoma.",
        "R": "La explotación requiere que un usuario realice alguna acción, como hacer clic en un enlace, abrir un archivo o visitar una página web maliciosa.",
    },
    "S": {
        "U": "El impacto se limita al componente vulnerable. No afecta recursos más allá de su alcance de autorización.",
        "C": "El impacto se extiende más allá del componente vulnerable, afectando recursos en otros componentes o sistemas con diferente contexto de seguridad.",
    },
    "C": {
        "H": "Se produce una pérdida total de confidencialidad. Toda la información del componente afectado puede ser divulgada al atacante.",
        "L": "Se produce una pérdida parcial de confidencialidad. El atacante obtiene acceso a información restringida, pero no tiene control total sobre los datos expuestos.",
        "N": "No hay impacto en la confidencialidad. No se divulga información sensible.",
    },
    "I": {
        "H": "Se produce una pérdida total de integridad. El atacante puede modificar cualquier dato o archivo del componente afectado sin restricciones.",
        "L": "Se produce una pérdida parcial de integridad. El atacante puede modificar algunos datos, pero no tiene control total sobre las modificaciones.",
        "N": "No hay impacto en la integridad. No se pueden modificar datos del sistema.",
    },
    "A": {
        "H": "Se produce una pérdida total de disponibilidad. El atacante puede hacer que el recurso afectado quede completamente inaccesible o inoperativo.",
        "L": "Se produce una pérdida parcial de disponibilidad. El atacante puede degradar el rendimiento o interrumpir parcialmente la disponibilidad del recurso.",
        "N": "No hay impacto en la disponibilidad. El sistema permanece operativo.",
    },
}


class DescriptionService:
    def get_metric_details(self, vector: CvssVector) -> list[MetricDetail]:
        metrics_data = [
            ("AV", vector.attack_vector),
            ("AC", vector.attack_complexity),
            ("PR", vector.privileges_required),
            ("UI", vector.user_interaction),
            ("S", vector.scope),
            ("C", vector.confidentiality),
            ("I", vector.integrity),
            ("A", vector.availability),
        ]

        details: list[MetricDetail] = []
        for abbrev, metric_value in metrics_data:
            weight = 0.0
            if abbrev == "S":
                weight = 0.0
            elif abbrev == "PR":
                pr = metric_value
                weight = pr.get_weight(vector.scope.is_changed)  # type: ignore[union-attr]
            elif hasattr(metric_value, "weight"):
                weight = metric_value.weight  # type: ignore[union-attr]

            details.append(
                MetricDetail(
                    metric_name=_METRIC_NAMES[abbrev],
                    abbreviation=abbrev,
                    value_name=_VALUE_NAMES[abbrev][metric_value.abbreviation],
                    value_abbreviation=metric_value.abbreviation,
                    numeric_weight=weight,
                    description=_DESCRIPTIONS[abbrev][metric_value.abbreviation],
                )
            )

        return details

    def get_risk_description(self, vector: CvssVector, severity: Severity, base_score: float) -> str:
        parts: list[str] = []

        severity_text = {
            Severity.CRITICAL: "Vulnerabilidad de severidad CRITICA",
            Severity.HIGH: "Vulnerabilidad de severidad ALTA",
            Severity.MEDIUM: "Vulnerabilidad de severidad MEDIA",
            Severity.LOW: "Vulnerabilidad de severidad BAJA",
            Severity.NONE: "Vulnerabilidad sin impacto significativo",
        }
        parts.append(f"{severity_text[severity]} (puntuacion base: {base_score}).")

        if vector.attack_vector == AttackVector.NETWORK:
            parts.append("Es explotable de forma remota a traves de la red, lo que amplifica enormemente el riesgo.")
        elif vector.attack_vector == AttackVector.ADJACENT_NETWORK:
            parts.append("Requiere acceso a la red adyacente para su explotacion.")
        elif vector.attack_vector == AttackVector.LOCAL:
            parts.append("Requiere acceso local al sistema para su explotacion.")
        else:
            parts.append("Requiere acceso fisico al dispositivo para su explotacion.")

        if vector.attack_complexity == AttackComplexity.LOW:
            parts.append("La complejidad de ataque es baja, permitiendo explotacion consistente.")
        else:
            parts.append("La complejidad de ataque es alta, requiriendo condiciones especificas.")

        if vector.privileges_required == PrivilegesRequired.NONE:
            parts.append("No requiere autenticacion previa.")
        elif vector.privileges_required == PrivilegesRequired.LOW:
            parts.append("Requiere privilegios basicos de usuario.")
        else:
            parts.append("Requiere privilegios administrativos elevados.")

        if vector.user_interaction == UserInteraction.NONE:
            parts.append("No requiere interaccion del usuario para su explotacion.")

        if vector.scope.is_changed:
            parts.append("El impacto trasciende el componente vulnerable, afectando otros sistemas.")

        impact_areas: list[str] = []
        if vector.confidentiality == Impact.HIGH:
            impact_areas.append("confidencialidad")
        if vector.integrity == Impact.HIGH:
            impact_areas.append("integridad")
        if vector.availability == Impact.HIGH:
            impact_areas.append("disponibilidad")

        if impact_areas:
            parts.append(f"Compromete severamente la {', '.join(impact_areas)} del sistema afectado.")

        return " ".join(parts)
