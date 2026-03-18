from src.domain.entities.cvss_vector import CvssVector
from src.domain.value_objects.metrics import (
    AttackComplexity,
    AttackVector,
    Impact,
    PrivilegesRequired,
    UserInteraction,
)
from src.domain.value_objects.severity import Severity


class MitigationService:
    def get_mitigations(self, vector: CvssVector, severity: Severity) -> list[str]:
        mitigations: list[str] = []

        # Attack Vector mitigations
        if vector.attack_vector == AttackVector.NETWORK:
            mitigations.append(
                "Implementar segmentacion de red y reglas de firewall/WAF para restringir el acceso a los servicios expuestos."
            )
            mitigations.append(
                "Aplicar listas de control de acceso (ACL) basadas en IP y limitar la exposicion de puertos y servicios en la red."
            )
        elif vector.attack_vector == AttackVector.ADJACENT_NETWORK:
            mitigations.append(
                "Segmentar la red utilizando VLANs y controlar el trafico entre segmentos con firewalls internos."
            )
        elif vector.attack_vector == AttackVector.LOCAL:
            mitigations.append(
                "Restringir el acceso local al sistema mediante politicas de control de acceso y principio de minimo privilegio."
            )
        elif vector.attack_vector == AttackVector.PHYSICAL:
            mitigations.append(
                "Implementar controles de seguridad fisica: cerraduras, camaras de vigilancia y registro de acceso a equipos."
            )

        # Privileges Required mitigations
        if vector.privileges_required == PrivilegesRequired.NONE:
            mitigations.append(
                "Implementar autenticacion obligatoria en todos los puntos de acceso. Considerar autenticacion multifactor (MFA)."
            )
        elif vector.privileges_required == PrivilegesRequired.LOW:
            mitigations.append(
                "Revisar y restringir los permisos asignados a usuarios con privilegios basicos. Aplicar principio de minimo privilegio."
            )

        # User Interaction mitigations
        if vector.user_interaction == UserInteraction.REQUIRED:
            mitigations.append(
                "Capacitar a los usuarios sobre ingenieria social y phishing. Implementar filtros de contenido y navegacion segura."
            )

        # Attack Complexity mitigations
        if vector.attack_complexity == AttackComplexity.LOW:
            mitigations.append(
                "Priorizar la remediacion inmediata dado que la vulnerabilidad es facilmente explotable sin condiciones especiales."
            )

        # Scope mitigations
        if vector.scope.is_changed:
            mitigations.append(
                "Implementar aislamiento de componentes y sandboxing para limitar la propagacion del impacto a otros sistemas."
            )

        # Confidentiality mitigations
        if vector.confidentiality == Impact.HIGH:
            mitigations.append(
                "Aplicar cifrado de datos en reposo y en transito. Implementar controles de prevencion de perdida de datos (DLP)."
            )
        elif vector.confidentiality == Impact.LOW:
            mitigations.append(
                "Clasificar la informacion expuesta y aplicar controles de acceso basados en la sensibilidad de los datos."
            )

        # Integrity mitigations
        if vector.integrity == Impact.HIGH:
            mitigations.append(
                "Implementar controles de integridad como firmas digitales, checksums y mecanismos de deteccion de alteraciones."
            )
        elif vector.integrity == Impact.LOW:
            mitigations.append(
                "Implementar validacion de entrada y controles de integridad en los datos criticos del sistema."
            )

        # Availability mitigations
        if vector.availability == Impact.HIGH:
            mitigations.append(
                "Implementar redundancia, balanceo de carga y planes de recuperacion ante desastres para garantizar la continuidad del servicio."
            )
        elif vector.availability == Impact.LOW:
            mitigations.append(
                "Monitorear el rendimiento del sistema y establecer alertas tempranas para detectar degradacion del servicio."
            )

        # General severity-based mitigations
        if severity in (Severity.CRITICAL, Severity.HIGH):
            mitigations.append(
                "Aplicar parches de seguridad de forma inmediata. Considerar la implementacion de controles compensatorios mientras se despliega la correccion definitiva."
            )

        return mitigations
