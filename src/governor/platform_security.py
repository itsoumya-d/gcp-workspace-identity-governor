from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set
from datetime import datetime, timezone

class EnvironmentType(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"

class AccessDecision(str, Enum):
    APPROVED = "APPROVED"
    DOWNGRADED = "DOWNGRADED"
    REJECTED = "REJECTED"

@dataclass
class PlatformSecurityPolicy:
    production_developer_default_readonly: bool = True
    require_scoped_secrets: bool = True
    disallow_cluster_admin_workloads: bool = True
    allowed_developer_prod_roles: Set[str] = field(default_factory=lambda: {"roles/viewer", "roles/monitoring.viewer", "roles/logging.viewer"})
    prohibited_developer_prod_roles: Set[str] = field(default_factory=lambda: {"roles/editor", "roles/owner", "roles/resourcemanager.admin", "roles/iam.securityAdmin"})

@dataclass
class AccessEvaluationResult:
    user: str
    environment: EnvironmentType
    decision: AccessDecision
    assigned_roles: List[str]
    remediated_roles: List[str]
    rationale: str

@dataclass
class SecretBindingAudit:
    service_account: str
    secret_path: str
    role: str
    is_compliant: bool
    remediation_note: Optional[str] = None

@dataclass
class WorkloadRBACValidation:
    cluster: str
    namespace: str
    ksa_name: str
    gsa_email: str
    is_least_privilege: bool
    flagged_permissions: List[str]
    remediated_binding: str

class PlatformSecurityReconciler:
    def __init__(self, policy: Optional[PlatformSecurityPolicy] = None):
        self.policy = policy or PlatformSecurityPolicy()
        self.audit_log: List[Dict[str, any]] = []

    def reconcile_developer_access(
        self,
        user_email: str,
        env: EnvironmentType,
        requested_roles: List[str],
        break_glass_approved: bool = False
    ) -> AccessEvaluationResult:
        if env != EnvironmentType.PRODUCTION or break_glass_approved:
            res = AccessEvaluationResult(
                user=user_email,
                environment=env,
                decision=AccessDecision.APPROVED,
                assigned_roles=requested_roles,
                remediated_roles=[],
                rationale="Approved under standard development or verified break-glass protocol"
            )
            self._log_audit("DEV_ACCESS_APPROVED", user_email, requested_roles)
            return res

        assigned = []
        remediated = []
        for role in requested_roles:
            if role in self.policy.prohibited_developer_prod_roles or (
                self.policy.production_developer_default_readonly and role not in self.policy.allowed_developer_prod_roles
            ):
                remediated.append(role)
            else:
                assigned.append(role)

        if not assigned:
            # Fallback to read-only default
            assigned.append("roles/viewer")

        decision = AccessDecision.DOWNGRADED if remediated else AccessDecision.APPROVED
        rationale = (
            f"Production access is read-only by default for developers; prohibited roles {remediated} downgraded to least-privilege"
            if remediated
            else "Production read-only access verified compliant"
        )

        res = AccessEvaluationResult(
            user=user_email,
            environment=env,
            decision=decision,
            assigned_roles=assigned,
            remediated_roles=remediated,
            rationale=rationale
        )
        self._log_audit("DEV_ACCESS_DOWNGRADED" if remediated else "DEV_ACCESS_COMPLIANT", user_email, assigned, remediated)
        return res

    def audit_secret_access(
        self,
        service_account: str,
        secret_path: str,
        role: str
    ) -> SecretBindingAudit:
        # Applications must only receive least-privilege secretAccessor on specific resource paths
        is_admin_role = "admin" in role.lower() or "secretmanager.admin" in role.lower()
        is_wildcard = secret_path == "*" or secret_path.endswith("/*")

        if is_admin_role or (is_wildcard and self.policy.require_scoped_secrets):
            audit = SecretBindingAudit(
                service_account=service_account,
                secret_path=secret_path,
                role=role,
                is_compliant=False,
                remediation_note="Microservices must only get scoped secretAccessor permissions on exact secret resource paths"
            )
        else:
            audit = SecretBindingAudit(
                service_account=service_account,
                secret_path=secret_path,
                role=role,
                is_compliant=True,
                remediation_note="Scoped secret binding compliant"
            )

        self._log_audit("SECRET_ACCESS_AUDITED", service_account, [role], is_compliant=audit.is_compliant)
        return audit

    def validate_workload_identity_rbac(
        self,
        cluster: str,
        namespace: str,
        ksa_name: str,
        gsa_email: str,
        k8s_roles: List[str]
    ) -> WorkloadRBACValidation:
        flagged = []
        for r in k8s_roles:
            if "cluster-admin" in r.lower() or "*" in r:
                flagged.append(r)

        is_least_priv = len(flagged) == 0 or not self.policy.disallow_cluster_admin_workloads
        remediated = f"RoleBinding:{namespace}:{ksa_name}-least-privilege" if flagged else "unchanged"

        val = WorkloadRBACValidation(
            cluster=cluster,
            namespace=namespace,
            ksa_name=ksa_name,
            gsa_email=gsa_email,
            is_least_privilege=is_least_priv,
            flagged_permissions=flagged,
            remediated_binding=remediated
        )
        self._log_audit("WORKLOAD_IDENTITY_RBAC_CHECK", gsa_email, k8s_roles, is_compliant=is_least_priv)
        return val

    def _log_audit(self, event_type: str, target: str, roles: List[str], remediated: Optional[List[str]] = None, is_compliant: bool = True):
        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "target": target,
            "roles": roles,
            "remediated": remediated or [],
            "compliant": is_compliant
        })
