import pytest
from src.governor.platform_security import (
    PlatformSecurityPolicy,
    PlatformSecurityReconciler,
    EnvironmentType,
    AccessDecision,
)

def test_production_developer_read_only_default_enforcement():
    reconciler = PlatformSecurityReconciler()
    res = reconciler.reconcile_developer_access(
        user_email="engineer@corp.internal",
        env=EnvironmentType.PRODUCTION,
        requested_roles=["roles/editor", "roles/resourcemanager.admin"]
    )
    assert res.decision == AccessDecision.DOWNGRADED
    assert "roles/viewer" in res.assigned_roles
    assert "roles/editor" in res.remediated_roles
    assert "roles/resourcemanager.admin" in res.remediated_roles
    assert "read-only by default" in res.rationale

def test_developer_break_glass_approval():
    reconciler = PlatformSecurityReconciler()
    res = reconciler.reconcile_developer_access(
        user_email="oncall@corp.internal",
        env=EnvironmentType.PRODUCTION,
        requested_roles=["roles/editor"],
        break_glass_approved=True
    )
    assert res.decision == AccessDecision.APPROVED
    assert "roles/editor" in res.assigned_roles
    assert len(res.remediated_roles) == 0

def test_scoped_secrets_audit():
    reconciler = PlatformSecurityReconciler()
    
    # Non-compliant wildcard admin
    audit_bad = reconciler.audit_secret_access(
        service_account="catalog-service@proj.iam.gserviceaccount.com",
        secret_path="projects/proj/secrets/*",
        role="roles/secretmanager.admin"
    )
    assert audit_bad.is_compliant is False
    assert "must only get scoped secretAccessor" in audit_bad.remediation_note

    # Compliant exact path
    audit_ok = reconciler.audit_secret_access(
        service_account="catalog-service@proj.iam.gserviceaccount.com",
        secret_path="projects/proj/secrets/db-credentials/versions/latest",
        role="roles/secretmanager.secretAccessor"
    )
    assert audit_ok.is_compliant is True

def test_k8s_workload_identity_rbac_validation():
    reconciler = PlatformSecurityReconciler()
    
    # Overprivileged cluster-admin binding
    val = reconciler.validate_workload_identity_rbac(
        cluster="prod-core-cluster",
        namespace="workshop",
        ksa_name="workshop-service-sa",
        gsa_email="workshop-app@proj.iam.gserviceaccount.com",
        k8s_roles=["ClusterRole/cluster-admin"]
    )
    assert val.is_least_privilege is False
    assert "ClusterRole/cluster-admin" in val.flagged_permissions
    assert val.remediated_binding == "RoleBinding:workshop:workshop-service-sa-least-privilege"

    # Compliant namespace scoped role
    val_ok = reconciler.validate_workload_identity_rbac(
        cluster="prod-core-cluster",
        namespace="workshop",
        ksa_name="workshop-service-sa",
        gsa_email="workshop-app@proj.iam.gserviceaccount.com",
        k8s_roles=["Role/configmap-reader"]
    )
    assert val_ok.is_least_privilege is True
    assert len(val_ok.flagged_permissions) == 0
