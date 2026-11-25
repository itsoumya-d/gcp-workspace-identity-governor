import pytest
from src.governor.models import IdentityEvent, ActionType, IAMBinding
from src.governor.reconciler import IdentityReconciler

def test_user_onboarding():
    rec = IdentityReconciler()
    evt = IdentityEvent(
        event_id="e-1",
        user_email="dev1@corp.internal",
        action=ActionType.ONBOARD,
        department="Engineering",
        target_ou="/Engineering/Backend",
        target_roles=["proj-prod:roles/viewer", "proj-dev:roles/editor"]
    )
    res = rec.process_event(evt)
    assert res["status"] == "SUCCESS"
    assert rec.user_ous["dev1@corp.internal"] == "/Engineering/Backend"
    assert len(rec.project_bindings["proj-prod"]) == 1
    assert rec.project_bindings["proj-prod"][0].role == "roles/viewer"

def test_user_offboarding_full_revocation():
    rec = IdentityReconciler()
    onboard = IdentityEvent(
        event_id="e-2",
        user_email="contractor@corp.internal",
        action=ActionType.ONBOARD,
        department="SecOps",
        target_ou="/SecOps",
        target_roles=["proj-sec:roles/securityAdmin", "proj-audit:roles/viewer"]
    )
    rec.process_event(onboard)
    assert len(rec.project_bindings["proj-sec"]) == 1

    offboard = IdentityEvent(
        event_id="e-3",
        user_email="contractor@corp.internal",
        action=ActionType.OFFBOARD,
        department="SecOps",
        target_ou="/Suspended"
    )
    res = rec.process_event(offboard)
    assert res["status"] == "SUCCESS"
    assert res["revoked_roles"] == 2
    assert rec.user_ous["contractor@corp.internal"] == "/Suspended"
    assert len(rec.project_bindings["proj-sec"]) == 0
    assert len(rec.project_bindings["proj-audit"]) == 0
    assert len(rec.revocation_log) == 2

def test_role_change_reconciliation():
    rec = IdentityReconciler()
    rec.process_event(IdentityEvent(
        event_id="e-4",
        user_email="eng@corp.internal",
        action=ActionType.ONBOARD,
        department="Core",
        target_ou="/Core",
        target_roles=["proj-core:roles/viewer", "proj-core:roles/editor"]
    ))
    # Role change: promote to admin, drop editor
    rec.process_event(IdentityEvent(
        event_id="e-5",
        user_email="eng@corp.internal",
        action=ActionType.ROLE_CHANGE,
        department="Core",
        target_ou="/Core/Lead",
        target_roles=["proj-core:roles/viewer", "proj-core:roles/admin"]
    ))
    roles = [b.role for b in rec.project_bindings["proj-core"]]
    assert "roles/admin" in roles
    assert "roles/viewer" in roles
    assert "roles/editor" not in roles

def test_drift_detection():
    rec = IdentityReconciler()
    rec.project_bindings["proj-prod"] = [
        IAMBinding(project_id="proj-prod", role="roles/owner", member="user:rogue@corp.internal")
    ]
    expected = []
    drifts = rec.detect_drift(expected)
    assert len(drifts) == 1
    assert drifts[0].member == "user:rogue@corp.internal"
