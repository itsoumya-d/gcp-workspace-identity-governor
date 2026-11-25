from src.governor.models import IdentityEvent, ActionType

def test_models_scaffold():
    event = IdentityEvent(
        event_id="evt_01",
        user_email="alex@corp.internal",
        action=ActionType.ONBOARD,
        department="Engineering",
        target_ou="/Engineering/Platform"
    )
    assert event.user_email == "alex@corp.internal"
    assert event.action == ActionType.ONBOARD
