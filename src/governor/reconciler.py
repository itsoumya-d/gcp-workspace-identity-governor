from typing import List, Dict, Set
from .models import IdentityEvent, ActionType, IAMBinding

class IdentityReconciler:
    def __init__(self):
        # user_email -> ou_path
        self.user_ous: Dict[str, str] = {}
        # project_id -> list of IAMBinding
        self.project_bindings: Dict[str, List[IAMBinding]] = {}
        # user_email -> list of revoked roles
        self.revocation_log: List[Dict[str, str]] = []

    def process_event(self, event: IdentityEvent) -> Dict[str, any]:
        email = event.user_email
        member_tag = f"user:{email}"

        if event.action == ActionType.ONBOARD:
            self.user_ous[email] = event.target_ou
            for role_entry in event.target_roles:
                proj, role = role_entry.split(":")
                self.project_bindings.setdefault(proj, []).append(
                    IAMBinding(project_id=proj, role=role, member=member_tag)
                )
            return {"status": "SUCCESS", "ou": event.target_ou, "action": "ONBOARDED"}

        elif event.action == ActionType.OFFBOARD:
            self.user_ous[email] = "/Suspended"
            revoked_count = 0
            for proj, bindings in self.project_bindings.items():
                kept = []
                for b in bindings:
                    if b.member == member_tag:
                        self.revocation_log.append({
                            "user": email,
                            "project": proj,
                            "role": b.role,
                            "action": "REVOKED"
                        })
                        revoked_count += 1
                    else:
                        kept.append(b)
                self.project_bindings[proj] = kept
            return {"status": "SUCCESS", "revoked_roles": revoked_count, "action": "OFFBOARDED"}

        elif event.action == ActionType.ROLE_CHANGE:
            self.user_ous[email] = event.target_ou
            # Parse desired bindings
            desired_set: Set[str] = set(event.target_roles)
            
            # Clean up existing bindings
            for proj in list(self.project_bindings.keys()):
                kept = []
                for b in self.project_bindings[proj]:
                    pair = f"{proj}:{b.role}"
                    if b.member == member_tag:
                        if pair in desired_set:
                            kept.append(b)
                            desired_set.remove(pair)
                        else:
                            self.revocation_log.append({"user": email, "project": proj, "role": b.role, "action": "ROLE_PRUNED"})
                    else:
                        kept.append(b)
                self.project_bindings[proj] = kept

            # Add newly required bindings
            for pair in desired_set:
                proj, role = pair.split(":")
                self.project_bindings.setdefault(proj, []).append(
                    IAMBinding(project_id=proj, role=role, member=member_tag)
                )
            return {"status": "SUCCESS", "ou": event.target_ou, "action": "RECONCILED"}

        return {"status": "NOOP"}

    def detect_drift(self, expected_bindings: List[IAMBinding]) -> List[IAMBinding]:
        """Detects unauthorized IAM bindings present in cloud projects."""
        expected_set = {(b.project_id, b.role, b.member) for b in expected_bindings}
        drifts = []
        for proj, bindings in self.project_bindings.items():
            for b in bindings:
                if (b.project_id, b.role, b.member) not in expected_set:
                    drifts.append(b)
        return drifts
