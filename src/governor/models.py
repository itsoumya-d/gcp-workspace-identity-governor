from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional
from datetime import datetime

class ActionType(str, Enum):
    ONBOARD = "ONBOARD"
    OFFBOARD = "OFFBOARD"
    ROLE_CHANGE = "ROLE_CHANGE"
    SUSPEND = "SUSPEND"

@dataclass
class IdentityEvent:
    event_id: str
    user_email: str
    action: ActionType
    department: str
    target_ou: str
    target_roles: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class IAMBinding:
    project_id: str
    role: str
    member: str
