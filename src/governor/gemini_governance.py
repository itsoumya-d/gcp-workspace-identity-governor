from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set
from datetime import datetime, timezone
import re

class LicenseTier(str, Enum):
    GEMINI_ENTERPRISE = "GEMINI_ENTERPRISE"
    GEMINI_BUSINESS = "GEMINI_BUSINESS"
    UNLICENSED = "UNLICENSED"

class IntegrationConnectorType(str, Enum):
    GOOGLE_DRIVE = "GOOGLE_DRIVE"
    SLACK = "SLACK"
    JIRA = "JIRA"
    SALESFORCE = "SALESFORCE"
    SHAREPOINT = "SHAREPOINT"
    GENERIC_REST = "GENERIC_REST"

class DataSensitivityClass(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

@dataclass
class LicenseAllocation:
    user_email: str
    tier: LicenseTier
    assigned_ou: str
    allocated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

@dataclass
class EnterpriseIntegrationConfig:
    connector_id: str
    connector_type: IntegrationConnectorType
    service_account_email: str
    target_data_source: str
    sensitivity: DataSensitivityClass
    cmek_key_resource: Optional[str] = None
    allowed_read_scopes: List[str] = field(default_factory=list)
    compliance_signoff_id: Optional[str] = None

@dataclass
class LicenseAuditResult:
    user_email: str
    status: str
    tier: LicenseTier
    is_compliant: bool
    action_taken: str
    message: str

@dataclass
class IntegrationAuditResult:
    connector_id: str
    connector_type: IntegrationConnectorType
    is_compliant: bool
    action: str
    remediated_scopes: List[str]
    flagged_issues: List[str]

class GeminiEnterpriseGovernor:
    """Administers Google Cloud and Workspace Gemini Enterprise licensing and data integration governance."""
    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    SA_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com$")
    PROHIBITED_SCOPES: Set[str] = {"*", "roles/owner", "roles/editor", "https://www.googleapis.com/auth/cloud-platform"}

    def __init__(self, max_enterprise_licenses: int = 100, require_cmek_for_confidential: bool = True, disallow_restricted_indexing: bool = True):
        if max_enterprise_licenses <= 0:
            raise ValueError(f"max_enterprise_licenses must be positive, got {max_enterprise_licenses}")
        self.max_enterprise_licenses = max_enterprise_licenses
        self.require_cmek_for_confidential = require_cmek_for_confidential
        self.disallow_restricted_indexing = disallow_restricted_indexing
        self.allocations: Dict[str, LicenseAllocation] = {}
        self.connectors: Dict[str, EnterpriseIntegrationConfig] = {}
        self.audit_log: List[Dict[str, any]] = []

    def allocate_license(self, user_email: str, tier: LicenseTier, ou_path: str = "/Employees") -> LicenseAuditResult:
        if not user_email or not user_email.strip():
            raise ValueError("user_email cannot be empty")
        user_email = user_email.strip().lower()
        if not self.EMAIL_PATTERN.match(user_email):
            raise ValueError(f"Malformed user email: {user_email}")
        if not ou_path or not ou_path.startswith("/"):
            raise ValueError(f"Malformed OU path: {ou_path} (must start with '/')")

        if ou_path.startswith("/Suspended"):
            if user_email in self.allocations:
                self.allocations[user_email].is_active = False
            res = LicenseAuditResult(user_email, "DENIED", LicenseTier.UNLICENSED, False, "REVOKED_SUSPENDED_OU", "Suspended OU ineligible")
            self._log_audit("LICENSE_DENIED_SUSPENDED", user_email, res.action_taken)
            return res

        if tier == LicenseTier.UNLICENSED:
            if user_email in self.allocations:
                self.allocations[user_email].is_active = False
                self.allocations[user_email].tier = LicenseTier.UNLICENSED
            res = LicenseAuditResult(user_email, "SUCCESS", LicenseTier.UNLICENSED, True, "UNLICENSED", "License de-allocated")
            self._log_audit("LICENSE_DEALLOCATED", user_email, res.action_taken)
            return res

        if tier == LicenseTier.GEMINI_ENTERPRISE:
            active_ent = sum(1 for a in self.allocations.values() if a.is_active and a.tier == LicenseTier.GEMINI_ENTERPRISE and a.user_email != user_email)
            if active_ent >= self.max_enterprise_licenses:
                res = LicenseAuditResult(user_email, "REJECTED", tier, False, "CAPACITY_EXCEEDED", f"Quota exhausted ({self.max_enterprise_licenses})")
                self._log_audit("LICENSE_QUOTA_EXHAUSTED", user_email, res.action_taken)
                return res

        self.allocations[user_email] = LicenseAllocation(user_email, tier, ou_path, is_active=True)
        res = LicenseAuditResult(user_email, "SUCCESS", tier, True, "ALLOCATED", f"Allocated {tier.value} to {user_email}")
        self._log_audit("LICENSE_ALLOCATED", user_email, res.action_taken)
        return res

    def audit_integration_connector(self, config: EnterpriseIntegrationConfig) -> IntegrationAuditResult:
        if not config.connector_id or not config.connector_id.strip():
            raise ValueError("connector_id cannot be empty")
        if not config.service_account_email or not self.SA_PATTERN.match(config.service_account_email.strip()):
            raise ValueError(f"Malformed service account email: {config.service_account_email}")

        flagged: List[str] = []
        remediated: List[str] = []
        for scope in config.allowed_read_scopes:
            clean = scope.strip()
            if clean in self.PROHIBITED_SCOPES or "admin" in clean.lower():
                flagged.append(f"Prohibited overprivileged scope '{clean}' flagged")
            else:
                remediated.append(clean)
        if not remediated and not flagged:
            remediated.append("roles/cloudaicompanion.dataViewer")

        if self.require_cmek_for_confidential and config.sensitivity in (DataSensitivityClass.CONFIDENTIAL, DataSensitivityClass.RESTRICTED):
            if not config.cmek_key_resource or not config.cmek_key_resource.startswith("projects/"):
                flagged.append(f"CMEK required for {config.sensitivity.value} connector")

        if self.disallow_restricted_indexing and config.sensitivity == DataSensitivityClass.RESTRICTED:
            if not config.compliance_signoff_id or not config.compliance_signoff_id.strip():
                flagged.append("Restricted data requires compliance_signoff_id")

        is_comp = len(flagged) == 0
        self.connectors[config.connector_id] = config
        res = IntegrationAuditResult(config.connector_id, config.connector_type, is_comp, "APPROVED" if is_comp else "REMEDIATION_REQUIRED", remediated, flagged)
        self._log_audit("CONNECTOR_AUDITED", config.connector_id, res.action, is_compliant=is_comp)
        return res

    def can_access_feature(self, user_email: str, required_tier: LicenseTier) -> bool:
        alloc = self.allocations.get(user_email.strip().lower())
        if not alloc or not alloc.is_active:
            return False
        if required_tier == LicenseTier.GEMINI_ENTERPRISE:
            return alloc.tier == LicenseTier.GEMINI_ENTERPRISE
        if required_tier == LicenseTier.GEMINI_BUSINESS:
            return alloc.tier in (LicenseTier.GEMINI_ENTERPRISE, LicenseTier.GEMINI_BUSINESS)
        return True

    def export_audit_manifest(self) -> Dict[str, any]:
        active_ent = sum(1 for a in self.allocations.values() if a.is_active and a.tier == LicenseTier.GEMINI_ENTERPRISE)
        return {
            "total_users_tracked": len(self.allocations),
            "active_enterprise_licenses": active_ent,
            "enterprise_quota_limit": self.max_enterprise_licenses,
            "enterprise_quota_remaining": max(0, self.max_enterprise_licenses - active_ent),
            "total_connectors_registered": len(self.connectors),
        }

    def _log_audit(self, event_type: str, target: str, action: str, is_compliant: bool = True):
        self.audit_log.append({"timestamp": datetime.now(timezone.utc).isoformat(), "event": event_type, "target": target, "action": action, "compliant": is_compliant})
