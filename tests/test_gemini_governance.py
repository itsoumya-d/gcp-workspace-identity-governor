import pytest
from src.governor.gemini_governance import (
    GeminiEnterpriseGovernor,
    LicenseTier,
    IntegrationConnectorType,
    DataSensitivityClass,
    EnterpriseIntegrationConfig,
)

def test_gemini_enterprise_license_allocation_normal():
    """1. Normal case: Valid user email, enterprise license allocated, compliant audit result."""
    gov = GeminiEnterpriseGovernor(max_enterprise_licenses=10)
    res = gov.allocate_license("alice@corp.internal", LicenseTier.GEMINI_ENTERPRISE, "/Engineering")
    assert res.is_compliant is True and res.status == "SUCCESS" and res.action_taken == "ALLOCATED"
    assert gov.can_access_feature("alice@corp.internal", LicenseTier.GEMINI_ENTERPRISE) is True

    cfg = EnterpriseIntegrationConfig(
        connector_id="conn-drive-01",
        connector_type=IntegrationConnectorType.GOOGLE_DRIVE,
        service_account_email="drive-indexer@my-proj.iam.gserviceaccount.com",
        target_data_source="drive://shared-drives/engineering",
        sensitivity=DataSensitivityClass.INTERNAL,
        allowed_read_scopes=["roles/cloudaicompanion.dataViewer"],
    )
    audit = gov.audit_integration_connector(cfg)
    assert audit.is_compliant is True and audit.action == "APPROVED" and len(audit.flagged_issues) == 0

def test_gemini_governance_empty_input_validation():
    """2. Empty input: Rejects empty strings for user email, connector id, or quota."""
    gov = GeminiEnterpriseGovernor(max_enterprise_licenses=5)
    with pytest.raises(ValueError, match="user_email cannot be empty"):
        gov.allocate_license("", LicenseTier.GEMINI_ENTERPRISE)
    with pytest.raises(ValueError, match="connector_id cannot be empty"):
        gov.audit_integration_connector(
            EnterpriseIntegrationConfig("", IntegrationConnectorType.SLACK, "sa@p.iam.gserviceaccount.com", "slack://c", DataSensitivityClass.INTERNAL)
        )
    with pytest.raises(ValueError, match="max_enterprise_licenses must be positive"):
        GeminiEnterpriseGovernor(max_enterprise_licenses=0)

def test_gemini_governance_malformed_input():
    """3. Malformed input: Rejects invalid email syntax, invalid service account domains, and bad OU paths."""
    gov = GeminiEnterpriseGovernor()
    with pytest.raises(ValueError, match="Malformed user email"):
        gov.allocate_license("not-an-email", LicenseTier.GEMINI_ENTERPRISE)
    with pytest.raises(ValueError, match="Malformed OU path"):
        gov.allocate_license("u@corp.internal", LicenseTier.GEMINI_ENTERPRISE, "NoSlashOU")
    with pytest.raises(ValueError, match="Malformed service account email"):
        gov.audit_integration_connector(
            EnterpriseIntegrationConfig("c2", IntegrationConnectorType.JIRA, "user@gmail.com", "jira://i", DataSensitivityClass.INTERNAL)
        )

def test_gemini_enterprise_license_capacity_boundary():
    """4. Boundary value: Respects strict capacity limits, rejecting N+1 allocations when full."""
    gov = GeminiEnterpriseGovernor(max_enterprise_licenses=2)
    assert gov.allocate_license("u1@c.internal", LicenseTier.GEMINI_ENTERPRISE).status == "SUCCESS"
    assert gov.allocate_license("u2@c.internal", LicenseTier.GEMINI_ENTERPRISE).status == "SUCCESS"
    overflow = gov.allocate_license("u3@c.internal", LicenseTier.GEMINI_ENTERPRISE)
    assert overflow.status == "REJECTED" and overflow.action_taken == "CAPACITY_EXCEEDED"
    gov.allocate_license("u1@c.internal", LicenseTier.UNLICENSED)
    assert gov.allocate_license("u3@c.internal", LicenseTier.GEMINI_ENTERPRISE).status == "SUCCESS"

def test_gemini_integration_restricted_data_dependency_failure():
    """5. Dependency failure: Missing CMEK on confidential data or missing compliance signoff on restricted data."""
    gov = GeminiEnterpriseGovernor(require_cmek_for_confidential=True, disallow_restricted_indexing=True)
    cfg_conf = EnterpriseIntegrationConfig(
        connector_id="conf1",
        connector_type=IntegrationConnectorType.SALESFORCE,
        service_account_email="sa@p.iam.gserviceaccount.com",
        target_data_source="sf://accounts",
        sensitivity=DataSensitivityClass.CONFIDENTIAL,
        cmek_key_resource=None,
    )
    audit_conf = gov.audit_integration_connector(cfg_conf)
    assert audit_conf.is_compliant is False and any("CMEK required" in i for i in audit_conf.flagged_issues)

    cfg_rest = EnterpriseIntegrationConfig(
        connector_id="rest1",
        connector_type=IntegrationConnectorType.SHAREPOINT,
        service_account_email="sa@p.iam.gserviceaccount.com",
        target_data_source="sp://docs",
        sensitivity=DataSensitivityClass.RESTRICTED,
        cmek_key_resource="projects/p/locations/us/keyRings/kr/cryptoKeys/k1",
        compliance_signoff_id=None,
    )
    audit_rest = gov.audit_integration_connector(cfg_rest)
    assert audit_rest.is_compliant is False and any("compliance_signoff_id" in i for i in audit_rest.flagged_issues)

def test_gemini_governance_least_privilege_invariance():
    """6. Property that must always hold: Overprivileged scopes are flagged; suspended users cannot hold access."""
    gov = GeminiEnterpriseGovernor(max_enterprise_licenses=5)
    cfg = EnterpriseIntegrationConfig(
        connector_id="c-admin",
        connector_type=IntegrationConnectorType.GENERIC_REST,
        service_account_email="sa@p.iam.gserviceaccount.com",
        target_data_source="https://api.internal",
        sensitivity=DataSensitivityClass.INTERNAL,
        allowed_read_scopes=["*", "roles/owner", "roles/cloudaicompanion.dataViewer"],
    )
    audit = gov.audit_integration_connector(cfg)
    assert audit.is_compliant is False and "roles/owner" not in audit.remediated_scopes and "*" not in audit.remediated_scopes
    assert "roles/cloudaicompanion.dataViewer" in audit.remediated_scopes

    gov.allocate_license("bob@c.internal", LicenseTier.GEMINI_ENTERPRISE, "/Employees")
    assert gov.can_access_feature("bob@c.internal", LicenseTier.GEMINI_ENTERPRISE) is True
    rev = gov.allocate_license("bob@c.internal", LicenseTier.GEMINI_ENTERPRISE, "/Suspended/Dept")
    assert rev.status == "DENIED" and rev.action_taken == "REVOKED_SUSPENDED_OU"
    assert gov.can_access_feature("bob@c.internal", LicenseTier.GEMINI_ENTERPRISE) is False
