# GCP & Workspace Identity Governor

Automated identity lifecycle, organizational unit (OU) governance, least-privilege GCP IAM reconciliation, and Kubernetes Workload Identity security engine in Python.

## Core Capabilities

- **Automated Identity Lifecycle**: User onboarding/offboarding workflows between HRIS webhooks and Cloud Identity with immediate token revocation.
- **Production Developer Least-Privilege**: Enforces read-only by default (`roles/viewer`) for developer access in production environments, automatically downgrading or flagging overprivileged roles (`roles/editor`, `roles/owner`) unless break-glass is verified.
- **Scoped Secrets Access Auditing**: Audits application service accounts to ensure microservices only receive scoped `roles/secretmanager.secretAccessor` on exact resource paths, preventing wildcard administrative exposure.
- **Kubernetes Workload Identity RBAC Validation**: Validates KSA-to-GSA workload identity mappings and remediates wildcard or `cluster-admin` bindings into namespace-scoped least-privilege RoleBindings.
- **Gemini Enterprise Licensing & Integration Governance**: Administers Google Cloud and Workspace Gemini Enterprise license quotas, least-privilege role mappings, CMEK encryption enforcement, and third-party data integration compliance (Drive, Slack, Jira, Salesforce, SharePoint).
- **Deterministic Drift Detection**: Continuous policy reconciliation and compliance audit manifests.

## Gemini Enterprise Licensing & Integration Governance

### Overview

`GeminiEnterpriseGovernor` provides centralized governance over Google Cloud projects and Google Workspace environments deploying Gemini Enterprise:

1. **Licensing Allocation & Quota Enforcement**: Allocates and reconciles user licenses (`GEMINI_ENTERPRISE`, `GEMINI_BUSINESS`) based on organizational units (OU), automatically rejecting suspended accounts and enforcing quota boundaries.
2. **Least-Privilege Connector Access Control**: Audits enterprise data connectors (Google Drive, Slack, Jira, Salesforce, SharePoint) to verify that service accounts only hold scoped data viewing roles rather than wildcard or administrative permissions (`roles/owner`, `roles/editor`).
3. **CMEK & Data Sensitivity Boundaries**: Enforces Customer-Managed Encryption Key (CMEK) requirements on confidential data sources and blocks model ingestion of restricted enterprise data unless accompanied by verified compliance sign-offs.

### Runnable Example

```python
from src.governor import (
    GeminiEnterpriseGovernor,
    LicenseTier,
    IntegrationConnectorType,
    DataSensitivityClass,
    EnterpriseIntegrationConfig,
)

# 1. Initialize governor with quota and data protection policies
governor = GeminiEnterpriseGovernor(
    max_enterprise_licenses=50,
    require_cmek_for_confidential=True,
    disallow_restricted_indexing=True,
)

# 2. Allocate enterprise license to an engineering team member
alloc_res = governor.allocate_license(
    user_email="engineer@corp.internal",
    tier=LicenseTier.GEMINI_ENTERPRISE,
    ou_path="/Engineering",
)
print(f"Allocation status: {alloc_res.status}, Action: {alloc_res.action_taken}")

# 3. Audit enterprise data integration connector for least-privilege compliance
connector_cfg = EnterpriseIntegrationConfig(
    connector_id="drive-knowledge-sync",
    connector_type=IntegrationConnectorType.GOOGLE_DRIVE,
    service_account_email="gemini-drive-sync@project.iam.gserviceaccount.com",
    target_data_source="drive://shared-drives/product-specs",
    sensitivity=DataSensitivityClass.INTERNAL,
    allowed_read_scopes=["roles/cloudaicompanion.dataViewer"],
)

audit_res = governor.audit_integration_connector(connector_cfg)
print(f"Connector compliant: {audit_res.is_compliant}, Action: {audit_res.action}")

# 4. Export consolidated governance audit manifest
manifest = governor.export_audit_manifest()
print(f"Active Enterprise Licenses: {manifest['active_enterprise_licenses']}/{manifest['enterprise_quota_limit']}")
```

### Operational Limits

- License allocation evaluates deterministic capacity in memory; persistent state synchronization requires hooking into directory sync webhooks or Cloud Identity Directory API callbacks.
- CMEK validation checks resource path format conformance (`projects/*/locations/*/keyRings/*/cryptoKeys/*`); live Cloud KMS cryptographic status validation requires configured Google Cloud ADC credentials.

## Test Suite

```bash
python -m pytest -v
```
