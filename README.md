# GCP & Workspace Identity Governor

Automated identity lifecycle, organizational unit (OU) governance, least-privilege GCP IAM reconciliation, and Kubernetes Workload Identity security engine in Python.

## Core Capabilities

- **Automated Identity Lifecycle**: User onboarding/offboarding workflows between HRIS webhooks and Cloud Identity with immediate token revocation.
- **Production Developer Least-Privilege**: Enforces read-only by default (`roles/viewer`) for developer access in production environments, automatically downgrading or flagging overprivileged roles (`roles/editor`, `roles/owner`) unless break-glass is verified.
- **Scoped Secrets Access Auditing**: Audits application service accounts to ensure microservices only receive scoped `roles/secretmanager.secretAccessor` on exact resource paths, preventing wildcard administrative exposure.
- **Kubernetes Workload Identity RBAC Validation**: Validates KSA-to-GSA workload identity mappings and remediates wildcard or `cluster-admin` bindings into namespace-scoped least-privilege RoleBindings.
- **Deterministic Drift Detection**: Continuous policy reconciliation and compliance audit manifests.

## Test Suite

```bash
python -m pytest -v
```
