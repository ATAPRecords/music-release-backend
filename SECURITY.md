# Secret handling and incident remediation

Do not commit passwords, database connection credentials, signing keys or live environment files. Use an untracked local `.env` or the hosting provider's secret settings. `.env.example` intentionally contains no usable credentials.

## Outstanding exposure response

Removing `.env` from the current tree does not invalidate credentials or remove older Git history. Treat previously committed credentials as compromised until they are rotated or revoked at the issuing service.

Before merging this cleanup into a deployment branch:

1. Confirm which deployed services and local processes use this repository, including any automatic deployments.
2. Rotate or revoke the exposed MongoDB database-user credential in Atlas. Update the appropriate deployment secret without writing its value into Git, logs, issues or pull requests. Do not resume an inactive cluster merely to test an exposed credential.
3. Replace any deployed JWT signing key that matches the tracked sample/exposed key with a cryptographically random key. This intentionally invalidates existing sessions; coordinate the rollout and sign-in test.
4. Verify the hosting service has its required environment variables configured independently of the tracked file. Preserve current service availability during the change.
5. Review database activity and current access permissions. Do not assume historical network settings are current, or that a lack of visible activity proves no access occurred.
6. After rotation, coordinate historical secret removal across branches, tags, pull requests and clones. A force-push/history rewrite requires an explicit reviewed plan; do not perform one casually. Consider GitHub support for cached references. Do not keep compromised credentials valid solely for rollback.
7. Test service startup, authorized sign-in and database access using the updated deployment. Record completion without including secret values.

## Scope of this patch

This patch removes the tracked environment file from the proposed tree and adds ignore/sample guidance. It does not rotate credentials, change database permissions, rewrite history, merge another application branch, or deploy the service. Until service-side rotation is verified, the incident is not resolved.
