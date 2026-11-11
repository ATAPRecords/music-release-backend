# Nexus Studio App — unified repository (development branch)

The **Studio App** is the 2025 studio/client management product, not the separate music-publishing catalog.

## Folders
- `frontend/`: interactive browser prototype; open `frontend/index.html` in a browser. The **Release & Royalty Center** links to `frontend/release.html`.
- `backend/`: copied Node/Express/MongoDB authentication starter from the original root service, preserved for migration and security hardening.
- Original root `server.js`, `package.json`, `routes/`, `controllers/`, and `models/`: intentionally left untouched for compatibility until audited.

## Demo status
The frontend currently uses sample data and in-memory/browser-only interactions. It is **not wired to MongoDB, payment processors, real bookings, royalties, distribution, or copyright registration**. Do not enter client secrets or financial data. The release checklist is for planning, not proof of registration.

## Run prototype
Open `frontend/index.html` directly in Chrome, Safari, or Edge. Or serve locally: `python3 -m http.server 8000` from repository root and visit `http://localhost:8000/frontend/`.

## Required next work
1. Audit and rotate any secrets historically present in the tracked root `.env`; remove secrets from repository/history safely and restrict access. Adding `.gitignore` does not erase prior exposure.
2. Fix security issues in the legacy authentication code (password field in responses, Apple token expiry handling, authorization and validation, errors), add integration tests, and decide entrypoint migration. **Do not deploy legacy authentication as-is.**
3. Build a shared API for business-scoped identities, permissions, bookings, session time logs, jobs and staff.
4. Add verified payment receipts, allocation ledger, file upload/version approvals.
5. Implement royalty account authorizations, registration status, imports, deduplication and reconciliation only with provider-supported workflows.
6. Add automated tests and a staging deployment.

A pull request should remain draft until the architecture and security work are reviewed.
