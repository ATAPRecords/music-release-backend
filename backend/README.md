# Studio App backend — migration copy

These are copies of the existing 2025 root Node/Express/MongoDB backend source files; they were placed in `backend/` without moving or deleting the originals, to preserve existing setup.

This authentication implementation is **not production safe**. In particular:
- It returns user objects containing password hashes in some auth responses.
- Apple token verification is configured to ignore expiration.
- It lacks robust validation, error handling and tenancy authorization.
- The repository historically included a tracked `.env`; rotate any exposed credentials.

Do not use production data or connect this to a public deployment until security review and fixes are complete. The frontend is not yet connected to these routes.
