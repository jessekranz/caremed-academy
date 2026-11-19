# Secure pilot: controls and threat-model notes

## Implemented

- No default passwords or seeded user accounts; admin created interactively.
- Argon2id password hashing with unique salts; no plaintext password storage.
- Random 40-byte-url-safe session identifiers, SHA-256 hash only in database, 8-hour absolute expiry; HttpOnly/SameSite=Strict/Secure cookies by default.
- Request-origin checking and per-session unpredictable CSRF token for state-changing requests.
- Server-side RBAC enforcing driver/instructor/admin; driver cannot submit instructor observation; instructor cannot self-admin; administrator cannot submit observations.
- Credential entries default pending; admin verification required. The driver cannot self-verify.
- Practical evaluation creates an immutable instructor-signed snapshot; secondary admin confirmation separately recorded; cannot confirm a pass lacking critical checklist completion.
- Server-side attempts tied to module version; published-version changes invalidate previous completion credit.
- Audit entries track successful/failed login, credential events, assessments, user creation, editorial changes, practical signatures and reviews.
- CSP, clickjacking, caching, MIME sniffing and referrer security headers for rendered portal pages.

## Known limitations and required remediation before production

- No MFA, automatic password reset, invitation email verification, account lockout, or application-level rate limiting. Use managed enterprise identity/OIDC before launch.
- SQLite and app-managed schema are a deployment starter only; use PostgreSQL with transactional migrations and retention/legal-hold policy.
- Audit trail is append-only at application layer but **not tamper-proof against a DBA/server administrator**. Export to immutable storage/SIEM with external timestamping.
- No uploaded evidence attachments, privacy consent collection, driver photograph/license validation, supervisor identity proofing, digital signatures meeting a specific legal e-sign standard, or external registry lookup.
- No formal course/assessment approval workflow beyond an admin editorial status; no manufacturer or HFS certification is implied.
- Dispatch integration is outside this portal. Transport authorization defaults to disabled, and the employee eligibility endpoint checks current prerequisites and a signed compliance decision when enabled.
- No reviewed HIPAA compliance claim. Do not store rider, trip or medical information.
- No tenant isolation, accessibility certification, professional security audit, high-availability guarantees, backups or incident response integrations supplied.
- TLS proxy config, host validation, secure proxy trust, external secrets handling and request/response limits must be hardened per hosting environment.

## Personal data minimization

Only store work email, display name, assigned role, user-entered credential references and expirations, test answers, instructor observations and review metadata. Never put passenger names or health data in instructor notes. Define retention and purging requirements with counsel.
