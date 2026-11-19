# Deployment playbook (secure staging first)

## What runs where

- `app/` Python FastAPI service: authenticated employee, instructor and administrative pages. Needs a long-running Python process.
- `site/assets/`: branded images and conceptual videos; served as static public training media. Do not upload private passenger information.
- `site/index.html`: **legacy unverified V4 demonstration**; do NOT link it as the live employee portal. It uses local browser storage and has no server-side authorization.
- `data/`: SQLite pilot database; this directory must be outside any public document root with restrictive file permissions.

### Cloudways caveat
A standard WordPress/PHP Cloudways application does not directly run FastAPI. Use a separate Python-capable hosting service or a properly administered VPS/container for the secure portal, behind TLS; do not simply upload the entire ZIP to `public_html`.

## Staging process

1. Provision a private domain such as `training-staging.<your domain>` with a valid TLS certificate.
2. Deploy behind an HTTPS reverse proxy; set `CAREMED_SECURE_COOKIES=1` and set `CAREMED_DB` to a private, backed-up location.
3. Create admin by running `python scripts/create_admin.py` on the server (SSH only). Never ship a sample password.
4. Log in, add named instructor and driver accounts, use individual passwords. Do not share accounts.
5. Before accepting real staff, implement enforced MFA, controlled enrollment/password-reset flows, login throttling and account lockout, session management and backup-restore tests.
6. Perform independent penetration testing, accessibility audit, and operational security review; only then consider production rollout.
7. Replace SQLite with PostgreSQL and automated transactional migrations before a multi-user production deployment.
8. Do not input patient trip or medical data into the system. If expanding to rider/patient integrations, conduct HIPAA applicability/BAA and privacy/security review first.
9. Verify each individual media asset and manual against fleet inventory and approved instructor review.
10. Commission/verify the HFS-approved external driver training pathway. Internal training does not confer that certification.

## Smoke test

```bash
pip install -r requirements.txt
python scripts/create_admin.py
CAREMED_SECURE_COOKIES=0 uvicorn app.main:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000/login
```

### Operational protections still needed
- Production reverse proxy request limits, WAF/rate limit, central logs and alerts.
- MFA for all roles, ideally using a managed OIDC identity provider and hardware-backed factors for reviewers.
- Managed PostgreSQL migrations, encrypted backups, validated restore and immutable audit export.
- Password change/reset and verified email enrollment; current initial password is admin-issued only.
- Long-term record retention/legal hold policies and secure document evidence storage.
- Explicit HFS training certificate verification and independent legal/compliance signoff.
- Multi-vehicle qualification matrix, version-specific requalification, dispatch-level eligibility integration.

**Avoid treating the pilot as deploy-and-forget.** The authentication workflow is functional, but this is not independently security audited or production qualified.
