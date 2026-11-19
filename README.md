# CareMed Driver Academy: Secure Pilot

This release adds a **real server-side employee portal** to the previous visual training prototype: Argon2 password hashing, server-stored sessions, `HttpOnly`/`SameSite=Strict` cookies, CSRF protection, driver/instructor/admin roles, credential verification, 18 imported training lessons, 54 graded knowledge questions, 5 interactive decision simulations, signed practical observations, independent admin review and audit trail.

**It is a pilot, not an authorized production qualification service.** No manufacturer has approved the instructional material, no HFS safety training approval has been granted, and **no driver dispatch clearance is issued**. The previous 18-lesson visual preview is retained separately under `site/index.html` and still uses browser-local demonstration state. The new secure portal independently imports the 18 lessons and 54 questions into server-side records.

## Launch locally

Python 3.11+ recommended. From the project root:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
# ONLY for local HTTP testing, never for deployment:
# Windows PowerShell: $env:CAREMED_SECURE_COOKIES='0'
# macOS/Linux: export CAREMED_SECURE_COOKIES=0
python scripts/create_admin.py
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/login. Create instructor and driver accounts from the administrator dashboard.

## Intended deployment

Use a dedicated Python-capable server (container/VPS/PaaS) for the API and database. **A static upload to Cloudflare Pages does not run this backend.** Put the app behind a correctly configured TLS reverse proxy, secure the database location outside the webroot, restrict access to staff and run infrastructure security reviews. A production deployment should migrate from the starter SQLite database to a managed PostgreSQL database with backups and point-in-time recovery.

See `docs/DEPLOYMENT.md`, `docs/SAFETY-CONTENT-APPROVAL.md`, and `docs/OPERATIONS-AND-SECURITY.md`.


## Important delivery distinction

The seven full-length **filming scripts/storyboards** are in `docs/VIDEO-PRODUCTION-BOOK.md`. They are **not completed videos** and have not received manufacturer approval. The three included 12-second MP4 clips are preliminary visual briefings only. Actual full-length operational demonstrations require the verified vehicle conversion, actual WTORS equipment, safe on-vehicle filming, and written manufacturer/authorized trainer approval. Details are in `docs/SAFETY-CONTENT-APPROVAL.md`.

## Server-side versus visual demo

Log in to the secure portal to record real user-specific training activity within this pilot database. Do not use `site/index.html` for qualifications. The pilot enforces instructor observation and distinct admin review. The state credential must come from an external source. No rider data should be entered.

## Driver onboarding

The secure portal displays the driver's current stage, examination results and required credential status. Instructors document supervised training and schedule and sign practical examinations. Administrators verify records, independently review practical exams, and approve or withdraw driver compliance.

The portal checks a current driver license, Illinois HFS safety training certificate and insurance eligibility. Local permits and CPR can be tracked as additional records. The written exam uses the approved academy question bank and requires all answers correct. The portal flags required records within 30 days of expiry.

Transport authorization is disabled by default. If CareMed approves operational use, set `CAREMED_TRANSPORT_ENABLED=1` to enable the authorization check. `GET /transport-authorization` checks the signed-in driver's current status and returns 403 unless all gates and a current compliance approval are present. A dispatch integration would need to enforce those same requirements when accepting a trip. This repository has no trip acceptance system. Pending renewals and changed evidence require fresh verification and compliance approval. Previously recorded practical observations remain in the history. An appointment-linked practical examination is required for the onboarding workflow.

## Sign-in limit

Five wrong passwords in 15 minutes, for one email or from one network address, blocks sign-in for the rest of that 15 minutes. Every block is in the audit log. Behind a reverse proxy, start uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy address>` so the limit sees each person's real address instead of the proxy's.

## Preview website

The visual preview in `site/` is published to GitHub Pages at https://jessekranz.github.io/caremed-academy/ on every push to `main` (`.github/workflows/pages.yml`). It is a prototype that keeps progress only in the viewer's browser. The secure portal in `app/` is not published there.
