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

Log in to the secure portal to record real user-specific training activity within this pilot database. Do not use `site/index.html` for qualifications. The pilot enforces instructor observation and distinct admin review, but DOES NOT declare any driver ready for transport or generate state certification. No rider data should be entered.
