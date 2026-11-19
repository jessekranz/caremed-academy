"""Ordered onboarding requirements and current transport eligibility."""

import hashlib
import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

STAGES = (
    "Application",
    "Document Verification",
    "Background Screening",
    "Illinois Certification",
    "Online Academy",
    "Written Examination",
    "Supervised Training",
    "Practical Examination",
    "Compliance Approval",
    "Active CareMed Driver",
)

CREDENTIALS = {
    "driver_license": "Driver license",
    "hfs_safety": "Illinois HFS safety training certificate",
    "insurance": "Insurance eligibility",
    "local_license": "Local chauffeur / permit",
    "cpr": "CPR / first aid",
}
REQUIRED_CREDENTIALS = ("driver_license", "hfs_safety", "insurance")

SCHEMA = """
CREATE TABLE IF NOT EXISTS onboarding_records (
    id INTEGER PRIMARY KEY,
    driver_id INTEGER NOT NULL REFERENCES users(id),
    actor_id INTEGER NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL CHECK(kind IN ('application','screening','supervision')),
    passed INTEGER NOT NULL CHECK(passed IN (0,1)),
    note TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS written_exams (
    id INTEGER PRIMARY KEY,
    driver_id INTEGER NOT NULL REFERENCES users(id),
    curriculum TEXT NOT NULL,
    correct INTEGER NOT NULL,
    total INTEGER NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evaluation_appointments (
    id INTEGER PRIMARY KEY,
    driver_id INTEGER NOT NULL REFERENCES users(id),
    instructor_id INTEGER NOT NULL REFERENCES users(id),
    scheduled_for TEXT NOT NULL,
    location TEXT NOT NULL,
    cancelled_at TEXT,
    evaluation_id INTEGER UNIQUE REFERENCES evaluations(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_open_practical ON evaluation_appointments(driver_id)
    WHERE cancelled_at IS NULL AND evaluation_id IS NULL;
CREATE TABLE IF NOT EXISTS compliance_decisions (
    id INTEGER PRIMARY KEY,
    driver_id INTEGER NOT NULL REFERENCES users(id),
    administrator_id INTEGER NOT NULL REFERENCES users(id),
    snapshot TEXT,
    note TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_onboarding_driver ON onboarding_records(driver_id, kind, id);
CREATE INDEX IF NOT EXISTS idx_bank_attempts_driver ON bank_attempts(user_id, module_id, module_version);
CREATE INDEX IF NOT EXISTS idx_written_driver ON written_exams(driver_id, curriculum, id);
CREATE INDEX IF NOT EXISTS idx_compliance_driver ON compliance_decisions(driver_id, id);
"""


def illinois_now():
    return datetime.now(ZoneInfo("America/Chicago"))


def illinois_today():
    return illinois_now().date()


def illinois_date(timestamp):
    return datetime.fromisoformat(timestamp).astimezone(ZoneInfo("America/Chicago")).date().isoformat()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def driver_state(c, driver_id, transport_enabled):
    today = illinois_today()
    driver = c.execute("SELECT active FROM users WHERE role='driver' AND id=?", (driver_id,)).fetchone()
    if driver is None:
        return None

    credentials = {
        row["kind"]: row
        for row in c.execute("SELECT * FROM credentials WHERE user_id=?", (driver_id,))
    }
    credential_status = {}
    for kind in REQUIRED_CREDENTIALS:
        evidence = credentials.get(kind)
        if evidence is None:
            credential_status[kind] = "Missing"
        elif evidence["expires_on"] < today.isoformat():
            credential_status[kind] = "Expired"
        elif evidence["status"] == "verified":
            credential_status[kind] = "Verified"
        else:
            credential_status[kind] = evidence["status"].title()

    records = {
        row["kind"]: row for row in c.execute(
            "SELECT * FROM onboarding_records WHERE driver_id=? ORDER BY id", (driver_id,)
        )
    }
    application = records.get("application")
    screening = records.get("screening")
    supervision = records.get("supervision")
    modules = c.execute("SELECT id,version,status FROM modules ORDER BY id").fetchall()
    curriculum = fingerprint([tuple(module) for module in modules])
    completed = c.execute(
        """SELECT count(DISTINCT m.id) FROM modules m JOIN bank_attempts a ON a.module_id=m.id
           WHERE a.user_id=? AND a.module_version=m.version AND m.status='approved'
           AND a.total_count>0 AND a.correct_count=a.total_count""", (driver_id,)
    ).fetchone()[0]
    academy = bool(modules) and completed == len(modules)
    exam = c.execute(
        """SELECT * FROM written_exams WHERE driver_id=? AND curriculum=?
           ORDER BY (correct=total AND total>0) DESC,id DESC LIMIT 1""", (driver_id, curriculum)
    ).fetchone()
    written = bool(exam and exam["total"] and exam["correct"] == exam["total"])
    practical = c.execute(
        """SELECT e.*,r.decision FROM evaluation_appointments a
           JOIN evaluations e ON e.id=a.evaluation_id
           LEFT JOIN reviews r ON r.evaluation_id=e.id
           WHERE a.driver_id=? ORDER BY e.id DESC LIMIT 1""", (driver_id,)
    ).fetchone()
    competent = bool(practical and practical["result"] == "pass" and practical["critical_pass"]
                     and practical["decision"] != "rejected")

    checks = (
        bool(application),
        credential_status["driver_license"] == "Verified",
        bool(screening and screening["passed"]),
        credential_status["hfs_safety"] == "Verified",
        academy,
        written,
        bool(supervision and supervision["passed"]),
        competent,
    )
    snapshot = None
    if all(checks) and driver["active"] and credential_status["insurance"] == "Verified" and practical["decision"] == "confirmed":
        snapshot = fingerprint([
            curriculum, exam["id"], application["id"], screening["id"], supervision["id"], practical["id"],
            [tuple(credentials[kind]) for kind in REQUIRED_CREDENTIALS],
        ])
    approval = c.execute(
        "SELECT snapshot FROM compliance_decisions WHERE driver_id=? ORDER BY id DESC LIMIT 1", (driver_id,)
    ).fetchone()
    approved = bool(snapshot and approval and snapshot == approval["snapshot"])
    authorized = approved and transport_enabled
    progress = (*checks, approved, authorized)
    stage = next((index for index, complete in enumerate(progress) if not complete), len(STAGES))
    renewal_date = (today + timedelta(days=30)).isoformat()
    renewals = [
        CREDENTIALS[kind] for kind in REQUIRED_CREDENTIALS
        if kind in credentials and credentials[kind]["expires_on"] <= renewal_date
    ]
    return {
        "stage": stage, "checks": progress, "completed": completed, "total": len(modules),
        "curriculum": curriculum, "exam": exam, "practical": practical, "competent": competent,
        "supervision": supervision,
        "credentials": credentials, "credential_status": credential_status, "renewals": renewals,
        "snapshot": snapshot, "authorized": authorized, "approved": approved, "active": bool(driver["active"]),
    }
