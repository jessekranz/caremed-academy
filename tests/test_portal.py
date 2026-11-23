import os,tempfile,sys
from pathlib import Path
TEST_DIR=tempfile.TemporaryDirectory()
os.environ['CAREMED_DB']=str(Path(TEST_DIR.name)/'test.sqlite3')
os.environ['CAREMED_SECURE_COOKIES']='0'
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from datetime import timedelta
from app import main as portal, onboarding
from app.main import app,db,PH,now,CRITERIA
from fastapi.testclient import TestClient
import re

def new_user(name,role):
    with db() as c:
        cur=c.execute('INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)',(f'{name}@example.test',name,role,PH.hash('SecureTestPassword!99'),now()))
        return cur.lastrowid

def client_for(name):
    cli=TestClient(app,follow_redirects=False)
    r=cli.post('/login',data={'email':f'{name}@example.test','password':'SecureTestPassword!99'})
    assert r.status_code==303
    p=cli.get('/dashboard', follow_redirects=True);assert p.status_code==200
    csrf=re.search(r'name="csrf" value="([^"]+)"',p.text)
    assert csrf
    return cli,csrf.group(1)

def test_workflow(monkeypatch):
    monkeypatch.setattr(portal, 'TRANSPORT_ENABLED', False)
    driver = new_user('driver', 'driver')
    new_user('instructor', 'instructor')
    new_user('other-instructor', 'instructor')
    new_user('admin', 'admin')
    d, dc = client_for('driver')
    i, ic = client_for('instructor')
    other, oc = client_for('other-instructor')
    a, ac = client_for('admin')
    today = onboarding.illinois_today()
    expiry = (today + timedelta(days=20)).isoformat()

    assert d.get('/admin').status_code == 403
    assert 'aria-current="step"><span>Application' in d.get('/dashboard').text
    assert d.get('/transport-authorization').status_code == 403
    assert d.get('/written-exam').status_code == 409
    assert d.get('/courses/1').status_code == 200
    answers = {'answer_0': 1, 'answer_1': 0, 'answer_2': 1}
    assert d.post('/courses/1/answer', data={'csrf': 'bogus', **answers}).status_code == 403
    assert d.post('/courses/1/answer', data={'csrf': dc, **answers}).status_code == 200
    assert a.post('/admin/modules/1', data={'csrf': ac, 'status': 'approved'}).status_code == 303
    assert d.post('/courses/1/answer', data={'csrf': dc, **answers}).status_code == 409
    assert i.post('/evaluations/supervision', data={
        'csrf': ic, 'driver_id': driver, 'training_date': today.isoformat(), 'notes': 'Completed supervised sessions',
    }).status_code == 409
    assert d.post('/evaluations', data={'csrf': dc}).status_code == 403

    def submit_credential(kind, reference):
        result = d.post('/credentials', data={
            'csrf': dc, 'kind': kind, 'reference': reference, 'expires_on': expiry,
        })
        assert result.status_code == 303
        with db() as c:
            return c.execute('SELECT * FROM credentials WHERE user_id=? AND kind=?', (driver, kind)).fetchone()

    def credential_decision(record, decision='verified'):
        return a.post(f'/admin/credential/{record["id"]}', data={
            'csrf': ac, 'decision': decision, 'revision': portal.credential_revision(record),
        })

    assert d.post('/onboarding/application', data={'csrf': dc}).status_code == 303
    old_license = submit_credential('driver_license', 'OLD-01')
    license_record = submit_credential('driver_license', 'LICENSE-01')
    assert credential_decision(old_license).status_code == 409
    assert credential_decision(license_record).status_code == 303
    hfs = submit_credential('hfs_safety', 'HFS-01')
    assert credential_decision(hfs).status_code == 409
    assert a.post(f'/admin/drivers/{driver}/screening', data={
        'csrf': ac, 'decision': 'cleared', 'reference': 'SCREEN-01',
    }).status_code == 303
    assert credential_decision(hfs).status_code == 303

    with db() as c:
        module_ids = [row[0] for row in c.execute('SELECT id FROM modules ORDER BY id')]
        gradebook = {}
        exam_answers = {}
        for question in c.execute('SELECT * FROM bank_questions'):
            gradebook.setdefault(question['module_id'], {})[f'answer_{question["ordinal"]}'] = question['answer_index']
        for question in c.execute('SELECT * FROM exam_questions'):
            exam_answers[f'question_{question["id"]}'] = question['answer_index']
        assert len(exam_answers) == len(module_ids)
        lesson_prompts = {row[0] for row in c.execute('SELECT prompt FROM bank_questions')}
        assert not lesson_prompts & {row[0] for row in c.execute('SELECT prompt FROM exam_questions')}
    for module_id in module_ids:
        assert a.post(f'/admin/modules/{module_id}', data={'csrf': ac, 'status': 'approved'}).status_code == 303
        assert d.post(f'/courses/{module_id}/answer', data={'csrf': dc, **gradebook[module_id]}).status_code == 200

    exam = d.get('/written-exam')
    curriculum = re.search(r'name="curriculum" value="([^"]+)"', exam.text).group(1)
    first_question, correct_answer = next(iter(exam_answers.items()))
    wrong_answers = {**exam_answers, first_question: (correct_answer + 1) % 3}
    assert d.post('/written-exam', data={'csrf': dc, 'curriculum': curriculum, **wrong_answers}).status_code == 303
    assert 'aria-current="step"><span>Written Examination' in d.get('/dashboard').text
    assert d.post('/written-exam', data={'csrf': dc, 'curriculum': curriculum, **exam_answers}).status_code == 303
    assert 'aria-current="step"><span>Supervised Training' in d.get('/dashboard').text
    assert i.post('/evaluations/supervision', data={
        'csrf': ic, 'driver_id': driver, 'training_date': today.isoformat(), 'notes': 'Completed supervised sessions',
    }).status_code == 303

    clock = onboarding.illinois_now()
    monkeypatch.setattr(portal, 'illinois_now', lambda: clock)
    appointment_form = {
        'csrf': ic, 'driver_id': driver,
        'scheduled_for': clock.strftime('%Y-%m-%dT%H:%M'), 'location': 'Training lot',
    }
    assert i.post('/evaluations/appointments', data=appointment_form).status_code == 303
    assert i.post('/evaluations/appointments', data=appointment_form).status_code == 409
    assert 'Training lot' in d.get('/evaluations').text
    with db() as c:
        appointment = c.execute('SELECT id FROM evaluation_appointments WHERE driver_id=?', (driver,)).fetchone()[0]
    base = {
        'csrf': ic, 'appointment_id': appointment, 'vehicle_reference': 'VAN-001',
        'equipment_reference': 'TEST RAMP MODEL / WTORS', 'observed_at': today.isoformat(),
        'notes': 'Documented checklist and practical exam results.', 'result': 'pass', 'critical_pass': '1',
    }
    assert i.post('/evaluations', data={**base, 'checks': ['0', '1']}).status_code == 400
    passed = {**base, 'checks': list(map(str, range(len(CRITERIA))))}
    assert other.post('/evaluations', data={**passed, 'csrf': oc}).status_code == 404
    assert i.post('/evaluations', data=passed).status_code == 303
    assert i.post('/evaluations', data=passed).status_code == 404
    with db() as c:
        evaluation = c.execute('SELECT id FROM evaluations WHERE driver_id=?', (driver,)).fetchone()[0]
    review = {'csrf': ac, 'decision': 'confirmed', 'notes': 'Independent review of observed result'}
    assert i.post(f'/admin/review/{evaluation}', data={**review, 'csrf': ic}).status_code == 403
    assert a.post(f'/admin/review/{evaluation}', data=review).status_code == 303
    assert a.post(f'/admin/review/{evaluation}', data=review).status_code == 409

    url = f'/admin/drivers/{driver}/compliance'
    decision = {'csrf': ac, 'decision': 'approve', 'notes': 'Evidence reviewed and approved'}
    assert a.post(url, data={**decision, 'snapshot': 'early'}).status_code == 409
    insurance = submit_credential('insurance', 'INSURANCE-01')
    assert credential_decision(insurance).status_code == 303
    admin_page = a.get('/admin').text
    assert 'Renewal due' in admin_page
    snapshot = re.search(r'name="snapshot" value="([^"]+)"', admin_page).group(1)
    assert a.post(url, data={**decision, 'snapshot': snapshot}).status_code == 303
    assert d.get('/transport-authorization').json() == {'authorized': False}
    monkeypatch.setattr(portal, 'TRANSPORT_ENABLED', True)
    assert d.get('/transport-authorization').status_code == 200
    assert 'Authorized for transport' in a.get('/admin').text
    assert 'aria-current="step"' not in d.get('/dashboard').text
    assert submit_credential('insurance', 'INSURANCE-01')['status'] == 'verified'
    assert d.get('/transport-authorization').status_code == 200

    with monkeypatch.context() as expiry_clock:
        expiry_clock.setattr(onboarding, 'illinois_today', lambda: today + timedelta(days=21))
        assert d.get('/transport-authorization').status_code == 403
        assert 'Expired' in d.get('/dashboard').text

    assert a.post(url, data={**decision, 'decision': 'revoke', 'snapshot': snapshot}).status_code == 303
    assert d.get('/transport-authorization').status_code == 403
    assert a.post(url, data={**decision, 'snapshot': snapshot}).status_code == 303
    insurance = submit_credential('insurance', 'INSURANCE-02')
    assert d.get('/transport-authorization').status_code == 403
    assert credential_decision(insurance).status_code == 303
    assert d.get('/transport-authorization').status_code == 403
    assert a.post(url, data={**decision, 'snapshot': snapshot}).status_code == 409
    new_snapshot = re.search(r'name="snapshot" value="([^"]+)"', a.get('/admin').text).group(1)
    assert a.post(url, data={**decision, 'snapshot': new_snapshot}).status_code == 303
    assert d.get('/transport-authorization').status_code == 200
    assert a.post('/admin/modules/1', data={'csrf': ac, 'status': 'draft'}).status_code == 303
    assert d.get('/transport-authorization').status_code == 403
    assert 'aria-current="step"><span>Online Academy' in d.get('/dashboard').text

    assert d.post('/logout', data={'csrf': dc}).status_code == 303
    assert d.get('/dashboard').status_code == 401


def test_no_public_admin():
    c=TestClient(app)
    assert c.get('/admin').status_code==401
    assert c.get('/healthz').json()['status']=='ok'

def test_wrong_passwords_lock_the_account_for_15_minutes():
    new_user('locked','driver')
    c=TestClient(app,follow_redirects=False)
    for _ in range(5):
        r=c.post('/login',data={'email':'locked@example.test','password':'wrong-password-123'})
        assert 'Invalid email or password' in r.text
    r=c.post('/login',data={'email':'locked@example.test','password':'SecureTestPassword!99'})
    assert r.status_code==200 and 'Too many failed sign-ins' in r.text and 'caremed_session' not in r.cookies
    with db() as conn:
        assert conn.execute("SELECT count(*) FROM audit WHERE action='login_locked'").fetchone()[0]>=1
        conn.execute('DELETE FROM login_failures')
    assert c.post('/login',data={'email':'locked@example.test','password':'SecureTestPassword!99'}).status_code==303

def test_queries_work_when_sqlite_rejects_double_quoted_text():
    source=(Path(__file__).resolve().parent.parent/'app'/'main.py').read_text(encoding='utf-8')
    for line in source.splitlines():
        if 'execute(' in line:
            assert not re.search(r'="(approved|pending|driver|draft)"',line),line
