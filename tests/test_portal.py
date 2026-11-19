import os,tempfile,sys
from pathlib import Path
TEST_DIR=tempfile.TemporaryDirectory()
os.environ['CAREMED_DB']=str(Path(TEST_DIR.name)/'test.sqlite3')
os.environ['CAREMED_SECURE_COOKIES']='0'
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
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
    p=cli.get('/dashboard');assert p.status_code==200
    csrf=re.search(r'name="csrf" value="([^"]+)"',p.text)
    assert csrf
    return cli,csrf.group(1)

def test_workflow():
    driver=new_user('driver','driver');instructor=new_user('instructor','instructor');admin=new_user('admin','admin')
    d,dc=client_for('driver');i,ic=client_for('instructor');a,ac=client_for('admin')
    assert d.get('/admin').status_code==403
    assert d.get('/courses/1').status_code==200
    assert d.post('/courses/1/answer',data={'csrf':'bogus','answer_0':1,'answer_1':0,'answer_2':1}).status_code==403
    assert d.post('/courses/1/answer',data={'csrf':dc,'answer_0':1,'answer_1':0,'answer_2':1}).status_code==200
    with db() as conn:assert conn.execute('SELECT count(*) FROM bank_attempts WHERE user_id=?',(driver,)).fetchone()[0]==1
    assert d.post('/credentials',data={'csrf':dc,'kind':'hfs_safety','reference':'HFS-TEST-01','expires_on':'2028-12-10'}).status_code==303
    assert d.post('/evaluations',data={'csrf':dc}).status_code==403
    with db() as conn:credential=conn.execute('SELECT id FROM credentials WHERE user_id=?',(driver,)).fetchone()[0]
    assert a.post(f'/admin/credential/{credential}',data={'csrf':ac,'decision':'verified'}).status_code==303
    with db() as conn:assert conn.execute('SELECT status FROM credentials WHERE id=?',(credential,)).fetchone()[0]=='verified'
    base={'csrf':ic,'driver_id':driver,'vehicle_reference':'VAN-001','equipment_reference':'TEST RAMP MODEL / WTORS','observed_at':'2026-11-19','notes':'Actual verified training observation placeholder for internal integration testing.','result':'pass','critical_pass':'1'}
    assert i.post('/evaluations',data={**base,'checks':['0','1']}).status_code==400
    r=i.post('/evaluations',data={**base,'checks':[str(x) for x in range(len(CRITERIA))]});assert r.status_code==303
    with db() as conn:ev=conn.execute('SELECT id FROM evaluations WHERE driver_id=?',(driver,)).fetchone()[0]
    assert i.post(f'/admin/review/{ev}',data={'csrf':ic,'decision':'confirmed','notes':'Looks complete'}).status_code==403
    assert a.post(f'/admin/review/{ev}',data={'csrf':ac,'decision':'confirmed','notes':'Independently verified record.'}).status_code==303
    assert a.post(f'/admin/review/{ev}',data={'csrf':ac,'decision':'confirmed','notes':'Duplicate review forbidden.'}).status_code==409
    with db() as conn:
        assert conn.execute('SELECT count(*) FROM reviews').fetchone()[0]==1
        assert conn.execute('SELECT count(*) FROM audit').fetchone()[0]>=7
    assert d.post('/logout',data={'csrf':dc}).status_code==303
    assert d.get('/dashboard').status_code==401

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
