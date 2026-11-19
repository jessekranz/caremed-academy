"""CareMed Academy secure pilot: server-side authorization, audit and instructor workflow.
Not a regulatory approval or an operational driver dispatch release system.
"""
import os, sqlite3, secrets, hashlib, hmac, json, re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from urllib.parse import quote
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

BASE=Path(__file__).resolve().parent.parent
DB=Path(os.getenv('CAREMED_DB', str(BASE/'data'/'academy.sqlite3')))
DB.parent.mkdir(parents=True, exist_ok=True)
SECURE=os.getenv('CAREMED_SECURE_COOKIES','1') != '0'
PH=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=2)
app=FastAPI(title='CareMed Academy secure pilot',docs_url=None,redoc_url=None,openapi_url=None)
app.mount('/assets',StaticFiles(directory=str(BASE/'site'/'assets')),name='assets')

def now():return datetime.now(timezone.utc).isoformat()
@contextmanager
def db():
    c=sqlite3.connect(DB,timeout=15);c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA busy_timeout=15000')
    try:yield c;c.commit()
    except Exception:c.rollback();raise
    finally:c.close()

def initdb():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('driver','instructor','admin')), password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, expires TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS modules(id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, answer_index INTEGER NOT NULL, choices TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('draft','approved')) DEFAULT 'draft', version INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), module_id INTEGER NOT NULL REFERENCES modules(id), module_version INTEGER NOT NULL, answer INTEGER NOT NULL, correct INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS bank_questions(id INTEGER PRIMARY KEY,module_id INTEGER NOT NULL REFERENCES modules(id),ordinal INTEGER NOT NULL,prompt TEXT NOT NULL,choices TEXT NOT NULL,answer_index INTEGER NOT NULL,rationale TEXT NOT NULL,UNIQUE(module_id,ordinal));
        CREATE TABLE IF NOT EXISTS scenario_attempts(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),scenario_id TEXT NOT NULL,answers_json TEXT NOT NULL,correct_count INTEGER NOT NULL,total_count INTEGER NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS bank_attempts(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),module_id INTEGER NOT NULL REFERENCES modules(id),module_version INTEGER NOT NULL,correct_count INTEGER NOT NULL,total_count INTEGER NOT NULL,answers_json TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS credentials(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL, reference TEXT NOT NULL, expires_on TEXT NOT NULL, verified_by INTEGER REFERENCES users(id), verified_at TEXT, status TEXT NOT NULL CHECK(status IN ('pending','verified','rejected')) DEFAULT 'pending', UNIQUE(user_id,kind));
        CREATE TABLE IF NOT EXISTS evaluations(id INTEGER PRIMARY KEY, driver_id INTEGER NOT NULL REFERENCES users(id), instructor_id INTEGER NOT NULL REFERENCES users(id), vehicle_reference TEXT NOT NULL, equipment_reference TEXT NOT NULL, checklist TEXT NOT NULL, critical_pass INTEGER NOT NULL, result TEXT NOT NULL CHECK(result IN ('pass','fail')), notes TEXT NOT NULL, observed_at TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, evaluation_id INTEGER NOT NULL UNIQUE REFERENCES evaluations(id), reviewer_id INTEGER NOT NULL REFERENCES users(id), decision TEXT NOT NULL CHECK(decision IN ('confirmed','rejected')), notes TEXT NOT NULL, reviewed_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL, subject TEXT NOT NULL, event TEXT NOT NULL, occurred_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_attempt_user ON attempts(user_id,module_id);
        CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit(subject);
        ''')
        if not c.execute('SELECT 1 FROM modules LIMIT 1').fetchone():
            curriculum=json.loads((BASE/'app'/'curriculum.json').read_text(encoding='utf-8'))
            for m in curriculum['modules']:
                body='\n\n'.join([m['intro']]+[f'{section[0]}: {section[1]}' for section in m['sections']])
                c.execute('INSERT INTO modules(id,title,body,answer_index,choices,status,version) VALUES(?,?,?,?,?,?,1)',(m['n'],m['title'],body,m['q'][0][2],json.dumps(m['q'][0][1]),'draft'))
                for n,q in enumerate(m['q']):
                    c.execute('INSERT INTO bank_questions(module_id,ordinal,prompt,choices,answer_index,rationale) VALUES(?,?,?,?,?,?)',(m['n'],n,q[0],json.dumps(q[1]),q[2],q[3]))

initdb()

def audit(c,uid,action,subject,event):
    c.execute('INSERT INTO audit(actor_id,action,subject,event,occurred_at) VALUES(?,?,?,?,?)',(uid,action,subject,event,now()))

def user_session(request):
    token=request.cookies.get('caremed_session')
    if not token:return None,None
    digest=hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        row=c.execute('SELECT s.csrf,s.expires,u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND u.active=1',(digest,)).fetchone()
    if not row or datetime.fromisoformat(row['expires']) <= datetime.now(timezone.utc):return None,None
    return dict(row),digest

def require(request,roles=None):
    u,digest=user_session(request)
    if not u:raise HTTPException(401,'Login required')
    if roles and u['role'] not in roles:raise HTTPException(403,'Insufficient permissions')
    return u

def verify_csrf(request,u,csrf):
    if not csrf or not hmac.compare_digest(u['csrf'],csrf):raise HTTPException(403,'Invalid CSRF token')
    origin=request.headers.get('origin')
    if origin:
        from urllib.parse import urlsplit
        parsed=urlsplit(origin)
        if parsed.netloc != request.url.netloc or parsed.scheme != request.url.scheme:raise HTTPException(403,'Cross-origin submission denied')

def e(text):
    from html import escape
    return escape(str(text),quote=True)

def page(title,body,u=None):
    who=f'<div class="who">{e(u["name"])} · {e(u["role"])} <form method="post" action="/logout"><input type="hidden" name="csrf" value="{e(u["csrf"])}"><button class="ghost">Sign out</button></form></div>' if u else ''
    nav=('<nav><a href="/dashboard">Dashboard</a><a href="/courses">Courses</a><a href="/simulations">Simulations</a><a href="/credentials">Credentials</a><a href="/evaluations">Evaluations</a><a href="/media">Media & manuals</a><a href="/account">Account security</a>' + ('<a href="/admin">Management</a>' if u['role']=='admin' else '')+'</nav>') if u else ''
    return HTMLResponse(f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><link rel="icon" href="/assets/images/favicon.svg"><link rel="stylesheet" href="/portal.css"><title>{e(title)} · CareMed Academy</title></head><body><header><div class="top"><a href="/dashboard" class="logo">✦ Care<span>Med</span> <small>DRIVER ACADEMY</small></a>{who}</div>{nav}</header><main>{body}</main><footer>Secure pilot · Training content is DRAFT, not manufacturer-approved or HFS-approved. No dispatch authorization is issued by this system.</footer></body></html>''',headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'X-Frame-Options':'DENY'})

def msg(s):return '<p class="notice">'+e(s)+'</p>'
def field(name,label,value='',kind='text',extra=''):
    return f'<label>{e(label)}<input name="{e(name)}" type="{e(kind)}" value="{e(value)}" required {extra}></label>'
def cs(u):return '<input type="hidden" name="csrf" value="'+e(u['csrf'])+'">'
def card(title,contents):return f'<section class="card"><h2>{e(title)}</h2>{contents}</section>'
def redirect(to):return RedirectResponse(to,status_code=303)

@app.get('/portal.css')
def css():return FileResponse(BASE/'app'/'portal.css',media_type='text/css',headers={'Cache-Control':'public, max-age=3600'})
@app.get('/')
def root():return redirect('/dashboard')
@app.get('/login')
def login_form(request:Request):
    if user_session(request)[0]:return redirect('/dashboard')
    return page('Sign in','<div class="narrow">'+card('Secure sign in','<p>Use the employee account created by your CareMed administrator.</p><form action="/login" method="post">'+field('email','Work email',kind='email',extra='autocomplete="username"')+field('password','Password',kind='password',extra='autocomplete="current-password"')+'<button>Sign in</button></form>')+'</div>')
@app.post('/login')
def login(request:Request,email:str=Form(...),password:str=Form(...)):
    with db() as c:
        row=c.execute('SELECT * FROM users WHERE email=? AND active=1',(email.strip().lower(),)).fetchone()
        ok=False
        if row:
            try:ok=PH.verify(row['password_hash'],password)
            except (VerifyMismatchError,VerificationError):pass
        if not ok:
            audit(c,row['id'] if row else None,'login_failed','account', 'Rejected authentication')
            return page('Sign in',msg('Invalid email or password.')+'<p><a href="/login">Try again</a></p>')
        token=secrets.token_urlsafe(40);digest=hashlib.sha256(token.encode()).hexdigest();csrf=secrets.token_urlsafe(32)
        exp=(datetime.now(timezone.utc)+timedelta(hours=8)).isoformat()
        c.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires) VALUES(?,?,?,?)',(digest,row['id'],csrf,exp))
        audit(c,row['id'],'login','account','Successful authentication')
    response=redirect('/dashboard');response.set_cookie('caremed_session',token,secure=SECURE,httponly=True,samesite='strict',max_age=28800,path='/');return response
@app.post('/logout')
def logout(request:Request,csrf:str=Form(...)):
    u,digest=user_session(request)
    if u:
        verify_csrf(request,u,csrf)
        with db() as c:c.execute('DELETE FROM sessions WHERE token_hash=?',(digest,));audit(c,u['id'],'logout','account','Session terminated')
    response=redirect('/login');response.delete_cookie('caremed_session',path='/');return response

@app.get('/dashboard')
def dashboard(request:Request):
    u=require(request)
    with db() as c:
        passed=c.execute('SELECT count(distinct a.module_id) n FROM bank_attempts a JOIN modules m ON m.id=a.module_id WHERE a.user_id=? AND a.correct_count=a.total_count AND a.module_version=m.version AND m.status="approved"',(u['id'],)).fetchone()['n']
        approved=c.execute('SELECT count(*) n FROM modules WHERE status="approved"').fetchone()['n']
        pending=c.execute('SELECT count(*) n FROM evaluations e LEFT JOIN reviews r ON r.evaluation_id=e.id WHERE r.id IS NULL').fetchone()['n'] if u['role']!='driver' else 0
    body='<div class="hero"><div><div class="eyebrow">CARED FOR. TRAINED WELL.</div><h1>Every ride begins with trust.</h1><p>Role-based training, credential checks and independently reviewed practical evaluations for Illinois accessible transportation.</p><a class="button" href="/courses">Explore training →</a></div><img src="/assets/images/caremed-hero.webp" alt="Illustrative accessible van and passenger at a clinic"></div>'
    body+='<div class="stats">'+card('Approved course completions',f'<div class="big">{passed} / {approved}</div><p>Draft lessons do not count toward qualification.</p>')+card('Your role',f'<div class="big">{e(u["role"].title())}</div><p>Access is enforced on the server.</p>')+card('Awaiting secondary review',f'<div class="big">{pending}</div><p>Instructor and admin approvals are independently recorded.</p>')+'</div>'
    body+=card('Qualification status',msg('NOT CLEARED FOR DISPATCH. CareMed has not approved the final curriculum, equipment manuals, manufacturer videos or operational authorization requirements. This system deliberately does not issue dispatch clearance.'))
    return page('Dashboard',body,u)

@app.get('/courses')
def courses(request:Request):
    u=require(request)
    with db() as c:rows=c.execute('SELECT * FROM modules ORDER BY id').fetchall()
    body='<h1>Learning paths</h1><p>Training content is in editorial review. Draft lessons are accessible for evaluation but do not count as approved completions.</p><div class="grid">'
    for m in rows:
        body+=card(m['title'],f'<p>{e(m["body"].split("\n")[0])}</p><span class="tag">{e(m["status"].upper())} · v{m["version"]}</span><p><a class="button" href="/courses/{m["id"]}">Open lesson →</a></p>')
    return page('Courses',body+'</div>',u)
@app.get('/courses/{module_id}')
def course(request:Request,module_id:int):
    u=require(request)
    with db() as c:m=c.execute('SELECT * FROM modules WHERE id=?',(module_id,)).fetchone()
    if not m:raise HTTPException(404)
    body=f'<a href="/courses">← All lessons</a><h1>{e(m["title"])}</h1><p class="tag">{e(m["status"].upper())} · Version {m["version"]}</p><div class="card">'+''.join(f'<p>{e(part)}</p>' for part in m['body'].split('\n\n'))
    if module_id in (2,3):body+='<img class="illustration" src="/assets/images/vehicle-orientation.svg" alt="Conceptual rear-entry van diagram. Not operating instructions.">'
    if module_id in (2,3,4):
        vid='ramp-briefing' if module_id in (2,3) else 'securement-briefing'
        body+=f'<video controls preload="metadata" poster="/assets/images/academy-video-poster.webp"><source src="/assets/videos/{vid}.mp4" type="video/mp4"></video><p class="muted">12-second conceptual briefing, NOT manufacturer-approved demonstration.</p>'
    choices=json.loads(m['choices']);q=m['body'].split('Knowledge check: ')[-1]
    with db() as c: questions=c.execute('SELECT * FROM bank_questions WHERE module_id=? ORDER BY ordinal',(module_id,)).fetchall()
    body+=f'<h2>Three-question knowledge check</h2><form action="/courses/{module_id}/answer" method="post">'+cs(u)
    for question in questions:
        body+=f'<fieldset><legend>{question["ordinal"]+1}. {e(question["prompt"])}</legend>'
        for i,choice in enumerate(json.loads(question['choices'])):
            body+=f'<label class="radio"><input type="radio" name="answer_{question["ordinal"]}" value="{i}" required> {e(choice)}</label>'
        body+='</fieldset>'
    body+='<button>Submit response</button></form></div>'
    return page(m['title'],body,u)
@app.post('/courses/{module_id}/answer')
async def answer(request:Request,module_id:int):
    u=require(request);form=await request.form();verify_csrf(request,u,str(form.get('csrf','')))
    with db() as c:
        m=c.execute('SELECT * FROM modules WHERE id=?',(module_id,)).fetchone()
        if not m:raise HTTPException(404)
        questions=c.execute('SELECT * FROM bank_questions WHERE module_id=? ORDER BY ordinal',(module_id,)).fetchall()
        answers=[];feedback=[];correct=0
        for q in questions:
            try:chosen=int(str(form[f'answer_{q["ordinal"]}']))
            except (ValueError,KeyError):raise HTTPException(400,'Missing or invalid answer')
            if chosen not in range(len(json.loads(q['choices']))):raise HTTPException(400)
            success=chosen==q['answer_index'];correct+=int(success);answers.append(chosen)
            feedback.append(f'<li><b>Question {q["ordinal"]+1}: {"Correct" if success else "Needs review"}.</b> {e(q["rationale"])}</li>')
        c.execute('INSERT INTO bank_attempts(user_id,module_id,module_version,correct_count,total_count,answers_json,created_at) VALUES(?,?,?,?,?,?,?)',(u['id'],module_id,m['version'],correct,len(questions),json.dumps(answers),now()))
        audit(c,u['id'],'module_assessment',f'module:{module_id}',f'v{m["version"]}, score={correct}/{len(questions)}, status={m["status"]}')
    label=f'Score: {correct} / {len(questions)}. ' + ('All answers correct.' if correct==len(questions) else 'Review and retake the lesson.')
    if m['status']!='approved':label+=' This draft lesson does not count toward approved completion.'
    return page('Knowledge check',card('Assessment result',msg(label)+'<ol>'+''.join(feedback)+'</ol>'+f'<p><a class="button" href="/courses/{module_id}">Return to lesson</a></p>'),u)

@app.get('/credentials')
def credentials(request:Request):
    u=require(request)
    with db() as c:
        rows=c.execute('SELECT x.*,v.name verifier FROM credentials x LEFT JOIN users v ON v.id=x.verified_by WHERE x.user_id=? ORDER BY x.kind',(u['id'],)).fetchall()
    body='<h1>Credential registry</h1><p>Driver licenses and HFS certificates must be verified by an administrator. Do not enter patient information.</p>'
    for x in rows:body+=card(x['kind'],f'<p>Reference: {e(x["reference"])} · Expires: {e(x["expires_on"])} · Status: <b>{e(x["status"])}</b></p><p>Verified by: {e(x["verifier"] or "Not yet verified")}</p>')
    body+=card('Submit credential for review','<form method="post" action="/credentials">'+cs(u)+'<label>Credential type<select name="kind"><option value="driver_license">Driver license</option><option value="hfs_safety">HFS-approved safety training</option><option value="local_license">Local chauffeur / permit</option><option value="cpr">CPR / AED (where required by policy)</option></select></label>'+field('reference','Certificate or license reference')+field('expires_on','Expiration date',kind='date')+'<button>Submit for verification</button></form>')
    return page('Credentials',body,u)
@app.post('/credentials')
def credentials_post(request:Request,csrf:str=Form(...),kind:str=Form(...),reference:str=Form(...),expires_on:str=Form(...)):
    u=require(request);verify_csrf(request,u,csrf)
    if kind not in {'driver_license','hfs_safety','local_license','cpr'} or not (2<=len(reference.strip())<=120) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}',expires_on):raise HTTPException(400)
    try:datetime.strptime(expires_on,'%Y-%m-%d')
    except ValueError:raise HTTPException(400)
    with db() as c:
        c.execute('INSERT INTO credentials(user_id,kind,reference,expires_on,status,verified_by,verified_at) VALUES(?,?,?,?,"pending",NULL,NULL) ON CONFLICT(user_id,kind) DO UPDATE SET reference=excluded.reference,expires_on=excluded.expires_on,status="pending",verified_by=NULL,verified_at=NULL',(u['id'],kind,reference.strip(),expires_on))
        audit(c,u['id'],'credential_submitted',f'user:{u["id"]}',kind)
    return redirect('/credentials')

CRITERIA=['Vehicle parked and secured on appropriate surface','Environment and ramp clearance assessed','Conversion/ramp identified by manual and serial','Ramp inspected according to exact maker instructions','Passenger consulted and consent obtained','Wheelchair handled within documented limitations','Approved wheelchair securement points identified','Four-point or installed approved securement correctly demonstrated','Occupant lap and shoulder restraints correctly demonstrated','Final restraint safety confirmation','Safe unloading demonstrated','Appropriate emergency escalation demonstrated']
@app.get('/evaluations')
def evaluations(request:Request):
    u=require(request)
    with db() as c:
        if u['role']=='driver':
            rows=c.execute('SELECT e.*,i.name instructor,r.decision FROM evaluations e JOIN users i ON i.id=e.instructor_id LEFT JOIN reviews r ON r.evaluation_id=e.id WHERE driver_id=? ORDER BY e.id DESC',(u['id'],)).fetchall()
        else:rows=c.execute('SELECT e.*,d.name driver,i.name instructor,r.decision FROM evaluations e JOIN users d ON d.id=e.driver_id JOIN users i ON i.id=e.instructor_id LEFT JOIN reviews r ON r.evaluation_id=e.id ORDER BY e.id DESC LIMIT 100').fetchall()
    body='<h1>Observed practical examinations</h1><p>Only instructors may submit observed evaluations. A different administrator must independently review the result.</p>'
    for x in rows:
        who=x['driver'] if 'driver' in x.keys() else u['name']
        body+=card(f'Evaluation #{x["id"]} · {who}',f'<p>Instructor: {e(x["instructor"])} · Result: {e(x["result"].upper())} · Review: {e(x["decision"] or "AWAITING REVIEW")}</p><p>Vehicle: {e(x["vehicle_reference"])} · Equipment: {e(x["equipment_reference"])}</p>')
    if u['role']=='instructor':
        with db() as c:drivers=c.execute('SELECT id,name,email FROM users WHERE role="driver" AND active=1 ORDER BY name').fetchall()
        opts=''.join(f'<option value="{x["id"]}">{e(x["name"])} ({e(x["email"])})</option>' for x in drivers)
        form='<form action="/evaluations" method="post">'+cs(u)+f'<label>Driver<select name="driver_id" required>{opts}</select></label>'+field('vehicle_reference','Vehicle VIN or fleet identifier')+field('equipment_reference','Actual ramp + tie-down make/model/serial')+field('observed_at','Observed date',kind='date')
        form+='<fieldset><legend>Observed competencies (mark only when personally witnessed)</legend>'
        for i,t in enumerate(CRITERIA):form+=f'<label class="radio"><input type="checkbox" name="checks" value="{i}"> {e(t)}</label>'
        form+='</fieldset><label class="radio"><input type="checkbox" name="critical_pass" value="1"> I personally observed all critical safety steps and no critical failure occurred.</label><label>Assessment decision<select name="result"><option value="fail">Fail / requires remediation</option><option value="pass">Pass (only if all competencies demonstrated)</option></select></label><label>Observed details and remediation<textarea name="notes" required minlength="20" maxlength="3000"></textarea></label><button>Sign and submit observation</button></form>'
        body+=card('New practical observation',form)
    return page('Evaluations',body,u)
@app.post('/evaluations')
async def evaluations_post(request:Request):
    u=require(request,{'instructor'});form=await request.form();verify_csrf(request,u,str(form.get('csrf','')))
    try:driver_id=int(form['driver_id']);checks={int(x) for x in form.getlist('checks')};observed_at=datetime.strptime(str(form['observed_at']),'%Y-%m-%d').date().isoformat()
    except (KeyError,ValueError):raise HTTPException(400)
    if any(x not in range(len(CRITERIA)) for x in checks):raise HTTPException(400)
    result=str(form.get('result','fail'));critical=str(form.get('critical_pass',''))=='1'
    vehicle=str(form.get('vehicle_reference','')).strip();equipment=str(form.get('equipment_reference','')).strip();notes=str(form.get('notes','')).strip()
    if len(vehicle)<3 or len(equipment)<5 or not 20<=len(notes)<=3000 or result not in {'pass','fail'}:raise HTTPException(400)
    if result=='pass' and (not critical or len(checks)!=len(CRITERIA)):raise HTTPException(400,'Cannot pass without every competency and critical-safety confirmation')
    with db() as c:
        driver=c.execute('SELECT id FROM users WHERE id=? AND role="driver" AND active=1',(driver_id,)).fetchone()
        if not driver:raise HTTPException(400,'Invalid driver')
        cur=c.execute('INSERT INTO evaluations(driver_id,instructor_id,vehicle_reference,equipment_reference,checklist,critical_pass,result,notes,observed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(driver_id,u['id'],vehicle,equipment,json.dumps(sorted(checks)),int(critical),result,notes,observed_at,now()))
        audit(c,u['id'],'evaluation_signed',f'evaluation:{cur.lastrowid}',f'Observed result: {result}; vehicle={vehicle}; complete={len(checks)}')
    return redirect('/evaluations')

@app.get('/admin')
def admin(request:Request):
    u=require(request,{'admin'})
    with db() as c:
        users=c.execute('SELECT id,email,name,role,active FROM users ORDER BY id DESC LIMIT 100').fetchall()
        pending=c.execute('SELECT x.*,u.name driver FROM credentials x JOIN users u ON u.id=x.user_id WHERE x.status="pending" ORDER BY x.id').fetchall()
        reviews=c.execute('SELECT e.*,d.name driver,i.name instructor FROM evaluations e JOIN users d ON d.id=e.driver_id JOIN users i ON i.id=e.instructor_id LEFT JOIN reviews r ON r.evaluation_id=e.id WHERE r.id IS NULL ORDER BY e.id').fetchall()
        mods=c.execute('SELECT id,title,status,version FROM modules ORDER BY id').fetchall()
        logs=c.execute('SELECT a.*,u.email FROM audit a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 35').fetchall()
    body='<h1>Administration & approval</h1>'+msg('The platform intentionally does not issue driver dispatch authorization or state/manufacturer certification.')
    body+=card('Add employee','<form method="post" action="/admin/users">'+cs(u)+field('name','Name')+field('email','Email',kind='email')+field('password','Temporary password (share securely; require change before production)',kind='password',extra='minlength="14"')+'<label>Role<select name="role"><option value="driver">Driver</option><option value="instructor">Instructor</option><option value="admin">Administrator</option></select></label><button>Create account</button></form>')
    body+=card('Users','<div class="tablewrap"><table><tr><th>Name</th><th>Email</th><th>Role</th><th>Active</th></tr>'+''.join(f'<tr><td>{e(x["name"])}</td><td>{e(x["email"])}</td><td>{e(x["role"])}</td><td>{"Yes" if x["active"] else "No"}</td></tr>' for x in users)+'</table></div>')
    forms=''
    for x in pending:
        forms+=f'<form method="post" action="/admin/credential/{x["id"]}">'+cs(u)+f'<b>{e(x["driver"])} · {e(x["kind"])}</b><p>Reference: {e(x["reference"])} · Expires {e(x["expires_on"])}</p><label>Decision<select name="decision"><option value="rejected">Reject</option><option value="verified">Verify (after independently checking original)</option></select></label><button>Record decision</button></form>'
    body+=card('Pending credential verification',forms or '<p>No pending credentials.</p>')
    review_forms=''
    for x in reviews:
        review_forms+=f'<form action="/admin/review/{x["id"]}" method="post">'+cs(u)+f'<b>{e(x["driver"])} · Evaluation #{x["id"]}</b><p>Instructor: {e(x["instructor"])} · Result: {e(x["result"])} · Vehicle: {e(x["vehicle_reference"])} · Equipment: {e(x["equipment_reference"])}</p><p>Observed: {e(x["observed_at"])} · Criteria checked: {len(json.loads(x["checklist"]))}/{len(CRITERIA)} · Critical pass: {bool(x["critical_pass"])}</p><p>Notes: {e(x["notes"])}</p><label>Independent review<select name="decision"><option value="rejected">Reject</option><option value="confirmed">Confirm observed record</option></select></label><label>Review notes<textarea name="notes" required minlength="10" maxlength="2000"></textarea></label><button>Sign review</button></form>'
    body+=card('Instructor observations awaiting independent review',review_forms or '<p>No observations awaiting review.</p>')
    module_forms=''
    for m in mods:
        module_forms+=f'<form class="inlineform" action="/admin/modules/{m["id"]}" method="post">'+cs(u)+f'<span>{e(m["title"])} · v{m["version"]} · <b>{e(m["status"])}</b></span><select name="status"><option value="draft">Draft</option><option value="approved" {"selected" if m["status"]=="approved" else ""}>Approved internal content</option></select><button>Update</button></form>'
    body+=card('Internal lesson publication (not external approval)',module_forms)
    body+=card('Recent audit activity','<div class="tablewrap"><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Subject</th></tr>'+''.join(f'<tr><td>{e(x["occurred_at"][:19])}</td><td>{e(x["email"] or "Unknown")}</td><td>{e(x["action"])}</td><td>{e(x["subject"])}</td></tr>' for x in logs)+'</table></div>')
    return page('Administration',body,u)
@app.post('/admin/users')
def add_user(request:Request,csrf:str=Form(...),name:str=Form(...),email:str=Form(...),password:str=Form(...),role:str=Form(...)):
    u=require(request,{'admin'});verify_csrf(request,u,csrf)
    if role not in {'driver','instructor','admin'} or len(password)<14 or len(password)>256 or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email.strip()) or not 2<=len(name.strip())<=80:raise HTTPException(400)
    with db() as c:
        try:cur=c.execute('INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)',(email.strip().lower(),name.strip(),role,PH.hash(password),now()))
        except sqlite3.IntegrityError:raise HTTPException(409,'Account already exists')
        audit(c,u['id'],'user_created',f'user:{cur.lastrowid}',f'role={role}')
    return redirect('/admin')
@app.post('/admin/credential/{credential_id}')
def verify_credential(request:Request,credential_id:int,csrf:str=Form(...),decision:str=Form(...)):
    u=require(request,{'admin'});verify_csrf(request,u,csrf)
    if decision not in {'verified','rejected'}:raise HTTPException(400)
    with db() as c:
        x=c.execute('SELECT * FROM credentials WHERE id=? AND status="pending"',(credential_id,)).fetchone()
        if not x:raise HTTPException(404)
        if x['user_id']==u['id']:raise HTTPException(403,'No self-verification')
        c.execute('UPDATE credentials SET status=?,verified_by=?,verified_at=? WHERE id=?',(decision,u['id'],now(),credential_id))
        audit(c,u['id'],'credential_'+decision,f'credential:{credential_id}',f'owner={x["user_id"]}')
    return redirect('/admin')
@app.post('/admin/review/{eval_id}')
def admin_review(request:Request,eval_id:int,csrf:str=Form(...),decision:str=Form(...),notes:str=Form(...)):
    u=require(request,{'admin'});verify_csrf(request,u,csrf)
    if decision not in {'confirmed','rejected'} or not 10<=len(notes.strip())<=2000:raise HTTPException(400)
    with db() as c:
        x=c.execute('SELECT * FROM evaluations WHERE id=?',(eval_id,)).fetchone()
        if not x:raise HTTPException(404)
        if x['instructor_id']==u['id'] or x['driver_id']==u['id']:raise HTTPException(403,'Independent reviewer required')
        if decision=='confirmed' and x['result']=='pass' and (not x['critical_pass'] or len(json.loads(x['checklist']))!=len(CRITERIA)):raise HTTPException(400)
        try:c.execute('INSERT INTO reviews(evaluation_id,reviewer_id,decision,notes,reviewed_at) VALUES(?,?,?,?,?)',(eval_id,u['id'],decision,notes.strip(),now()))
        except sqlite3.IntegrityError:raise HTTPException(409,'Already reviewed')
        audit(c,u['id'],'evaluation_review',f'evaluation:{eval_id}',f'decision={decision}')
    return redirect('/admin')
@app.post('/admin/modules/{module_id}')
def admin_module(request:Request,module_id:int,csrf:str=Form(...),status:str=Form(...)):
    u=require(request,{'admin'});verify_csrf(request,u,csrf)
    if status not in {'draft','approved'}:raise HTTPException(400)
    with db() as c:
        m=c.execute('SELECT * FROM modules WHERE id=?',(module_id,)).fetchone()
        if not m:raise HTTPException(404)
        if m['status']!=status:
            c.execute('UPDATE modules SET status=?,version=version+1 WHERE id=?',(status,module_id))
            audit(c,u['id'],'module_status',f'module:{module_id}',f'{m["status"]}->{status}; new version {m["version"]+1}')
    return redirect('/admin')

@app.get('/healthz')
def healthz():return {'status':'ok'}

@app.get('/media')
def media_library(request:Request):
    u=require(request)
    videos=[('Ramp safety orientation','ramp-briefing','Conceptual only. Do not use for ramp operation.'),('Restraint system awareness','securement-briefing','Not a manufacturer-approved tie-down demonstration.'),('Winter surface awareness','winter-briefing','Risk awareness, not a substitute for supervised practical training.')]
    body='<h1>Media and manufacturer reference center</h1>'+msg('These three short CareMed clips are editorial placeholders. No full-length manufacturer-approved CareMed videos have been filmed or authorized yet.')
    for title,file,desc in videos:
        body+=card(title,f'<video controls preload="metadata" poster="/assets/images/academy-video-poster.webp"><source src="/assets/videos/{file}.mp4" type="video/mp4"></video><p>{e(desc)}</p>')
    refs=[('Illinois HFS Safety Training','https://hfs.illinois.gov/impact/safetytraining.html'),('BraunAbility commercial Sienna reference · verify conversion first','https://www.braunability.com/us/en/commercial/mobility-products/wheelchair-vans/rear-entry-toyota-sienna-hybrid-wheelchair-minivan.html'),('VMI Sienna manual reference · verify conversion first','https://www.vantagemobility.com/wp-content/uploads/2024/05/Toyota_RearEntry_2024_OwnersManual_FINAL.pdf'),('Q’STRAINT manufacturer securement training · verify WTORS first','https://training.qstraint.com/aqademy-overview/')]
    body+=card('Manufacturer and regulatory resources','<p>External sites are references only; no implied endorsement or approval.</p><ul>'+''.join(f'<li><a href="{e(url)}" rel="noopener noreferrer" target="_blank">{e(name)}</a></li>' for name,url in refs)+'</ul>')
    return page('Media and manuals',body,u)

@app.get('/account')
def account(request:Request):
    u=require(request)
    return page('Account security','<h1>Account security</h1>'+card('Change password','<form action="/account/password" method="post">'+cs(u)+field('old_password','Current password',kind='password')+field('new_password','New password (14+ characters)',kind='password',extra='minlength="14"')+'<button>Change password and sign out everywhere</button></form>'),u)
@app.post('/account/password')
def password_change(request:Request,csrf:str=Form(...),old_password:str=Form(...),new_password:str=Form(...)):
    u=require(request);verify_csrf(request,u,csrf)
    if not 14<=len(new_password)<=256 or new_password==old_password:raise HTTPException(400,'Password must be new and 14+ characters')
    try:old_ok=PH.verify(u['password_hash'],old_password)
    except (VerifyMismatchError,VerificationError):old_ok=False
    if not old_ok:raise HTTPException(403,'Current password does not match')
    with db() as c:
        c.execute('UPDATE users SET password_hash=? WHERE id=?',(PH.hash(new_password),u['id']))
        c.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
        audit(c,u['id'],'password_changed',f'user:{u["id"]}','All sessions revoked')
    response=redirect('/login');response.delete_cookie('caremed_session',path='/');return response

@app.get('/simulations')
def simulations(request:Request):
    u=require(request)
    bank=json.loads((BASE/'app'/'curriculum.json').read_text(encoding='utf-8'))['simulations']
    body='<h1>Decision laboratory</h1><p>Five realistic scenarios. Select one response per decision. These are learning exercises, not clinical advice or a manufacturer operating procedure.</p><div class="grid">'
    for item in bank:
        body+=card(item['title'],f'<p>{e(item["sub"])}</p><p>{len(item["steps"])} decisions</p><a class="button" href="/simulations/{e(item["id"])}">Start scenario →</a>')
    return page('Simulations',body+'</div>',u)
@app.get('/simulations/{scenario_id}')
def simulation(request:Request,scenario_id:str):
    u=require(request)
    scenarios=json.loads((BASE/'app'/'curriculum.json').read_text(encoding='utf-8'))['simulations']
    item=next((x for x in scenarios if x['id']==scenario_id),None)
    if not item:raise HTTPException(404)
    body=f'<a href="/simulations">← All scenarios</a><h1>{e(item["title"])}</h1><p>{e(item["sub"])}</p><form action="/simulations/{e(item["id"])}" method="post">'+cs(u)
    for index,step in enumerate(item['steps']):
        body+=f'<fieldset class="card"><legend>{index+1}. {e(step["p"])}</legend>'
        for j,choice in enumerate(step['options']):body+=f'<label class="radio"><input type="radio" name="choice_{index}" value="{j}" required> {e(choice[0])}</label>'
        body+='</fieldset>'
    return page(item['title'],body+'<button>Submit decisions</button></form>',u)
@app.post('/simulations/{scenario_id}')
async def simulation_submit(request:Request,scenario_id:str):
    u=require(request);form=await request.form();verify_csrf(request,u,str(form.get('csrf','')))
    scenarios=json.loads((BASE/'app'/'curriculum.json').read_text(encoding='utf-8'))['simulations']
    item=next((x for x in scenarios if x['id']==scenario_id),None)
    if not item:raise HTTPException(404)
    answers=[];correct=0;details=[]
    for n,step in enumerate(item['steps']):
        try:answer=int(str(form[f'choice_{n}']))
        except (KeyError,ValueError):raise HTTPException(400)
        if answer not in range(len(step['options'])):raise HTTPException(400)
        option=step['options'][answer];answers.append(answer);correct+=int(bool(option[1]));details.append(f'<li><b>Decision {n+1}: {"Safe" if option[1] else "Needs review"}</b><p>{e(option[2])}</p></li>')
    with db() as c:
        c.execute('INSERT INTO scenario_attempts(user_id,scenario_id,answers_json,correct_count,total_count,created_at) VALUES(?,?,?,?,?,?)',(u['id'],scenario_id,json.dumps(answers),correct,len(item['steps']),now()))
        audit(c,u['id'],'scenario_completed',f'scenario:{scenario_id}',f'{correct}/{len(item["steps"])} safe decisions')
    return page('Scenario result',card(item['title'],msg(f'{correct} of {len(item["steps"])} safety decisions correct. This is a practice assessment, not a verified practical skill.')+'<ol>'+''.join(details)+'</ol><p><a href="/simulations">Return to simulations</a></p>'),u)
