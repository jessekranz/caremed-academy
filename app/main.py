"""CareMed Academy secure pilot: server-side authorization, audit and instructor workflow.
Includes a pilot-gated check for current CareMed transport eligibility.
"""
import os, sqlite3, secrets, hashlib, hmac, json, re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from urllib.parse import quote
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from app.onboarding import CREDENTIALS, SCHEMA, STAGES, driver_state, fingerprint, illinois_date, illinois_now, illinois_today

BASE=Path(__file__).resolve().parent.parent
DB=Path(os.getenv('CAREMED_DB', str(BASE/'data'/'academy.sqlite3')))
DB.parent.mkdir(parents=True, exist_ok=True)
SECURE=os.getenv('CAREMED_SECURE_COOKIES','1') != '0'
TRANSPORT_ENABLED=os.getenv('CAREMED_TRANSPORT_ENABLED') == '1'
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
        CREATE TABLE IF NOT EXISTS exam_questions(id INTEGER PRIMARY KEY,module_id INTEGER NOT NULL REFERENCES modules(id),ordinal INTEGER NOT NULL,prompt TEXT NOT NULL,choices TEXT NOT NULL,answer_index INTEGER NOT NULL,rationale TEXT NOT NULL,UNIQUE(module_id,ordinal));
        CREATE TABLE IF NOT EXISTS scenario_attempts(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),scenario_id TEXT NOT NULL,answers_json TEXT NOT NULL,correct_count INTEGER NOT NULL,total_count INTEGER NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS bank_attempts(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),module_id INTEGER NOT NULL REFERENCES modules(id),module_version INTEGER NOT NULL,correct_count INTEGER NOT NULL,total_count INTEGER NOT NULL,answers_json TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS credentials(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL, reference TEXT NOT NULL, expires_on TEXT NOT NULL, verified_by INTEGER REFERENCES users(id), verified_at TEXT, status TEXT NOT NULL CHECK(status IN ('pending','verified','rejected')) DEFAULT 'pending', UNIQUE(user_id,kind));
        CREATE TABLE IF NOT EXISTS evaluations(id INTEGER PRIMARY KEY, driver_id INTEGER NOT NULL REFERENCES users(id), instructor_id INTEGER NOT NULL REFERENCES users(id), vehicle_reference TEXT NOT NULL, equipment_reference TEXT NOT NULL, checklist TEXT NOT NULL, critical_pass INTEGER NOT NULL, result TEXT NOT NULL CHECK(result IN ('pass','fail')), notes TEXT NOT NULL, observed_at TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, evaluation_id INTEGER NOT NULL UNIQUE REFERENCES evaluations(id), reviewer_id INTEGER NOT NULL REFERENCES users(id), decision TEXT NOT NULL CHECK(decision IN ('confirmed','rejected')), notes TEXT NOT NULL, reviewed_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL, subject TEXT NOT NULL, event TEXT NOT NULL, occurred_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_attempt_user ON attempts(user_id,module_id);
        CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit(subject);
        CREATE TABLE IF NOT EXISTS login_failures(id INTEGER PRIMARY KEY, who TEXT NOT NULL, occurred_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_login_failures ON login_failures(who,occurred_at);
        ''')
        c.executescript(SCHEMA)
        curriculum=json.loads((BASE/'app'/'curriculum.json').read_text(encoding='utf-8'))
        if not c.execute('SELECT 1 FROM modules LIMIT 1').fetchone():
            for m in curriculum['modules']:
                body='\n\n'.join([m['intro']]+[f'{section[0]}: {section[1]}' for section in m['sections']])
                c.execute('INSERT INTO modules(id,title,body,answer_index,choices,status,version) VALUES(?,?,?,?,?,?,1)',(m['n'],m['title'],body,m['q'][0][2],json.dumps(m['q'][0][1]),'draft'))
                for n,q in enumerate(m['q']):
                    c.execute('INSERT INTO bank_questions(module_id,ordinal,prompt,choices,answer_index,rationale) VALUES(?,?,?,?,?,?)',(m['n'],n,q[0],json.dumps(q[1]),q[2],q[3]))
        # The written exam has its own question bank, separate from the lesson quizzes.
        if not c.execute('SELECT 1 FROM exam_questions LIMIT 1').fetchone():
            ordinals={}
            for item in curriculum.get('exam',[]):
                q=item['q'];ordinal=ordinals.get(item['n'],0);ordinals[item['n']]=ordinal+1
                c.execute('INSERT INTO exam_questions(module_id,ordinal,prompt,choices,answer_index,rationale) VALUES(?,?,?,?,?,?)',(item['n'],ordinal,q[0],json.dumps(q[1]),q[2],q[3]))

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
    nav=('<nav><a href="/dashboard">Dashboard</a><a href="/courses">Courses</a><a href="/simulations">Simulations</a>' + ('<a href="/credentials">Credentials</a>' if u['role']=='driver' else '') + '<a href="/evaluations">Evaluations</a><a href="/media">Media & manuals</a><a href="/account">Account security</a>' + ('<a href="/admin">Management</a>' if u['role']=='admin' else '')+'</nav>') if u else ''
    return HTMLResponse(f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><link rel="icon" type="image/png" href="/assets/images/favicon.png"><link rel="apple-touch-icon" href="/assets/images/apple-touch-icon.png"><link rel="stylesheet" href="/portal.css"><title>{e(title)} · CareMed Academy</title></head><body><header><div class="top"><a href="/dashboard" class="logo"><img src="/assets/images/caremed-driver-logo.png" width="52" height="55" alt="CareMed Rides Driver"> <small>DRIVER ACADEMY</small></a>{who}</div>{nav}</header><main>{body}</main><footer>Secure pilot · Training content is DRAFT, not manufacturer-approved or HFS-approved. {'Transport authorization enabled.' if TRANSPORT_ENABLED else 'Transport authorization disabled in this pilot.'}</footer></body></html>''',headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'X-Frame-Options':'DENY'})

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
MAX_FAILURES=5
FAILURE_WINDOW=timedelta(minutes=15)
def client_address(request):
    return request.client.host if request.client else 'unknown'
def login_keys(email,request):
    return ('email:'+hashlib.sha256(email.encode()).hexdigest(),'ip:'+client_address(request))
def too_many_failures(c,keys):
    since=(datetime.now(timezone.utc)-FAILURE_WINDOW).isoformat()
    for key in keys:
        if c.execute('SELECT count(*) FROM login_failures WHERE who=? AND occurred_at>?',(key,since)).fetchone()[0]>=MAX_FAILURES:return True
    return False
@app.post('/login')
def login(request:Request,email:str=Form(...),password:str=Form(...)):
    email=email.strip().lower()
    keys=login_keys(email,request)
    with db() as c:
        if too_many_failures(c,keys):
            audit(c,None,'login_locked','account','Too many failed sign-ins')
            return page('Sign in',msg('Too many failed sign-ins. Wait 15 minutes and try again, or ask your administrator.'))
        row=c.execute('SELECT * FROM users WHERE email=? AND active=1',(email,)).fetchone()
        ok=False
        if row:
            try:ok=PH.verify(row['password_hash'],password)
            except (VerifyMismatchError,VerificationError):pass
        else:
            PH.hash(password)  # same work as a real check, so unknown emails aren't faster
        if not ok:
            for key in keys:c.execute('INSERT INTO login_failures(who,occurred_at) VALUES(?,?)',(key,now()))
            audit(c,row['id'] if row else None,'login_failed','account', 'Rejected authentication')
            return page('Sign in',msg('Invalid email or password.')+'<p><a href="/login">Try again</a></p>')
        c.execute('DELETE FROM login_failures WHERE who=?',(keys[0],))
        c.execute('DELETE FROM login_failures WHERE occurred_at<?',((datetime.now(timezone.utc)-FAILURE_WINDOW).isoformat(),))
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

def current_progress(c, driver_id):
    state = driver_state(c, driver_id, TRANSPORT_ENABLED)
    if state is None:
        raise HTTPException(404, 'Driver not found')
    return state


def require_stage(state, stage):
    if not state['active'] or state['stage'] < stage:
        raise HTTPException(409, 'Complete the earlier onboarding requirements first')


def credential_status_html(state):
    items = []
    for kind, status in state['credential_status'].items():
        record = state['credentials'].get(kind)
        date = f' (expires {e(record["expires_on"])})' if record else ''
        items.append(f'<li>{e(CREDENTIALS[kind])} <strong>{e(status)}</strong>{date}</li>')
    return '<ul>' + ''.join(items) + '</ul>'


def exam_result(exam):
    return f'{exam["correct"]} / {exam["total"]}' if exam else 'Awaiting examination'


@app.get('/dashboard')
def dashboard(request: Request):
    u = require(request)
    if u['role'] == 'instructor':
        return redirect('/evaluations')
    if u['role'] == 'admin':
        return redirect('/admin')
    with db() as c:
        c.execute('BEGIN')
        state = current_progress(c, u['id'])
    stage = state['stage']
    steps = []
    for index, name in enumerate(STAGES):
        status = 'Complete' if index < stage else 'Current' if index == stage else 'Upcoming'
        current = ' aria-current="step"' if index == stage else ''
        steps.append(f'<li{current}><span>{e(name)}</span><strong>{status}</strong></li>')
    next_actions = (
        '<p>Confirm that you are starting driver onboarding.</p><form method="post" action="/onboarding/application">' + cs(u) + '<button>Submit application</button></form>',
        '<p>Submit your driver license reference or wait for your administrator to verify it.</p><a class="button" href="/credentials">View credentials</a>',
        '<p>Your administrator will record the background screening outcome.</p>',
        '<p>Submit your Illinois HFS safety training certificate for verification.</p><a class="button" href="/credentials">View credentials</a>',
        '<p>Complete the approved lessons and their knowledge checks.</p><a class="button" href="/courses">Open the academy</a>',
        '<p>Take the written examination after completing the academy.</p><a class="button" href="/written-exam">Open written examination</a>',
        '<p>Your instructor will document your supervised training.</p>',
        '<p>Your instructor will schedule and document your practical examination.</p><a class="button" href="/evaluations">View practical examination</a>',
        '<p>Management will review your practical examination and insurance eligibility before approving your record.</p><a class="button" href="/credentials">View credentials</a>',
        '<p>Compliance approval is current. Transport authorization is disabled for this pilot.</p>',
        '<p>Your CareMed transport authorization is current.</p>',
    )
    practical = state['practical']
    practical_result = practical['result'].title() if practical else 'Awaiting examination'
    if practical:
        practical_result += ' / ' + (practical['decision'] or 'awaiting review')
    body = f'<h1>Your onboarding journey</h1><div class="journey-layout"><div>{card("Next action", next_actions[stage])}'
    body += card('Requirements', credential_status_html(state)) + card(
        'Examination results',
        f'<p>Written examination <strong>{e(exam_result(state["exam"]))}</strong></p><p>Practical examination <strong>{e(practical_result)}</strong></p>',
    )
    body += '</div>' + card('Onboarding stages', '<ol class="journey">' + ''.join(steps) + '</ol>') + '</div>'
    body += '<div class="stats">' + card('Training completion', f'<p>{state["completed"]} of {state["total"]} lessons completed</p>')
    body += card('Practical competency', '<p>Demonstrated</p>' if state['competent'] else '<p>Outstanding</p>')
    body += card('Transport authorization', '<p>Authorized</p>' if state['authorized'] else '<p>Ineligible</p>') + '</div>'
    return page('Onboarding', body, u)


@app.post('/onboarding/application')
def submit_application(request: Request, csrf: str = Form(...)):
    u = require(request, {'driver'})
    verify_csrf(request, u, csrf)
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        state = current_progress(c, u['id'])
        require_stage(state, 0)
        if state['stage'] == 0:
            record_onboarding(c, u['id'], u['id'], 'application', True, 'Employee confirmed application')
    return redirect('/dashboard')


def record_onboarding(c, driver_id, actor_id, kind, passed, note):
    c.execute(
        'INSERT INTO onboarding_records(driver_id,actor_id,kind,passed,note,recorded_at) VALUES(?,?,?,?,?,?)',
        (driver_id, actor_id, kind, int(passed), note, now()),
    )
    audit(c, actor_id, 'onboarding_' + kind, f'user:{driver_id}', f'passed={passed}')


def written_questions(c):
    return c.execute("""SELECT q.* FROM exam_questions q JOIN modules m ON m.id=q.module_id
                        WHERE m.status='approved' ORDER BY m.id,q.ordinal""").fetchall()


@app.get('/written-exam')
def written_exam(request: Request):
    u = require(request, {'driver'})
    with db() as c:
        c.execute('BEGIN')
        state = current_progress(c, u['id'])
        require_stage(state, 5)
        questions = list(written_questions(c))
    if state['checks'][5]:
        return page('Written examination', card('Written examination passed', f'<p>{e(exam_result(state["exam"]))}</p>'), u)
    secrets.SystemRandom().shuffle(questions)
    body = ('<h1>Written examination</h1><p>These are new scenario questions, separate from the lesson quizzes, '
            'shown in a random order. Every answer must be correct to pass.</p>')
    body += '<form method="post" action="/written-exam">' + cs(u)
    body += f'<input type="hidden" name="curriculum" value="{state["curriculum"]}">'
    for number, question in enumerate(questions, 1):
        body += f'<fieldset class="card"><legend>{number}. {e(question["prompt"])}</legend>'
        for index, choice in enumerate(json.loads(question['choices'])):
            body += f'<label class="radio"><input type="radio" name="question_{question["id"]}" value="{index}" required> {e(choice)}</label>'
        body += '</fieldset>'
    return page('Written examination', body + '<button>Submit examination</button></form>', u)


@app.post('/written-exam')
async def submit_written_exam(request: Request):
    u = require(request, {'driver'})
    form = await request.form()
    verify_csrf(request, u, str(form.get('csrf', '')))
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        state = current_progress(c, u['id'])
        require_stage(state, 5)
        if state['checks'][5]:
            return redirect('/written-exam')
        if form.get('curriculum') != state['curriculum']:
            raise HTTPException(409, 'Curriculum changed. Reopen the examination.')
        questions = written_questions(c)
        if not questions:
            raise HTTPException(409, 'No approved examination questions')
        correct = 0
        for question in questions:
            try:
                answer_index = int(form[f'question_{question["id"]}'])
            except (ValueError, KeyError, TypeError):
                raise HTTPException(400, 'Answer every examination question')
            if answer_index not in range(len(json.loads(question['choices']))):
                raise HTTPException(400, 'Invalid examination answer')
            correct += answer_index == question['answer_index']
        c.execute('INSERT INTO written_exams(driver_id,curriculum,correct,total,recorded_at) VALUES(?,?,?,?,?)',
                  (u['id'], state['curriculum'], correct, len(questions), now()))
        audit(c, u['id'], 'written_exam', f'user:{u["id"]}', f'{correct}/{len(questions)}')
    return redirect('/dashboard')


@app.get('/transport-authorization')
def transport_authorization(request: Request):
    u = require(request, {'driver'})
    with db() as c:
        c.execute('BEGIN')
        state = current_progress(c, u['id'])
    status = 200 if state['authorized'] else 403
    return JSONResponse({'authorized': state['authorized']}, status_code=status, headers={'Cache-Control': 'no-store'})


@app.get('/courses')
def courses(request: Request):
    u = require(request)
    with db() as c:
        rows = c.execute("""SELECT m.*, EXISTS(
                                SELECT 1 FROM bank_attempts a WHERE a.user_id=? AND a.module_id=m.id
                                AND a.module_version=m.version AND a.total_count>0 AND a.correct_count=a.total_count
                            ) completed FROM modules m ORDER BY m.id""", (u['id'],)).fetchall()
    body = '<h1>Online Academy</h1><p>Complete each approved lesson and its knowledge check.</p><div class="grid">'
    for module in rows:
        status = 'Draft preview'
        if module['status'] == 'approved':
            status = 'Complete' if module['completed'] else 'Required'
        intro = module['body'].split('\n', 1)[0]
        details = f'<p>{e(intro)}</p><span class="tag">{status}</span>'
        details += f'<p><a class="button" href="/courses/{module["id"]}">Open lesson</a></p>'
        body += card(module['title'], details)
    return page('Online Academy', body + '</div>', u)


@app.get('/courses/{module_id}')
def course(request:Request,module_id:int):
    u=require(request)
    with db() as c:
        c.execute('BEGIN')
        m=c.execute('SELECT * FROM modules WHERE id=?',(module_id,)).fetchone()
        state = current_progress(c, u['id']) if u['role'] == 'driver' else None
        questions = c.execute('SELECT * FROM bank_questions WHERE module_id=? ORDER BY ordinal', (module_id,)).fetchall()
    if not m:raise HTTPException(404)
    body=f'<a href="/courses">← All lessons</a><h1>{e(m["title"])}</h1><p class="tag">{e(m["status"].upper())} · Version {m["version"]}</p><div class="card">'+''.join(f'<p>{e(part)}</p>' for part in m['body'].split('\n\n'))
    if module_id in (2,3):body+='<img class="illustration" src="/assets/images/vehicle-orientation.svg" alt="Conceptual rear-entry van diagram. Not operating instructions.">'
    if module_id in (2,3,4):
        vid='ramp-briefing' if module_id in (2,3) else 'securement-briefing'
        body+=f'<video controls preload="metadata" poster="/assets/images/academy-video-poster.webp"><source src="/assets/videos/{vid}.mp4" type="video/mp4"></video><p class="muted">12-second conceptual briefing, NOT manufacturer-approved demonstration.</p>'
    if state and state['stage'] < 4 and m['status'] == 'approved':
        body += '<p>Complete the first four onboarding stages to submit the knowledge check.</p><a href="/dashboard">Back to onboarding</a>'
        return page(m['title'], body + '</div>', u)
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
        c.execute('BEGIN IMMEDIATE')
        m=c.execute('SELECT * FROM modules WHERE id=?',(module_id,)).fetchone()
        if not m:raise HTTPException(404)
        if u['role'] == 'driver' and m['status'] == 'approved':
            require_stage(current_progress(c, u['id']), 4)
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
def credentials(request: Request):
    u = require(request, {'driver'})
    with db() as c:
        c.execute('BEGIN')
        state = current_progress(c, u['id'])
    body = '<h1>Credential registry</h1>'
    body += card('Required credentials', credential_status_html(state))
    for kind, record in state['credentials'].items():
        body += card(CREDENTIALS.get(kind, kind),
                     f'<p>Reference {e(record["reference"])} · Expires {e(record["expires_on"])} · {e(record["status"].title())}</p>')
    options = ''.join(f'<option value="{kind}">{e(label)}</option>' for kind, label in CREDENTIALS.items())
    if state['stage'] >= 1:
        form = '<form method="post" action="/credentials">' + cs(u) + f'<label>Credential type<select name="kind">{options}</select></label>'
        form += field('reference', 'Document or policy reference', extra='maxlength="120"')
        form += field('expires_on', 'Expiration date', kind='date') + '<button>Submit for verification</button></form>'
        body += card('Submit or renew a credential', form)
    else:
        body += '<p><a href="/dashboard">Submit your application</a> to begin credential verification.</p>'
    return page('Credentials', body, u)


@app.post('/credentials')
def credentials_post(request: Request, csrf: str = Form(...), kind: str = Form(...),
                     reference: str = Form(...), expires_on: str = Form(...)):
    u = require(request, {'driver'})
    verify_csrf(request, u, csrf)
    reference = reference.strip()
    expiry = parse_date(expires_on)
    if kind not in CREDENTIALS or not 2 <= len(reference) <= 120 or expiry < illinois_today():
        raise HTTPException(400, 'Enter a credential reference and a current expiration date')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        require_stage(current_progress(c, u['id']), 1)
        result = c.execute("""INSERT INTO credentials(user_id,kind,reference,expires_on,status)
                     VALUES(?,?,?,?,'pending') ON CONFLICT(user_id,kind) DO UPDATE SET
                     reference=excluded.reference,expires_on=excluded.expires_on,
                     status='pending',verified_by=NULL,verified_at=NULL
                     WHERE credentials.reference<>excluded.reference OR credentials.expires_on<>excluded.expires_on
                     OR credentials.status='rejected'""",
                  (u['id'], kind, reference, expires_on))
        if result.rowcount:
            audit(c, u['id'], 'credential_submitted', f'user:{u["id"]}', kind)
    return redirect('/credentials')


def parse_date(value):
    try:
        parsed = datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        raise HTTPException(400, 'Enter a valid date')
    if parsed.isoformat() != value:
        raise HTTPException(400, 'Enter a valid date')
    return parsed


CRITERIA=['Vehicle parked and secured on appropriate surface','Environment and ramp clearance assessed','Conversion/ramp identified by manual and serial','Ramp inspected according to exact maker instructions','Passenger consulted and consent obtained','Wheelchair handled within documented limitations','Approved wheelchair securement points identified','Four-point or installed approved securement correctly demonstrated','Occupant lap and shoulder restraints correctly demonstrated','Final restraint safety confirmation','Safe unloading demonstrated','Appropriate emergency escalation demonstrated']
def practical_form(u, appointment):
    form = '<form action="/evaluations" method="post">' + cs(u)
    form += f'<input type="hidden" name="appointment_id" value="{appointment["id"]}">'
    form += field('vehicle_reference', 'Vehicle VIN or fleet identifier', extra='maxlength="120"')
    form += field('equipment_reference', 'Ramp and tie-down make, model and serial', extra='maxlength="120"')
    form += field('observed_at', 'Observed date', appointment['scheduled_for'], kind='date')
    form += '<fieldset><legend>Observed competencies</legend>'
    for index, criterion in enumerate(CRITERIA):
        form += f'<label class="radio"><input type="checkbox" name="checks" value="{index}"> {e(criterion)}</label>'
    form += '</fieldset><label class="radio"><input type="checkbox" name="critical_pass" value="1"> I personally observed all critical safety steps, with no critical failure.</label>'
    form += '<label>Result<select name="result"><option value="fail">Fail / remediation required</option><option value="pass">Pass</option></select></label>'
    form += '<label>Observation and remediation notes<textarea name="notes" required minlength="20" maxlength="3000"></textarea></label>'
    return form + '<button>Sign practical result</button></form>'


@app.get('/evaluations')
def evaluations(request: Request):
    u = require(request)
    with db() as c:
        c.execute('BEGIN')
        rows = c.execute("""SELECT ev.*,d.name driver,i.name instructor,r.decision
                            FROM evaluations ev JOIN users d ON d.id=ev.driver_id
                            JOIN users i ON i.id=ev.instructor_id LEFT JOIN reviews r ON r.evaluation_id=ev.id
                            WHERE (? != 'driver' OR ev.driver_id=?) ORDER BY ev.id DESC LIMIT 100""",
                         (u['role'], u['id'])).fetchall()
        appointments = c.execute("""SELECT a.*,d.name driver,i.name instructor
                                    FROM evaluation_appointments a JOIN users d ON d.id=a.driver_id
                                    JOIN users i ON i.id=a.instructor_id
                                    WHERE a.cancelled_at IS NULL AND a.evaluation_id IS NULL
                                    AND (? != 'driver' OR a.driver_id=?)
                                    AND (? != 'instructor' OR a.instructor_id=?)
                                    ORDER BY a.scheduled_for,a.id""",
                                 (u['role'], u['id'], u['role'], u['id'])).fetchall()
        candidates = []
        if u['role'] == 'instructor':
            drivers = c.execute("SELECT id,name FROM users WHERE role='driver' AND active=1 ORDER BY name").fetchall()
            booked = {row[0] for row in c.execute(
                'SELECT driver_id FROM evaluation_appointments WHERE cancelled_at IS NULL AND evaluation_id IS NULL'
            )}
            candidates = [(driver, current_progress(c, driver['id'])['stage']) for driver in drivers]
        appointment_states = {a['id']: current_progress(c, a['driver_id']) for a in appointments} if u['role'] == 'instructor' else {}

    title = 'Instructor dashboard' if u['role'] == 'instructor' else 'Practical examinations'
    body = f'<h1>{title}</h1>'
    if u['role'] == 'instructor':
        for stage, action, label in (
            (6, 'supervision', 'Record supervised training'),
            (7, 'appointments', 'Schedule practical examination'),
        ):
            options = ''.join(f'<option value="{d["id"]}">{e(d["name"])}</option>' for d, current in candidates
                              if current == stage and (stage == 6 or d['id'] not in booked))
            form = '<p>No drivers are ready for this step.</p>'
            if options:
                form = f'<form method="post" action="/evaluations/{action}">' + cs(u)
                form += f'<label>Driver<select name="driver_id" required>{options}</select></label>'
                if stage == 6:
                    form += '<label>Training completed on<input type="date" name="training_date" required></label>'
                    form += '<label>Supervised training completed<textarea name="notes" required minlength="10" maxlength="1000"></textarea></label>'
                else:
                    form += field('scheduled_for', 'Date and time (Central)', kind='datetime-local')
                    form += field('location', 'Training location', extra='maxlength="160"')
                form += f'<button>{label}</button></form>'
            body += card(label, form)
    if not appointments:
        body += card('Scheduled practical examinations', '<p>No open appointments.</p>')
    for appointment in appointments:
        scheduled = appointment['scheduled_for'].replace('T', ' at ')
        details = f'<p>{e(scheduled)} Central &middot; {e(appointment["location"])}</p><p>Instructor {e(appointment["instructor"])}</p>'
        if u['role'] == 'instructor':
            state = appointment_states[appointment['id']]
            if state['stage'] == 7 and state['active'] and appointment['scheduled_for'] <= illinois_now().strftime('%Y-%m-%dT%H:%M'):
                details += practical_form(u, appointment)
            details += f'<form method="post" action="/evaluations/appointments/{appointment["id"]}/cancel">' + cs(u) + '<button>Cancel appointment</button></form>'
        body += card(f'Appointment for {appointment["driver"]}', details)
    history = []
    for row in rows:
        label = f'{e(row["driver"])} &middot; {e(row["observed_at"])} &middot; {e(row["result"].title())}'
        details = f'<p>{e(row["instructor"])} &middot; {e(row["decision"] or "Awaiting review")}</p>'
        details += f'<p>Vehicle {e(row["vehicle_reference"])} &middot; Equipment {e(row["equipment_reference"])}</p>'
        if u['role'] != 'driver':
            details += f'<p>{e(row["notes"])}</p>'
        history.append(f'<details class="compliance-driver"><summary>{label}</summary>{details}</details>')
    body += card('Examination history', ''.join(history) or '<p>No practical results recorded.</p>')
    return page(title, body, u)


@app.post('/evaluations/supervision')
def complete_supervision(request: Request, driver_id: int = Form(...), csrf: str = Form(...),
                         training_date: str = Form(...), notes: str = Form(...)):
    u = require(request, {'instructor'})
    verify_csrf(request, u, csrf)
    if parse_date(training_date) > illinois_today() or not 10 <= len(notes.strip()) <= 1000:
        raise HTTPException(400, 'Enter the completed training date and supervision notes')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        state = current_progress(c, driver_id)
        if state['stage'] != 6 or not state['active']:
            raise HTTPException(409, 'Driver is not at supervised training')
        if training_date < illinois_date(state['exam']['recorded_at']):
            raise HTTPException(400, 'Supervised training must follow the written examination')
        record_onboarding(c, driver_id, u['id'], 'supervision', True, f'{training_date} | {notes.strip()}')
    return redirect('/evaluations')


@app.post('/evaluations/appointments')
def schedule_practical(request: Request, driver_id: int = Form(...), csrf: str = Form(...),
                       scheduled_for: str = Form(...), location: str = Form(...)):
    u = require(request, {'instructor'})
    verify_csrf(request, u, csrf)
    try:
        scheduled = datetime.strptime(scheduled_for, '%Y-%m-%dT%H:%M')
    except ValueError:
        raise HTTPException(400, 'Enter a valid Central date and time')
    if scheduled.isoformat(timespec='minutes') != scheduled_for or scheduled < illinois_now().replace(second=0, microsecond=0, tzinfo=None) or not 2 <= len(location.strip()) <= 160:
        raise HTTPException(400, 'Enter a current or future appointment and a location')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        state = current_progress(c, driver_id)
        if state['stage'] != 7 or not state['active']:
            raise HTTPException(409, 'Driver is not at the practical examination')
        try:
            appointment = c.execute('INSERT INTO evaluation_appointments(driver_id,instructor_id,scheduled_for,location) VALUES(?,?,?,?)',
                                    (driver_id, u['id'], scheduled_for, location.strip()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, 'Driver already has an open appointment')
        audit(c, u['id'], 'practical_scheduled', f'appointment:{appointment.lastrowid}', f'driver={driver_id}')
    return redirect('/evaluations')


@app.post('/evaluations/appointments/{appointment_id}/cancel')
def cancel_practical(request: Request, appointment_id: int, csrf: str = Form(...)):
    u = require(request, {'instructor'})
    verify_csrf(request, u, csrf)
    with db() as c:
        result = c.execute("""UPDATE evaluation_appointments SET cancelled_at=?
                              WHERE id=? AND instructor_id=? AND cancelled_at IS NULL AND evaluation_id IS NULL""",
                           (now(), appointment_id, u['id']))
        if result.rowcount != 1:
            raise HTTPException(404, 'Open appointment not found')
        audit(c, u['id'], 'practical_cancelled', f'appointment:{appointment_id}', 'Cancelled by assigned instructor')
    return redirect('/evaluations')


@app.post('/evaluations')
async def evaluations_post(request:Request):
    u=require(request,{'instructor'});form=await request.form();verify_csrf(request,u,str(form.get('csrf','')))
    try:appointment_id=int(form['appointment_id']);checks={int(x) for x in form.getlist('checks')};observed_at=parse_date(str(form['observed_at'])).isoformat()
    except (KeyError,ValueError):raise HTTPException(400)
    if any(x not in range(len(CRITERIA)) for x in checks):raise HTTPException(400)
    result=str(form.get('result','fail'));critical=str(form.get('critical_pass',''))=='1'
    vehicle=str(form.get('vehicle_reference','')).strip();equipment=str(form.get('equipment_reference','')).strip();notes=str(form.get('notes','')).strip()
    if not 3<=len(vehicle)<=120 or not 5<=len(equipment)<=120 or not 20<=len(notes)<=3000 or result not in {'pass','fail'}:raise HTTPException(400)
    if result=='pass' and (not critical or len(checks)!=len(CRITERIA)):raise HTTPException(400,'Cannot pass without every competency and critical-safety confirmation')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        appointment = c.execute("""SELECT * FROM evaluation_appointments
                                   WHERE id=? AND instructor_id=? AND cancelled_at IS NULL AND evaluation_id IS NULL""",
                                (appointment_id, u['id'])).fetchone()
        if not appointment:
            raise HTTPException(404, 'Open appointment not found')
        driver_id = appointment['driver_id']
        state = current_progress(c, driver_id)
        if state['stage'] != 7 or not state['active']:
            raise HTTPException(409, 'Driver is not at the practical examination')
        if not appointment['scheduled_for'][:10] <= observed_at <= illinois_today().isoformat() or appointment['scheduled_for'] > illinois_now().strftime('%Y-%m-%dT%H:%M'):
            raise HTTPException(400, 'Observation must be on or after the appointment and cannot be in the future')
        cur=c.execute('INSERT INTO evaluations(driver_id,instructor_id,vehicle_reference,equipment_reference,checklist,critical_pass,result,notes,observed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(driver_id,u['id'],vehicle,equipment,json.dumps(sorted(checks)),int(critical),result,notes,observed_at,now()))
        c.execute('UPDATE evaluation_appointments SET evaluation_id=? WHERE id=?', (cur.lastrowid, appointment_id))
        audit(c,u['id'],'evaluation_signed',f'evaluation:{cur.lastrowid}',f'Observed result: {result}; vehicle={vehicle}; complete={len(checks)}')
    return redirect('/evaluations')

def compliance_dashboard(c, u, drivers):
    entries = []
    for driver in drivers:
        state = current_progress(c, driver['id'])
        stage = state['stage']
        if not state['active']:
            status = 'Inactive account'
        elif state['authorized']:
            status = 'Authorized for transport'
        elif state['approved']:
            status = 'Compliance approved'
        elif state['snapshot']:
            status = 'Ready for compliance approval'
        else:
            status = STAGES[min(stage, 9)]
        summary = f'<strong>{e(driver["name"])}</strong> &middot; {e(status)}'
        if state['renewals']:
            summary += ' &middot; Renewal due'
        detail = f'<p>Academy {state["completed"]}/{state["total"]} &middot; Written exam {e(exam_result(state["exam"]))} &middot; Practical competency {"demonstrated" if state["competent"] else "outstanding"}</p>'
        detail += credential_status_html(state)
        for kind, credential in state['credentials'].items():
            if credential['status'] == 'verified':
                detail += f'<form method="post" action="/admin/credential/{credential["id"]}">' + cs(u)
                detail += f'<input type="hidden" name="revision" value="{credential_revision(credential)}"><input type="hidden" name="decision" value="withdrawn">'
                detail += f'<button>Withdraw verification for {e(CREDENTIALS.get(kind, kind))}</button></form>'
        if state['renewals']:
            detail += '<p>Expired or expiring within 30 days &middot; ' + e(', '.join(state['renewals'])) + '</p>'
        if state['supervision']:
            detail += f'<p>Supervised training &middot; {e(state["supervision"]["note"])}</p>'
        if state['practical'] and state['practical']['decision'] is None:
            detail += '<p>Practical examination is awaiting independent review.</p>'
        if state['active'] and stage >= 2:
            screen_controls = '<label>Screening outcome<select name="decision"><option value="failed">Did not clear</option><option value="cleared">Cleared</option></select></label>'
            if stage > 2:
                screen_controls = '<input type="hidden" name="decision" value="failed">'
            label = 'Record background screening' if stage == 2 else 'Withdraw screening clearance'
            detail += f'<form method="post" action="/admin/drivers/{driver["id"]}/screening">' + cs(u) + screen_controls
            detail += field('reference', 'Screening reference', extra='maxlength="120"') + f'<button>{label}</button></form>'
        if state['snapshot'] or state['approved']:
            decision = 'revoke' if state['approved'] else 'approve'
            label = 'Withdraw compliance approval' if state['approved'] else 'Approve compliance'
            detail += f'<form method="post" action="/admin/drivers/{driver["id"]}/compliance">' + cs(u)
            detail += f'<input type="hidden" name="decision" value="{decision}"><input type="hidden" name="snapshot" value="{state["snapshot"]}">'
            detail += field('notes', 'Decision notes', extra='minlength="10" maxlength="1000"') + f'<button>{label}</button></form>'
        entries.append(f'<details class="compliance-driver"><summary>{summary}</summary>{detail}</details>')
    return card('Driver compliance', ''.join(entries) or '<p>No driver accounts yet.</p>')


@app.post('/admin/drivers/{driver_id}/screening')
def admin_screening(request: Request, driver_id: int, csrf: str = Form(...),
                    decision: str = Form(...), reference: str = Form(...)):
    u = require(request, {'admin'})
    verify_csrf(request, u, csrf)
    if decision not in {'cleared', 'failed'} or not 2 <= len(reference.strip()) <= 120:
        raise HTTPException(400, 'Enter the screening outcome and reference')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        state = current_progress(c, driver_id)
        require_stage(state, 2)
        if decision == 'cleared' and state['stage'] != 2:
            raise HTTPException(409, 'Screening is already cleared')
        record_onboarding(c, driver_id, u['id'], 'screening', decision == 'cleared', reference.strip())
    return redirect('/admin')


@app.post('/admin/drivers/{driver_id}/compliance')
def admin_compliance(request: Request, driver_id: int, csrf: str = Form(...),
                     decision: str = Form(...), snapshot: str = Form(...), notes: str = Form(...)):
    u = require(request, {'admin'})
    verify_csrf(request, u, csrf)
    if decision not in {'approve', 'revoke'} or not 10 <= len(notes.strip()) <= 1000:
        raise HTTPException(400, 'Enter a valid decision and decision notes')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        state = current_progress(c, driver_id)
        if not state['snapshot'] or state['snapshot'] != snapshot or state['approved'] != (decision == 'revoke'):
            raise HTTPException(409, 'Driver compliance changed or prerequisites are incomplete')
        approved_snapshot = snapshot if decision == 'approve' else None
        c.execute('INSERT INTO compliance_decisions(driver_id,administrator_id,snapshot,note,recorded_at) VALUES(?,?,?,?,?)',
                  (driver_id, u['id'], approved_snapshot, notes.strip(), now()))
        audit(c, u['id'], 'compliance_' + decision, f'user:{driver_id}', f'decision={decision}')
    return redirect('/admin')


def credential_revision(credential):
    return fingerprint([credential['reference'], credential['expires_on'], credential['verified_at']])


@app.get('/admin')
def admin(request:Request):
    u=require(request,{'admin'})
    with db() as c:
        c.execute('BEGIN')
        drivers = c.execute("SELECT id,name FROM users WHERE role='driver' ORDER BY name,id").fetchall()
        compliance = compliance_dashboard(c, u, drivers)
        users=c.execute('SELECT id,email,name,role,active FROM users ORDER BY id DESC LIMIT 100').fetchall()
        pending=c.execute('SELECT x.*,u.name driver FROM credentials x JOIN users u ON u.id=x.user_id WHERE x.status=\'pending\' ORDER BY x.id').fetchall()
        reviews=c.execute('SELECT e.*,d.name driver,i.name instructor FROM evaluations e JOIN users d ON d.id=e.driver_id JOIN users i ON i.id=e.instructor_id LEFT JOIN reviews r ON r.evaluation_id=e.id WHERE r.id IS NULL ORDER BY e.id').fetchall()
        mods=c.execute('SELECT id,title,status,version FROM modules ORDER BY id').fetchall()
        logs=c.execute('SELECT a.*,u.email FROM audit a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 35').fetchall()
    body = '<h1>Compliance dashboard</h1>' + compliance
    if not TRANSPORT_ENABLED:
        body += msg('Transport authorization is disabled in this pilot.')
    body+=card('Add employee','<form method="post" action="/admin/users">'+cs(u)+field('name','Name')+field('email','Email',kind='email')+field('password','Temporary password (share securely; require change before production)',kind='password',extra='minlength="14"')+'<label>Role<select name="role"><option value="driver">Driver</option><option value="instructor">Instructor</option><option value="admin">Administrator</option></select></label><button>Create account</button></form>')
    body+=card('Users','<div class="tablewrap"><table><tr><th>Name</th><th>Email</th><th>Role</th><th>Active</th></tr>'+''.join(f'<tr><td>{e(x["name"])}</td><td>{e(x["email"])}</td><td>{e(x["role"])}</td><td>{"Yes" if x["active"] else "No"}</td></tr>' for x in users)+'</table></div>')
    forms=''
    for x in pending:
        forms+=f'<form method="post" action="/admin/credential/{x["id"]}">'+cs(u)+f'<input type="hidden" name="revision" value="{credential_revision(x)}"><b>{e(x["driver"])} · {e(x["kind"])}</b><p>Reference: {e(x["reference"])} · Expires {e(x["expires_on"])}</p><label>Decision<select name="decision"><option value="rejected">Reject</option><option value="verified">Verify (after independently checking original)</option></select></label><button>Record decision</button></form>'
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
def verify_credential(request: Request, credential_id: int, csrf: str = Form(...),
                      decision: str = Form(...), revision: str = Form(...)):
    u = require(request, {'admin'})
    verify_csrf(request, u, csrf)
    if decision not in {'verified', 'rejected', 'withdrawn'}:
        raise HTTPException(400, 'Invalid credential decision')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        prior_status = 'verified' if decision == 'withdrawn' else 'pending'
        x = c.execute('SELECT * FROM credentials WHERE id=? AND status=?', (credential_id, prior_status)).fetchone()
        if not x or credential_revision(x) != revision:
            raise HTTPException(409, 'Credential changed. Reopen the compliance dashboard.')
        if x['user_id'] == u['id']:
            raise HTTPException(403, 'No self-verification')
        if decision == 'verified':
            state = current_progress(c, x['user_id'])
            require_stage(state, 3 if x['kind'] == 'hfs_safety' else 1)
            if x['expires_on'] < illinois_today().isoformat():
                raise HTTPException(409, 'Credential has expired')
        status = 'verified' if decision == 'verified' else 'rejected'
        c.execute('UPDATE credentials SET status=?,verified_by=?,verified_at=? WHERE id=?',
                  (status, u['id'], now(), credential_id))
        audit(c, u['id'], 'credential_' + decision, f'credential:{credential_id}', f'owner={x["user_id"]}')
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
        c.execute('BEGIN IMMEDIATE')
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
        body+=card(title,f'<video controls preload="metadata" poster="/assets/images/academy-video-poster.webp"><source src="/assets/videos/{file}.mp4" type="video/mp4"></video><p>{e(desc)} Plays at 0.4× speed so each caption can be read.</p>')
    refs=[('Illinois HFS Safety Training','https://hfs.illinois.gov/impact/safetytraining.html'),('BraunAbility commercial Sienna reference · verify conversion first','https://www.braunability.com/us/en/commercial/mobility-products/wheelchair-vans/rear-entry-toyota-sienna-hybrid-wheelchair-minivan.html'),('VMI Sienna manual reference · verify conversion first','https://www.vantagemobility.com/wp-content/uploads/2024/05/Toyota_RearEntry_2024_OwnersManual_FINAL.pdf'),('Q’STRAINT manufacturer securement training · verify WTORS first','https://training.qstraint.com/aqademy-overview/')]
    body+=card('Manufacturer and regulatory resources','<p>External sites are references only; no implied endorsement or approval.</p><ul>'+''.join(f'<li><a href="{e(url)}" rel="noopener noreferrer" target="_blank">{e(name)}</a></li>' for name,url in refs)+'</ul>')
    body+='<script src="/assets/js/slow-video.js" defer></script>'
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
