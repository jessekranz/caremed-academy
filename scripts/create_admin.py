import os,sys,getpass
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from app.main import db,PH,now,audit
email=input('Admin email: ').strip().lower();name=input('Admin name: ').strip();password=getpass.getpass('Admin password (>=14 characters): ')
if len(password)<14 or '@' not in email or len(name)<2:raise SystemExit('Invalid admin details')
with db() as c:
    cur=c.execute('INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)',(email,name,'admin',PH.hash(password),now()))
    audit(c,cur.lastrowid,'bootstrap_admin',f'user:{cur.lastrowid}','Local secure administrator bootstrap')
print('Administrator created. No credentials printed.')
