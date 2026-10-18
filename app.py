# -*- coding: utf-8 -*-
"""Bunyan Web Trial - safe web adaptation of the supplied desktop database."""
import os, sqlite3, hashlib, hmac, csv, io
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, abort

ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(ROOT, 'bunyan.db')
app = Flask(__name__)
app.secret_key = os.environ.get('BUNYAN_SECRET_KEY', 'CHANGE-THIS-SECRET-BEFORE-PRODUCTION-9c3b5e7a')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

EDITABLE = ['code','name','ptype','gov','district','location','lat','lon','contractor','contract_no','contract_date','start_date','planned_end','actual_end','status','planned','actual','amount','currency','spent','description','obstacles','action','status_details','financial_progress','contractor_dues']
LABELS = {
 'code':'رمز المشروع','name':'اسم المشروع','ptype':'نوع المشروع','gov':'المحافظة','district':'القضاء / المنطقة','location':'موقع المشروع','lat':'خط العرض','lon':'خط الطول','contractor':'الشركة المنفذة','contract_no':'رقم العقد','contract_date':'تاريخ العقد','start_date':'تاريخ المباشرة','planned_end':'تاريخ الإنجاز المخطط','actual_end':'تاريخ الإنجاز الفعلي','status':'موقف المشروع','planned':'الإنجاز المخطط %','actual':'الإنجاز الفعلي %','amount':'مبلغ العقد','currency':'العملة','spent':'المصروف','description':'وصف المشروع','obstacles':'المشاكل والمعوقات','action':'آخر الإجراءات','status_details':'تفاصيل الموقف','financial_progress':'الإنجاز المالي %','contractor_dues':'مستحقات المقاول'
}
STATUSES = ['قيد التنفيذ','منجز','متوقف','متلكئ','قيد الإحالة','لم يبدأ','لم تتم المباشرة','مستمر','معلق','مكتمل جزئياً','أخرى']

def db():
    c=sqlite3.connect(DB_PATH, timeout=20)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def verify_password(password, stored):
    try:
        salt, digest = stored.split('$',1)
        candidate = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 180000).hex()
        return hmac.compare_digest(candidate, digest)
    except Exception:
        return False

def current_user():
    if not session.get('uid'): return None
    with db() as c: return c.execute('SELECT id,username,full_name,role,permissions,active FROM users WHERE id=?',(session['uid'],)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user(): return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def allowed(permission):
    u=current_user()
    return bool(u and (u['username']=='admin' or permission in (u['permissions'] or '').split(',')))

def project_count():
    with db() as c: return c.execute('SELECT COUNT(*) FROM projects').fetchone()[0]

@app.context_processor
def inject():
    return {'me':current_user(), 'allowed':allowed, 'labels':LABELS, 'statuses':STATUSES, 'project_total':project_count()}

@app.route('/')
def index():
    if not current_user(): return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username','').strip()
        password=request.form.get('password','')
        with db() as c: user=c.execute('SELECT * FROM users WHERE username=? AND active=1',(username,)).fetchone()
        if user and verify_password(password,user['password_hash']):
            session.clear(); session['uid']=user['id']
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('اسم المستخدم أو كلمة المرور غير صحيحة، أو أن الحساب غير فعال.','error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    with db() as c:
        total=c.execute('SELECT COUNT(*) FROM projects').fetchone()[0]
        statuses=c.execute("SELECT COALESCE(NULLIF(status,''),'غير محدد') status,COUNT(*) n FROM projects GROUP BY status ORDER BY n DESC").fetchall()
        govs=c.execute("SELECT COALESCE(NULLIF(gov,''),'غير محدد') gov,COUNT(*) n FROM projects GROUP BY gov ORDER BY n DESC LIMIT 8").fetchall()
        recent=c.execute('SELECT id,code,name,gov,status,actual,planned,updated FROM projects ORDER BY id DESC LIMIT 8').fetchall()
    return render_template('dashboard.html', total=total, statuses=statuses, govs=govs, recent=recent)

@app.route('/projects')
@login_required
def projects():
    q=request.args.get('q','').strip(); gov=request.args.get('gov','').strip(); status=request.args.get('status','').strip()
    sql='SELECT id,code,name,ptype,gov,status,planned,actual,amount,updated FROM projects WHERE 1=1'; args=[]
    if q:
        sql += ' AND (name LIKE ? OR code LIKE ? OR contractor LIKE ? OR location LIKE ?)'; args += [f'%{q}%']*4
    if gov: sql += ' AND gov=?'; args.append(gov)
    if status: sql += ' AND status=?'; args.append(status)
    sql += ' ORDER BY id DESC'
    with db() as c:
        rows=c.execute(sql,args).fetchall()
        govs=[r[0] for r in c.execute("SELECT DISTINCT gov FROM projects WHERE gov IS NOT NULL AND gov<>'' ORDER BY gov").fetchall()]
    return render_template('projects.html', rows=rows, q=q, gov=gov, status=status, govs=govs)

@app.route('/project/<int:pid>')
@login_required
def project_detail(pid):
    with db() as c:
        p=c.execute('SELECT * FROM projects WHERE id=?',(pid,)).fetchone()
        if not p: abort(404)
        updates=c.execute('SELECT * FROM updates WHERE project_id=? ORDER BY id DESC LIMIT 20',(pid,)).fetchall()
        attachments=c.execute('SELECT * FROM attachments WHERE project_id=? ORDER BY id DESC',(pid,)).fetchall()
        correspondence=c.execute('SELECT * FROM correspondence WHERE project_id=? ORDER BY id DESC LIMIT 20',(pid,)).fetchall()
    return render_template('project_detail.html', p=p, updates=updates, attachments=attachments, correspondence=correspondence)

@app.route('/project/new', methods=['GET','POST'])
@login_required
def project_new():
    if not allowed('projects_add'): abort(403)
    if request.method=='POST':
        data={k:request.form.get(k,'').strip() for k in EDITABLE}
        if not data['name']:
            flash('اسم المشروع حقل مطلوب.','error')
            return render_template('project_form.html', p=data, mode='new')
        numeric=['planned','actual','amount','spent','financial_progress','contractor_dues']
        for k in numeric:
            try: data[k]=float(data[k]) if data[k] else 0
            except ValueError: data[k]=0
        data['updated']=datetime.now().strftime('%Y-%m-%d %H:%M')
        cols=EDITABLE+['updated']
        with db() as c:
            cur=c.execute('INSERT INTO projects('+','.join(cols)+') VALUES('+','.join('?' for _ in cols)+')',[data.get(k,'') for k in cols])
            pid=cur.lastrowid
        flash('تمت إضافة المشروع.','success'); return redirect(url_for('project_detail',pid=pid))
    return render_template('project_form.html', p={}, mode='new')

@app.route('/project/<int:pid>/edit', methods=['GET','POST'])
@login_required
def project_edit(pid):
    if not allowed('projects_edit'): abort(403)
    with db() as c: p=c.execute('SELECT * FROM projects WHERE id=?',(pid,)).fetchone()
    if not p: abort(404)
    if request.method=='POST':
        data={k:request.form.get(k,'').strip() for k in EDITABLE}
        if not data['name']:
            flash('اسم المشروع حقل مطلوب.','error'); return render_template('project_form.html',p=data,mode='edit')
        for k in ['planned','actual','amount','spent','financial_progress','contractor_dues']:
            try: data[k]=float(data[k]) if data[k] else 0
            except ValueError: data[k]=0
        data['updated']=datetime.now().strftime('%Y-%m-%d %H:%M')
        with db() as c: c.execute('UPDATE projects SET '+','.join(k+'=?' for k in EDITABLE+['updated'])+' WHERE id=?',[data.get(k,'') for k in EDITABLE+['updated']]+[pid])
        flash('تم حفظ التعديلات.','success'); return redirect(url_for('project_detail',pid=pid))
    return render_template('project_form.html',p=dict(p),mode='edit')

@app.route('/export.csv')
@login_required
def export_csv():
    if not allowed('reports'): abort(403)
    output=io.StringIO(newline=''); output.write('\ufeff')
    with db() as c:
        cols=[r['name'] for r in c.execute('PRAGMA table_info(projects)').fetchall()]
        w=csv.writer(output); w.writerow([LABELS.get(k,k) for k in cols])
        for row in c.execute('SELECT * FROM projects ORDER BY id'):
            w.writerow([row[k] for k in cols])
    return Response(output.getvalue(),mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=bunyan_projects.csv'})

@app.route('/health')
def health():
    with db() as c:
        integrity=c.execute('PRAGMA integrity_check').fetchone()[0]
        n=c.execute('SELECT COUNT(*) FROM projects').fetchone()[0]
    return {'status':'ok' if integrity=='ok' else 'error','database':integrity,'projects':n}

if __name__=='__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
