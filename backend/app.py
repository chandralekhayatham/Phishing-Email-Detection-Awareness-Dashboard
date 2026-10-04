from flask import Flask, request, jsonify, send_from_directory
from pathlib import Path
import sqlite3, json, csv
from backend.services.risk_engine import calculate_phishing_score

ROOT=Path(__file__).resolve().parents[1]; DB=ROOT/'phishing_dashboard.db'
app=Flask(__name__, static_folder=str(ROOT/'frontend/static'))

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS analyses (analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,sender_domain TEXT,subject TEXT,risk_score REAL,classification TEXT,indicators TEXT,created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
    return c

def domain(sender): return sender.split('@',1)[1].lower() if '@' in sender else ''

@app.get('/')
def home(): return send_from_directory(ROOT/'frontend','index.html')
@app.get('/api/health')
def health(): return {'status':'ok'}
@app.post('/api/analyze')
def analyze():
    data=request.get_json(silent=True) or {}
    required=['sender','subject','body']
    if any(not str(data.get(k,'' )).strip() for k in required): return jsonify({'error':'sender, subject and body are required'}),400
    result=calculate_phishing_score(data['sender'],data['subject'],data['body'],data.get('urls',''),data.get('attachment_name',''))
    c=db(); cur=c.execute('INSERT INTO analyses(sender_domain,subject,risk_score,classification,indicators) VALUES(?,?,?,?,?)',(domain(data['sender']),data['subject'],result['risk_score'],result['classification'],json.dumps(result['findings']))); result['analysis_id']=cur.lastrowid; c.commit(); c.close()
    return jsonify(result)
@app.get('/api/analyses')
def analyses():
    c=db(); rows=[dict(r) for r in c.execute('SELECT * FROM analyses ORDER BY analysis_id DESC')]; c.close(); return jsonify(rows)
@app.get('/api/analyses/<int:aid>')
def analysis(aid):
    c=db(); r=c.execute('SELECT * FROM analyses WHERE analysis_id=?',(aid,)).fetchone(); c.close()
    if not r:return jsonify({'error':'not found'}),404
    return jsonify(dict(r))
@app.delete('/api/analyses/<int:aid>')
def delete(aid):
    c=db(); c.execute('DELETE FROM analyses WHERE analysis_id=?',(aid,)); c.commit(); c.close(); return {'deleted':aid}
@app.get('/api/dashboard/stats')
def stats():
    c=db(); rows=c.execute('SELECT classification,COUNT(*) n FROM analyses GROUP BY classification').fetchall(); avg=c.execute('SELECT AVG(risk_score) FROM analyses').fetchone()[0]; total=c.execute('SELECT COUNT(*) FROM analyses').fetchone()[0]; inds={}
    for r in c.execute('SELECT indicators FROM analyses'): 
        for item in json.loads(r[0] or '[]'): inds[item[0]]=inds.get(item[0],0)+1
    c.close(); return jsonify({'total_emails_analyzed':total,'average_risk_score':round(avg or 0,1),'classification_distribution':{r[0]:r[1] for r in rows},'top_indicators':sorted(inds.items(),key=lambda x:x[1],reverse=True)[:8]})
@app.get('/api/awareness')
def awareness():
    return jsonify({'lessons':[{'title':'Check the sender','text':'Inspect the full sender address and domain; a familiar display name is not proof of legitimacy.'},{'title':'Slow down urgency','text':'Urgency and threats are common social-engineering signals. Verify independently before acting.'},{'title':'Inspect links safely','text':'Read the hostname before clicking. This project analyzes URLs statically and never visits them.'},{'title':'Treat attachments carefully','text':'Unexpected executable or script attachments deserve extra scrutiny. Never execute them just to investigate.'}], 'checklist':['Verify sender through a trusted channel','Inspect domain spelling','Avoid unexpected links','Never share credentials or OTPs','Report suspicious messages','Use official apps/websites directly']})
if __name__=='__main__': app.run(host='127.0.0.1',port=5000,debug=False)
