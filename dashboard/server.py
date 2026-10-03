#!/usr/bin/env python3
"""Local HydraCrack enterprise dashboard + REST API. Bind to localhost only."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html,json,os,sqlite3,urllib.parse,hashlib
import sys
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0,ROOT)
from audit import DB_PATH,init_db,authenticate,create_demo_admin,create_token
HOST='127.0.0.1'; PORT=8765

def audits():
    init_db();
    with sqlite3.connect(DB_PATH) as db:
        rows=db.execute('SELECT audit_id,timestamp_utc,owner,scope,algorithm,risk_score,risk_level,cracked,hash_fingerprint FROM audits ORDER BY id DESC').fetchall()
    keys=['audit_id','timestamp_utc','owner','scope','algorithm','risk_score','risk_level','cracked','hash_fingerprint']; return [dict(zip(keys,r)) for r in rows]

def page():
    rows=audits(); latest=rows[0] if rows else None
    counts={x:sum(1 for r in rows if r['risk_level']==x) for x in ['LOW','MEDIUM','HIGH','CRITICAL']}
    bars=''.join(f'<div class="bar"><span>{k}</span><i style="width:{min(100,counts[k]*18)}%">{counts[k]}</i></div>' for k in counts)
    table=''.join(f'<tr><td>{html.escape(r["audit_id"])}</td><td>{html.escape(r["timestamp_utc"][:19])}</td><td>{html.escape(r["algorithm"])}</td><td>{r["risk_score"]}/100</td><td><b>{html.escape(r["risk_level"])}</b></td><td>{"Yes" if r["cracked"] else "No"}</td></tr>' for r in rows[:20]) or '<tr><td colspan="6">No audits yet</td></tr>'
    card=(f'<div class="score">{latest["risk_score"]}<small>/100</small></div><b>Risk: {html.escape(latest["risk_level"])}</b><p>Algorithm: <code>{html.escape(latest["algorithm"])}</code><br>Fingerprint: <code>{html.escape(latest["hash_fingerprint"])}</code></p>' if latest else '<div class="score">—</div><p>Run an authorized audit to populate the dashboard.</p>')
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>HydraCrack Enterprise</title><style>body{{font-family:Inter,Arial;background:#08111f;color:#e7eef9;max-width:1100px;margin:auto;padding:28px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}}.card{{background:#111c2e;border:1px solid #223451;border-radius:16px;padding:20px;margin:14px 0}}.score{{font-size:56px;font-weight:800}}small{{font-size:20px;color:#8ea1bb}}table{{width:100%;border-collapse:collapse}}td,th{{padding:10px;border-bottom:1px solid #24344c;text-align:left}}code{{color:#8de6b4}}.bar{{margin:8px 0}}.bar span{{display:inline-block;width:90px}}.bar i{{display:inline-block;background:#3b82f6;height:22px;border-radius:5px;font-style:normal;padding-left:7px;box-sizing:border-box;min-width:28px}}</style></head><body><h1>HydraCrack Enterprise Audit</h1><p>Local-only • authorized security assessment platform</p><div class="grid"><div class="card">{card}</div><div class="card"><h2>Risk distribution</h2>{bars}</div><div class="card"><h2>Platform</h2><p>Audit history: <b>{len(rows)}</b></p><p>REST API: <code>/api/audits</code></p><p>SIEM export: <code>/api/siem</code></p></div></div><div class="card"><h2>Audit history</h2><table><tr><th>ID</th><th>Time</th><th>Algorithm</th><th>Score</th><th>Risk</th><th>Recovered</th></tr>{table}</table></div></body></html>'''

class Handler(BaseHTTPRequestHandler):
    def _json(self,data,status=200):
        raw=json.dumps(data,indent=2).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        path=urllib.parse.urlparse(self.path).path
        if path in ('/','/index.html'):
            raw=page().encode(); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        if path=='/api/audits': self._json({'count':len(audits()),'audits':audits()}); return
        if path=='/api/siem':
            events=[]
            for r in audits(): events.append({'event_type':'hydra_audit','audit_id':r['audit_id'],'severity':r['risk_level'],'score':r['risk_score'],'algorithm':r['algorithm'],'recovered':bool(r['cracked']),'scope':r['scope']})
            self._json({'format':'JSONL-compatible-events','events':events}); return
        self.send_error(404)
    def do_POST(self):
        if urllib.parse.urlparse(self.path).path!='/api/login': self.send_error(404); return
        n=int(self.headers.get('Content-Length','0')); body=json.loads(self.rfile.read(n) or b'{}'); user=authenticate(body.get('username',''),body.get('password',''))
        if not user:self._json({'error':'invalid credentials'},401); return
        self._json({'user':user,'token':create_token(user['username'])})
    def log_message(self,*args): pass
if __name__=='__main__':
    init_db(); create_demo_admin(); print(f'Dashboard: http://{HOST}:{PORT} (local only)'); print('Demo login: admin / HydraAudit!2026'); ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
