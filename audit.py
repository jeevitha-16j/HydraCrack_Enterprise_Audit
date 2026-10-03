#!/usr/bin/env python3
"""HydraCrack Enterprise Security Audit core.

Defensive/local auditing only. No remote credential collection or attack capability.
"""
import argparse, csv, hashlib, json, os, re, sqlite3, secrets
from datetime import datetime, timezone

ROOT=os.path.dirname(os.path.abspath(__file__))
DB_PATH=os.path.join(ROOT,'reports','hydra_audit.db')
ALGORITHMS={
 'md5':{'bits':128,'status':'legacy','kdf':False},
 'sha1':{'bits':160,'status':'legacy','kdf':False},
 'sha256':{'bits':256,'status':'general-purpose','kdf':False},
 'sha512':{'bits':512,'status':'general-purpose','kdf':False},
 'bcrypt':{'bits':0,'status':'password-kdf','kdf':True},
 'scrypt':{'bits':0,'status':'password-kdf','kdf':True},
 'argon2id':{'bits':0,'status':'password-kdf','kdf':True},
}
RECOMMENDATIONS=[
 'Use Argon2id, scrypt, or bcrypt for password storage rather than fast general-purpose hashes.',
 'Use a unique random salt for every password.',
 'Require long, unique passwords and screen against known/common passwords.',
 'Record explicit authorization and scope for every audit.',
]
COMMON={'password','password123','admin','admin123','qwerty','qwerty123','123456','letmein','welcome','hydracrack','changeme'}

def hash_metadata(value):
    value=value.strip().lower()
    return {32:'md5',40:'sha1',64:'sha256',128:'sha512'}.get(len(value))

def risk_for(algo, cracked=False, password=None, salted=False):
    score=0; reasons=[]
    if algo in ('md5','sha1'):
        score+=65; reasons.append('legacy fast hash algorithm')
    elif algo in ('sha256','sha512'):
        score+=35; reasons.append('fast general-purpose hash; unsuitable for password storage without a dedicated password KDF')
    elif algo in ('bcrypt','scrypt','argon2id'):
        score+=0; reasons.append('dedicated password KDF detected')
    if not salted and algo not in ('bcrypt','scrypt','argon2id'):
        score+=15; reasons.append('no unique salt evidence supplied')
    if cracked:
        score+=40; reasons.append('candidate recovered during authorized audit')
    if password:
        if len(password)<12: score+=10; reasons.append('candidate is shorter than 12 characters')
        if password.lower() in COMMON: score+=20; reasons.append('candidate resembles a common password')
    score=min(score,100)
    level='LOW' if score<30 else 'MEDIUM' if score<60 else 'HIGH' if score<85 else 'CRITICAL'
    return score,level,reasons

def init_db(path=DB_PATH):
    os.makedirs(os.path.dirname(path),exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS audits (
          id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT UNIQUE, timestamp_utc TEXT,
          owner TEXT, scope TEXT, algorithm TEXT, risk_score INTEGER, risk_level TEXT,
          cracked INTEGER, hash_fingerprint TEXT, findings_json TEXT, notes TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT,
          role TEXT, created_utc TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS api_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, token_hash TEXT UNIQUE,
          created_utc TEXT, revoked INTEGER DEFAULT 0)''')
        db.commit()

def create_demo_admin(path=DB_PATH, username='admin', password='HydraAudit!2026'):
    init_db(path)
    ph=hashlib.pbkdf2_hmac('sha256',password.encode(),b'hydra-audit',210000).hex()
    with sqlite3.connect(path) as db:
        db.execute('INSERT OR IGNORE INTO users(username,password_hash,role,created_utc) VALUES(?,?,?,?)',(username,ph,'admin',datetime.now(timezone.utc).isoformat()))
        db.commit()

def authenticate(username,password,path=DB_PATH):
    ph=hashlib.pbkdf2_hmac('sha256',password.encode(),b'hydra-audit',210000).hex()
    with sqlite3.connect(path) as db:
        row=db.execute('SELECT username,role FROM users WHERE username=? AND password_hash=?',(username,ph)).fetchone()
    return {'username':row[0],'role':row[1]} if row else None

def create_token(username,path=DB_PATH):
    token=secrets.token_urlsafe(32); th=hashlib.sha256(token.encode()).hexdigest()
    with sqlite3.connect(path) as db:
        db.execute('INSERT INTO api_tokens(username,token_hash,created_utc) VALUES(?,?,?)',(username,th,datetime.now(timezone.utc).isoformat())); db.commit()
    return token

def audit_hash(hash_value, algorithm=None, cracked=False, password=None, owner='Authorized Lab', notes='', scope='Synthetic classroom data', salted=False):
    h=hash_value.strip().lower(); algo=algorithm or hash_metadata(h)
    valid=bool(algo and re.fullmatch(r'[0-9a-f]+',h))
    score,level,reasons=risk_for(algo,cracked,password,salted) if valid else (100,'INVALID',['unrecognized or malformed hash'])
    return {'report_version':'3.0','audit_id':secrets.token_hex(8),'timestamp_utc':datetime.now(timezone.utc).isoformat(),'scope_owner':owner,'scope':scope,'authorization_required':True,'hash_fingerprint':hashlib.sha256(h.encode()).hexdigest()[:16] if h else '', 'algorithm':algo or 'unknown','valid_format':valid,'salt_evidence':bool(salted),'cracked_in_authorized_audit':bool(cracked),'risk_score':score,'risk_level':level,'findings':reasons,'notes':notes,'recommendations':RECOMMENDATIONS}

def save_report(report,json_path=None,csv_path=None,db_path=DB_PATH):
    init_db(db_path); os.makedirs(os.path.dirname(json_path or os.path.join(ROOT,'reports','audit_report.json')),exist_ok=True)
    json_path=json_path or os.path.join(ROOT,'reports','audit_report.json'); csv_path=csv_path or os.path.join(ROOT,'reports','audit_report.csv')
    with open(json_path,'w',encoding='utf-8') as f: json.dump(report,f,indent=2)
    exists=os.path.exists(csv_path)
    with open(csv_path,'a',newline='',encoding='utf-8') as f:
        row={k:('; '.join(v) if isinstance(v,list) else v) for k,v in report.items()}
        w=csv.DictWriter(f,fieldnames=row.keys());
        if not exists:w.writeheader()
        w.writerow(row)
    with sqlite3.connect(db_path) as db:
        db.execute('INSERT OR REPLACE INTO audits(audit_id,timestamp_utc,owner,scope,algorithm,risk_score,risk_level,cracked,hash_fingerprint,findings_json,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
          (report['audit_id'],report['timestamp_utc'],report['scope_owner'],report['scope'],report['algorithm'],report['risk_score'],report['risk_level'],int(report['cracked_in_authorized_audit']),report['hash_fingerprint'],json.dumps(report['findings']),report['notes']))
        db.commit()
    return json_path,csv_path

def main():
    p=argparse.ArgumentParser(description='HydraCrack defensive password-audit report generator')
    p.add_argument('--hash',required=True); p.add_argument('--algo',choices=ALGORITHMS); p.add_argument('--cracked',action='store_true'); p.add_argument('--password')
    p.add_argument('--owner',default='Authorized Lab'); p.add_argument('--scope',default='Synthetic classroom data'); p.add_argument('--notes',default=''); p.add_argument('--salted',action='store_true')
    p.add_argument('--json',default=os.path.join(ROOT,'reports','audit_report.json')); p.add_argument('--csv',default=os.path.join(ROOT,'reports','audit_report.csv'))
    a=p.parse_args(); report=audit_hash(a.hash,a.algo,a.cracked,a.password,a.owner,a.notes,a.scope,a.salted); save_report(report,a.json,a.csv); print(json.dumps(report,indent=2)); print(f'\nReport saved under {os.path.dirname(a.json)}')
if __name__=='__main__': main()
