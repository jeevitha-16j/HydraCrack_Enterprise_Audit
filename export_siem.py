#!/usr/bin/env python3
"""Export audit history as JSONL and CEF-like events for SIEM ingestion."""
import json,os,sqlite3
ROOT=os.path.dirname(os.path.abspath(__file__)); DB=os.path.join(ROOT,'reports','hydra_audit.db'); OUT=os.path.join(ROOT,'exports'); os.makedirs(OUT,exist_ok=True)
with sqlite3.connect(DB) as db: rows=db.execute('SELECT audit_id,timestamp_utc,algorithm,risk_score,risk_level,cracked,scope FROM audits ORDER BY id').fetchall()
with open(os.path.join(OUT,'hydra_audit_events.jsonl'),'w',encoding='utf-8') as f:
 for r in rows:f.write(json.dumps({'event_type':'hydra_audit','audit_id':r[0],'timestamp_utc':r[1],'algorithm':r[2],'risk_score':r[3],'risk_level':r[4],'recovered':bool(r[5]),'scope':r[6]})+'\n')
with open(os.path.join(OUT,'hydra_audit_events.cef'),'w',encoding='utf-8') as f:
 for r in rows:f.write(f'CEF:0|HydraCrack|Security Audit|3.0|HYDRA-AUDIT|Password security audit|{r[3]}|rt={r[1]} cs1={r[2]} cs1Label=algorithm cs2={r[4]} cs2Label=riskLevel\n')
print('SIEM exports written to exports/')
