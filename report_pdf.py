#!/usr/bin/env python3
"""Generate a professional PDF from the latest audit report."""
import json,os
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
ROOT=os.path.dirname(os.path.abspath(__file__))
def generate(src=None,out=None):
 src=src or os.path.join(ROOT,'reports','audit_report.json'); out=out or os.path.join(ROOT,'reports','hydra_audit_report.pdf')
 with open(src,encoding='utf-8') as f:d=json.load(f)
 styles=getSampleStyleSheet(); doc=SimpleDocTemplate(out,pagesize=A4,rightMargin=42,leftMargin=42,topMargin=42,bottomMargin=42); story=[Paragraph('HydraCrack Security Audit Report',styles['Title']),Paragraph('Authorized security assessment • local/synthetic data',styles['Normal']),Spacer(1,16)]
 data=[['Field','Value'],['Audit ID',d['audit_id']],['UTC Timestamp',d['timestamp_utc']],['Owner',d['scope_owner']],['Scope',d['scope']],['Algorithm',d['algorithm']],['Risk',f"{d['risk_score']}/100 — {d['risk_level']}"],['Hash fingerprint',d['hash_fingerprint']]]
 t=Table(data,colWidths=[140,350]); t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#17324d')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),.5,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('PADDING',(0,0),(-1,-1),7)])); story += [t,Spacer(1,18),Paragraph('Findings',styles['Heading2'])]
 for x in d['findings']: story.append(Paragraph('• '+x,styles['BodyText']))
 story += [Spacer(1,12),Paragraph('Recommendations',styles['Heading2'])]
 for x in d['recommendations']: story.append(Paragraph('• '+x,styles['BodyText']))
 story += [Spacer(1,16),Paragraph('Responsible-use note: test only data and systems for which explicit authorization exists.',styles['Italic'])]
 doc.build(story); return out
if __name__=='__main__': print(generate())
