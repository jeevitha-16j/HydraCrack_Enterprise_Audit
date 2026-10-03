@echo off
call .venv\Scripts\activate
python audit.py --hash 482c811da5d5b4bc6d497ffa98491e38 --algo md5 --cracked --password password123 --owner "College Security Lab" --scope "Synthetic classroom data" --notes "Authorized demonstration"
python report_pdf.py
python export_siem.py
pause
