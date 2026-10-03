@echo off
cd /d "%~dp0"
python audit.py --hash 098f6bcd4621d373cade4e832627b4f6 --cracked --password test --owner "College Authorized Lab" --notes "Synthetic classroom hash"
echo.
echo Report saved under reports\
pause
