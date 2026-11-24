@echo off
chcp 65001 >nul
set ITMON_ENROLL_KEY=enroll-dev
set ITMON_ADMIN_PASSWORD=admin123
set ITMON_SECRET=change-me-to-a-long-random-string-please
cd /d "%~dp0"
start "ITMon server" cmd /k "cd server && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"
timeout /t 3 >nul
start "ITMon agent" cmd /k "python agent\agent.py"
timeout /t 5 >nul
start http://localhost:8000
