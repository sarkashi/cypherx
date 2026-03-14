@echo off
chcp 65001 >nul
echo.
echo   CypherX v1.0.0
echo   ----------------------------------
echo.

python --version >nul 2>&1 || (echo   [ERROR] Python not found. Install from python.org && pause && exit /b 1)
echo   [*] Python found

echo   [*] Installing packages...
pip install -r requirements.txt -q
echo   [OK] Packages installed

if not exist results    mkdir results
if not exist reports    mkdir reports
if not exist logs       mkdir logs
if not exist wordlists  mkdir wordlists
echo   [OK] Directories created

echo.
echo   CypherX v1.0.0 installed.
echo   Run: python cypherx.py --help
echo.
pause
