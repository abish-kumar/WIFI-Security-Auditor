@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 goto usepy
where python >nul 2>nul
if %errorlevel%==0 goto usepython
echo Python 3.8+ was not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
goto end
:usepy
py -3 run.py %*
goto end
:usepython
python run.py %*
:end
pause
