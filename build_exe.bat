@echo off
setlocal
cd /d "%~dp0"
py -3.12 -m venv .venv-build
if errorlevel 1 exit /b 1
.venv-build\Scripts\python -m pip install -r requirements-build.txt
if errorlevel 1 exit /b 1
.venv-build\Scripts\python -m pip install --no-build-isolation --no-deps -e .
if errorlevel 1 exit /b 1
.venv-build\Scripts\python -m unittest discover -v
if errorlevel 1 exit /b 1
.venv-build\Scripts\python scripts\build.py --gui-smoke
if errorlevel 1 exit /b 1
echo Build and CLI smoke tests completed. See dist\.
