@echo off
setlocal

set "PORT=8080"
set "APP_DIR=%~dp0"

cd /d "%APP_DIR%"

echo ===============================================
echo  AES-CBC Web V1.0.0
echo  Local URL: http://localhost:%PORT%/
echo ===============================================
echo.

where python >nul 2>nul
if %errorlevel%==0 (
    start "" "http://localhost:%PORT%/"
    python -m http.server %PORT%
    goto :end
)

where py >nul 2>nul
if %errorlevel%==0 (
    start "" "http://localhost:%PORT%/"
    py -m http.server %PORT%
    goto :end
)

echo Python was not found. Opening index.html directly instead.
echo If Web Crypto is unavailable, install Python and run this file again.
echo.
start "" "%APP_DIR%index.html"

:end
endlocal
