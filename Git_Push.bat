@echo off
setlocal

set "REPO_DIR=%~dp0"
cd /d "%REPO_DIR%"

echo ===============================================
echo  AES-CBC Web - Git Push Helper
echo ===============================================
echo.

where git >nul 2>nul
if not %errorlevel%==0 (
    echo Git was not found. Please install Git first.
    pause
    exit /b 1
)

if not exist ".git" (
    echo This folder is not a Git repository.
    echo Run git init first, then try again.
    pause
    exit /b 1
)

git status --short
echo.

set "MSG="
set /p MSG=Commit message: 
if "%MSG%"=="" set "MSG=Update AES-CBC web tool"

echo.
echo Adding files...
git add .
if not %errorlevel%==0 goto :error

echo.
echo Creating commit...
git commit -m "%MSG%"
if %errorlevel%==1 (
    echo.
    echo No commit was created. This may mean there are no changes to commit.
)

echo.
echo Pushing to remote...
git push
if not %errorlevel%==0 goto :error

echo.
echo Done. Changes were pushed successfully.
pause
exit /b 0

:error
echo.
echo Git push helper failed. Please check the message above.
pause
exit /b 1
