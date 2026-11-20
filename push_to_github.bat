@echo off
echo ======================================================================
echo  SentinelGate: Pushing to GitHub
echo  Target: https://github.com/roneeshraj/SentinelGate.git
echo ======================================================================
"C:\Program Files\Git\cmd\git.exe" push origin main
if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] SentinelGate successfully pushed to GitHub!
) else (
    echo.
    echo [NOTICE] If prompted for GitHub login, please sign in via browser or enter your GitHub Personal Access Token.
)
echo ======================================================================
pause
