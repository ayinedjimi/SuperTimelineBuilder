@echo off
setlocal

echo ========================================
echo Super Timeline Builder - Compilation
echo WinToolsSuite v3.0
echo ========================================
echo.

REM Vérifier cl.exe
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Compilateur MSVC non trouve
    echo Executez depuis "Developer Command Prompt for VS"
    pause
    exit /b 1
)

set SRC=SuperTimelineBuilder.cpp
set OUT=SuperTimelineBuilder.exe
set LIBS=comctl32.lib wevtapi.lib advapi32.lib user32.lib gdi32.lib comdlg32.lib

echo [1/2] Compilation %SRC%...
cl.exe /nologo /W4 /EHsc /O2 /std:c++17 /D_UNICODE /DUNICODE ^
    /Fe:%OUT% %SRC% ^
    /link %LIBS% /SUBSYSTEM:WINDOWS /MANIFEST:EMBED

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERREUR] Echec de la compilation
    pause
    exit /b 1
)

echo.
echo [2/2] Nettoyage...
del *.obj 2>nul

echo.
echo ========================================
echo Compilation reussie: %OUT%
echo Taille:
dir /-C %OUT% | find ".exe"
echo ========================================
echo.
echo UTILISATION:
echo   %OUT%
echo.
echo NOTE: Necessite privileges admin pour
echo       acces complet Event Logs
echo.
pause
