@echo off
cls
setlocal enableextensions
setlocal enabledelayedexpansion

echo.
echo Kompiliert für alle Delphis in %ProgramFiles(x86)%\Embarcadero
echo TODO : auf Pfade aus Registry umstellen
echo HKCU\Software\Embarcadero\BDS\*.0 : RootDir
echo.
echo erstellt pro DelphiVersion+ProjectConfig ein Vergeichnis mit den DCUs 
echo ..\Compiled\DCU_IDE$(ProductVersion)_$(Platform)_$(Config)
echo.

title CLEAR
echo.
echo ##### CLEAR #####
echo. 
echo delete "..\Compiled"
echo.
del "%~dpn0.log"
rd /s /q "%~dp0..\Compiled"

cd /d "%ProgramFiles(x86)%\Embarcadero"
for /r %%X in (rsvars*.bat) do call :run_compiler "%%X"

echo.
title %comspec%
type "%~dpn0.log"
echo.
find /c "FAIL " "%~dpn0.log" >nul
if not errorlevel 1 pause
exit /b


:run_compiler
title COMPILE
echo.
echo ##### %~dp1 #####
echo.

setlocal
call "%~1"
set IDEVER=unknown
for /f "delims=" %%E in ("%BDS%") do set IDEVER=%%~nxE
echo. >> "%~dpn0.log" 
echo ### Delphi %IDEVER% ### >> "%~dpn0.log" 
echo. >> "%~dpn0.log" 

for %%P in (Win32,Win64,Linux64,Android,Android64,iOSDevice64,iOSSimulator,OSX32,OSX64) do (
  for %%C in (Debug,Release) do (
    call :do_compile "Source\DEC60.dproj" %%P %%C
  )
)

echo. >> "%~dpn0.log" 
for %%P in (Win32) do (
  for %%C in (Debug,GUI,MobileGUI,TestInsight) do (
    call :do_compile "Unit Tests\DECDUnitTestSuite.dproj" %%P %%C
  )
  for %%C in (Debug,Console) do (
    call :do_compile "Unit Tests\DECDUnitXTestSuite.dproj" %%P %%C
  )
)

echo. >> "%~dpn0.log" 
call :do_compile "Demos\Cipher_Console\Cipher_Console.dproj"
call :do_compile "Demos\Cipher_FMX\Cipher_FMX.dproj"
call :do_compile "Demos\CryptoWorkbench_VCL\CryptoWorkbench_VCL.dproj"
call :do_compile "Demos\Format_Console\Format_Console.dproj"
call :do_compile "Demos\Hash_Console\Hash_Console.dproj"
call :do_compile "Demos\Hash_FMX\Hash_FMX.dproj"
call :do_compile "Demos\Progress_VCL\Progress_VCL.dproj"
call :do_compile "Demos\Random_Console\Random_Console.dproj"

echo. >> "%~dpn0.log" 
title RUN Tests
echo ##### RUN Tests #####
REM for %%C in (Debug,Console,GUI) do (
REM   for %%P in (Win32) do (
REM     echo ### Test # %~dp0..\Compiled\BIN_IDE%IDEVER%_%%P_%%C\DECDUnitTestSuite.exe
REM     "%~dp0..\Compiled\BIN_IDE%IDEVER%_%%P_%%C\DECDUnitTestSuite.exe"
REM     "%~dp0..\Compiled\BIN_IDE%IDEVER%_%%P_%%C\DECDUnitXTestSuite.exe"
REM ) )
"%~dp0..\Compiled\BIN_IDE%IDEVER%_Win32_Console\DECDUnitTestSuite.exe"
"%~dp0..\Compiled\BIN_IDE%IDEVER%_Win32_Debug\DECDUnitTestSuite.exe"
"%~dp0..\Compiled\BIN_IDE%IDEVER%_Win32_Debug\DECDUnitXTestSuite.exe"
"%~dp0..\Compiled\BIN_IDE%IDEVER%_Win32_GUI\DECDUnitXTestSuite.exe"

endlocal
exit /b


:do_compile
title COMPILE %2 %3 : %~1
echo ### %2 %3 # %~1
set params=
if not "%2" == "" set params=/p:Platform=%2 /p:Config=%3
REM msbuild "%~dp0..\%~1" /t:Rebuild %params%     :: $(ProductVersion) fehlt im msbuild, aber in InlineCompiler der IDE ist es vorhanden
msbuild "%~dp0..\%~1" /t:Rebuild %params% /p:ProductVersion=%IDEVER%
if errorlevel 1 (
  :: remove if dir is empty
  if not "%2" == "" (
    rd /q "%~dp0..\Compiled\BIN_IDE%IDEVER%_%%P_%%C" >nul
    rd /q "%~dp0..\Compiled\DCP_IDE%IDEVER%_%%P_%%C" >nul
    rd /q "%~dp0..\Compiled\DCU_IDE%IDEVER%_%%P_%%C" >nul
  )
  echo FAIL   %2 %3 : %~1 >> "%~dpn0.log"
  rundll32 user32.dll,MessageBeep
  timeout 11
) else (
  echo OK     %2 %3 : %~1 >> "%~dpn0.log" 
)
echo.
exit /b
