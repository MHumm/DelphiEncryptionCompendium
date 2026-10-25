@echo off
where dxcomply.exe >nul 2>nul

:: errorlevel 0 bedeutet: Gefunden
if %errorlevel% == 0 (
    goto :found
) else (
    goto :missing
)

:found
  dxcomply --library --project=Source\DEC60.dproj --source-dir=..\Source --version=6.4.1 --repo-url=https://github.com/MHumm/DelphiEncryptionCompendium --licence=Apache-2.0 --supplier="Team DEC" --supplier-url=https://github.com/MHumm/DelphiEncryptionCompendium --sbom-creator=markus.humm@gmail.com --report=html --output=..\bom.json
  goto :end

:missing
  ECHO dx.comply Delphi IDE plugin from Olaf Monien needed
  
:end