$pythonUrl = "https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe"
$installerPath = "$env:TEMP\python-installer.exe"
Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath
Start-Process -FilePath $installerPath -ArgumentList "/quiet PrependPath=1 Include_test=0" -Wait
Remove-Item $installerPath
