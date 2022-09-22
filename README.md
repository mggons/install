# Para usar el instalador de Windows 10/11 mediante Windows Packet Manager (WINGET)


para usar los programas puedes iniciar un cmd en modo administrador 
luego escribir los siguientes comandos 

1. powershell Set-ExecutionPolicy Unrestricted; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/mggons/install/main/wininstall.ps1'))

2. @powershell Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/mggons/install/main/wininstall.ps1'))
