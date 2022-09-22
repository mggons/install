# Instalador de programas Windows 10/11 usando Windows Packet Manager (WINGET)


Para usar los programas puedes iniciar un cmd(Administrador) o powershell(Administrador)
luego escribir cualquiera de los siguientes dos comandos: 

ó usar el Programs.bat proporcionado que se podra descargar en el siguiente link: 

# Codigo 1 
1. powershell Set-ExecutionPolicy Unrestricted; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/mggons/install/main/wininstall.ps1'))
# Codigo 2
2. powershell Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/mggons/install/main/wininstall.ps1'))
