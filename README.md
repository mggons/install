# Uso de los programas 


para usar los programas puedes iniciar un cmd en modo administrador 
luego escribir los siguientes comandos 

powershell Set-ExecutionPolicy Unrestricted<br>
@powershell Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/mggons/install/main/winget.ps1'))
