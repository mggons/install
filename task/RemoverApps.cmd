@Echo off 
TITLE Instalando Adguard Espere...
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )

pushd "%~dp0"
cd /d "%~dp0"

attrib +h .\ooshutup10.cfg
ping 127.0.0.1 -n 3 > nul
attrib +h .\oosu10.exe
ping 127.0.0.1 -n 3 > nul

DEL /F C:\ODT\Adguard.cmd
ping 127.0.0.1 -n 3 > nul
DEL /F C:\ODT\Setup_Adguard.exe
ping 127.0.0.1 -n 3 > nul
DEL /F C:\AutoSetup.exe
ping 127.0.0.1 -n 3 > nul
DEL /F C:\Cambios.reg
ping 127.0.0.1 -n 3 > nul
DEL /F C:\AutoClean_Temp.xml
ping 127.0.0.1 -n 3 > nul
DEL /F C:\Optimize_RAM.xml
ping 127.0.0.1 -n 3 > nul
DEL /F C:\ActiveOOSU.xml
ping 127.0.0.1 -n 3 > nul
DEL /F C:\Reset_Adguard.xml
ping 127.0.0.1 -n 3 > nul
DEL /F C:\RegOptimize.reg
ping 127.0.0.1 -n 3 > nul

exit
