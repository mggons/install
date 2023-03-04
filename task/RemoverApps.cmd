@Echo off 
TITLE Instalando Adguard Espere...
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )

pushd "%~dp0"
cd /d "%~dp0"

DEL /F C:\ODT\Adguard.cmd
DEL /F C:\ODT\Setup_Adguard.exe
RD /Q C:\ODT
DEL /F C:\AutoSetup.exe
DEL /F C:\ooshutup.cfg
DEL /F C:\OOSU10.exe

exit