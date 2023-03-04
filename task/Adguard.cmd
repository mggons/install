@Echo off 
TITLE Instalando Adguard Espere...
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )

pushd "%~dp0"
cd /d "%~dp0"

cls
echo.-------------------------------------------------------------
echo		Scripts En ejecucion PorFavor Espere...
echo	               Instalando Adguard
echo.-------------------------------------------------------------
C:\ODT\AutoSetup.exe
ping 127.0.0.1 -n 20 > nul
taskkill /f /IM msedge.exe
ping 127.0.0.1 -n 2 > nul
taskkill /f /IM Setup_Adguard.tmp /T
echo completo.
ping 127.0.0.1 -n 3 > nul

exit