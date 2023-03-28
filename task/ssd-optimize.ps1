Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

# Disable automatic pagefile management
$cs = gwmi Win32_ComputerSystem
if ($cs.AutomaticManagedPagefile) {
    $cs.AutomaticManagedPagefile = $False
    $cs.Put()
}
# Disable a *single* pagefile if any
$pg = gwmi win32_pagefilesetting
if ($pg) {
    $pg.Delete()
}
