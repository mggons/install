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

Write-Host "Ocultando Actualizacion KB5005463"
Install-PackageProvider -Name Nuget -Force
Install-Module PSWindowsUpdate -Force
Hide-WindowsUpdate -KBArticleID KB5005463 -Confirm:$False

Write-Host "Instalando Winget"
Add-AppxPackage -Path C:\Cambios\Postinstall\appx\Microsoft.UI.Xaml.2.7_7.2109.13004.0_x64.appx
Add-AppxPackage -Path C:\Cambios\Postinstall\appx\Microsoft.UI.Xaml.2.7_7.2109.13004.0_x86.appx
Add-AppxPackage -Path C:\Cambios\Postinstall\appx\Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64.appx

# GUI Specs
Write-Host "Checking winget..."

Try{
	# Check if winget is already installed
	$er = (invoke-expression "winget -v") 2>&1
	if ($lastexitcode) {throw $er}
	Write-Host "winget is already installed."
}
Catch{
	# winget is not installed. Install it from the Github release
	Write-Host "winget is not found, installing it right now."

	$asset = Invoke-RestMethod -Method Get -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' | ForEach-Object assets | Where-Object name -like "*.msixbundle"
	$output = $PSScriptRoot + "\winget-latest.appxbundle"
	Write-Host "Downloading latest winget release"
	Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $output

	Write-Host "Installing the winget package"
	Add-AppxPackage -Path $output

    Write-Host "Cleanup winget install package"
    if (Test-Path -Path $output) {
        Remove-Item $output -Force -ErrorAction SilentlyContinue
    }
}


# GUI Specs
Write-Host "Checking winget..."

Try{
	# Check if winget is already installed
	$er = (invoke-expression "winget -v") 2>&1
	if ($lastexitcode) {throw $er}
	Write-Host "winget is already installed."
}
Catch{
	# winget is not installed. Install it from the Github release
	Write-Host "winget is not found, installing it right now."

	$asset = Invoke-RestMethod -Method Get -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' | ForEach-Object assets | Where-Object name -like "*.msixbundle"
	$output = $PSScriptRoot + "\winget-latest.appxbundle"
	Write-Host "Downloading latest winget release"
	Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $output

	Write-Host "Installing the winget package"
	Add-AppxPackage -Path $output

    Write-Host "Cleanup winget install package"
    if (Test-Path -Path $output) {
        Remove-Item $output -Force -ErrorAction SilentlyContinue
    }
}


$delay = 15
$Counter_Form = New-Object System.Windows.Forms.Form
$Counter_Form.Text = "Countdown Timer!"
$Counter_Form.Width = 150
$Counter_Form.Height = 70
$Counter_Label = New-Object System.Windows.Forms.Label
$Counter_Label.AutoSize = $true 
$Counter_Form.Controls.Add($Counter_Label)
while ($delay -ge 0)
{
  $Counter_Form.Show()
  $Counter_Label.Text = "En espera: $($delay)"
  start-sleep 1
  $delay -= 1
}
$Counter_Form.Close()