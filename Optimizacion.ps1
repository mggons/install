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

	Write-Host "Installing the Microsoft.WindowsStore"
	Add-AppxPackage -Path C:\Cambios\Postinstall\appx\Microsoft.WindowsStore.appxbundle

	Write-Host "Installing the Microsoft.VCLibs.14.00_x86"
	Add-AppxPackage -Path C:\Cambios\Postinstall\appx\Microsoft.VCLibs.14.00_x86.appxbundle

	Write-Host "Installing the Microsoft.NET.Native.Runtime.2.0"
	Add-AppxPackage -Path C:\Cambios\Postinstall\appx\Microsoft.NET.Native.Runtime.2.0.appxbundle

	Write-Host "Installing the Microsoft.NET.Native.Framework.2.0"
	Add-AppxPackage -Path C:\Cambios\Postinstall\appx\Microsoft.NET.Native.Framework.2.0.appxbundle

	Write-Host "Installing the Microsoft.MicrosoftSolitaireCollection_4.11.12160.0"
	Add-AppxPackage -Path C:\Cambios\Postinstall\appx\Microsoft.MicrosoftSolitaireCollection_4.11.12160.0.appxbundle

Function Mostrar-MensajeCuadroDialogo {
Param
(
[string]$Mensaje, 
[string]$Titulo, 
[System.Windows.Forms.MessageBoxButtons]$Botones, 
[System.Windows.Forms.MessageBoxIcon]$Icono
)
    return [System.Windows.Forms.MessageBox]::Show($Mensaje, $Titulo, $Botones, $Icono)
}


Write-Host "------------------------------------"
Write-Host "Optimizando Windows PorFavor Espere."
Write-Host "------------------------------------"

Write-Host "Mostrando detalles de operaciones de archivo..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1



Write-Host "Establezca el factor de calidad de los fondos de escritorio JPEG al máximo"
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force
	


Write-Host "Borrar archivos temporales cuando las apps no se usen"
	if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1")
			{
				New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 1 -Force
			}
			

Write-Host "Deshabilitar noticias e intereses"
    $ResultText.text += "`r`n" +"Disabling Extra Junk"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0

Write-Host "Removiendo noticias e interés de la barra de tareas" 
    Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 0 -Force
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"))
			{
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force
			}
			New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name EnableFeeds -PropertyType DWord -Value 0 -Force

Write-Host "Iconos en el area de notificacion"
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -PropertyType DWord -Value 1 -Force
	
Write-Host "Meet now"
	$Settings = Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3 -Name Settings -ErrorAction Ignore
			$Settings[9] = 128
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3 -Name Settings -PropertyType Binary -Value $Settings -Force
	
Write-Host "Deshabilitando la búsqueda de Bing en el menú Inicio..."
    $ResultText.text = "`r`n" +"`r`n" + "Disabling Search, Cortana, Start menu search... Please Wait"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -PropertyType DWord -Value 0 -Force
    if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId"))
		{
		New-Item -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Force
		}
	New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Name State -PropertyType DWord -Value 1 -Force
	
	
Write-Host "Ocultar cuadro/botón de búsqueda..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

Write-Host "Eliminación de mosaicos del menú Inicio"
    Set-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -Value '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <LayoutOptions StartTileGroupCellWidth="6" />'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <DefaultLayoutOverride>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <StartLayoutCollection>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:StartLayout GroupCellWidth="6" />'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </StartLayoutCollection>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  </DefaultLayoutOverride>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <CustomTaskbarLayoutCollection>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:TaskbarLayout>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        <taskbar:TaskbarPinList>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:UWA AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        </taskbar:TaskbarPinList>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      </defaultlayout:TaskbarLayout>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </CustomTaskbarLayoutCollection>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '</LayoutModificationTemplate>'

    $START_MENU_LAYOUT = @"
    <LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
        <LayoutOptions StartTileGroupCellWidth="6" />
        <DefaultLayoutOverride>
            <StartLayoutCollection>
                <defaultlayout:StartLayout GroupCellWidth="6" />
            </StartLayoutCollection>
        </DefaultLayoutOverride>
    </LayoutModificationTemplate>
"@

    $layoutFile="C:\Windows\StartMenuLayout.xml"

    #Eliminar archivo de diseño si ya existe
    If(Test-Path $layoutFile)
    {
        Remove-Item $layoutFile
    }

    #Crea el archivo de diseño en blanco
    $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

    $regAliases = @("HKLM", "HKCU")

    #Asigne el diseño de inicio y fuerce su aplicación con "LockedStartLayout" tanto a nivel de máquina como de usuario
    foreach ($regAlias in $regAliases){
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer"
        IF(!(Test-Path -Path $keyPath)) {
            New-Item -Path $basePath -Name "Explorer"
        }
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
        Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
    }

#Reinicie Explorer, abra el menú de inicio (necesario para cargar el nuevo diseño) y espere unos segundos para que se procese
    Stop-Process -name explorer
    Start-Sleep -s 5
    $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
    Start-Sleep -s 5

#Habilite la capacidad de anclar elementos nuevamente al deshabilitar "LockedStartLayout"
    foreach ($regAlias in $regAliases){
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer"
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0

Write-Host "Ajustes de búsqueda y menú de inicio completos"
    $ResultText.text = "`r`n" +"`r`n" + "Search and Start Menu Tweaks Complete"
    
}

	
$Bloatware = @(
    #Unnecessary Windows 10 AppX Apps
    "Microsoft.3DBuilder"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.AppConnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.MinecraftUWP"
    "Microsoft.GamingServices"
    # "Microsoft.WindowsReadingList"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    # "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.Sway"
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    # "Microsoft.Whiteboard"
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    # "Microsoft.WindowsSoundRecorder"
    # "Microsoft.XboxApp"
    "Microsoft.ConnectivityStore"
    "Microsoft.CommsPhone"
    # "Microsoft.ScreenSketch"
    # "Microsoft.Xbox.TCUI"
    "Microsoft.XboxGameOverlay"
    # "Microsoft.XboxGameCallableUI"
    # "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.MixedReality.Portal"
    # "Microsoft.XboxIdentityProvider"
    #"Microsoft.ZuneMusic"
    #"Microsoft.ZuneVideo"
    #"Microsoft.YourPhone"
    "Microsoft.Getstarted"
    "MicrosoftTeams_8wekyb3d8bbwe"
    "Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe"
    "Microsoft.Todos_8wekyb3d8bbwe"
    "Microsoft.Teams"
    "Microsoft.MicrosoftOfficeHub"
	"Microsoft.549981C3F5F10"
	"Microsoft.XboxGameCallableUI"
	"Microsoft.XboxSpeechToTextOverlay"
	"Microsoft.Xbox.TCUI"


    #Sponsored Windows 10 AppX Apps
    #Add sponsored/featured apps to remove in the "*AppName*" format
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*CandySoda*"
    "*BubbleWitch3Saga*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Royal Revolt*"
    "*Sway*"
    "*Spotify*"
    "*Speed Test*"
    #"*Dolby*"
    "*Viber*"
    "*ACGMediaPlayer*"
    "*Netflix*"
    "*OneCalendar*"
    "*LinkedInforWindows*"
    "*HiddenCityMysteryofShadows*"
    "*Hulu*"
    "*HiddenCity*"
    "*AdobePhotoshopExpress*"
    "*Plex*"
    "*SketchBook*"
    "*Disney.37853FC22B2CE*"
    "*March of Empires: War of Lords*"

    #Optional: Por lo general, no se elimina, pero puede hacerlo si lo necesita por algún motivo.
    "*Microsoft.Advertising.Xaml*"
    "*Microsoft.MSPaint*"
    #"*Microsoft.MicrosoftStickyNotes*"
    "*Microsoft.Windows.Photos*"
    #"*Microsoft.WindowsCalculator*"
    #"*Microsoft.WindowsStore*"
	
	
)

 Write-Host "Eliminación de bloatware"
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $Bloat."
        $ResultText.text = "`r`n" +"`r`n" + "Trying to remove $Bloat."
    }

    Write-Host "Finalizó la eliminación de aplicaciones Bloatware"
    $ResultText.text = "`r`n" +"`r`n" + "Finished Removing Bloatware Apps"
	# SVCHost Tweak
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304

Write-Host "Ejecutar O&O Shutup con la configuración recomendada"
    $ResultText.text += "`r`n" +"Running O&O Shutup with Recommended Settings"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg" -Destination ooshutup10.cfg
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
    ./OOSU10.exe ooshutup10.cfg /quiet

Write-Host "Restringiendo Windows Update P2P solo a la red local..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1

	New-ItemProperty -Path Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings -Name DownloadMode -PropertyType DWord -Value 0 -Force
			Delete-DeliveryOptimizationCache -Force


Write-Host "Deshabilitando Cortana..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
Write-Host "Deshabilitando Cortana"
    $ResultText.text = "`r`n" +"`r`n" + "Disabled Cortana"

Write-Host "Habilitación del modo oscuro"
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -Value 0 -Type Dword -Force
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0 -Type Dword -Force
    Write-Host "Enabled Dark Mode"
    $ResultText.text = "`r`n" +"`r`n" + "Enabled Dark Mode"
	
Write-Host "Inhabilitando telemetría..."
    $ResultText.text += "`r`n" +"Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

Write-Host "Inhabilitando Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

Write-Host "Deshabilitando sugerencias de aplicaciones..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

#Write-Host "Disabling Activity History..."
#    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
#    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
#    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

Write-Host "Inhabilitando las actualizaciones automáticas de Maps..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

Write-Host "Inhabilitando experiencias personalizadas..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    
Write-Host "Inhabilitando ID de publicidad..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

Write-Host "Deshabilitando informe de errores..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    
Write-Host "Deteniendo y deshabilitando el servicio de seguimiento de diagnósticos..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
    Write-Host "Stopping and disabling Home Groups services..."
    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service "HomeGroupListener" -StartupType Disabled
    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service "HomeGroupProvider" -StartupType Disabled
    
#Write-Host "Inhabilitando la asistencia remota..."
#    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

Write-Host "Inhabilitando el sensor de almacenamiento..."
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
    Write-Host "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled

Write-Host "Desactivando Hibernación..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

#Write-Host "Mostrando detalles del administrador de tareas..."
#    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
#    Do {
#        Start-Sleep -Milliseconds 100
#       $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
#    } Until ($preferences)
#    Stop-Process $taskmgr
#    $preferences.Preferences[28] = 0
#    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences

Write-Host "Ocultar el botón Vista de tareas..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

Write-Host "Icono de personas ocultas..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
	
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People))
			{
				New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Force
			}
			New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Name PeopleBand -PropertyType DWord -Value 0 -Force


Write-Host "Ocultar iconos de la bandeja..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 1
#Write-Host "Enabling NumLock after startup..."
#    If (!(Test-Path "HKU:")) {
#        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
#    }
#    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
#    Add-Type -AssemblyName System.Windows.Forms
#    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
#        $wsh = New-Object -ComObject WScript.Shell
#        $wsh.SendKeys('{NUMLOCK}')
#    }

Write-Host "Segundos en el relog"
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSecondsInSystemClock -PropertyType DWord -Value 1 -Force

Write-Host "Cambiando la vista predeterminada del Explorador a Esta PC..."
    $ResultText.text += "`r`n" +"Quality of Life Tweaks"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

Write-Host "Ocultando el ícono de Objetos 3D de Esta PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

#Network Tweaks
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20

Write-Host "Habilitando la oferta de controladores a través de Windows Update..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue

Write-Host "Habilitando el reinicio automático de Windows Update..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue

Write-Host "Oferta de controlador habilitado a través de Windows Update"
    $ResultText.text = "`r`n" +"`r`n" + "Set Windows Updates to Stock Settings"

Write-Host "Ajuste de efectos visuales para el rendimiento..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
    Write-Host "Adjusted visual effects for performance"
    $ResultText.text = "`r`n" +"`r`n" + "Adjusted VFX for performance"

Write-Host "Restaurando el historial del portapapeles..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -ErrorAction SilentlyContinue
	Write-Host "Done - Reverted to Stock Settings"
    $ResultText.text = "`r`n" +"`r`n" + "Enabled Clipboard History"

Write-Host "Habilitando proveedor de ubicación..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -ErrorAction SilentlyContinue
	Write-Host "Enabling Location Scripting..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -ErrorAction SilentlyContinue

Write-Host "Habilitando ubicación..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "Value" -Type String -Value "Allow"

Write-Host "Permitir el acceso a la ubicación..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value "1"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation_UserInControlOfTheseApps" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation_ForceAllowTheseApps" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation_ForceDenyTheseApps" -ErrorAction SilentlyContinue
	Write-Host "Done - Reverted to Stock Settings"
    $ResultText.text = "`r`n" +"`r`n" + "Location Tracking now on... Reboot to check."

Write-Host "Iconos grandes del panel de control"
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
		{
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
		}
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force
		New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 1 -Force

Write-Host "Enable Sensor de Almacenamiento x30 dias"
		if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy))
			{
		    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -ItemType Directory -Force
			}
			New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01 -PropertyType DWord -Value 1 -Force
		
			if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1")
			{
				New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -PropertyType DWord -Value 30 -Force
			}



Write-Host "InstallVCRedistx64"
function InstallVCRedistx64
{
	$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
	$Parameters = @{
		Uri             = "https://aka.ms/vs/17/release/VC_redist.x64.exe"
		OutFile         = "$DownloadsFolder\VC_redist.x64.exe"
		UseBasicParsing = $true
		Verbose         = $true
	}
	Invoke-WebRequest @Parameters

	Start-Process -FilePath "$DownloadsFolder\VC_redist.x64.exe" -ArgumentList "/install /passive /norestart" -Wait
	<#
		PowerShell 5.1 (7.2 too) interprets the 8.3 file name literally, if an environment variable contains a non-latin word,
		so you won't be able to remove "$env:TEMP\dd_vcredist_amd64_*.log" file explicitly

		Another ways to get normal path to %TEMP%
		[Environment]::GetEnvironmentVariable("TEMP", "User")
		(Get-ItemProperty -Path HKCU:\Environment -Name TEMP).TEMP
		[System.IO.Path]::GetTempPath()
	#>
	Get-ChildItem -Path "$DownloadsFolder\VC_redist.x64.exe", "$env:TEMP\dd_vcredist_amd64_*.log" -Force | Remove-Item -Recurse -Force -ErrorAction Ignore
}


Write-Host "Quitar - Aplicaciones agregadas recientemente en el menú Inicio"
			if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
			{
				New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
			}
			New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name HideRecentlyAddedApps -PropertyType DWord -Value 1 -Force
			New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -PropertyType DWord -Value 0 -Force


			# Eliminar todas las aplicaciones excluidas que se ejecutan en segundo plano
			Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | ForEach-Object -Process {
				Remove-ItemProperty -Path $_.PsPath -Name * -Force
			}

			# Excluir aplicaciones del paquete únicamente
			$BackgroundAccessApplications = @((Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications).PSChildName)
			$ExcludedBackgroundAccessApplications = @()
			foreach ($BackgroundAccessApplication in $BackgroundAccessApplications)
			{
				if (Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object -FilterScript {$_.PackageFamilyName -eq $BackgroundAccessApplication})
				{
					$ExcludedBackgroundAccessApplications += $BackgroundAccessApplication
				}
			}

			Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | Where-Object -FilterScript {$_.PSChildName -in $ExcludedBackgroundAccessApplications} | ForEach-Object -Process {
				New-ItemProperty -Path $_.PsPath -Name Disabled -PropertyType DWord -Value 1 -Force
				New-ItemProperty -Path $_.PsPath -Name DisabledByUser -PropertyType DWord -Value 1 -Force
			}

			# Abra la página "Aplicaciones en segundo plano"
			Start-Process -FilePath ms-settings:privacy-backgroundapps
			

Write-Host "La tarea programada de limpieza de Windows para limpiar archivos y actualizaciones no utilizados de Windows"
function CleanupTask
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Register"
		)]
		[switch]
		$Register
	)	

		switch ($PSCmdlet.ParameterSetName)
	{
		"Register"
		{
			if (-not (Get-ScheduledTask -TaskPath "\SophiApp\" -TaskName "Windows Cleanup" -ErrorAction Ignore))
			{
				Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
					Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore
				}

				$VolumeCaches = @(
					# Delivery Optimization Files
					"Delivery Optimization Files",

					# Device driver packages
					"Device Driver Packages",

					# Previous Windows Installation(s)
					"Previous Installations",

					# Setup log files
					"Setup Log Files",

					# Temporary Setup Files
					"Temporary Setup Files",

					# Windows Update Cleanup
					"Update Cleanup",

					# Microsoft Defender
					"Windows Defender",

					# Windows upgrade log files
					"Windows Upgrade Log Files"
				)
				foreach ($VolumeCache in $VolumeCaches)
				{
					New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$VolumeCache" -Name StateFlags1337 -PropertyType DWord -Value 2 -Force
				}

				$CleanupTask = @"
Get-Process -Name cleanmgr | Stop-Process -Force
Get-Process -Name Dism | Stop-Process -Force
Get-Process -Name DismHost | Stop-Process -Force

`$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
`$ProcessInfo.FileName = """$env:SystemRoot\system32\cleanmgr.exe"""
`$ProcessInfo.Arguments = """/sagerun:1337"""
`$ProcessInfo.UseShellExecute = `$true
`$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

`$Process = New-Object -TypeName System.Diagnostics.Process
`$Process.StartInfo = `$ProcessInfo
`$Process.Start() | Out-Null

Start-Sleep -Seconds 3

[int]`$SourceMainWindowHandle = (Get-Process -Name cleanmgr | Where-Object -FilterScript {`$_.PriorityClass -eq """BelowNormal"""}).MainWindowHandle

function MinimizeWindow
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = `$true)]
		`$Process
	)

	`$ShowWindowAsync = @{
		Namespace = """WinAPI"""
		Name = """Win32ShowWindowAsync"""
		Language = """CSharp"""
		MemberDefinition = @'
[DllImport("""user32.dll""")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
'@
	}

	if (-not ("""WinAPI.Win32ShowWindowAsync""" -as [type]))
	{
		Add-Type @ShowWindowAsync
	}
	`$MainWindowHandle = (Get-Process -Name `$Process | Where-Object -FilterScript {`$_.PriorityClass -eq """BelowNormal"""}).MainWindowHandle
	[WinAPI.Win32ShowWindowAsync]::ShowWindowAsync(`$MainWindowHandle, 2)
}

while (`$true)
{
	[int]`$CurrentMainWindowHandle = (Get-Process -Name cleanmgr | Where-Object -FilterScript {`$_.PriorityClass -eq """BelowNormal"""}).MainWindowHandle
	if (`$SourceMainWindowHandle -ne `$CurrentMainWindowHandle)
	{
		MinimizeWindow -Process cleanmgr
		break
	}
	Start-Sleep -Milliseconds 5
}

`$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
`$ProcessInfo.FileName = """`$env:SystemRoot\system32\dism.exe"""
`$ProcessInfo.Arguments = """/Online /English /Cleanup-Image /StartComponentCleanup /NoRestart"""
`$ProcessInfo.UseShellExecute = `$true
`$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

`$Process = New-Object -TypeName System.Diagnostics.Process
`$Process.StartInfo = `$ProcessInfo
`$Process.Start() | Out-Null
"@

				# Create the "Windows Cleanup" task
				$Action     = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -Command $CleanupTask"
				$Settings   = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
				$Principal  = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
				$Parameters = @{
					TaskName    = "Windows Cleanup"
					TaskPath    = "Sophia Script"
					Principal   = $Principal
					Action      = $Action
					Description = $Localization.CleanupTaskDescription
					Settings    = $Settings
				}
				Register-ScheduledTask @Parameters -Force

				# Persist the Settings notifications to prevent to immediately disappear from Action Center
				if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"))
				{
					New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" -Force
				}
				New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" -Name ShowInActionCenter -PropertyType DWord -Value 1 -Force

				# Register the "WindowsCleanup" protocol to be able to run the scheduled task by clicking the "Run" button in a toast
				if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup\shell\open\command))
				{
					New-Item -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup\shell\open\command -Force
				}
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Name "(default)" -PropertyType String -Value "URL:WindowsCleanup" -Force
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Name "URL Protocol" -PropertyType String -Value "" -Force
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Name EditFlags -PropertyType DWord -Value 2162688 -Force

				# Start the "Windows Cleanup" task if the "Run" button clicked
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup\shell\open\command -Name "(default)" -PropertyType String -Value 'powershell.exe -Command "& {Start-ScheduledTask -TaskPath ''\Sophia Script\'' -TaskName ''Windows Cleanup''}"' -Force

				$ToastNotification = @"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

[xml]`$ToastTemplate = @"""
<toast duration="""Long""" scenario="""reminder""">
	<visual>
		<binding template="""ToastGeneric""">
			<text>$($Localization.CleanupTaskNotificationTitle)</text>
			<group>
				<subgroup>
					<text hint-style="""title""" hint-wrap="""true""">$($Localization.CleanupTaskNotificationEventTitle)</text>
				</subgroup>
			</group>
			<group>
				<subgroup>
					<text hint-style="""body""" hint-wrap="""true""">$($Localization.CleanupTaskNotificationEvent)</text>
				</subgroup>
			</group>
		</binding>
	</visual>
	<audio src="""ms-winsoundevent:notification.default""" />
	<actions>
		<input id="""SnoozeTimer""" type="""selection""" title="""$($Localization.CleanupTaskNotificationSnoozeInterval)""" defaultInput="""1""">
			<selection id="""1""" content="""$($Localization.Minute)""" />
			<selection id="""30""" content="""$($Localization.HalfHour)""" />
			<selection id="""240""" content="""$($Localization.FourHours)""" />
		</input>
		<action activationType="""system""" arguments="""snooze""" hint-inputId="""SnoozeTimer""" content="""""" id="""test-snooze"""/>
		<action arguments="""WindowsCleanup:""" content="""$($Localization.Run)""" activationType="""protocol"""/>
		<action arguments="""dismiss""" content="""""" activationType="""system"""/>
	</actions>
</toast>
"""@

`$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
`$ToastXml.LoadXml(`$ToastTemplate.OuterXml)

`$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New(`$ToastXML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("""windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel""").Show(`$ToastMessage)
"@

				# Create the "Windows Cleanup Notification" task
				$Action    = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -Command $ToastNotification"
				$Settings  = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
				$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
				$Trigger   = New-ScheduledTaskTrigger -Daily -DaysInterval 30 -At 9pm
				$Parameters = @{
					TaskName    = "Windows Cleanup Notification"
					TaskPath    = "Sophia Script"
					Action      = $Action
					Settings    = $Settings
					Principal   = $Principal
					Trigger     = $Trigger
					Description = $Localization.CleanupNotificationTaskDescription
				}
				Register-ScheduledTask @Parameters -Force
			}
		}
		"Delete"
		{
			Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
				Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore
			}

			Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" -Name ShowInActionCenter -Force -ErrorAction Ignore

			Unregister-ScheduledTask -TaskPath "\Sophia Script\" -TaskName "Windows Cleanup", "Windows Cleanup Notification" -Confirm:$false -ErrorAction Ignore

			Remove-Item -Path Registry::HKEY_CLASSES_ROOT\WindowsCleanup -Recurse -Force -ErrorAction Ignore
		}
	}


Write-Host "The Temp scheduled task for cleaning up the %TEMP% folder"
if (-not (Get-ScheduledTask -TaskPath "\SophiApp\" -TaskName "Temp" -ErrorAction Ignore))
			{
				$TempTask = @"
Get-ChildItem -Path `$env:TEMP -Recurse -Force | Where-Object {`$_.CreationTime -lt (Get-Date).AddDays(-1)} | Remove-Item -Recurse -Force

[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

[xml]`$ToastTemplate = @"""
<toast duration="""Long""">
	<visual>
		<binding template="""ToastGeneric""">
			<text>$($Localization.TaskNotificationTitle)</text>
			<group>
				<subgroup>
					<text hint-style="""body""" hint-wrap="""true""">$($Localization.TempTaskNotificationEvent)</text>
				</subgroup>
			</group>
		</binding>
	</visual>
	<audio src="""ms-winsoundevent:notification.default""" />
</toast>
"""@

`$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
`$ToastXml.LoadXml(`$ToastTemplate.OuterXml)

`$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New(`$ToastXML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("""windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel""").Show(`$ToastMessage)
"@

				# Create the "Temp" task
				$Action    = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -Command $TempTask"
				$Settings  = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
				$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
				$Trigger   = New-ScheduledTaskTrigger -Daily -DaysInterval 60 -At 9pm
				$Parameters = @{
					TaskName    = "Temp"
					TaskPath    = "Sophia Script"
					Action      = $Action
					Settings    = $Settings
					Principal   = $Principal
					Trigger     = $Trigger
					Description = $Localization.FolderTaskDescription -f "%TEMP%"
				}
				Register-ScheduledTask @Parameters -Force
			}
}

Write-Host "Microsoft Defender Exploit Guard network protection"
if ((Get-MpComputerStatus).AntivirusEnabled)
			{
				Set-MpPreference -EnableNetworkProtection Enabled
			}
		
if ((Get-MpComputerStatus).AntivirusEnabled)
			{
				Set-MpPreference -PUAProtection Enabled
			}		


			
Write-Host "Oculte el elemento Enviar a del menú contextual de carpetas"			
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(default)" -PropertyType String -Value "-{7BA4C740-9E81-11CF-99D3-00AA004AE837}" -Force

Write-Host "Agregando DNS de Adguard - ELiminar publicidad"
set-DnsClientServerAddress -InterfaceAlias “Ethernet” -ServerAddresses 176.103.130.130,176.103.130.131,1.1.1.1,8.8.8.8,8.8.4.4.4
set-DnsClientServerAddress -InterfaceAlias “Wi-Fi” -ServerAddresses 176.103.130.130,176.103.130.131,1.1.1.1,8.8.8.8,8.8.4.4.4
Set-DNSClientServerAddress "Ethernet" -ServerAddresses ("2a00:5a60::ad1:0ff","2a00:5a60::ad2:0ff")
Set-DNSClientServerAddress "Wi-Fi" -ServerAddresses ("2a00:5a60::ad1:0ff","2a00:5a60::ad2:0ff")
ipconfig /flushdns

Write-Host "Proceso completado..."
