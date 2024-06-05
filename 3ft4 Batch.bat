@echo off
setlocal EnableDelayedExpansion 
:: Apache License
:: Version 2.0, January 2004
:: http://www.apache.org/licenses/
:: Made by 3ft4©

:: Set title
title 3ft4 Batch %Version%

:: Checking Administrator Rights
cd %systemroot%\system32
call :IsAdmin

:: Set Version Bat
Set Version=v0.0.1

:: Add ANSI escape sequences
reg add "HKCU\CONSOLE" /v "VirtualTerminalLevel" /t REG_DWORD /d "1" /f >nul 2>&1

:: Set Powershell Execution Policy to Unrestricted
powershell "Set-ExecutionPolicy Unrestricted"

:: Color Character
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (set "DEL=%%a" & set "COL=%%b")

:Home
cls
echo.
echo 1 - Interface
echo 2 - Optimization
echo 3 - Clear
echo 4 - Activation
echo 5 - Software
echo 6 - About
echo 7 - Exit
echo.
choice /c:"1234567" /n /m "%BS%"
set MenuItem=%errorlevel%
if "%MenuItem%"=="1" goto :Interface
if "%MenuItem%"=="2" goto :Optimization
if "%MenuItem%"=="3" goto :Clear
if "%MenuItem%"=="4" goto :Activation
if "%MenuItem%"=="5" goto :Software
if "%MenuItem%"=="6" goto :About
if "%MenuItem%"=="7" endlocal

<Interface>
    :Interface
    cls
    echo.
    echo 1 - Explorer
    echo 2 - Theme
    echo 3 - Back
    echo.
    choice /c:"123" /n /m "%BS%"
    set MenuItem=%errorlevel%
    if "%MenuItem%"=="1" goto :Explorer
    if "%MenuItem%"=="2" goto :Theme
    if "%MenuItem%"=="3" goto :Home

    <Explorer>
        :Explorer
        cls
        echo.
        echo To cancel an action, select the item you want to cancel again.
        echo.
        echo 1 - Delete Home in Explorer
        echo 2 - Delete the Gallery item in Explorer
        echo 3 - Delete Network in Explorer
        echo 4 - Remove duplicate disks (is not canceled)
        echo 5 - Disable desktop wallpaper compression
        echo 6 - Back
        echo.
        choice /c:"123456" /n /m "%BS%"
        set MenuItem=%errorlevel%
        if "%MenuItem%"=="1" goto :ehome
        if "%MenuItem%"=="2" goto :egallery
        if "%MenuItem%"=="3" goto :enetwork
        if "%MenuItem%"=="4" goto :edisks
        if "%MenuItem%"=="5" goto :ewallpaper
        if "%MenuItem%"=="6" goto :Interface

        :ehome
        reg query "HKCU\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /v "System.IsPinnedToNameSpaceTree" >nul 2>&1
        if %errorlevel% equ 0 (
            reg delete "HKCU\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /v "System.IsPinnedToNameSpaceTree" /f >nul 2>&1
        ) else (
            reg add "HKCU\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /v "System.IsPinnedToNameSpaceTree" /d "0" /t REG_DWORD /f >nul 2>&1
        )
        taskkill /f /im explorer.exe >nul 2>&1
        start explorer.exe >nul 2>&1
        goto :Explorer

        :egallery
        reg query "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" >nul 2>&1
        if %errorlevel% equ 0 (
            reg delete "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /f >nul 2>&1
        ) else (
            reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /d "0" /t REG_DWORD /f >nul 2>&1
        )
        taskkill /f /im explorer.exe >nul 2>&1
        start explorer.exe >nul 2>&1
        goto :Explorer

        :enetwork
        reg query "HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v "System.IsPinnedToNameSpaceTree" >nul 2>&1
        if %errorlevel% equ 0 (
            reg delete "HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v "System.IsPinnedToNameSpaceTree" /f >nul 2>&1
        ) else (
            reg add "HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v "System.IsPinnedToNameSpaceTree" /d "0" /t REG_DWORD /f >nul 2>&1
        )
        taskkill /f /im explorer.exe >nul 2>&1
        start explorer.exe >nul 2>&1
        goto :Explorer

        :edisks
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders" /f >nul 2>&1
        reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders" /f >nul 2>&1
        taskkill /f /im explorer.exe >nul 2>&1
        start explorer.exe >nul 2>&1
        goto :Explorer

        :ewallpaper
        reg query "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" >nul 2>&1
        if %errorlevel% equ 0 (
            reg delete "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /f >nul 2>&1
        ) else (
            reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /d "100" /t REG_DWORD /f >nul 2>&1
        )
        taskkill /f /im explorer.exe >nul 2>&1
        start explorer.exe >nul 2>&1
        goto :Explorer

    </Explorer>

    <Theme>
        :Theme
        cls
        echo.
        echo To cancel an action, select the item you want to cancel again.
        echo.
        echo 1 - Enable Dark mode
        echo 2 - Disable transparency
        echo 3 - Enable seconds in the clock on the taskbar
        echo 4 - Back
        echo.
        choice /c:"1234" /n /m "%BS%"
        set MenuItem=%errorlevel%
        if "%MenuItem%"=="1" goto :tdark
        if "%MenuItem%"=="2" goto :ttransparency
        if "%MenuItem%"=="3" goto :tseconds
        if "%MenuItem%"=="4" goto :Interface

        :tdark
        for /f "tokens=3" %%a in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme"') do set lightTheme=%%a >nul 2>&1
        if %lightTheme%==0x1 (
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f >nul 2>&1
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f >nul 2>&1
        ) else (
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 1 /f >nul 2>&1
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 1 /f >nul 2>&1
        )
        taskkill /f /im explorer.exe >nul 2>&1
        start explorer.exe >nul 2>&1
        goto :Theme

        :ttransparency
        for /f "tokens=3" %%a in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency"') do set transparency=%%a >nul 2>&1
        if %transparency%==0x1 (
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f >nul 2>&1
        ) else (
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 1 /f >nul 2>&1
        )
        taskkill /f /im explorer.exe >nul 2>&1
        start explorer.exe >nul 2>&1
        goto :Theme

        :tseconds
        reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSecondsInSystemClock" >nul 2>&1
        if %errorlevel% equ 0 (
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSecondsInSystemClock" /f >nul 2>&1
        ) else (
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSecondsInSystemClock" /t REG_DWORD /d "1" /f >nul 2>&1
        )
        taskkill /f /im explorer.exe >nul 2>&1
        start explorer.exe >nul 2>&1
        goto :Theme

    </Theme>

</Interface>

<Optimization>
    :Optimization
    cls
    echo. 
    echo 1 - Basic settings
    echo 2 - Debloat MS apps
    echo 3 - Network
    echo 4 - Privacy
    echo 5 - Disable Windows Defender 
    echo 6 - Disable Windows Update
    echo 7 - GPU
    echo 8 - Back
    echo.
    choice /c:"12345678" /n /m "%BS%"
    set MenuItem=%errorlevel%
    if "%MenuItem%"=="1" goto :Basic
    if "%MenuItem%"=="2" goto :Debloat
    if "%MenuItem%"=="3" goto :Network
    if "%MenuItem%"=="4" goto :Privacy
    if "%MenuItem%"=="5" goto :Defender
    if "%MenuItem%"=="6" goto :Update
    if "%MenuItem%"=="7" goto :GPU
    if "%MenuItem%"=="8" goto :Home

    <Basic>
        :Basic
        cls
        echo PowerShell Unrestricted
        powershell "Set-ExecutionPolicy Unrestricted" >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWERSHELL_TELEMETRY_OPTOUT" /t REG_DWORD /d "1" /f >NUL 2>&1

        echo Mitigations
        PowerShell Set-ProcessMitigation -System -Disable CFG
        for /f "tokens=3 skip=2" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do (
            set "mitigation_mask=%%a"
        ) > nul 2>&1
        for /L %%a in (0,1,9) do (
            set "mitigation_mask=!mitigation_mask:%%a=2!"
        ) > nul 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "%mitigation_mask%" /f > nul 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "%mitigation_mask%" /f > nul 2>&1

        echo Disable EnableAeroPeek
        Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable save taskbar thumbnail previews
        Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable Superfetch
        sc config SysMain start=disabled >NUL 2>&1

        echo Driver searching
        Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable startup apps
        Reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f >NUL 2>&1
        Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f >NUL 2>&1

        echo Disable Auto Download Store
        Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "0"/ f >NUL 2>&1

        echo Disable UAC
        Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Delete Config xbox
        reg delete "HKCU\System\GameConfigStore\Children" /f >NUL 2>&1
        reg delete "HKCU\System\GameConfigStore\Parents" /f >NUL 2>&1

        echo MenuShowDelay
        Reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable Virtualization
        Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo WDF
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Wdf" /v "WdfGlobalLogsDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Wdf" /v "WdfGlobalSleepStudyDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

        echo Kernel 
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "EnableWerUserReporting" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "PowerOffFrozenProcessors" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "EnableWerUserReporting" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "IdleScanInterval" /t REG_DWORD /d "300" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MSDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "FxAccountingTelemetryDisabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingFlushInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceIdleResiliency" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Memory Managment
        PowerShell -Command "Disable-MMAgent -PageCombining" >NUL 2>&1
        PowerShell -Command "Disable-MMAgent -PageCombining" >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f >NUL 2>&1 
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f >NUL 2>&1 
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >NUL 2>&1

        echo Optimize shutdown time
        reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillService" /t REG_SZ /d "1000" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "HungAppTimeout" /t REG_SZ /d "4000" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "AutoEndTasks" /t REG_SZ /d "1" /f >NUL 2>&1

        echo Disable Maps
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f >NUL 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f >NUL 2>&1

        echo Spectre, Meltdown and CPU Microcode
        del "C:\Windows\System32\mcupdate_GenuineIntel.dll" /s /f /q >NUL 2>&1
        del "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /s /f /q >NUL 2>&1

        echo Win32PrioritySeparation
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "18" /f >NUL 2>&1

        echo Disable Maintance
        Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

        echo Disable Fault Tolerant Heap
        Reg add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable PowerThrottling
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >NUL 2>&1

        echo Disable GpuEnergyDrv
        Reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

        echo Disable Energy Logging
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable Windows Insider Experiments
        Reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo TimeStampInterval
        Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "1" /f >NUL 2>&1

        echo SystemResponsiveness
        Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >NUL 2>&1

        echo Disabling Frequent and Recent Files
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "TelemetrySalt" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f >NUL 2>&1

        echo Disable Shared Experiences
        Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable Tailored Experiences
        Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f  >NUL 2>&1

        echo Disable Bing Search
        Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >NUL 2>&1
 
        echo Disable Microsoft Setting Synchronization  
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable Error Reporting
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >NUL 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >NUL 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f >NUL 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >NUL 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Consent" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Enable FSO
        reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f >NUL 2>&1

        echo Disable Xbox GameBar
        reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable Policy
        reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f >NUL 2>&1

        echo Enbale DistributeTimers
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f >NUL 2>&1

        echo Customer experience improvement program
        Reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable Sticky Key
        reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "506" /f >NUL 2>&1

        echo Disable Remote Assistance
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Retrieval of online tips and help in the immersive control panel
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f  >NUL 2>&1

        echo Disable Typing insights
        reg add "HKCU\SOFTWARE\Microsoft\input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable LargeSystemCache
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disavble PPM
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM" /v Start /t REG_DWORD /d "3" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\IntelPPM" /v Start /t REG_DWORD /d "3" /f >NUL 2>&1

        echo Setting Mouse
        reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f  >NUL 2>&1
        reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f  >NUL 2>&1
        reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >NUL 2>&1

        echo Disable Windows Remediation
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SlideshowEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "1" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280815Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-202914Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable DMA
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /t REG_DWORD /d "2" /f 
        for /f %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /s /f DmaRemappingCompatible ^| find /i "Services\"') do (
            reg add "%%i" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f 
        ) >NUL 2>&1

        echo Disable USB IDLE
        for %%a in (EnhancedPowerManagementEnabled AllowIdleIrpInD3 EnableSelectiveSuspend DeviceSelectiveSuspended SelectiveSuspendEnabled SelectiveSuspendOn EnumerationRetryCount ExtPropDescSemaphore WaitWakeEnabled D3ColdSupported WdfDirectedPowerTransitionEnable EnableIdlePowerManagement IdleInWorkingState IoLatencyCap) do (
            for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do (
                reg add "%%b" /v "%%a" /t REG_DWORD /d "0" /f 
            )
        ) >NUL 2>&1

        echo Disable Autologgers
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f  >NUL 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f >NUL 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Power settings
        powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >NUL 2>&1
        powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61 >NUL 2>&1
        powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0 >NUL 2>&1
        powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >NUL 2>&1
        powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 100 >NUL 2>&1
        powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318584 100 >NUL 2>&1
        powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 5000 >NUL 2>&1\
        Powercfg /setvalueindex scheme_current_sub_processor PROCTHROTTLEMIN 100 >NUL 2>&1
        Powercfg /setvalueindex scheme_current_sub_processor PROCTHROTTLEMAX 100 >NUL 2>&1
        Powercfg /setvalueindex scheme_current_sub_processor perfautonomous 1 >NUL 2>&1
        Powercfg /setvalueindex scheme_current_sub_processor PERFEPP  0 >NUL 2>&1
        Powercfg /setvalueindex scheme_current_sub_processor PERFBOOSTMODE 4 >NUL 2>&1
        powercfg -setactive scheme_current

        echo Disable core isolation
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Disable Hiberboot
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1 

        echo Disable Hibirnate
        powercfg /h off >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
        Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f >NUL 2>&1

        echo Setting BCD
        bcdedit /set firstmegabytepolicy     UseAll >NUL 2>&1
        bcdedit /set avoidlowmemory          0x8000000 >NUL 2>&1
        bcdedit /set configaccesspolicy      Default >NUL 2>&1
        bcdedit /set displaymessageoverride  Recovery >NUL 2>&1
        bcdedit /set recoveryenabled         Yes >NUL 2>&1
        bcdedit /set noumex                  Yes >NUL 2>&1
        bcdedit /set vm                      No >NUL 2>&1
        bcdedit /set bootems                 No >NUL 2>&1
        bcdedit /set nointegritychecks       No >NUL 2>&1
        bcdedit /set testsigning             No >NUL 2>&1
        bcdedit /set extendedinput           Yes >NUL 2>&1
        bcdedit /set highestmode             Yes >NUL 2>&1
        bcdedit /set isolatedcontext         No >NUL 2>&1
        bcdedit /set forcefipscrypto         No >NUL 2>&1
        bcdedit /set allowedinmemorysettings 0x0 >NUL 2>&1
        bcdedit /set nx                      AlwaysOff >NUL 2>&1
        bcdedit /set pae                     ForceEnable >NUL 2>&1
        bcdedit /set perfmem                 0 >NUL 2>&1
        bcdedit /set x2apicpolicy            Enable >NUL 2>&1
        bcdedit /set msi                     Default >NUL 2>&1
        bcdedit /set bootmenupolicy          Legacy >NUL 2>&1
        bcdedit /set hypervisorlaunchtype    Off >NUL 2>&1
        bcdedit /set bootux                  Disabled >NUL 2>&1
        bcdedit /set tpmbootentropy          ForceDisable >NUL 2>&1
        bcdedit /set vsmlaunchtype           Off >NUL 2>&1
        bcdedit /set nolowmem                Yes >NUL 2>&1
        bcdedit /set usephysicaldestination  No >NUL 2>&1
        bcdedit /set onecpu                  No >NUL 2>&1
        bcdedit /set maxproc                 Yes >NUL 2>&1
        bcdedit /set usefirmwarepcisettings  No >NUL 2>&1
        bcdedit /set halbreakpoint           No >NUL 2>&1
        bcdedit /set ems                     No >NUL 2>&1

        echo Setting Fsutil
        fsutil behavior set disablelastaccess 1 >NUL 2>&1
        fsutil behavior set disable8dot3 1 >NUL 2>&1
        
        echo Disable Tasks
        schtasks /change /TN "Microsoft\Windows\Autochk\Proxy" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\Maintenance\WinSAT" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /DISABLE > NUL 2>&1
        schtasks /change /TN "Microsoft\Windows\PI\Sqm-Tasks" /DISABLE > NUL 2>&1
        schtasks /Change /Disable /TN "\MicrosoftEdgeUpdateTaskMachineCore" > NUL 2>&1 
        schtasks /Change /Disable /TN "\MicrosoftEdgeUpdateTaskMachineUA" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Autochk\Proxy" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\StorageSense" > NUL 2>&1 
        schtasks /Change /Disable /TN "\MicrosoftEdgeUpdateBrowserReplacementTask" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Registry\RegIdleBackup" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Report policies" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Work" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\UPnP\UPnPHostConfig" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\SmartRetry" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\International\Synchronize Language Settings" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Multimedia\Microsoft\Windows\Multimedia" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Printing\EduPrintProv" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Ras\MobilityManager" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\PushToInstall\LoginCheck" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\WaaSMedic\PerformRemediation" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Wininet\CacheTask" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Device Setup\Metadata Refresh" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" > NUL 2>&1 
        schtasks /Change /Disable /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" > NUL 2>&1 

        echo Install DevManView
        curl -g -k -L -# -o "C:\Windows\System32\DevManView.exe" "https://github.com/ancel1x/Ancels-Performance-Batch/raw/main/bin/DevManView.exe" > NUL 2>&1 
        timeout /t 3 /nobreak > NUL

        echo Disable Devices through DevManView
        DevManView.exe /disable "High Precision Event Timer" > NUL 2>&1 
        DevManView.exe /disable "Microsoft GS Wavetable Synth" > NUL 2>&1 
        DevManView.exe /disable "Microsoft RRAS Root Enumerator" > NUL 2>&1 
        DevManView.exe /disable "Intel Management Engine" > NUL 2>&1 
        DevManView.exe /disable "Intel Management Engine Interface" > NUL 2>&1 
        DevManView.exe /disable "Intel SMBus" > NUL 2>&1 
        DevManView.exe /disable "SM Bus Controller" > NUL 2>&1 
        DevManView.exe /disable "Amdlog" > NUL 2>&1 
        DevManView.exe /disable "AMD PSP" > NUL 2>&1 
        DevManView.exe /disable "System Speaker" > NUL 2>&1 
        DevManView.exe /disable "Composite Bus Enumerator" > NUL 2>&1 
        DevManView.exe /disable "Microsoft Virtual Drive Enumerator" > NUL 2>&1 
        DevManView.exe /disable "Microsoft Hyper-V Virtualization Infrastructure Driver" > NUL 2>&1 
        DevManView.exe /disable "NDIS Virtual Network Adapter Enumerator" > NUL 2>&1 
        DevManView.exe /disable "Remote Desktop Device Redirector Bus" > NUL 2>&1 
        DevManView.exe /disable "UMBus Root Bus Enumerator" > NUL 2>&1 
        goto :Optimization
    </Basic>

    <Debloat>
        :Debloat
        cls
        del C:\Users\Public\Desktop\* /F /Q >NUL 2>&1

        echo Debloat Yandex music
        powershell "Get-AppxPackage -Allusers *yandex.music* | Remove-AppxPackage"

        echo Debloat Skype
        powershell "Get-AppxPackage -Allusers *Microsoft.SkypeApp* | Remove-AppxPackage"

        echo Debloat Camera
        powershell "Get-AppxPackage -Allusers *Microsoft.WindowsCamera* | Remove-AppxPackage"

        echo Debloat Xbox
        powershell "Get-AppxPackage -Allusers *Microsoft.Xbox.TCUI* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *Microsoft.XboxApp* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *Microsoft.XboxGameOverlay* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *Microsoft.XboxIdentityProvider* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *Microsoft.GamingApp* | Remove-AppxPackage"

        echo Debloat Grove Music
        powershell "Get-AppxPackage -Allusers *Microsoft.ZuneMusic* | Remove-AppxPackage"

        echo Debloat FeedbackHub
        powershell "Get-AppxPackage -Allusers *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"

        echo Debloat Microsoft-Tips
        powershell "Get-AppxPackage -Allusers *Microsoft.Getstarted* | Remove-AppxPackage"

        echo Debloat 3D Viewer
        powershell "Get-AppxPackage -Allusers *Microsoft.Microsoft3DViewer* | Remove-AppxPackage"

        echo Debloat 3D Builder
        powershell "Get-AppxPackage -Allusers *3DBuilder* | Remove-AppxPackage"

        echo Debloat MS Solitaire
        powershell "Get-AppxPackage -Allusers *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"

        echo Debloat Paint 3d
        powershell "Get-AppxPackage -Allusers *paint3d* | Remove-AppxPackage

        echo Debloat Paint
        powershell "Get-AppxPackage -Allusers *Microsoft.MSPaint* | Remove-AppxPackage

        echo Debloat BingWeather
        powershell "Get-AppxPackage -Allusers *Microsoft.BingWeather* | Remove-AppxPackage"

        echo Debloat Mail / Calendar
        powershell "Get-AppxPackage -Allusers *microsoft.windowscommunicationsapps* | Remove-AppxPackage"

        echo Debloat Your Phone
        powershell "Get-AppxPackage -Allusers *Microsoft.YourPhone* | Remove-AppxPackage"

        echo Debloat People
        powershell "Get-AppxPackage -Allusers *Microsoft.People* | Remove-AppxPackage"

        echo Debloat Wallet
        powershell "Get-AppxPackage -Allusers *Microsoft.Wallet* | Remove-AppxPackage"

        echo Debloat Maps
        powershell "Get-AppxPackage -Allusers *Microsoft.WindowsMaps* | Remove-AppxPackage"

        echo Debloat Onenote
        powershell "Get-AppxPackage -Allusers *Microsoft.Office.OneNote* | Remove-AppxPackage"

        echo Debloat Office
        powershell "Get-AppxPackage -Allusers *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"

        echo Debloat Voice Recorder
        powershell "Get-AppxPackage -Allusers *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"

        echo Debloat Movies and TV
        powershell "Get-AppxPackage -Allusers *Microsoft.ZuneVideo* | Remove-AppxPackage"

        echo Debloat Mixed Reality
        powershell "Get-AppxPackage -Allusers *Microsoft.MixedReality.Portal* | Remove-AppxPackage"

        echo Debloat Sticky notes
        powershell "Get-AppxPackage -Allusers *StickyNotes* | Remove-AppxPackage"

        echo Debloat Get Help
        powershell "Get-AppxPackage -Allusers *Microsoft.GetHelp* | Remove-AppxPackage"

        echo Debloat One Drive
        TASKKILL /f /im OneDrive.exe > NUL 2>&1 
        %systemroot%\System32\OneDriveSetup.exe /uninstall >NUL 2>&1
        %systemroot%\SysWOW64\OneDriveSetup.exe /uninstall >NUL 2>&1
        powershell "Get-AppxPackage -Allusers *OneDrive* | Remove-AppxPackage"

        echo Debloat Microsoft.OutlookForWindows
        powershell "Get-AppxPackage -AllUsers *outlook* | Remove-AppxPackage"

        echo Debloat One connect
        powershell "Get-AppxPackage -AllUsers *OneConnect* | Remove-AppxPackage"

        echo Debloat To do
        powershell "Get-AppxPackage -Allusers *Todos* | Remove-AppxPackage"

        echo Debloat PowerAutomate
        powershell "Get-AppxPackage -Allusers *PowerAutomateDesktop* | Remove-AppxPackage"

        echo Debloat Bing News
        powershell "Get-AppxPackage -Allusers *Microsoft.BingNews* | Remove-AppxPackage"

        echo Debloat Microsoft Teams
        powershell "Get-AppxPackage -Allusers *MicrosoftTeams* | Remove-AppxPackage"

        echo Debloat Family
        powershell "Get-AppxPackage -Allusers *MicrosoftFamilySafety* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *MicrosoftCorporationII.MicrosoftFamily | Remove-AppxPackage"

        echo Debloat QuickAssist
        powershell "Get-AppxPackage -Allusers *MicrosoftCorporationII.QuickAssist* | Remove-AppxPackage"

        echo Debloat Dev Home
        powershell "Get-AppxPackage -Allusers *Microsoft.DevHome* | Remove-AppxPackage"

        echo Debloat White Board
        powershell "Get-AppxPackage -Allusers *Whiteboard* | Remove-AppxPackage"

        echo Debloat Disney
        powershell "Get-AppxPackage -Allusers *Disney* | Remove-AppxPackage"

        echo Debloat Clipchamp
        powershell "Get-AppxPackage -Allusers *Clipchamp.Clipchamp* | Remove-AppxPackage"

        echo Debloat Alarms
        powershell "Get-AppxPackage -Allusers *Microsoft.WindowsAlarms* | Remove-AppxPackage"

        echo Debloat Cortana 
        powershell "Get-AppxPackage -allusers *Microsoft.549981C3F5F10* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *26720RandomSaladGamesLLC.3899848563C1F_kx24dqmazqk8j* | Remove-AppxPackage"
        powershell "Get-AppxPackage -Allusers *26720RandomSaladGamesLLC.Spades_kx24dqmazqk8j* | Remove-AppxPackage"

        goto :Optimization
    </Debloat>

    <Network>
        :Network
        cls
        echo Disable Components
        powershell Enable-NetAdapterBinding -Name * -ComponentID ms_pacer >NUL 2>&1
        powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_lldp,ms_lltdio,ms_msclient,ms_rspndr,ms_server,ms_implat,ms_tcpip6,ms_pppoe,ms_rdma_ndk,ms_ndisuio,ms_wfplwf_upper,ms_wfplwf_lower,ms_netbt,ms_netbios,ms_ndiscap"

        echo Configure Registry / Tcpip
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f >NUL 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f >NUL 2>&1
        goto :Optimization
    </Network>

    <Privacy>
        :Privacy
        cls
        echo Disable Telemetry
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "DoSvc" /t REG_DWORD /d "3" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "DisableOptinExperience" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
        reg add "HKLM\SYSTEM\DriverDatabase\Policies\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >nul 2>&1
        reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1

        echo Setting Privacy
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1
        Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f >NUL 2>&1

        echo Setting OOSU
        curl.exe "https://drive.usercontent.google.com/download?id=1LoxXTnt4NqZRBVHSzwPQcDI3-dOKm-Wa&export=download&authuser=0" -o "%TEMP%\ooshutup10.cfg" >NUL 2>&1
        curl.exe -s "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -o "%TEMP%\OOSU10.exe" >NUL 2>&1
        start /wait "" "%TEMP%\OOSU10.exe" "%TEMP%\ooshutup10.cfg" /quiet >NUL 2>&1
        goto :Optimization
    </Privacy>

    <Defender>
        :Defender
        cls
        reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" >nul 2>&1
        if %errorlevel% equ 0 (
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup " /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /f >nul 2>&1
            reg deleye "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /f >nul 2>&1
        ) else (
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup " /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen " /t REG_DWORD /d "1" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting " /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f >nul 2>&1
        )
        goto :Optimization
    </Defender>

    <Update>
        :Update
        cls
        reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" >nul 2>&1
        if %errorlevel% equ 0 (
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWUfBSafeguards" /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetAutoRestartNotificationDisable" /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" /f >nul 2>&1
            reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "2" /f >NUL 2>&1
            sc config wuauserv start= auto
            sc start wuauserv
        ) else (
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWUfBSafeguards" /t REG_DWORD /d "1" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetAutoRestartNotificationDisable" /t REG_DWORD /d "1" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
            sc stop wuauserv
            sc config wuauserv start= disabled
        )  
        goto :Optimization
    </Update>

    <GPU>
        :GPU
        cls
        echo. 
        echo 1 - Nvidia
        echo 2 - AMD (https://github.com/imribiy/amd-gpu-tweaks)
        echo 3 - Back
        echo.
        choice /c:"123" /n /m "%BS%"
        set MenuItem=%errorlevel%
        if "%MenuItem%"=="1" goto :Nvidia
        if "%MenuItem%"=="2" goto :AMD
        if "%MenuItem%"=="3" goto :Optimization

        <Nvidia>
            :Nvidia
            cls
            echo.
            echo 1 - Settings
            echo 2 - Disable Telemetry (https://privacy.sexy)
            echo 3 - NvidiaProfileInspector
            echo 4 - Back
            echo.
            choice /c:"1234" /n /m "%BS%"
            set MenuItem=%errorlevel%
            if "%MenuItem%"=="1" goto :NVSettings
            if "%MenuItem%"=="2" goto :NVTelemetry
            if "%MenuItem%"=="3" goto :NVProfileInspector
            if "%MenuItem%"=="4" goto :GPU

            <NVSettings>
                :NVSettings
                cls
                echo Disable Dynamic P-state
                for /f "tokens=*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HK"') do (
                    reg add "%%a" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
                ) > nul 2>&1

                echo Disable HDCP
                for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID ^| findstr /L "PCI\VEN_"') do (for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\ControlSet001\Enum\%%i" /v "Driver" ^| find "{"') do (Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%a" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f > nul 2>&1))

                echo Disable WriteCombining
                reg add "HKLM\SYSTEM\CurrentControlSet\services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f > nul 2>&1

                echo Disable DMA
                reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f > nul 2>&1

                echo Disable Preemtion
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d "1" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "EnableCEPreemption" /t REG_DWORD /d "0" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "DisablePreemptionOnS3S4" /t REG_DWORD /d "1" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "ComputePreemption" /t REG_DWORD /d "0" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "EnableMidGfxPreemption" /t REG_DWORD /d "0" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "EnableMidGfxPreemptionVGPU" /t REG_DWORD /d "0" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "EnableMidBufferPreemptionForHighTdrTimeout" /t REG_DWORD /d "0" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "EnableMidBufferPreemption" /t REG_DWORD /d "0" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "EnableAsyncMidBufferPreemption" /t REG_DWORD /d "0" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t REG_DWORD /d "0" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "DisplayPowerSaving" /t REG_DWORD /d "0" /f > nul 2>&1
                Reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f > nul 2>&1
                goto :Nvidia
            </NVSettings>

            <NVTelemetry>
                :NVTelemetry
                cls
                echo Disable NVIDIA Telemetry Report task
                PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) {; Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) {; $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) {; Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try {; $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch {; Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) {; Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }" > nul 2>&1

                echo Disable NVIDIA Telemetry Report on Logon task
                PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) {; Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) {; $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) {; Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try {; $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch {; Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) {; Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }" > nul 2>&1

                echo Disable NVIDIA telemetry monitor task
                PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) {; Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) {; $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) {; Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try {; $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch {; Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) {; Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }" > nul 2>&1

                echo Remove Nvidia telemetry packages
                if exist "%ProgramFiles%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (
                    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
                    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
                ) > nul 2>&1

                echo Remove Nvidia telemetry components
                PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%PROGRAMFILES(X86)%\NVIDIA Corporation\NvTelemetry\*"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; $renamedCount   = 0; $skippedCount   = 0; $failedCount    = 0; $foundAbsolutePaths = @(); Write-Host 'Iterating files and directories recursively.'; try {; $foundAbsolutePaths += @(; Get-ChildItem -Path $expandedPath -Force -Recurse -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] {; <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; try {; $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] {; <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) {; Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) {; if (Test-Path -Path $path -PathType Container) {; Write-Host "^""Skipping folder (not its contents): `"^""$path`"^""."^""; $skippedCount++; continue; }; if($revert -eq $true) {; if (-not $path.EndsWith('.OLD')) {; Write-Host "^""Skipping non-backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; } else {; if ($path.EndsWith('.OLD')) {; Write-Host "^""Skipping backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; }; $originalFilePath = $path; Write-Host "^""Processing file: `"^""$originalFilePath`"^""."^""; if (-Not (Test-Path $originalFilePath)) {; Write-Host "^""Skipping, file `"^""$originalFilePath`"^"" not found."^""; $skippedCount++; exit 0; }; if ($revert -eq $true) {; $newFilePath = $originalFilePath.Substring(0, $originalFilePath.Length - 4); } else {; $newFilePath = "^""$($originalFilePath).OLD"^""; }; try {; Move-Item -LiteralPath "^""$($originalFilePath)"^"" -Destination "^""$newFilePath"^"" -Force -ErrorAction Stop; Write-Host "^""Successfully processed `"^""$originalFilePath`"^""."^""; $renamedCount++; } catch {; Write-Error "^""Failed to rename `"^""$originalFilePath`"^"" to `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; $failedCount++; }; }; if (($renamedCount -gt 0) -or ($skippedCount -gt 0)) {; Write-Host "^""Successfully processed $renamedCount items and skipped $skippedCount items."^""; }; if ($failedCount -gt 0) {; Write-Warning "^""Failed to processed $($failedCount) items."^""; }" > nul 2>&1
                PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%PROGRAMFILES%\NVIDIA Corporation\NvTelemetry\*"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; $renamedCount   = 0; $skippedCount   = 0; $failedCount    = 0; $foundAbsolutePaths = @(); Write-Host 'Iterating files and directories recursively.'; try {; $foundAbsolutePaths += @(; Get-ChildItem -Path $expandedPath -Force -Recurse -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] {; <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; try {; $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] {; <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) {; Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) {; if (Test-Path -Path $path -PathType Container) {; Write-Host "^""Skipping folder (not its contents): `"^""$path`"^""."^""; $skippedCount++; continue; }; if($revert -eq $true) {; if (-not $path.EndsWith('.OLD')) {; Write-Host "^""Skipping non-backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; } else {; if ($path.EndsWith('.OLD')) {; Write-Host "^""Skipping backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; }; $originalFilePath = $path; Write-Host "^""Processing file: `"^""$originalFilePath`"^""."^""; if (-Not (Test-Path $originalFilePath)) {; Write-Host "^""Skipping, file `"^""$originalFilePath`"^"" not found."^""; $skippedCount++; exit 0; }; if ($revert -eq $true) {; $newFilePath = $originalFilePath.Substring(0, $originalFilePath.Length - 4); } else {; $newFilePath = "^""$($originalFilePath).OLD"^""; }; try {; Move-Item -LiteralPath "^""$($originalFilePath)"^"" -Destination "^""$newFilePath"^"" -Force -ErrorAction Stop; Write-Host "^""Successfully processed `"^""$originalFilePath`"^""."^""; $renamedCount++; } catch {; Write-Error "^""Failed to rename `"^""$originalFilePath`"^"" to `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; $failedCount++; }; }; if (($renamedCount -gt 0) -or ($skippedCount -gt 0)) {; Write-Host "^""Successfully processed $renamedCount items and skipped $skippedCount items."^""; }; if ($failedCount -gt 0) {; Write-Warning "^""Failed to processed $($failedCount) items."^""; }" > nul 2>&1

                echo Disable Nvidia telemetry drivers
                PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%SYSTEMROOT%\System32\DriverStore\FileRepository\NvTelemetry*.dll"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; $renamedCount   = 0; $skippedCount   = 0; $failedCount    = 0; $foundAbsolutePaths = @(); Write-Host 'Iterating files and directories recursively.'; try {; $foundAbsolutePaths += @(; Get-ChildItem -Path $expandedPath -Force -Recurse -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] {; <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; try {; $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] {; <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) {; Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) {; if (Test-Path -Path $path -PathType Container) {; Write-Host "^""Skipping folder (not its contents): `"^""$path`"^""."^""; $skippedCount++; continue; }; if($revert -eq $true) {; if (-not $path.EndsWith('.OLD')) {; Write-Host "^""Skipping non-backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; } else {; if ($path.EndsWith('.OLD')) {; Write-Host "^""Skipping backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; }; $originalFilePath = $path; Write-Host "^""Processing file: `"^""$originalFilePath`"^""."^""; if (-Not (Test-Path $originalFilePath)) {; Write-Host "^""Skipping, file `"^""$originalFilePath`"^"" not found."^""; $skippedCount++; exit 0; }; if ($revert -eq $true) {; $newFilePath = $originalFilePath.Substring(0, $originalFilePath.Length - 4); } else {; $newFilePath = "^""$($originalFilePath).OLD"^""; }; try {; Move-Item -LiteralPath "^""$($originalFilePath)"^"" -Destination "^""$newFilePath"^"" -Force -ErrorAction Stop; Write-Host "^""Successfully processed `"^""$originalFilePath`"^""."^""; $renamedCount++; } catch {; Write-Error "^""Failed to rename `"^""$originalFilePath`"^"" to `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; $failedCount++; }; }; if (($renamedCount -gt 0) -or ($skippedCount -gt 0)) {; Write-Host "^""Successfully processed $renamedCount items and skipped $skippedCount items."^""; }; if ($failedCount -gt 0) {; Write-Warning "^""Failed to processed $($failedCount) items."^""; }" > nul 2>&1

                echo Disable participation in Nvidia telemetry
                PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client' /v 'OptInOrOutPreference' /t 'REG_DWORD' /d '0' /f" > nul 2>&1
                PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS' /v 'EnableRID44231' /t 'REG_DWORD' /d '0' /f" > nul 2>&1
                PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS' /v 'EnableRID64640' /t 'REG_DWORD' /d '0' /f" > nul 2>&1
                PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS' /v 'EnableRID66610' /t 'REG_DWORD' /d '0' /f" > nul 2>&1
                PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup' /v 'SendTelemetryData' /t 'REG_DWORD' /d '0' /f" > nul 2>&1

                echo Disable Nvidia Telemetry Container service
                PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'NvTelemetryContainer'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }" > nul 2>&1
                goto :Nvidia
            </NVTelemetry>

            <NVProfileInspector>
                :NVProfileInspector
                cls
                curl -g -k -L -# -o "%temp%\nvidiaProfileInspector.zip" "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip" 
                powershell -NoProfile Expand-Archive '%temp%\nvidiaProfileInspector.zip' -DestinationPath '%TEMP%\NvidiaProfileInspector\' 
                timeout 1 > nul 2>&1
                del /f /s /q %temp%\nvidiaProfileInspector.zip > nul 2>&1
                curl -g -k -L -# -o "%temp%\NvidiaProfileInspector\3ft4.nip" "https://raw.githubusercontent.com/3ft4/3ft4-Batch/main/Files/3ft4.nip" 
                start "" /wait "%temp%\NvidiaProfileInspector\nvidiaProfileInspector.exe" "%temp%\NvidiaProfileInspector\3ft4.nip" 
                goto :Nvidia

            </NVProfileInspector>

        </Nvidia>

        <AMD>
            :AMD
            cls
            Reg.exe add "HKCU\Software\AMD\CN" /v "AutoUpdateTriggered" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "PowerSaverAutoEnable_CUR" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "BuildType" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "WizardProfile" /t REG_SZ /d "PROFILE_CUSTOM" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "UserTypeWizardShown" /t REG_DWORD /d "1" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "AutoUpdate" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "RSXBrowserUnavailable" /t REG_SZ /d "true" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "SystemTray" /t REG_SZ /d "false" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "AllowWebContent" /t REG_SZ /d "false" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "CN_Hide_Toast_Notification" /t REG_SZ /d "true" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN" /v "AnimationEffect" /t REG_SZ /d "false" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN\OverlayNotification" /v "AlreadyNotified" /t REG_DWORD /d "1" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\CN\VirtualSuperResolution" /v "AlreadyNotified" /t REG_DWORD /d "1" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\DVR" /v "PerformanceMonitorOpacityWA" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\DVR" /v "DvrEnabled" /t REG_DWORD /d "1" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\DVR" /v "ActiveSceneId" /t REG_SZ /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\DVR" /v "PrevInstantReplayEnable" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\DVR" /v "PrevInGameReplayEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\DVR" /v "PrevInstantGifEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\DVR" /v "RemoteServerStatus" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKCU\Software\AMD\DVR" /v "ShowRSOverlay" /t REG_SZ /d "false" /f > nul 2>&1
            Reg.exe add "HKCU\Software\ATI\ACE\Settings\ADL\AppProfiles" /v "AplReloadCounter" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKLM\Software\AMD\Install" /v "AUEP" /t REG_DWORD /d "1" /f > nul 2>&1
            Reg.exe add "HKLM\Software\AUEP" /v "RSX_AUEPStatus" /t REG_DWORD /d "2" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "NotifySubscription" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "IsComponentControl" /t REG_BINARY /d "00000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_USUEnable" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_RadeonBoostEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "IsAutoDefault" /t REG_BINARY /d "01000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_ChillEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ACE" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoDegree_SET" /t REG_BINARY /d "3020322034203820313600" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_SET" /t REG_BINARY /d "302031203220332034203500" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION" /t REG_BINARY /d "3200" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AAF" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "GI" /t REG_BINARY /d "31000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "CatalystAI" /t REG_BINARY /d "31000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TemporalAAMultiplier_NA" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "EnableTripleBuffering" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ExportCompressedTex" /t REG_BINARY /d "31000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "PixelCenter" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ZFormats_NA" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "DitherAlpha_NA" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SwapEffect_D3D_SET" /t REG_BINARY /d "3020312032203320342038203900" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ" /t REG_BINARY /d "3200" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "VSyncControl" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureLod" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ASE" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ASD" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ASTT" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AntiAliasSamples" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AntiAlias" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoDegree" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoType" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AntiAliasMapping_SET" /t REG_BINARY /d "3028303A302C313A3029203228303A322C313A3229203428303A342C313A3429203828303A382C313A382900" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AntiAliasSamples_SET" /t REG_BINARY /d "3020322034203800" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_SET" /t REG_BINARY /d "3020313620323400" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SwapEffect_OGL_SET" /t REG_BINARY /d "3020312032203320342035203620372038203920313120313220313320313420313520313620313700" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_SET" /t REG_BINARY /d "31203220342036203820313620333220363400" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "HighQualityAF" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "DisplayCrossfireLogo" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AppGpuId" /t REG_BINARY /d "300078003000310030003000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SwapEffect" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "PowerState" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AntiStuttering" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TurboSync" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SurfaceFormatReplacements" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "EQAA" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ShaderCache" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "MLF" /t REG_BINARY /d "3000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TruformMode_NA" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "LRTCEnable" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "3to2Pulldown" /t REG_BINARY /d "31000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "MosquitoNoiseRemoval_ENABLE" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "MosquitoNoiseRemoval" /t REG_BINARY /d "350030000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "Deblocking_ENABLE" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "Deblocking" /t REG_BINARY /d "350030000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "DemoMode" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "OverridePA" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "DynamicRange" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "StaticGamma_ENABLE" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "BlueStretch_ENABLE" /t REG_BINARY /d "31000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "BlueStretch" /t REG_BINARY /d "31000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "LRTCCoef" /t REG_BINARY /d "3100300030000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "DynamicContrast_ENABLE" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "WhiteBalanceCorrection" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "Fleshtone_ENABLE" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "Fleshtone" /t REG_BINARY /d "350030000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "ColorVibrance_ENABLE" /t REG_BINARY /d "31000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "ColorVibrance" /t REG_BINARY /d "340030000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "Detail_ENABLE" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "Detail" /t REG_BINARY /d "310030000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "Denoise_ENABLE" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "Denoise" /t REG_BINARY /d "360034000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "TrueWhite" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "OvlTheaterMode" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "StaticGamma" /t REG_BINARY /d "3100300030000000" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD\DXVA" /v "InternetVideo" /t REG_BINARY /d "30000000" /f > nul 2>&1
            Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_DEF" /t REG_SZ /d "1" /f > nul 2>&1
            Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f > nul 2>&1
            Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f > nul 2>&1
            Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Services\amdwddmg" /v "ChillEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Services\AMD Crash Defender Service" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Services\AMD External Events Utility" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Services\amdfendr" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Services\amdfendrmgr" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
            Reg.exe add "HKLM\System\CurrentControlSet\Services\amdlog" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
            sc config amdlog start=disabled > nul 2>&1
            sc config "AMD External Events Utility" start=disabled > nul 2>&1
            goto :GPU
        </AMD>

    </GPU>

</Optimization>

<Clear>
    :Clear
    cls

    echo Clear prefetch folder
    del /s /f /q %WINDIR%\Prefetch >NUL 2>&1

    echo Clear temporary system folder
    del /s /f /q %WINDIR%\Temp >NUL 2>&1
    rd /s /q "%WINDIR%\Temp" >NUL 2>&1

    echo Clear temporary user folder
    rd /s /q "%USERPROFILE%\AppData\Local\Temp" >NUL 2>&1
    cleanmgr /sagerun:0
    timeout 2 >NUL 2>&1
    goto :Home
</Clear>

<Activation>
    :Activation
    cls
    echo.
    echo Made by MASSGRAVE (https://github.com/massgravel/Microsoft-Activation-Scripts)
    start /wait powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://massgrave.dev/get | iex"
    goto :Home
</Activation>

<Software>
    :Software
    cls
    echo.
    echo 1 - DirectX
    echo 2 - .Net Framewok
    echo 3 - MSI AFTERBURNER
    echo 4 - Nvidia APP (Beta)
    echo 5 - Discord 
    echo 6 - Steam
    echo 7 - Spotify
    echo 8 - Back
    choice /c:"12345678" /n /m "%BS%"
    set MenuItem=%errorlevel%
    if "%MenuItem%"=="1" goto :DirectX
    if "%MenuItem%"=="2" goto :NetFramewok
    if "%MenuItem%"=="3" goto :MSIAFTERBURNER
    if "%MenuItem%"=="4" goto :NVAPP
    if "%MenuItem%"=="5" goto :Discord
    if "%MenuItem%"=="6" goto :Steam
    if "%MenuItem%"=="7" goto :Spotify
    if "%MenuItem%"=="8" goto :Home
    
    :DirectX
    cls
    curl -g -k -L -# -o "%temp%\dxwebsetup.exe" "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe" 
    start /wait %temp%\dxwebsetup.exe > nul 2>&1
    timeout 2 > nul 2>&1
    del /s /f /q %temp%\dxwebsetup.exe > nul 2>&1
    goto :Software

    :NetFramewok
    cls
    curl -g -k -L -# -o "%temp%\ndp48-x86-x64-allos-enu.exe" "https://go.microsoft.com/fwlink/?linkid=2088631" 
    start /wait %temp%\ndp48-x86-x64-allos-enu.exe > nul 2>&1
    timeout 2 > nul 2>&1
    del /s /f /q %temp%\ndp48-x86-x64-allos-enu.exe > nul 2>&1
    goto :Software

    :MSIAFTERBURNER
    cls
    curl -g -k -L -# -o "%temp%\MSIAfterburnerSetup.zip" "https://download.msi.com/uti_exe/vga/MSIAfterburnerSetup.zip?__token__=exp=1717741079~acl=/*~hmac=8232476c44c21c0e35971684ea4ba9c6017212e09878b9929e983bae4a2d8d34" 
    powershell -NoProfile Expand-Archive '%temp%\MSIAfterburnerSetup.zip' -DestinationPath '%temp%\MSIAfterburnerSetup\' 
    start /wait %temp%\MSIAfterburnerSetup\MSIAfterburnerSetup465.exe > nul 2>&1
    timeout 2 > nul 2>&1
    del /s /f /q %temp%\ndp48-x86-x64-allos-enu.exe > nul 2>&1
    goto :Software

    :NVAPP
    cls
    curl -g -k -L -# -o "%temp%\NVIDIA_app_beta_v10.0.0.535.exe" "https://ru.download.nvidia.com/nvapp/client/10.0.0.535/NVIDIA_app_beta_v10.0.0.535.exe" 
    start /wait %temp%\NVIDIA_app_beta_v10.0.0.535.exe > nul 2>&1
    timeout 2 > nul 2>&1
    del /s /f /q %temp%\NVIDIA_app_beta_v10.0.0.535.exe > nul 2>&1
    goto :Software

    :Discord
    cls
    curl -g -k -L -# -o "%temp%\DiscordSetup.exe" "https://discord.com/api/downloads/distributions/app/installers/latest?channel=stable&platform=win&arch=x64" 
    start /wait %temp%\DiscordSetup.exe > nul 2>&1
    timeout 2 > nul 2>&1
    del /s /f /q %temp%\DiscordSetup.exe > nul 2>&1
    goto :Software

    :Steam 
    cls
    curl -g -k -L -# -o "%temp%\SteamSetup.exe" "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe" 
    start /wait %temp%\SteamSetup.exe > nul 2>&1
    timeout 2 > nul 2>&1
    del /s /f /q %temp%\SteamSetup.exe > nul 2>&1
    goto :Software

    :Spotify
    cls
    curl -g -k -L -# -o "%temp%\SpotifySetup.exe" "https://download.scdn.co/SpotifySetup.exe" 
    start /wait %temp%\SpotifySetup.exe > nul 2>&1
    timeout 2 > nul 2>&1
    del /s /f /q %temp%\SpotifySetup.exe > nul 2>&1
    goto :Software

</Software>

<About>
    :About
    cls
    echo. 
    echo Made by: 3ft4
    echo License: Apache License (http://www.apache.org/licenses/)
    echo Discord: dsc.gg/3ft4
    echo Version: %Version%
    echo Credits: imribiy (XOS), https://privacy.sexy/, Matishzz, Amitxv, djdallmann, massgravel.
    echo.
    echo Press any key to return...
    pause > nul 2>&1
    goto :Home
</About>

:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
 Pause & Exit
)
Cls
goto:eof