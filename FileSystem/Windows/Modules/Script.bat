@Echo off
Title MW11
setlocal EnableDelayedExpansion

Echo "Disabling Process Mitigations"
call C:\Windows\Modules\disable-process-mitigations.bat >nul 2>&1
cls

Echo "Execution Policy To Unrestricted"
powershell set-executionpolicy unrestricted -force >nul 2>&1
cls

Echo "Disabling reserved storage"
DISM /Online /Set-ReservedStorageState /State:Disabled >nul 2>&1
cls

Echo "Editing Bcdedit"
bcdedit /set disabledynamictick yes
bcdedit /set {current} description "MW11"
label C: Windows
cls

Echo "Restore old context menu"
Reg add "HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
@=""
cls

echo "POWERSAVING"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"
cls

echo "POWERPLAN"
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /delete 381b4222-f694-41f0-9685-ff5bb260df2e
powercfg /delete a1841308-3541-4fab-bc81-f71556f20b4a
powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0
powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /setacvalueindex scheme_current 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 100
powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 5000
powercfg /setactive scheme_current
cls

echo "LOCKSCREEN"
rmdir "C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z" /s /q

echo "SLEEPSTUDY"
wevtutil.exe set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:false
wevtutil.exe set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:false
wevtutil.exe set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:false

Echo "Optimizing Scheduled Tasks"
schtasks /Delete /TN "\Microsoft\Windows\Location" /F
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\InstallService\ScanForUpdates" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Maintenance\WinSAT" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\PI\Sqm-Tasks" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Registry\RegIdleBackup" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" /DISABLE
schtasks /Change /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /DISABLE
cls

Echo "Changing fsutil behaviors"
fsutil behavior set disable8dot3 1 > NUL 2>&1
fsutil behavior set disablelastaccess 1 > NUL 2>&1
cls

Echo "Disabling Drivers and Services"
for %%z in (
      Sense
      MapsBroker
	OneSyncSvc
	SysMain
	spooler
      WSearch
      Sense
      SecurityHealthService
      WinDefend
      WdNisSvc
      WdNisDrv
      WdFilter
      WdBoot
) do (
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%%z" /v "Start" /t REG_DWORD /d "4" /f
)
cls

Echo "Setting Timer Resolution"
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "TimerResolution" /t REG_SZ /d "C:\Windows\SetTimerResolution.exe --resolution 5070 --no-console" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t Reg_DWORD /d "1" /f >nul 2>&1
cls

Echo "Renaming microcodes"
cd C:\Windows\System32
takeown /f "mcupdate_AuthenticAMD.dll"
icacls "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /grant Administrators:F
ren mcupdate_AuthenticAMD.dll mcupdate_AuthenticAMD.old
takeown /f "mcupdate_GenuineIntel.dll"
icacls "C:\Windows\System32\mcupdate_GenuineIntel.dll" /grant Administrators:F
ren mcupdate_GenuineIntel.dll mcupdate_GenuineIntel.old
cls

Echo "Fix explorer white bar bug"
cmd /c "start C:\Windows\explorer.exe"
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
cmd /c "start C:\Windows\explorer.exe"
cls

Echo "Cleanup"
takeown /f "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" /a >nul 2>&1 & icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" /grant Administrators:F >nul 2>&1
xcopy "%WinDir%\Modules\cleanup.bat" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" /i >nul 2>&1
cls

shutdown -r -t 0
