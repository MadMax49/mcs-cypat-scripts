#Requires -RunAsAdministrator

$global:mainUser = Read-Host "Please enter the main user on this machine"
$global:distro = Read-Host "Please enter the type of machine this is (win10 or server19)"
if ( -not ('win10', 'server19').contains($global:distro.ToLower()) ) {
    Read-Host "Invalid type! Press ENTER to exit."
    exit 1
}

$safeYN = Read-Host "Should the script continue as normal or should it be run in safe mode? (type safe if safe mode is wanted)"

function Install-Programs {
    Write-Host "Installing the chocolatey package manager"
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Write-Host "Installing python3"
    choco install -y python3 --pre --force
    refreshenv
    Invoke-WebRequest "https://bootstrap.pypa.io/get-pip.py" -OutFile "get-pip.py"
    py "get-pip.py"
    Remove-Item "get-pip.py"
    $env:Path += ";C:\Python311\Scripts"
    py -m pip install --upgrade pip
    pip install bs4
    Write-Host "Installing MalwareBytes"
    choco install -y malwarebytes
    Write-Host "Upgrading firefox"
    choco upgrade -y firefox
}

function Edit-LocalUsers {
    $mainUser = $global:mainUser
    Disable-LocalUser -Name "Guest"
    Disable-LocalUser -Name "Administrator"
    $readme = Read-Host "Please enter the link to the README"
    $admins=$( py C:\Users\$mainUser\Desktop\windows\scraper.py $readme admins)
    $adminsList = $admins -split ";"
    $users=$( py C:\Users\$mainUser\Desktop\windows\scraper.py $readme users)
    $usersList = $users -split ";"
    $authUsersList = @($adminsList) + $usersList
    $currentUserList = Get-LocalUser | Where-Object -Property Enabled -eq True | Select-Object -Property Name 
    $currentAdminList = Get-LocalGroupMember -Group "Administrators" | Where-Object -Property PrincipalSource -eq Local | Select-Object -Property Name
    for ($i=0; $i -lt $currentAdminList.Length; $i++) {
        $currentAdminList[$i] = $currentAdminList[$i].Name.Split('\')[1]
    }
    for ($i=0; $i -lt $currentUserList.Length; $i++) {
        $currentUserList[$i] = $currentUserList[$i].Name
    }
    foreach ($user in $usersList) {
        if (-not ($user -in $currentUserList)) {
            # adds user if user on README is not on the local system
            $NewPass = ConvertTo-SecureString "M3rc1l3ss_cYp@t!1" -AsPlainText -Force
            New-LocalUser $user -Password $NewPass -Description "user added to the machine"
            Add-LocalGroupMember -Group "Users" -Member $user
        }
    }

    foreach ($user in $currentUserList) {
        cmd.exe /c "wmic UserAccount where Name='$user' set PasswordExpires=true" | Out-Null
        if (-not ($user -in $authUsersList)) {
            # delete user if user on the current system and not on the README
            Disable-LocalUser -Name $user
        }
        if (-not ($user -eq $mainUser)) {
            # Set new passwords for all users other than the main user
            $NewPass = ConvertTo-SecureString "M3rc1l3ss_cYp@t!1" -AsPlainText -Force
            Set-LocalUser -Name $user -Password $NewPass
        }
    }
    foreach ($admin in $currentAdminList) {
        # if admin is an admin on the system but not an authorized admin in the readme, remove from the group
        if (-not ($admin -in $adminsList)) {
            Remove-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction Ignore
        }
    }
    foreach ($admin in $adminsList) {
        # if admin is an admin on the README but not on the system, make that user an admin
        if (-not ($admin -in $currentAdminList)) {
            Add-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction Ignore
        }
    }
}

function Start-Defender {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    New-NetFirewallRule -DisplayName "Block 23" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Block 1337" -Direction Inbound -LocalPort 1337 -Protocol TCP -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Block 515" -Direction Inbound -LocalPort 515 -Protocol TCP -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Block 111" -Direction Inbound -LocalPort 111 -Protocol TCP -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Block 135" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Block 137" -Direction Inbound -LocalPort 137 -Protocol TCP -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Block 138" -Direction Inbound -LocalPort 138 -Protocol TCP -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Block 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "Block 69" -Direction Inbound -LocalPort 69 -Protocol TCP -Action Block | Out-Null
    # Disable network discovery
    Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Set-NetFirewallRule -Profile 'Private, Domain' -Enabled false
    Set-MpPreference -DisableRealtimeMonitoring $False
    Set-MpPreference -PUAProtection Enabled
    # Update-MpSignature
}

function Edit-Registry($path, $name, $value, $type) {
    $path = 'HKLM:' + $path
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    Set-ItemProperty -Path $path -Name $name -Value $value -Type $type -Force
}

function Edit-LocalSecurity {
    $mainUser = $global:mainUser
    ipconfig /flushdns
    # Copy-Item "C:\Users\$mainUser\Desktop\windows\templates\SecGuide.adml" -Destination 'C:\Windows\PolicyDefinitions\en-US\'
    # Copy-Item "C:\Users\$mainUser\Desktop\windows\templates\SecGuide.admx" -Destination 'C:\Windows\PolicyDefinitions\'
    # Copy-Item "C:\Users\$mainUser\Desktop\windows\templates\MSS-legacy.adml" -Destination 'C:\Windows\PolicyDefinitions\en-US\'
    # Copy-Item "C:\Users\$mainUser\Desktop\windows\templates\MSS-legacy.admx" -Destination 'C:\Windows\PolicyDefinitions\en-US\'
    # gpupdate /force
    # Copy-Item "C:\Users\$mainUser\Desktop\windows\GroupPolicy" -Destination 'C:\Windows\System32\' -Recurse -Force
    # gpupdate /force
    auditpol /set /category:"*" /success:enable /failure:enable
    secedit /configure /db c:\windows\security\local.sdb /cfg c:\Users\$mainUser\Desktop\windows\secpol.cfg /areas SECURITYPOLICY
}

function Edit-Keys {
    # show files in explorer
    $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    # enable hidden files (on restart)
    Set-ItemProperty -Path $path -Name "Hidden" -Value 1 -Type DWord -Force
    # enable file extensions (on restart)
    Set-ItemProperty -Path $path -Name "HideFileExt" -Value 0 -Type DWord -Force
    # enable defender
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows Defender\' DisableAntiSpyware 0 DWord
    # enable right click (if they disable it)
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoViewContextMenu 0 DWord
    # enable cloud protection / automatic sample submission
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' SpynetReporting 2 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' SubmitSamplesConsent 1 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' MpCloudBlockLevel 2 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' DisableHeuristics 0 DWord
    # set UAC to maximum
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ConsentPromptBehaviorAdmin 2  DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ValidateAdminCodeSignatures 1 DWord 
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' PromptOnSecureDesktop 1 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' EnableVirtualization 1 DWord
    # enable automatic updates
    # # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' AUOptions 0 DWord
    # # stigs idk but they're recommended by the DOD
    # Edit-Registry '\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' RestrictNullSessAccess 1 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' RestrictAnonymous 1 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' NoLMHash 1 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' LmCompatibilityLevel 5 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowToGetHelp 0 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' fAllowToGetHelp 0 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' NoAutorun 1 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\' DisableExceptionChainValidation 0 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Installer\' AlwaysInstallElevated 0 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Explorer\' NoAutoplayfornonVolume 1 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' AllowBasic 0 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' AllowBasic 0 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' RestrictAnonymousSAM 1 DWord 
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\' NoDriveTypeAutoRun 255 DWord  
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\' EnhancedAntiSpoofing 1 DWord 
    # # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System\' EnableSmartScreen 1 DWord 
    # # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System\' ShellSmartScreenLevel 'Block' String 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Explorer\' NoDataExecutionPrevention 0 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\DataCollection\' AllowTelemetry 0 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\DataCollection\' LimitEnhancedDiagnosticDataWindowsAnalytics 1 DWord 
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' EveryoneIncludesAnonymous 0 DWord 
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' SupportedEncryptionTypes 2147483640 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\LSA\pku2u\' AllowOnlineID 0 DWord 
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\' allownullsessionfallback 0 DWord 
    # Edit-Registry '\SYSTEM\CurrentControlSet\Services\LDAP\' LDAPClientIntegrity 1 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\' RestrictRemoteClients 1 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\' DCSettingIndex 1 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System\' EnumerateLocalUsers 0 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\' ACSettingIndex 1 DWord 
    # Edit-Registry '\Software\Policies\Microsoft\Windows\Kernel DMA Protection' DeviceEnumerationPolicy 0 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System\' DontDisplayNetworkSelectionUI 1 DWord 
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' PreXPSP2ShellProtocolBehavior 0 DWord 
    # Edit-Registry '\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' RequireStrongKey 1 DWord 
    # Edit-Registry '\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' SealSecureChannel 1 DWord 
    # Edit-Registry '\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' RequireSignOrSeal 1 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' fPromptForPassword 1 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' fEncryptRPCTraffic 1 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' MinEncryptionLevel 3 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\' DisableEnclosureDownload 1 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Windows Search\' AllowIndexingEncryptedStoresOrItems 0 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Installer\' EnableUserControl 0 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' DisableAutomaticRestartSignOn 1 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' AllowUnencryptedTraffic 0 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Personalization\' NoLockScreenCamera 1 DWord 
    # Edit-Registry '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\' DisableIPSourceRouting 2 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' DisableIpSourceRouting 2 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Personalization\' NoLockScreenSlideshow 1 DWord 
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\' MinimumPINLength 6 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\GameDVR\' AllowGameDVR 0 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' fDisableCdm 1 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' DisablePasswordSaving 1 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\' EnablePlainTextPassword 0 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\' EnumerateAdministrators 0 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System' AllowDomainPINLogon 0 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' AllowWindowsInkWorkspace 1 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\' UseLogonCredential 0 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' SCENoApplyLegacyAuditPolicy 1 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoPreviewPane 1 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoReadingPane 1 DWord
    # Edit-Registry '\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\' DriverLoadPolicy 1 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' ConsentPromptBehaviorUser 0 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' FilterAdministratorToken 1 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' EnableScriptBlockLogging 1 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' EnableInstallerDetection 1 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Network Connections\' NC_ShowSharedAccessUI 0 DWord
    # Edit-Registry '\SOFTWARE\Classes\batfile\shell\runasuser\' SuppressionPolicy 4096 DWord
    # Edit-Registry '\SOFTWARE\Classes\cmdfile\shell\runasuser\' SuppressionPolicy 4096 DWord
    # Edit-Registry '\SOFTWARE\Classes\exefile\shell\runasuser\' SuppressionPolicy 4096 DWord
    # Edit-Registry '\SOFTWARE\Classes\mscfile\shell\runasuser\' SuppressionPolicy 4096 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' InactivityTimeoutSecs 900 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\' LetAppsActivateWithVoiceAboveLock 2 DWord
    # Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\' LetAppsActivateWithVoice 2 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' EnableLUA 1 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' Value 'Deny' String
    # Edit-Registry '\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\' DisableExceptionChainValidation 0 DWord
    # Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' SafeModeBlockNonAdmins 1 DWord
    # enable DEP
    # cmd.exe /c "BCDEDIT /set {current} nx OptOut"
    # Clear-RecycleBin -Force -ErrorAction Ignore
    # restart explorer for some changes to take effect
    Stop-Process -ProcessName explorer
}

function Disable-Features {
    $WarningPreference = 'SilentlyContinue'
    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "TFTP" -NoRestart | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "SimpleTCP" -NoRestart | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-Features" -NoRestart | Out-Null
}

function Stop-Services {
    Stop-Service -Name Spooler -Force -ErrorAction Ignore
    Set-Service -Name Spooler -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name RemoteAccess -Force -ErrorAction Ignore
    Set-Service -Name RemoteAccess -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name RemoteRegistry -Force -ErrorAction Ignore
    Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name msftpsvc -Force -ErrorAction Ignore
    Set-Service -Name msftpsvc -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name telnet -Force -ErrorAction Ignore
    Set-Service -Name telnet -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name upnphost -Force -ErrorAction Ignore
    Set-Service -Name upnphost -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name SSDPSRV -Force -ErrorAction Ignore
    Set-Service -Name SSDPSRV -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name tftpsvc -Force -ErrorAction Ignore
    Set-Service -Name tftpsvc -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name tapisrv -Force -ErrorAction Ignore
    Set-Service -Name tapisrv -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name lmhosts -Force -ErrorAction Ignore
    Set-Service -Name lmhosts -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name SNMPTRAP -Force -ErrorAction Ignore
    Set-Service -Name SNMPTRAP -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name SessionEnv -Force -ErrorAction Ignore
    Set-Service -Name SessionEnv -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name TermService -Force -ErrorAction Ignore
    Set-Service -Name TermService -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name TlntSvr -Force -ErrorAction Ignore
    Set-Service -Name TlntSvr -StartupType Disabled -ErrorAction Ignore
    Stop-Service -Name seclogon -Force -ErrorAction Ignore
    Set-Service -Name seclogon -StartupType Disabled -ErrorAction Ignore

    Start-Service -Name EventLog -ErrorAction Ignore
    Set-Service -Name EventLog -StartupType Enabled -ErrorAction Ignore
}

function Remove-HackingTools {
    $mainUser = $global:mainUser
    # Invoke-Item "C:\Program Files (x86)\Nmap\Uninstall.exe" -ArgumentList "/S /v /qn" -Wait -ErrorAction Ignore
    # Invoke-Item "C:\Program Files\Npcap\Uninstall.exe" -ArgumentList "/S /v /qn" -Wait -ErrorAction Ignore
    # Invoke-Item "C:\Program Files\Genshin Impact\Uninstall.exe" -ArgumentList "/S /v /qn" -Wait -ErrorAction Ignore
    # Invoke-Item "C:\Program Files\Wireshark\Uninstall.exe" -ArgumentList "/S /v /qn" -Wait -ErrorAction Ignore
    # Invoke-Item "C:\Users\$mainUser\AppData\Roaming\uTorrent Web\Uninstall.exe" -ArgumentList "/S /v /qn" -Wait -ErrorAction Ignore
}

function Get-FileType($type) {
    $path = "C:\Users\$mainUser\Desktop\media_files.log"
    Get-ChildItem -Path 'C:\Users\' -Filter "*.$type" -Recurse -File -Name | Out-File -FilePath $path -Append -Encoding UTF8
}

function Get-MediaFiles {
    $mainUser = $global:mainUser
    Write-Host "Logging the file directories of media files on the machine..."
    $path = "C:\Users\$mainUser\Desktop\media_files.log"
    New-Item -Path $path | Out-Null

    Write-Host "Logging most common types of media files..."
    Add-Content -Path $path -Value "Most common types of media files:"
    $commonList = ('midi', 'mid', 'mp3', 'ogg', 'wav', 'mov', 'wmv', 'mp4', 'avi', 'swf', 'ico', 'svg', 'gif', 'jpeg', 'jpg', 'png', 'exe', 'doc*', 'ppt*', 'xl*', 'pub', 'pdf', '7z', 'zip', 'rar', 'txt', 'pcapng', 'jar', 'json')
    $commonList | ForEach-Object {
        Get-FileType $_
    }

    Write-Host "Logging PHP files..."
    Add-Content -Path $path -Value "`nPHP files:"
    $phpList = ('php', 'php3', 'php4', 'php5', 'phtml', 'phpt', 'phps')
    $phpList | ForEach-Object {
        Get-FileType $_
    }

    Write-Host "Logging script files..."
    Add-Content -Path $path -Value "`nScript files:"
    $scriptList = ('sh', 'bash', 'bsh', 'csh', 'startx', 'bat', 'cmd', 'nt', 'asp', 'vb', 'pl', 'vps', 'tab', 'spf', 'rc', 'reg', 'py', 'ps1', 'psm1', 'c', 'cs', 'js', 'html')
    $scriptList | ForEach-Object {
        Get-FileType $_
    }

    Write-Host "Logging audio files..."
    Add-Content -Path $path -Value "`nAudio files:"
    $audioList = ('mod', 'mp2', 'mpa', 'abs', 'mpega', 'au', 'snd', 'aiff', 'aif', 'sid', 'flac')
    $audioList | ForEach-Object {
        Get-FileType $_
    }

    Write-Host "Logging video files..."
    Add-Content -Path $path -Value "`nVideo files:"
    $videoList = ("mpeg", "mpg", "mpe", "dl", "movie", "movi", "mv", "iff", "anim5", "anim3", "anim7", "vfw", "avx", "fli", "flc", "qt", "spl", "swf", "dcr", "dir", "dxr", "rpm", "rm", "smi", "ra", "ram", "rv", "asf", "asx", "wma", "wax", "wmx", "3gp", "flv", "m4v")
    $videoList | ForEach-Object {
        Get-FileType $_
    }

    Write-Host "Logging image files..."
    Add-Content -Path $path -Value "`nImage files:"
    $imageList = ("tiff", "tif", "rs", "rgb", "xwd", "xpm", "ppm", "pbm", "pgm", "pcx", "svgz", "im1", "jpe")
    $imageList | ForEach-Object {
        Get-FileType $_
    }
}

if ($safeYN -eq 'safe') {
    $type = Read-Host 'Choose to run certain parts of the script! (Install, Defender, Users, Hacking, Services, Features, Keys, Media, Local)'
    if ($type.ToLower() -eq 'install') {
        Install-Programs
    }
    elseif ($type.ToLower() -eq 'defender') {
        Start-Defender
    }
    elseif ($type.ToLower() -eq 'users') {
        Edit-Users
    }
    elseif ($type.ToLower() -eq 'hacking') {
        Remove-HackingTools
    }
    elseif ($type.ToLower() -eq 'services') {
        Stop-Services
    }
    elseif ($type.ToLower() -eq 'features') {
        Disable-Features
    }
    elseif ($type.ToLower() -eq 'keys') {
        Edit-Keys
    }
    elseif ($type.ToLower() -eq 'media') {
        Get-MediaFiles
    }
    elseif ($type.ToLower() -eq 'local') {
        Edit-LocalSecurity
    }
    else {
        Write-Host 'Invalid input'
    }
}
else {
    $stopwatch =  [system.diagnostics.stopwatch]::StartNew()
    Install-Programs
    Start-Defender
    Edit-LocalUsers
    Edit-LocalSecurity
    Edit-Keys
    Stop-Services
    Disable-Features
    Get-MediaFiles
    $scanYN = Read-Host 'Would you like to scan the machine for potential viruses or corrupted files (this may take some time)? (y/n)'
    if ($scanYN.ToLower() -eq 'y') {
        cmd.exe /c "DISM.exe /Online /Cleanup-image /Restorehealth"
        cmd.exe /c "sfc /scannow"
        Write-Warning "If the above command outputted to run sfc again once you've restarted the system, run sfc /scannow when you restart the system"
    }
    Write-Host "`nScript done! Please restart the system for some of the changes to take effect and go get the rest of the vulns! (It's suggested that on this restart, you also do updates)"
    Write-Host "`nScript completed in" $stopwatch.Elapsed.Minutes "minutes and" $stopwatch.Elapsed.Seconds "seconds"
    $stopwatch.Stop()
    # $restartYN = Read-Host 'Would you like to install all updates automatically and restart the computer now to apply changes? (y/n)'
    # if ($restartYN.ToLower() -eq 'y') {
    #     Install-Module PSWindowsUpdate -Confirm:$False -Force
    #     Get-WindowsUpdate -AcceptAll -Install -AutoReboot
    # }
    # else {
    #     Write-Host "Alright! Exiting now... Don't forget to restart soon."
    # }
}