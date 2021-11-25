#Requires -RunAsAdministrator

function Initialize-Script {
    $mainUser = Read-Host "Please enter the main user on this machine"
    $distro = Read-Host "Please enter the type of machine this is (win10 or server19)"
    if ( -Not ('win10', 'server19').contains($distro.ToLower()) ) {
        Read-Host "Invalid type! Press ENTER to exit."
        exit 1
    }
}

function Audit-Users {
    Disable-LocalUser -Name "Guest"
    Disable-LocalUser -Name "Administrator"
    $readme = Read-Host "Please enter the link to the README"
    $admins=$( python3 C:\Users\$mainUser\Desktop\windows\scraper.py $readme admins)
    $adminsList = $admins -split ";"
    $users=$( python3 C:\Users\$mainUser\Desktop\windows\scraper.py $readme users)
    $usersList = $users -split ";"
    $authUsersList = @($adminsList) + $usersList
    $currentUserList = Get-LocalUser | Where-Object -Property Enabled -eq True | Select-Object -Property Name 
    $currentAdminList = Get-LocalGroupMember -Group "Administrators" | Where-Object -Property PrincipalSource -eq Local | Select-Object -Property Name
    foreach ($admin in $currentAdminList) {
        $index = $currentAdminList.IndexOf($admin)
        $currentAdminList[$index] = $admin.Split('\')[1]
    }
    foreach ($user in $usersList) {
        if (-not $user.Name in $currentUserList) {
            # adds user if user on README is not on the local system
            $NewPass = ConvertTo-SecureString "M3rc1l3ss_cYp@t!1" -AsPlainText -Force
            New-LocalUser $user.Name -Password $NewPass -FullName $user.Name -Description "user added to the machine"
        }
    }

    foreach ($user in $currentUserList) {
        if (-not $user.Name in $authUSersList) {
            # delete user if user on the current system and not on the README
            Remove-LocalUser -Name $user.Name
        }
        if (-not $user.Name -eq $mainUser) {
            # Set new passwords for all users other than the main user
            $NewPass = ConvertTo-SecureString "M3rc1l3ss_cYp@t!1" -AsPlainText -Force
            Set-LocalUser -Name $user.Name -Password $NewPass
        }
    }
    foreach ($admin in $currentAdminList) {
        # if admin is an admin on the system but not an authorized admin in the readme, remove from the group
        if (-not $admin.Name in $adminsList) {
            Remove-LocalGroupMember -Group "Administrators" -Member $admin.Name
        }
    }
    foreach ($admin in $adminsList) {
        # if admin is an admin on the README but not on the system, make that user an admin
        if (-not $admin.Name in $currentAdminList) {
            Add-LocalGroupMemeber -Group "Administrators" -Member $admin.Name
        }
    }
}

function Manage-Defender {
    Set-NetFirewallProfile -Enabled $True
    New-NetFirewallRule -DisplayName "Block 23" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block 1337" -Direction Inbound -LocalPort 1337 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block 515" -Direction Inbound -LocalPort 515 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block 111" -Direction Inbound -LocalPort 111 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block 135" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block 137" -Direction Inbound -LocalPort 137 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block 138" -Direction Inbound -LocalPort 138 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block 69" -Direction Inbound -LocalPort 69 -Protocol TCP -Action Block
    Set-MpPreference -DisableRealtimeMonitoring $False
    Set-MpPreference -RealTimeProtectionEnabled $True
    Update-MpSignature
}

function Install-Programs {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    choco install -y python3
    choco install -y pip
    pip install bs4
    choco install -y malwarebytes
    choco install -y firefox
}

function Edit-Registry($path, $name, $value, $type) {
    $path = 'HKLM:' + $path
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    Set-ItemProperty -Path $path -Name $name -Value $value -Type $type -Force
}

function Secure-System {
    #stigs
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' AUOptions 0 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' RestrictNullSessAccess 1 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' RestrictAnonymous 1 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' NoLMHash 1 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' LmCompatibilityLevel 5 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowToGetHelp 0 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' fAllowToGetHelp 0 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' NoAutorun 1 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\' DisableExceptionChainValidation 0 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Installer\' AlwaysInstallElevated 0 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Explorer\' NoAutoplayfornonVolume 1 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' AllowBasic 0 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' AllowBasic 0 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' RestrictAnonymousSAM 1 DWord 
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\' NoDriveTypeAutoRun 255 DWord  
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\' EnhancedAntiSpoofing 1 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System\' EnableSmartScreen 1 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System\' ShellSmartScreenLevel 'Block' String 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Explorer\' NoDataExecutionPrevention 0 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\DataCollection\' AllowTelemetry 0 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\DataCollection\' LimitEnhancedDiagnosticDataWindowsAnalytics 1 DWord 
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' EveryoneIncludesAnonymous 0 DWord 
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' SupportedEncryptionTypes 2147483640 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\LSA\pku2u\' AllowOnlineID 0 DWord 
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\' allownullsessionfallback 0 DWord 
    Edit-Registry '\SYSTEM\CurrentControlSet\Services\LDAP\' LDAPClientIntegrity 1 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\' RestrictRemoteClients 1 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\' DCSettingIndex 1 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System\' EnumerateLocalUsers 0 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\' ACSettingIndex 1 DWord 
    Edit-Registry '\Software\Policies\Microsoft\Windows\Kernel DMA Protection' DeviceEnumerationPolicy 0 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System\' DontDisplayNetworkSelectionUI 1 DWord 
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' PreXPSP2ShellProtocolBehavior 0 DWord 
    Edit-Registry '\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' RequireStrongKey 1 DWord 
    Edit-Registry '\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' SealSecureChannel 1 DWord 
    Edit-Registry '\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' RequireSignOrSeal 1 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' fPromptForPassword 1 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' fEncryptRPCTraffic 1 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' MinEncryptionLevel 3 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\' DisableEnclosureDownload 1 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Windows Search\' AllowIndexingEncryptedStoresOrItems 0 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Installer\' EnableUserControl 0 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' DisableAutomaticRestartSignOn 1 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' AllowUnencryptedTraffic 0 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Personalization\' NoLockScreenCamera 1 DWord 
    Edit-Registry '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\' DisableIPSourceRouting 2 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' DisableIpSourceRouting 2 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Personalization\' NoLockScreenSlideshow 1 DWord 
    Edit-Registry '\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\' MinimumPINLength 6 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\GameDVR\' AllowGameDVR 0 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' fDisableCdm 1 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' DisablePasswordSaving 1 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\' EnablePlainTextPassword 0 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\' EnumerateAdministrators 0 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\System' AllowDomainPINLogon 0 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' AllowWindowsInkWorkspace 1 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\' UseLogonCredential 0 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Control\Lsa\' SCENoApplyLegacyAuditPolicy 1 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoPreviewPane 1 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoReadingPane 1 DWord
    Edit-Registry '\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\' DriverLoadPolicy 1 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' ConsentPromptBehaviorUser 0 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' FilterAdministratorToken 1 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' EnableScriptBlockLogging 1 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' EnableInstallerDetection 1 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\Network Connections\' NC_ShowSharedAccessUI 0 DWord
    Edit-Registry '\SOFTWARE\Classes\batfile\shell\runasuser\' SuppressionPolicy 4096 DWord
    Edit-Registry '\SOFTWARE\Classes\cmdfile\shell\runasuser\' SuppressionPolicy 4096 DWord
    Edit-Registry '\SOFTWARE\Classes\exefile\shell\runasuser\' SuppressionPolicy 4096 DWord
    Edit-Registry '\SOFTWARE\Classes\mscfile\shell\runasuser\' SuppressionPolicy 4096 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' InactivityTimeoutSecs 900 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\' LetAppsActivateWithVoiceAboveLock 2 DWord
    Edit-Registry '\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\' LetAppsActivateWithVoice 2 DWord
    Edit-Registry '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' EnableLUA 1 DWord

    cmd.exe /c "BCDEDIT /set {current} nx OptOut"
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220739
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220732
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220793
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220721
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220720
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220718
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220967
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220747
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220958
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220812
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220928
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220709
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220702
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220703 <<
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220705
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220742
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220717 
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220907
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220900
    # https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220782 

    Stop-Service -Name Spooler -Force
    Set-Service -Name Spooler -StartupType Disabled
}

function Get-MediaFiles {
    Write-Host "Logging the file directories of media files on the machine..."
    New-Item -Path 'C:\Users\$mainUser\Desktop\media_files.log'
	(
		"Most common types of media files:"
		Get-ChildItem -Path 'C:\' -Filter "*.midi" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mid" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mp3" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.ogg" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.wav" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mov" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.wmv" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mp4" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.avi" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.swf" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.ico" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.svg" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.gif" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.jpeg" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.jpg" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.png" -Recurse -File -Name

		"PHP files:"
		Get-ChildItem -Path 'C:\' -Filter "*.php" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.php3" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.php4" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.phtml" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.phps" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.phpt" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.php5" -Recurse -File -Name

		"Script files:"
		Get-ChildItem -Path 'C:\' -Filter "*.sh" -Recurse -File -Name 
		Get-ChildItem -Path 'C:\' -Filter "*.bash" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.bsh" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.csh" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.bash_profile" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.profile" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.bashrc" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.zsh" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.ksh" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.cc" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.startx" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.bat" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.cmd" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.nt" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.asp" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.vb" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.pl" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.vbs" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.tab" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.spf" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.rc" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.reg" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.py" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.ps1" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.psm1" -Recurse -File -Name

		"Audio:"
		Get-ChildItem -Path 'C:\' -Filter "*.mod" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mp2" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mpa" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.abs" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mpega" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.au" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.snd" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.aiff" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.aif" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.sid" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.flac" -Recurse -File -Name

		"Video:"
		Get-ChildItem -Path 'C:\' -Filter "*.mpeg" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mpg" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mpe" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.dl" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.movie" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.movi" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.mv" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.iff" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.anim5" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.anim3" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.anim7" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.vfw" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.avx" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.fli" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.flc" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.qt" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.spl" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.swf" -Recurse -File -Name 
		Get-ChildItem -Path 'C:\' -Filter "*.dcr" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.dir" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.dxr" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.rpm" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.rm" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.smi" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.ra" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.ram" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.rv" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.asf" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.asx" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.wma" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.wax" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.wmx" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.3gp" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.flv" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.m4v" -Recurse -File -Name

		"Images:"
		Get-ChildItem -Path 'C:\' -Filter "*.tiff" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.tif" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.rs" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.rgb" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.xwd" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.xpm" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.ppm" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.pbm" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.pgm" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.pcx" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.svgz" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.im1" -Recurse -File -Name
		Get-ChildItem -Path 'C:\' -Filter "*.jpe" -Recurse -File -Name

	) >> C:\Users\$mainUser\Desktop\media_files.log
}

Initialize-Script
Install-Programs
Manage-Defender
Audit-Users
Secure-System
Get-MediaFiles