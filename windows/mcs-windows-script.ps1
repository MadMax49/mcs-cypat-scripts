#Requires -RunAsAdministrator

function Init-Script {
    $mainUser = Read-Host "Please enter the main user on this machine"
    $distro = Read-Host "Please enter the type of machine this is (win10 or server19)"
    if ( -Not ('win10', 'server19').contains($distro.ToLower()) ) {
        Read-Host "Invalid type! Press ENTER to exit."
        exit 1
    }
}

function Audit-Users {
    Disable-LocalUser -Name "Guest"
    $readme = Read-Host "Please enter the link to the README"
    $admins=$( python3 C:\Users\$mainUser\Desktop\windows\scraper.py $readme admins)
    $adminsList = $admins -split ";"
    $users=$( python3 C:\Users\$mainUser\Desktop\windows\scraper.py $readme users)
    $usersList = $users -split ";"
    $currentUserList = Get-LocalUser | Where-Object -Property Enabled -eq True | Select-Object -Property Name 
    foreach ($user in $currentUserList) {
        if (-not $user -eq $mainUser) {
            Write-Host $user.Name
        }
    }
}

function Manange-Defender {
    Set-NetFirewallProfile -Enabled True
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

function Secure-System {
    cmd.exe /c "reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' /v AUOptions /t REG_DWORD /d 0 /f"
}

Install-Programs