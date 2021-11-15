#Requires -RunAsAdministrator

$mainUser = Read-Host "Please enter the main user on this machine"

function Parse-Readme {
    $readme = Read-Host "Please enter the link to the ReadMe"
    $admins=$( python3 C:\Users\$mainUser\Desktop\windows\scraper.py $readme admins)
    $adminsList = $admins -split ";"
    $users=$( python3 C:\Users\$mainUser\Desktop\windows\scraper.py $readme users)
    $usersList = $users -split ";"
    $currentUserList = Get-LocalUser | Where-Object -Property Enabled -eq True | Select-Object -Property Name 
    foreach ($user in $currentUserList) {
        Write-Host $user.Name
    }
}

function Install-Programs {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    choco install -y python3
    choco install -y pip
}

Install-Programs