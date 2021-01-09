@echo off

echo Checking if script is being run as admin
net sessions
if %errorlevel%==0 (
	echo Success!
) else (
	echo Please run this script as admin
	pause
	exit
)

@echo on
