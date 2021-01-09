#!/bin/bash
 
echo "MCS Debian Script v1.1 Updated 1/9/2021 at 5:36pm EST"
echo "Created by Massimo Marino"

if [[ "$(whoami)" != root ]]
then
	echo "This script can only be run as root"
	exit 1
fi

echo "What is the name of the main user account of this machine?"
read userName

first_time_initialize () {  
	echo "Creating backup folder and backing up important files"
	mkdir -p  /home/$userName/Desktop/backups
	chmod 777  /home/$userName/Desktop/backups
	cp /etc/group  /home/$userName/Desktop/backups/
	cp /etc/passwd  /home/$userName/Desktop/backups/
	touch  /home/$userName/Desktop/changelog.log
	chmod 777  /home/$userName/Desktop/changelog.log
	echo "List of changes made by script:" >  /home/$userName/Desktop/changelog.log
	echo "- Backups folder created" >>  /home/$userName/Desktop/changelog.log
	echo "- Important files backed up" >>  /home/$userName/Desktop/changelog.log
}

packages () { 
	echo "Updating apt"
	apt-get update -y -qq 
	apt-get upgrade -y -qq
	apt-get dist-upgrade -y -qq 
	echo "- Package installer 'apt' updated (update, upgrade, dist-upgrade)" >>  /home/$userName/Desktop/changelog.log

	echo "Installing useful packages"
	echo "Firefox (Browser)"
	apt-get install firefox-esr -y -qq 
	echo "RKHunter (AntiRootkit/antivirus)"
	apt-get install rkhunter -y -qq
	echo "AppArmor (Kernel enhancer)"
	apt-get install apparmor -y -qq
	apt-get install apparmor-profiles -y -qq 
	apt-get install apparmor-profiles-extra -y -qq
	echo "IPTables (Network manager)"
	apt-get install iptables -y -qq
	echo "PortSentry (Network manager)"
	apt-get install portsentry -y -qq 
	echo "Lynis (system auditer)"
	apt-get install lynis -y -qq 
	echo "UFW (Firewall)"
	apt-get install ufw -y -qq 
	apt-get install gufw -y -qq 
	echo "ClamAV (Antivirus)"
	apt-get install clamav -y -qq 
	apt-get install clamtk -y -qq 
	echo "Libpam (password complexity enforcers)"
	apt-get install libpam-cracklib -y -qq 
	apt-get install libpam-tmpdir -y -qq 
	echo "Auditd (auditer)"
	apt-get install auditd -y -qq 
	echo "Tree (view all files on machine)"
	apt-get install tree -y -qq
	echo "APT (APT package installer enchancements)"
	apt-get install apt-listchanges -y -qq 
	apt-get install apt-show-versions -y -qq 
	echo "Debian-Goodies (package assistant)"
	apt-get install debian-goodies -y -qq 
	echo "Debsecan (package vulnerability reporter)"
	apt-get install debsecan -y -qq 
	echo "Debsums (package verifier)"
	apt-get install debsums -y -qq
	echo "Fail2Ban (Firewall)"
	apt-get install fail2ban -y -qq
	echo "Install open-vm-tools?"
	read vmtoolsYN
	if [[ $vmtoolsYN == "yes" ]]
	then
		apt-get install open-vm-tools -y -qq
		echo "- Package open-vm-tools installed" >>  /home/$userName/Desktop/changelog.log
	fi
	apt-get install --reinstall coreutils -y -qq
	echo "- Packages firefox, debsecan, debsums, fail2ban, libpam-tmpdir, apt-listchanges, apt-show-versions, debian-goodies, apparmor, rkhunter, chkrootkit, iptables, portsentry, lynis, ufw, gufw, libpam-cracklib, auditd, tree, clamav, and clamtk installed; coreutils reinstalled" >>  /home/$userName/Desktop/changelog.log

}

firewall () { 
	echo "Configuring firewall (UFW)"
	ufw enable
	ufw deny 1337
	ufw deny 23
	ufw deny 2049
	ufw deny 515
	ufw deny 111
	ufw deny out 135/tcp
	ufw deny out 135/udp
	ufw deny out 137/tcp
	ufw deny out 137/udp
	ufw deny out 138/tcp
	ufw deny out 138/udp
	ufw deny out 139/tcp
	ufw deny out 139/udp
	ufw deny out 445/tcp
	ufw deny out 69/udp
	ufw deny out 514/udp
	ufw deny out 161/udp
	ufw deny out 162/udp
	ufw deny out 6660/tcp
	ufw deny out 6661/tcp
	ufw deny out 6662/tcp
	ufw deny out 6663/tcp
	ufw deny out 6664/tcp
	ufw deny out 6665/tcp
	ufw deny out 6666/tcp
	ufw deny out 6667/tcp
	ufw deny out 6668/tcp
	ufw deny out 6669/tcp
	ufw logging on
	ufw logging high
	echo "- Firewall configured (Firewall enabled, Ports 1337, 23, 2049, 515, 135, 137, 138, 139, 445, 69, 514, 161, 162, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, and 111 denied, Logging on and high)" >>  /home/$userName/Desktop/changelog.log

}

services () {
 
	echo "Service Auditing"
	echo "Is openssh-server a critical service on this machine?"
	read sshYN
	if [[ $sshYN == "yes" ]]; then
		apt-get install ssh -y -qq  
		apt-get install openssh-server -y -qq  
		apt-get upgrade openssl libssl-dev -y -qq  
		apt-cache policy openssl libssl-dev  
		echo "- Packages ssh and openssh-server installed and heartbleed bug fixed" >>  /home/$userName/Desktop/changelog.log
		
		 
		echo "Editing /etc/sshd/sshd_config"
		cp /etc/ssh/sshd_config  /home/$userName/Desktop/backups/
		sed -i '32s/.*/PermitRootLogin no/' /etc/ssh/sshd_config
		sed -i '87s/.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
		sed -i '100s/.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
		sed -i '99s/.*/Compression delayed/' /etc/ssh/sshd_config
		sed -i '27s/.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
		sed -i '34s/.*/MaxAuthTries 2/' /etc/ssh/sshd_config
		sed -i '35s/.*/MaxSessions 2/' /etc/ssh/sshd_config
		sed -i '95s/.*/TCPKeepAlive no/' /etc/ssh/sshd_config
		sed -i '89s/.*/X11Forwarding no/' /etc/ssh/sshd_config
		sed -i '86s/.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
		echo "- Configured /etc/ssh/sshd_config" >>  /home/$userName/Desktop/changelog.log	
		
		  
		echo "Securing SSH keys"
		mkdir  ~/.ssh
		chmod 700  ~/.ssh
		touch  ~/.ssh/authorized_keys
		chmod 600  ~/.ssh/authorized_keys
		echo "- Secured SSH keys" >>  ~/Desktop/changelog.log
		
		echo "SSH port can accept SSH connections"
		iptables -A INPUT -p tcp --dport ssh -j ACCEPT
		
		service ssh restart
	else
		echo "- openssh-server and ssh were not installed on this machine" >>  /home/$userName/Desktop/changelog.log
	fi
	 
	echo "Is NGINX a critical service on this machine?"
	read nginxYN
	if [[ $nginxYN == "yes" ]]; then
		apt-get install nginx  
		echo "- NGINX installed" >>  /home/$userName/Desktop/changelog.log
	elif [[ $nginxYN == "no" ]]; then
		apt-get purge nginx -y -qq  
		apt-get purge nginx-common -y -qq  
		echo "- NGINX removed from the machine" >>  /home/$userName/Desktop/changelog.log
	fi
	 
	echo "Is Samba a critical service on this machine?"
	read sambaYN
	if [[ $sambaYN == "yes" ]]; then
		ufw allow netbios-ns
		ufw allow netbios-dgm
		ufw allow netbios-ssn
		ufw allow microsoft-ds 
		apt-get install samba -y -qq  
		apt-get install system-config-samba -y -qq  
		echo "- Samba installed and allowed" >>  /home/$userName/Desktop/changelog.log
	elif [[ $sambaYN == "no" ]]; then
		ufw deny netbios-ns
		ufw deny netbios-dgm
		ufw deny netbios-ssn
		ufw deny microsoft-ds
		apt-get purge samba -y -qq   
		apt-get purge samba4 -y -qq  
		echo "- Samba uninstalled and blocked" >>  /home/$userName/Desktop/changelog.log
	fi
	 
	echo "Is FTP a critical service on this machine?"
	read ftpYN
	if [[ $ftpYN == "yes" ]]; then
		ufw allow ftp 
		ufw allow sftp 
		ufw allow saft 
		ufw allow ftps-data 
		ufw allow ftps
		service vsftpd restart
		echo "- FTP installed and allowed" >>  /home/$userName/Desktop/changelog.log
	elif [[ $ftpYN == "no" ]]; then
		ufw deny ftp 
		ufw deny sftp 
		ufw deny saft 
		ufw deny ftps-data 
		ufw deny ftps
		apt-get purge vsftpd -y -qq  
		echo "- FTP uninstalled and blocked" >>  /home/$userName/Desktop/changelog.log
	fi
	 
	echo "Is Telnet a critical service on this machine?"
	read telnetYN
	if [[ $telnetYN == "yes" ]]; then
		ufw allow telnet 
		ufw allow rtelnet 
		ufw allow telnets
		echo "- Telnet allowed" >>  /home/$userName/Desktop/changelog.log
	elif [[ $telnetYN == "no" ]]; then
		ufw deny telnet 
		ufw deny rtelnet 
		ufw deny telnets
		apt-get purge telnet -y -qq  
		apt-get purge telnetd -y -qq  
		apt-get purge inetutils-telnetd -y -qq  
		apt-get purge telnetd-ssl -y -qq  
		apt-get purge vsftpd -y -qq  
		echo "- Telnet uninstalled and blocked" >>  /home/$userName/Desktop/changelog.log
	fi
	 
	echo "Is MySQL a critical service on this machine?"
	read sqlYN
	if [[ $sqlYN == "yes" ]]; then
		ufw allow ms-sql-s 
		ufw allow ms-sql-m 
		ufw allow mysql 
		ufw allow mysql-proxy
		apt-get install mysql-server -y -qq  
		echo "- MySQL allowed and installed (WIP)" >>  /home/$userName/Desktop/changelog.log
	elif [[ $sqlYN == "no" ]]; then
		ufw deny ms-sql-s 
		ufw deny ms-sql-m 
		ufw deny mysql 
		ufw deny mysql-proxy
		apt-get purge mysql-server -y -qq  
		apt-get purge mysql -y -qq  
		echo "- MySQL uninstalled and blocked (WIP)" >>  /home/$userName/Desktop/changelog.log
	fi
 
	echo "Is this machine a web server?"
	read webYN
	if [[ $webYN == "yes" ]]; then
		apt-get install apache2 -y -qq  
		ufw allow http 
		ufw allow https
		iptables -A INPUT -p tcp --dport 80 -j ACCEPT
		echo "- Apache2 installed and http(s) allowed" >>  /home/$userName/Desktop/changelog.log
	elif [[ $webYN == "no" ]]; then
		ufw deny http
		ufw deny https
		apt-get purge apache2 -y -qq  
		#rm -r /var/www/*
		echo "- Apache2 removed and http(s) blocked" >>  /home/$userName/Desktop/changelog.log
	fi

}

general_config () {
 
	echo "Should root user be locked?"
	read lockRootYN
	if [[ $lockRootYN == yes ]]
	then 
		usermod -L root
		echo "- Root account locked. Use 'usermod -U root' to unlock it"
	fi
	
	echo "Denying outside packets"
	iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
	echo "- Denied outside packets" >>  /home/$userName/Desktop/changelog.log
	
	echo "Unaliasing all"
	unalias -a
	echo "- Unaliased all" >>  /home/$userName/Desktop/changelog.log

	echo "Enabling auditing"
	auditctl -e 1
	echo "- Auditing enabled with auditd (can be configured in /etc/audit/auditd.conf)" >>  /home/$userName/Desktop/changelog.log

	echo "Disabling reboot with Ctrl-Alt "
	sudo systemctl mask ctrl-alt-del.target
	sudo systemctl daemon-reload
	echo "- Disabled reboot with Ctrl-Alt " >>  /home/$userName/Desktop/changelog.log
	
	echo "Securing important files with chmod"
	chmod -R 644 /var/log
	chmod 664 /etc/passwd
	chmod 664 /etc/shadow
	chmod 664 /etc/group
	chmod 0700 /etc/rc*
	chmod 0700 /etc/init.d*
	chmod 0700 /etc/profile
	chmod 0700 /etc/hosts.allow
	chmod 0700 /etc/mtab
	chmod 2750 /bin/su
	chmod 2750 /bin/ping
	chmod 2750 /sbin/ifconfig
	chmod 2750 /usr/bin/w
	chmod 2750 /usr/bin/who
	chmod 2750 /usr/bin/whereis
	
}

hacking_tools () {
	
	echo "Updating packages"
	apt-get update  
	
	echo "Removing netcat"
	apt-get purge netcat -y -qq  
	apt-get purge netcat-openbsd -y -qq  
	apt-get purge netcat-traditional -y -qq  
	apt-get purge socat -y -qq    
	apt-get purge socket -y -qq  
	apt-get purge sbd -y -qq  
	rm /usr/bin/nc

	echo "Removing John the Ripper"
	apt-get purge john -y -qq  
	apt-get purge john-data -y -qq  
 
	echo "Removing Hydra"
	apt-get purge hydra -y -qq  
	apt-get purge hydra-gtk -y -qq  
 
	echo "Removing Aircrack-NG"
	apt-get purge aircrack-ng -y -qq  

	echo "Removing FCrackZIP"
	apt-get purge fcrackzip -y -qq  

	echo "Removing LCrack"
	apt-get purge lcrack -y -qq  

	echo "Removing OphCrack"
	apt-get purge ophcrack -y -qq  
	apt-get purge ophcrack-cli -y -qq  

	echo "Removing Pyrit"
	apt-get purge pyrit -y -qq  

	echo "Removing RARCrack"
	apt-get purge rarcrack -y -qq  

	echo "Removing SipCrack"
	apt-get purge sipcrack -y -qq  

	echo "Removing Zeitgeist"
	apt-get purge zeitgeist-core -y -qq  
	apt-get purge zeitgeist-datahub -y -qq  
	apt-get purge python-zeitgeist -y -qq  
	apt-get purge zeitgeist -y -qq  

	echo "Removing NFS"
	apt-get purge nfs-kernel-server -y -qq  
	apt-get purge nfs-common -y -qq  
	apt-get purge portmap -y -qq  
	apt-get purge rpcbind -y -qq  
	apt-get purge autofs -y -qq  

	echo "Removing VNC"
	apt-get purge vnc4server -y -qq  
	apt-get purge vncsnapshot -y -qq  
 
	echo "Removing Wireshark"
	apt-get purge wireshark -y -qq  

	echo "Removing Hashcat"
	apt-get purge hashcat -y -qq  
	apt-get purge hashcat-data -y -qq  
 
	echo "Removing CeWl"
	apt-get purge cewl -y -qq  

	echo "Removing Medusa"
	apt-get purge medusa -y -qq  

	echo "Removing Wfuzz"
	apt-get purge wfuzz -y -qq  

	echo "Removing nmap"
	apt-get purge nmap -y -qq  

	echo "Removing SQLMap"
	apt-get purge sqlmap  

	echo "Removing packages that can potentially contribute to backdoors"
	apt-get purge backdoor-factory -y -qq  
	apt-get purge shellinabox -y -qq  

	echo "Cleaning up Packages"
	apt-get autoremove -y -qq  
	apt-get autoclean -y -qq  
	apt-get clean -y -qq  
	echo "- Removed netcat, CeWl, nmap, Medusa, Wfuzz, Hashcat, John the Ripper, Hydra, Aircrack-NG, FCrackZIP, LCrack, OphCrack, Pyrit, rarcrack, SipCrack, Zeitgeist, NFS, VNC, and cleaned up packages" >>  /home/$userName/Desktop/changelog.log

}

file_config () {

	echo "Securing /etc/rc.local"
	echo > /etc/rc.local
	echo "exit 0" > /etc/rc.local
	echo "- /etc/rc.local secured" >>  /home/$userName/Desktop/changelog.log

	echo "Editing /etc/login.defs"
	cp /etc/login.defs  /home/$userName/Desktop/backups/
	sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
	sed -i '161s/.*/PASS_MIN_DAYS\o0117/' /etc/login.defs
	sed -i '162s/.*/PASS_WARN_AGE\o01114/' /etc/login.defs
	sed -i '151s/.*/UMASK\o011\o011027/' /etc/login.defs
	echo "- /etc/login.defs configured (Min days 7, Max days 30, Warn age 14, umask higher perms)" >>  /home/$userName/Desktop/changelog.log

	echo "Editing /etc/pam.d/common-password"
	cp /etc/pam.d/common-password  /home/$userName/Desktop/backups/
	sed -i '26s/.*/password\o011[success=1 default=ignore]\o011pam_unix.so obscure pam_unix.so obscure use_authtok try_first_pass remember=5 minlen=8/' /etc/pam.d/common-password
	sed -i '25s/.*/password\o011requisite\o011\o011\o011pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
	echo "- /etc/pam.d/common-password edited (remember=5, minlen=8, complexity requirements)" >>  /home/$userName/Desktop/changelog.log

	echo "Setting account lockout policy"
	cp /etc/pam.d/common-auth  /home/$userName/Desktop/backups/
	sed -i '16s/.*/# here are the per-package modules (the "Primary" block)\n/' /etc/pam.d/common-auth
	sed -i '17s/.*/auth\o011required\o011\o011\o011pam_tally2.so onerr=fail deny=5 unlock_time=1800 audit/' /etc/pam.d/common-auth
	echo "- Account lockout policy set in /etc/pam.d/common-auth" >>  /home/$userName/Desktop/changelog.log

	echo "Securing Shared Memory"
	cp /etc/fstab  /home/$userName/Desktop/backups/
	mount -o remount,noexec,nosuid /dev/shm
	echo "- Shared memory secured in  /etc/fstab" >>  /home/$userName/Desktop/changelog.log

	echo "Configuring rkhunter to allow checking for updates"
	cp /etc/rkhunter.conf  /home/$userName/Desktop.backups
	sed -i '104s/.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
	sed -i '118s/.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
	sed -i '1108s/.*/WEB_CMD=""/' /etc/rkhunter.conf
	echo "- Configured /etc/rkhunter.conf to allow for checking for updates" >>  /home/$userName/Desktop/changelog.log
	
	echo "Configuring /etc/sysctl.conf"
	cp /etc/sysctl.conf  /home/$userName/Desktop/backups/
	sed -i '59s/.*/net.ipv4.conf.all.log_martians = 1/' /etc/sysctl.conf
	sed -i '52s/.*/net.ipv4.conf.all.send_redirects = 0/' /etc/sysctl.conf
	sed -i '55s/.*/net.ipv4.conf.all.accept_source_route = 0/' /etc/sysctl.conf
	sed -i '56s/.*/net.ipv6.conf.all.accept_source_route = 0/' /etc/sysctl.conf
	sed -i '68s/.*/kernel.sysrq=0/' /etc/sysctl.conf
	sed -i '76s/.*/fs.protected_hardlinks=1/' /etc/sysctl.conf
	sed -i '77s/.*/fs.protected_symlinks=1/' /etc/sysctl.conf
	sed -i '25s/.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf
	sed -i '44s/.*/net.ipv4.conf.all.accept_redirects = 0/' /etc/sysctl.conf
	sed -i '45s/.*/net.ipv6.conf.all.accept_redirects = 0/' /etc/sysctl.conf
	echo "- /etc/sysctl.conf configured (basic)" >>  /home/$userName/Desktop/changelog.log

}

media_files () {

	echo "Logging the fire directories of media files on the machine"
	echo "Logging all media files"
	touch  /home/$userName/Desktop/media_files.log
	chmod 777  /home/$userName/Desktop/media_files.log

	echo "Most common types of media files" >>  /home/$userName/Desktop/media_files.log
	find / -name "*.midi" -type f >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mid" -type f  >>  /home/$userName/Desktop/media_files.log	
	find / -name "*.mp3" -type f   >>  /home/$userName/Desktop/media_files.log
	find / -name "*.ogg" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.wav" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.avi" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mov" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.wmv" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mp4" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.avi" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.swf" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.ico" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.svg" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.gif" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.jpeg" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.jpg" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.png" -type f    >>  /home/$userName/Desktop/media_files.log

	echo >>  /home/$userName/Desktop/media_files.log
	echo "PHP files:" >>  /home/$userName/Desktop/media_files.log
	find / -name "*.php" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.php3" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.php4" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.phtml" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.phps" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.phpt" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.php5" -type f  >>  /home/$userName/Desktop/media_files.log

	echo >>  /home/$userName/Desktop/media_files.log
	echo "Script files:" >>  /home/$userName/Desktop/media_files.log
	find / -name "*.sh" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.bash" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.bsh" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.csh" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.bash_profile" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.profile" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.bashrc" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.zsh" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.ksh" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.cc" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.startx" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.bat" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.cmd" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.nt" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.asp" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.vb" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.vbs" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.tab" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.spf" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.rc" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.reg" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.py" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.ps1" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.psm1" -type f  >>  /home/$userName/Desktop/media_files.log	
	
	echo >>  /home/$userName/Desktop/media_files.log
	echo "Audio:" >>  /home/$userName/Desktop/media_files.log	
	find / -name "*.mod" -type f  >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mp2" -type f   >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mpa" -type f   >>  /home/$userName/Desktop/media_files.log
	find / -name "*.abs" -type f   >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mpega" -type f   >>  /home/$userName/Desktop/media_files.log
	find / -name "*.au" -type f   >>  /home/$userName/Desktop/media_files.log
	find / -name "*.snd" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.aiff" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.aif" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.sid" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.flac" -type f    >>  /home/$userName/Desktop/media_files.log
	
	echo >>  /home/$userName/Desktop/media_files.log
	echo "Video:" >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mpeg" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mpg" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mpe" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.dl" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.movie" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.movi" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.mv" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.iff" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.anim5" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.anim3" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.anim7" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.vfw" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.avx" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.fli" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.flc" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.qt" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.spl" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.swf" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.dcr" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.dir" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.dxr" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.rpm" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.rm" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.smi" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.ra" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.ram" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.rv" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.asf" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.asx" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.wma" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.wax" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.wmx" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.3gp" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.flv" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.m4v" -type f    >>  /home/$userName/Desktop/media_files.log
	
	echo >>  /home/$userName/Desktop/media_files.log
	echo "Images:" >>  /home/$userName/Desktop/media_files.log
	find / -name "*.tiff" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.tif" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.rs" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.rgb" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.xwd" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.xpm" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.ppm" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.pbm" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.pgm" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.pcx" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.svgz" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.im1" -type f    >>  /home/$userName/Desktop/media_files.log
	find / -name "*.jpe" -type f    >>  /home/$userName/Desktop/media_files.log

}

second_time_failsafe () {

	failYN=""
	while [ $failYN != "exit" ]
	do
		 
		echo "Which part of the script would you like to redo? (all, packages, firewall, services, hacking_tools, general_config, file_config, media_files) (type exit to leave)"
		read failYN
		if [[ $failYN == "all" ]]
		then
			packages
			firewall
			services
			hacking_tools
			general_config
			file_config
			media_files
		elif [[ $failYN == "packages" ]]
		then
			packages
		elif [[ $failYN == "firewall" ]]
		then
			firewall
		elif [[ $failYN == "services" ]]
		then
			services
		elif [[ $failYN == "hacking_tools" ]]
		then
			hacking_tools
		elif [[ $failYN == "general_config" ]]
		then
			general_config
		elif [[ $failYN == "file_config" ]]
		then
			file_config
		elif [[ $failYN == "media_files" ]]
		then
			media_files
		else
			echo "Option not found"
		fi
	done
	exit 0

}		
	
failsafe= /home/$userName/Desktop/changelog.log
if [[ -f "$failsafe" ]]
then
	echo "This script is detected as being run for more than one time"
	echo "This has been known to cause a wide variety of problems, including potential loss of internet, which in worst case scenario, can necessetate a restart of the image."
	echo "Luckily, a system has been implemented to avoid this problem, functions"
	echo "Would you like to continue with choosing which parts of the script to redo?"
	read restartYN
	if [[ $restartYN == "yes" ]]
	then
		echo "Would you like to remove and replace the current installments of the changelog and backups? (other option is creating new files)"
		read removeYN
		if [[ $removeYN == "yes" ]]
		then
			rm  /home/$userName/Desktop/changelog.log
			rm -r  /home/$userName/Desktop/backups
			echo "Replacing backup folder and backing up important files"
			mkdir -p  /home/$userName/Desktop/backups
			chmod 777  /home/$userName/Desktop/backups
			cp /etc/group  /home/$userName/Desktop/backups/
			cp /etc/passwd  /home/$userName/Desktop/backups/
			touch changelog.log  /home/$userName/Desktop
			chmod 777  /home/$userName/Desktop/changelog.log
			echo "List of changes made by script:" >  /home/$userName/Desktop/changelog.log
			echo "- Backups folder recreated\n- Important files backed up" >>  /home/$userName/Desktop/changelog.log
			
			 
			second_time_failsafe
		elif [[ $removeYN == "no" ]]
		then
			  
			echo "Replacing legacy folder and backing up old files"
			mkdir -p  /home/$userName/Desktop/script_legacy
			mv  /home/$userName/Desktop/changelog.log  /home/$userName/Desktop/script_legacy
			mv -r  /home/$userName/Desktop/backups/  /home/$userName/Desktop/script_legacy
			echo "Creating new backups folder and backing up important files"
			mkdir -p  /home/$userName/Desktop/backups
			chmod 777  /home/$userName/Desktop/backups
			cp /etc/group  /home/$userName/Desktop/backups/
			cp /etc/passwd  /home/$userName/Desktop/backups/
			touch changelog2.log  /home/$userName/Desktop
			chmod 777  /home/$userName/Desktop/changelog.log
			echo "List of changes made by script:" >  /home/$userName/Desktop/changelog.log
			echo "- Backups folder recreated\n- Important files backed up" >>  /home/$userName/Desktop/changelog.log
			
			second_time_failsafe
		else
			echo "Option not recognized"
			exit 1
		fi
	elif [[ $restartYN == "no" ]]
	then
		echo "Exiting script"
		exit 1
	else
		echo "Option not recognized"
		exit 1
	fi
fi

end () {
	echo "Manual changes:"
	echo "- Run ClamTK antivirus scan"
	echo "- Run rkhunter scan (sudo rkhunter --check)"
	echo "- Run lynis audit (sudo lynis audit system)"
	echo "- Check for backdoors (netstat -anp | grep LISTEN | grep -v STREAM"
	echo "- Run bash vulnerability test"
	echo "- Check for malicious packages that might still be installed (dpkg -l | grep <keyword> (i.e. crack))"
	echo "- Make sure updates are checked for daily and update Ubuntu according to the ReadMe"
	echo "- Make sure root is the only root account (:0:) (in /etc/group)"
	echo "- Audit users"
}

echo "Type 'safe' to enter safe mode and anything else to continue"
read safecheck
if [[ $safecheck == "safe" ]]
then
	echo "Entering safe mode ..."
	echo "In safe mode, you can choose to only run certain parts of the script"
	second_time_failsafe
fi

#Calls for functions to run through individual portions of the script"
first_time_initialize
packages
general_config
firewall
services
hacking_tools
file_config
media_files

#reload certain services/packages and clean up machine
iptables -P INPUT DROP
rkhunter --propupd
service ssh restart
apt-get autoremove -y -qq  
apt-get autoclean -y -qq  
apt-get clean -y -qq  

#run rkhunter
rkhunter --check --vl --sk
cp /var/log/rkhunter.log  /home/$userName/Desktop

end

echo "Script done! Good luck :D"

clamtk