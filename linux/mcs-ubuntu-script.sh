#!/bin/bash
echo "MCS Ubuntu Script v5.8 Updated 1/14/2021 at 6:55pm EST"
echo "Created by Massimo Marino"

if [[ "$(whoami)" != root ]]
then
	echo "This script can only be run as root"
	exit 1
fi

first_time_initialize () {  
	echo "Creating backup folder and backing up important files"
	mkdir -p ~/Desktop/logs
	chmod 777 ~/Desktop/logs
	mkdir -p ~/Desktop/logs/backups
	chmod 777 ~/Desktop/logs/backups
	cp /etc/group ~/Desktop/logs/backups/
	cp /etc/passwd ~/Desktop/logs/backups/
	cp /etc/shadow ~/Desktop/logs/backups/
	touch ~/Desktop/logs/changelog.log
	chmod 777 ~/Desktop/logs/changelog.log
	echo "List of changes made by script:" > ~/Desktop/logs/changelog.log
	echo "- Backups folder created" >> ~/Desktop/logs/changelog.log
	echo "- Important files backed up" >> ~/Desktop/logs/changelog.log
}

packages () { 
	echo "Updating apt"
	apt-get update -y -qq 
	apt-get upgrade -y -qq
	apt-get dist-upgrade -y -qq 
	echo "- Package installer 'apt' updated (update, upgrade, dist-upgrade)" >> ~/Desktop/logs/changelog.log

	echo "Installing useful packages"
	echo "Firefox (Browser)"
	apt-get install firefox -y -qq 
	echo "RKHunter (AntiRootkit/antivirus)"
	apt-get install rkhunter -y -qq
	echo "AppArmor (Kernel enhancer)"
	apt-get install apparmor -y -qq
	apt-get install apparmor-profiles -y -qq 
	apt-get install apparmor-profiles-extra -y -qq
	echo "IPTables (Network manager)"
	apt-get install iptables -y -qq
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
	echo "AIDE (file integrity checker)"
	apt-get install aide -y -qq
	echo "Arpwatch (ethernet monitor)"
	apt-get install arpwatch -y -qq
	echo "Install VM tools?"
	read vmtoolsYN
	if [[ $vmtoolsYN == "yes" ]]
	then
		apt-get install open-vm-tools -y -qq
		echo "- Package open-vm-tools installed" >> ~/Desktop/logs/changelog.log
	fi
	apt-get install --reinstall coreutils -y -qq
	echo "- Packages firefox, debsecan, debsums, fail2ban, libpam-tmpdir, apt-listchanges, apt-show-versions, debian-goodies, apparmor, rkhunter, chkrootkit, iptables, portsentry, lynis, ufw, gufw, libpam-cracklib, auditd, tree, clamav, and clamtk installed; coreutils reinstalled" >> ~/Desktop/logs/changelog.log

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
	echo "- Firewall configured (Firewall enabled, Ports 1337, 23, 2049, 515, 135, 137, 138, 139, 445, 69, 514, 161, 162, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, and 111 denied, Logging on and high)" >> ~/Desktop/logs/changelog.log

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
		echo "- Packages ssh and openssh-server installed and heartbleed bug fixed" >> ~/Desktop/logs/changelog.log
		
		 
		echo "Editing /etc/sshd/sshd_config"
		cp /etc/ssh/sshd_config ~/Desktop/logs/backups/
		sed -i '13s/.*/Port 22/' /etc/ssh/sshd_config 
		sed -i '32s/.*/PermitRootLogin no/' /etc/ssh/sshd_config
		sed -i '87s/.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
		sed -i '100s/.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
		sed -i '98s/.*/Compression DELAYED/' /etc/ssh/sshd_config
		sed -i '27s/.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
		sed -i '34s/.*/MaxAuthTries 2/' /etc/ssh/sshd_config
		sed -i '35s/.*/MaxSessions 2/' /etc/ssh/sshd_config
		sed -i '95s/.*/TCPKeepAlive no/' /etc/ssh/sshd_config
		sed -i '89s/.*/X11Forwarding no/' /etc/ssh/sshd_config
		sed -i '86s/.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
		echo "- Configured /etc/ssh/sshd_config" >> ~/Desktop/logs/changelog.log	
		
		  
		echo "Securing SSH keys"
		mkdir ~/.ssh
		chmod 700 ~/.ssh
		touch ~/.ssh/authorized_keys
		chmod 600 ~/.ssh/authorized_keys
		echo "- Secured SSH keys" >> ~/Desktop/logs/changelog.log
		
		echo "SSH port can accept SSH connections"
		iptables -A INPUT -p tcp --dport ssh -j ACCEPT
		
		service ssh restart
	else
		echo "- openssh-server and ssh were not installed on this machine" >> ~/Desktop/logs/changelog.log
	fi
	 
	echo "Is NGINX a critical service on this machine?"
	read nginxYN
	if [[ $nginxYN == "yes" ]]; then
		apt-get install nginx -y -qq
		echo "- NGINX installed" >> ~/Desktop/logs/changelog.log
	elif [[ $nginxYN == "no" ]]; then
		apt-get purge nginx -y -qq  
		apt-get purge nginx-common -y -qq  
		apt-get purge nginx-core -y -qq
		echo "- NGINX removed from the machine" >> ~/Desktop/logs/changelog.log
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
		echo "- Samba installed and allowed" >> ~/Desktop/logs/changelog.log
	elif [[ $sambaYN == "no" ]]; then
		ufw deny netbios-ns
		ufw deny netbios-dgm
		ufw deny netbios-ssn
		ufw deny microsoft-ds
		apt-get purge samba -y -qq    
		echo "- Samba uninstalled and blocked" >> ~/Desktop/logs/changelog.log
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
		echo "- FTP installed and allowed" >> ~/Desktop/logs/changelog.log
	elif [[ $ftpYN == "no" ]]; then
		service stop vsftpd
		ufw deny ftp 
		ufw deny sftp 
		ufw deny saft 
		ufw deny ftps-data 
		ufw deny ftps
		apt-get purge vsftpd -y -qq  
		echo "- FTP uninstalled and blocked" >> ~/Desktop/logs/changelog.log
	fi
	 
	echo "Is Telnet a critical service on this machine?"
	read telnetYN
	if [[ $telnetYN == "yes" ]]; then
		ufw allow telnet 
		ufw allow rtelnet 
		ufw allow telnets
		echo "- Telnet allowed" >> ~/Desktop/logs/changelog.log
	elif [[ $telnetYN == "no" ]]; then
		service telnet stop
		ufw deny telnet 
		ufw deny rtelnet 
		ufw deny telnets
		apt-get purge telnet -y -qq  
		apt-get purge telnetd -y -qq  
		apt-get purge inetutils-telnetd -y -qq  
		apt-get purge telnetd-ssl -y -qq  
		apt-get purge vsftpd -y -qq  
		echo "- Telnet uninstalled and blocked" >> ~/Desktop/logs/changelog.log
	fi
	 
	echo "Is MySQL a critical service on this machine?"
	read sqlYN
	if [[ $sqlYN == "yes" ]]; then
		ufw allow ms-sql-s 
		ufw allow ms-sql-m 
		ufw allow mysql 
		ufw allow mysql-proxy
		echo "- MySQL allowed (WIP)" >> ~/Desktop/logs/changelog.log
	elif [[ $sqlYN == "no" ]]; then
		ufw deny ms-sql-s 
		ufw deny ms-sql-m 
		ufw deny mysql 
		ufw deny mysql-proxy
		apt-get purge mysql-server -y -qq  
		apt-get purge mysql -y -qq  
		echo "- MySQL uninstalled and blocked (WIP)" >> ~/Desktop/logs/changelog.log
	fi
 
	echo "Is this machine a web server?"
	read webYN
	if [[ $webYN == "yes" ]]; then
		echo "Apache2 or NGINX? (If unsure, choose Apache2) (Case sensitive)"
		read webserviceYN
		if [[ $webserviceYN == "NGINX" ]]; then
			apt-get purge apache2 -y -qq 
			apt-get purge apache2-bin -y -qq
			apt-get purge apache2-utils -y -qq
			apt-get purge libapache2-mod-evasive -y -qq
			apt-get purge libapache2-mod-security2 -y -qq
			echo "- Apache2 removed" >> ~/Desktop/logs/changelog.log
			apt-get install nginx -y -qq
			ufw allow http 
			ufw allow https
			echo "- NGINX installed" >> ~/Desktop/logs/changelog.log
		elif [[ $webserviceYN == "Apache2" ]]; then
			apt-get purge nginx -y -qq  
			apt-get purge nginx-common -y -qq  
			apt-get purge nginx-core -y -qq
			echo "- NGINX removed from the machine" >> ~/Desktop/logs/changelog.log
			apt-get install apache2 -y -qq 
			apt-get install apache2-utils -y -qq
			apt-get install libapache2-mod-evasive -y -qq
			apt-get install libapache2-mod-security2 -y -qq
			ufw allow http 
			ufw allow https
			systemctl restart apache2
			sed -i '92s/.*/Timeout 15/' /etc/apache2/apache2.conf
			sed -i '98s/.*/KeepAlive Off/' /etc/apache2/apache2.conf
			sed -i '126s/.*/HostnameLookups On/' /etc/apache2/apache2.conf
			chmod -R 444 /var/www
			echo "- Apache2 installed, configured, and http(s) allowed" >> ~/Desktop/logs/changelog.log
		fi
	elif [[ $webYN == "no" ]]; then
		apt-get purge nginx -y -qq  
		apt-get purge nginx-common -y -qq  
		apt-get purge nginx-core -y -qq
		echo "- NGINX removed from the machine" >> ~/Desktop/logs/changelog.log
		ufw deny http
		ufw deny https
		apt-get purge apache2 -y -qq 
		apt-get purge apache2-bin -y -qq
		apt-get purge apache2-utils -y -qq
		apt-get purge libapache2-mod-evasive -y -qq
		apt-get purge libapache2-mod-security2 -y -qq
		#rm -r /var/www/*
		echo "- Apache2 removed and http(s) blocked" >> ~/Desktop/logs/changelog.log
	fi

}

general_config () {
 
	echo "Should root user be locked?"
	read lockRootYN
	if [[ $lockRootYN == yes ]]
	then 
		usermod -L root
		echo "- Root account locked. Use 'usermod -U root' to unlock it (but good luck without root)"
	fi
	
	echo "Denying outside packets"
	iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
	echo "- Denied outside packets" >> ~/Desktop/logs/changelog.log
	
	echo "Unaliasing all"
	unalias -a
	echo "- Unaliased all" >> ~/Desktop/logs/changelog.log

	echo "Enabling auditing"
	auditctl -e 1
	echo "- Auditing enabled with auditd (can be configured in /etc/audit/auditd.conf)" >> ~/Desktop/logs/changelog.log

	echo "Disabling reboot with Ctrl-Alt "
	sudo systemctl mask ctrl-alt-del.target
	sudo systemctl daemon-reload
	echo "- Disabled reboot with Ctrl-Alt " >> ~/Desktop/logs/changelog.log
	
	echo "Securing important files with chmod"
	chmod -R 644 /var/log
	chmod 664 /etc/passwd
	chmod 664 /etc/shadow
	chmod 664 /etc/group
	chmod 0700 /etc/cups*
	chmod 0700 /etc/rc*
	chmod 0700 /etc/init.d*
	chmod 0755 /etc/profile
	chmod 0700 /etc/hosts.allow
	chmod 0700 /etc/sysctl.conf
	chmod 2750 /bin/su
	chmod 2750 /bin/ping
	chmod 2750 /sbin/ifconfig
	chmod 2750 /usr/bin/w
	chmod 2750 /usr/bin/who
	chmod 2750 /usr/bin/locate
	chmod 2750 /usr/bin/whereis
	echo "- /var/log, /etc/passwd/, /etc/shadow, /etc/groups/, /etc/cups*, /etc/rc*, /etc/init.d*, /etc/profile, /etc/hosts.allow, /etc/sysctl.conf, /bin/su, /bin/ping, /sbin/ifconfig, /usr/bin/w, /usr/bin/who, /usr/bin/locate, and /usr/bin/whereis permissions set" >> ~/Desktop/logs/changelog.log
	
	#echo "Configuring AIDE"
	#aideinit
	#cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
	#update-aide.conf
	#cp /var/lib/aide/aide.conf.autogenerated /etc/aide/aide.conf
	
	echo "Starting arpwatch"
	#chkconfig --level 35 arpwatch on
	/etc/init.d/arpwatch start
	arpwatch
	echo "- Arpwatch started" >> ~/Desktop/logs/changelog.log
	
	echo "Starting Postfix"
	cp /usr/share/postfix/main.cf.debian /etc/postfix/main.cf
	run postconf -e disable_vrfy_command=yes
	service postfix reload
	echo "- Postfix started" >> ~/Desktop/logs/changelog.log
	
	echo "Backing up and clearing crontab"
	touch ~/Desktop/logs/backups/crontab-backup
	crontab -l > ~/Desktop/logs/backups/crontab-backup
	crontab -r
	echo "- Crontab backed up and cleared" >> ~/Desktop/logs/changelog.log
	
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

	echo "Removing NFS"
	apt-get purge nfs-kernel-server -y -qq  
	apt-get purge nfs-common -y -qq  
	apt-get purge portmap -y -qq  
	apt-get purge rpcbind -y -qq  
	apt-get purge autofs -y -qq  

	echo "Removing VNC"
	apt-get purge vnc4server -y -qq  
	apt-get purge vncsnapshot -y -qq  
	apt-get purge vtgrab -y -qq  
 
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
	apt-get purge sqlmap -y -qq

	echo "Removing packages that can potentially contribute to backdoors"
	apt-get purge backdoor-factory -y -qq  
	apt-get purge shellinabox -y -qq  

	echo "Cleaning up Packages"
	apt-get autoremove -y -qq  
	apt-get autoclean -y -qq  
	apt-get clean -y -qq  
	echo "- Removed netcat, CeWl, nmap, Medusa, Wfuzz, Hashcat, John the Ripper, Hydra, Aircrack-NG, FCrackZIP, LCrack, OphCrack, Pyrit, rarcrack, SipCrack, NFS, VNC, and cleaned up packages" >> ~/Desktop/logs/changelog.log

}

file_config () {

	echo "Disallowing guest account"
	cp /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf ~/Desktop/logs/backups/
	sed -i '2s/$/\n/' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
	sed -i '3s/.*/allow-guest=false/' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
	echo "- Disabled guest account" >> ~/Desktop/logs/changelog.log

	echo "Securing /etc/rc.local"
	echo > /etc/rc.local
	echo "exit 0" > /etc/rc.local
	echo "- /etc/rc.local secured" >> ~/Desktop/logs/changelog.log

	echo "Editing /etc/login.defs"
	cp /etc/login.defs ~/Desktop/logs/backups/
	sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
	sed -i '161s/.*/PASS_MIN_DAYS\o0117/' /etc/login.defs
	sed -i '162s/.*/PASS_WARN_AGE\o01114/' /etc/login.defs
	sed -i '151s/.*/UMASK\o011\o011027/' /etc/login.defs
	echo "- /etc/login.defs configured (Min days 7, Max days 30, Warn age 14, umask higher perms)" >> ~/Desktop/logs/changelog.log

	echo "Editing /etc/pam.d/common-password"
	cp /etc/pam.d/common-password ~/Desktop/logs/backups/
	sed -i '26s/.*/password\o011[success=1 default=ignore]\o011pam_unix.so obscure pam_unix.so obscure use_authtok try_first_pass remember=5 minlen=8/' /etc/pam.d/common-password
	sed -i '25s/.*/password\o011requisite\o011\o011\o011pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
	echo "- /etc/pam.d/common-password edited (remember=5, minlen=8, complexity requirements)" >> ~/Desktop/logs/changelog.log

	echo "Setting account lockout policy"
	cp /etc/pam.d/common-auth ~/Desktop/logs/backups/
	sed -i '16s/$/\n/' /etc/pam.d/common-auth
	sed -i '17s/.*/auth\o011required\o011\o011\o011pam_tally2.so onerr=fail deny=5 unlock_time=600 audit/' /etc/pam.d/common-auth
	echo "- Account lockout policy set in /etc/pam.d/common-auth" >> ~/Desktop/logs/changelog.log

	echo "Securing Shared Memory"
	cp /etc/fstab ~/Desktop/logs/backups/
	mount -o remount,noexec,nosuid /dev/shm
	echo "- Shared memory secured in  /etc/fstab" >> ~/Desktop/logs/changelog.log

	echo "Configuring rkhunter to allow checking for updates"
	cp /etc/rkhunter.conf ~/Desktop/logs/backups
	sed -i '107s/.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
	sed -i '122s/.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
	sed -i '1189s/.*/WEB_CMD=""/' /etc/rkhunter.conf
	sed -i '440s/.*/PKGMGR=DPKG/' /etc/rkhunter.conf
	echo "- Configured /etc/rkhunter.conf to allow for checking for updates" >> ~/Desktop/logs/changelog.log
	
	echo "Configuring /etc/sysctl.conf"
	cp /etc/sysctl.conf ~/Desktop/logs/backups/
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
	echo "- /etc/sysctl.conf configured (basic)" >> ~/Desktop/logs/changelog.log

}

media_files () {

	echo "Logging the fire directories of media files on the machine"
	echo "Logging all media files"
	touch ~/Desktop/logs/media_files.log
	chmod 777 ~/Desktop/logs/media_files.log

	echo "Most common types of media files" >> ~/Desktop/logs/media_files.log
	find / -name "*.midi" >> ~/Desktop/logs/media_files.log
	find / -name "*.mid"  >> ~/Desktop/logs/media_files.log	
	find / -name "*.mp3"  >> ~/Desktop/logs/media_files.log
	find / -name "*.ogg" ! -path '*/snap/*' ! -path '*/usr/share/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.wav" ! -path '*/usr/share/*' ! -path '*/usr/lib/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.mov"  >> ~/Desktop/logs/media_files.log
	find / -name "*.wmv"  >> ~/Desktop/logs/media_files.log
	find / -name "*.mp4"  >> ~/Desktop/logs/media_files.log
	find / -name "*.avi"  >> ~/Desktop/logs/media_files.log
	find / -name "*.swf"  >> ~/Desktop/logs/media_files.log
	find / -name "*.ico" ! -path '*/usr/share/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.svg" ! -path '*/var/lib/*' ! -path '*/etc/alternatives/*' ! -path '*/snap/*' ! -path '*/usr/lib/*' ! -path '*/usr/share/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.gif" ! -path '*/usr/lib/*' ! -path '*/usr/share/*'>> ~/Desktop/logs/media_files.log
	find / -name "*.jpeg"  >> ~/Desktop/logs/media_files.log
	find / -name "*.jpg" ! -path '*/usr/share/*' ! -path '*/snap/*' ! -path '*/usr/lib/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.png" ! -path '*/etc/alternatives/*' ! -path '*/snap/*' ! -path '*/usr/lib/*' ! -path '*/usr/share/*' ! -path '*/var/lib/*' >> ~/Desktop/logs/media_files.log

	echo >> ~/Desktop/logs/media_files.log
	echo "PHP files:" >> ~/Desktop/logs/media_files.log
	find / -name "*.php" ! -path '*/var/cache/*'  >> ~/Desktop/logs/media_files.log
	find / -name "*.php3"   >> ~/Desktop/logs/media_files.log
	find / -name "*.php4"   >> ~/Desktop/logs/media_files.log
	find / -name "*.phtml"   >> ~/Desktop/logs/media_files.log
	find / -name "*.phps"   >> ~/Desktop/logs/media_files.log
	find / -name "*.phpt"   >> ~/Desktop/logs/media_files.log
	find / -name "*.php5"   >> ~/Desktop/logs/media_files.log

	echo >> ~/Desktop/logs/media_files.log
	echo "Script files:" >> ~/Desktop/logs/media_files.log
	find / -name "*.sh" ! -path '*/usr/libreoffice/*' ! -path '*/snap/*' ! -path '*/usr/bin/*' ! -path '*/usr/lib/*' ! -path '*/usr/share/*' ! -path '*/usr/src/*' ! -path '*/lib/*' ! -path '*/boot/*' ! -path '*/etc/profile.d/*' ! -path '*/etc/gdm3/*' ! -path '*/etc/acpi/*' ! -path '*/etc/wpa_supplicant/*' ! -path '*/etc/init.d/*' ! -path '*/etc/console-setup/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.bash" ! -path '*/usr/share/*'  >> ~/Desktop/logs/media_files.log
	find / -name "*.bsh"   >> ~/Desktop/logs/media_files.log
	find / -name "*.csh" ! -path '*/usr/share/*' ! -path '*/snap/*' ! -path '*/usr/lib/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.bash_profile" >> ~/Desktop/logs/media_files.log
	find / -name "*.profile" ! -path '*/snap/*' ! -path '*/usr/share/*' ! -path '*/usr/src/*'  >> ~/Desktop/logs/media_files.log
	find / -name "*.bashrc" ! -path '*/snap/*' ! -path '*/usr/share/*'  >> ~/Desktop/logs/media_files.log
	find / -name "*.zsh"   >> ~/Desktop/logs/media_files.log
	find / -name "*.ksh"   >> ~/Desktop/logs/media_files.log
	find / -name "*.cc" ! -path '*/usr/src/*'  >> ~/Desktop/logs/media_files.log
	find / -name "*.startx"   >> ~/Desktop/logs/media_files.log
	find / -name "*.bat" ! -path '*/usr/share/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.cmd" ! -path '*/usr/src/*'  >> ~/Desktop/logs/media_files.log
	find / -name "*.nt"   >> ~/Desktop/logs/media_files.log
	find / -name "*.asp" ! -path '*/usr/lib/*'  >> ~/Desktop/logs/media_files.log
	find / -name "*.vb"   >> ~/Desktop/logs/media_files.log
	find / -name "*.vbs"   >> ~/Desktop/logs/media_files.log
	find / -name "*.tab" ! -path '*/snap/*' ! -path '*/usr/share/*' ! -path '*/run/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.spf"   >> ~/Desktop/logs/media_files.log
	find / -name "*.rc" ! -path '*/snap/*' ! -path '*/usr/share/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.reg"   >> ~/Desktop/logs/media_files.log
	find / -name "*.py"  ! -path '*/snap/*' ! -path '*/usr/lib/*' ! -path '*/usr/share/*' ! -path '*/usr/src/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.ps1"   >> ~/Desktop/logs/media_files.log
	find / -name "*.psm1"   >> ~/Desktop/logs/media_files.log	
	
	echo >> ~/Desktop/logs/media_files.log
	echo "Audio:" >> ~/Desktop/logs/media_files.log	
	find / -name "*.mod"  ! -path '*/usr/share/*' ! -path '*/usr/lib/*' ! -path '*/boot/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.mp2"    >> ~/Desktop/logs/media_files.log
	find / -name "*.mpa"    >> ~/Desktop/logs/media_files.log
	find / -name "*.abs"    >> ~/Desktop/logs/media_files.log
	find / -name "*.mpega"    >> ~/Desktop/logs/media_files.log
	find / -name "*.au"    >> ~/Desktop/logs/media_files.log
	find / -name "*.snd"     >> ~/Desktop/logs/media_files.log
	find / -name "*.aiff"     >> ~/Desktop/logs/media_files.log
	find / -name "*.aif"     >> ~/Desktop/logs/media_files.log
	find / -name "*.sid"     >> ~/Desktop/logs/media_files.log
	find / -name "*.flac"     >> ~/Desktop/logs/media_files.log
	
	echo >> ~/Desktop/logs/media_files.log
	echo "Video:" >> ~/Desktop/logs/media_files.log
	find / -name "*.mpeg"     >> ~/Desktop/logs/media_files.log
	find / -name "*.mpg" ! -path '*/lib/*' >> ~/Desktop/logs/media_files.log
	find / -name "*.mpe"     >> ~/Desktop/logs/media_files.log
	find / -name "*.dl"     >> ~/Desktop/logs/media_files.log
	find / -name "*.movie"     >> ~/Desktop/logs/media_files.log
	find / -name "*.movi"     >> ~/Desktop/logs/media_files.log
	find / -name "*.mv"     >> ~/Desktop/logs/media_files.log
	find / -name "*.iff"     >> ~/Desktop/logs/media_files.log
	find / -name "*.anim5"     >> ~/Desktop/logs/media_files.log
	find / -name "*.anim3"     >> ~/Desktop/logs/media_files.log
	find / -name "*.anim7"     >> ~/Desktop/logs/media_files.log
	find / -name "*.vfw"     >> ~/Desktop/logs/media_files.log
	find / -name "*.avx"     >> ~/Desktop/logs/media_files.log
	find / -name "*.fli"     >> ~/Desktop/logs/media_files.log
	find / -name "*.flc"     >> ~/Desktop/logs/media_files.log
	find / -name "*.qt"     >> ~/Desktop/logs/media_files.log
	find / -name "*.spl"     >> ~/Desktop/logs/media_files.log
	find / -name "*.swf"     >> ~/Desktop/logs/media_files.log
	find / -name "*.dcr"     >> ~/Desktop/logs/media_files.log
	find / -name "*.dir"  ! -path '*/snap/*' ! -path '*/usr/share/*'  >> ~/Desktop/logs/media_files.log
	find / -name "*.dxr"     >> ~/Desktop/logs/media_files.log
	find / -name "*.rpm"     >> ~/Desktop/logs/media_files.log
	find / -name "*.rm"     >> ~/Desktop/logs/media_files.log
	find / -name "*.smi"     >> ~/Desktop/logs/media_files.log
	find / -name "*.ra"     >> ~/Desktop/logs/media_files.log
	find / -name "*.ram"     >> ~/Desktop/logs/media_files.log
	find / -name "*.rv"     >> ~/Desktop/logs/media_files.log
	find / -name "*.asf"     >> ~/Desktop/logs/media_files.log
	find / -name "*.asx"     >> ~/Desktop/logs/media_files.log
	find / -name "*.wma"     >> ~/Desktop/logs/media_files.log
	find / -name "*.wax"     >> ~/Desktop/logs/media_files.log
	find / -name "*.wmx"     >> ~/Desktop/logs/media_files.log
	find / -name "*.3gp"     >> ~/Desktop/logs/media_files.log
	find / -name "*.flv"     >> ~/Desktop/logs/media_files.log
	find / -name "*.m4v"     >> ~/Desktop/logs/media_files.log
	
	echo >> ~/Desktop/logs/media_files.log
	echo "Images:" >> ~/Desktop/logs/media_files.log
	find / -name "*.tiff"     >> ~/Desktop/logs/media_files.log
	find / -name "*.tif"     >> ~/Desktop/logs/media_files.log
	find / -name "*.rs"     >> ~/Desktop/logs/media_files.log
	find / -name "*.rgb"     >> ~/Desktop/logs/media_files.log
	find / -name "*.xwd"     >> ~/Desktop/logs/media_files.log
	find / -name "*.xpm"  ! -path '*/snap/*' ! -path '*/usr/share/*'  >> ~/Desktop/logs/media_files.log
	find / -name "*.ppm"  ! -path '*/usr/share/*'   >> ~/Desktop/logs/media_files.log
	find / -name "*.pbm"     >> ~/Desktop/logs/media_files.log
	find / -name "*.pgm"     >> ~/Desktop/logs/media_files.log
	find / -name "*.pcx"     >> ~/Desktop/logs/media_files.log
	find / -name "*.svgz" ! -path '*/usr/share/*'    >> ~/Desktop/logs/media_files.log
	find / -name "*.im1"     >> ~/Desktop/logs/media_files.log
	find / -name "*.jpe"     >> ~/Desktop/logs/media_files.log

}

user_auditing () {
	touch ~/Desktop/logs/userchangelog.log
	chmod 777 ~/Desktop/logs/userchangelog.log

	echo "Please enter a list of all authorized *administrators* on the machine (as stated on the README) separated by spaces (please put a space after the last item as well" 
	read authAdminList 
	IFS=' ' read -r -a authAdmins <<< "$authAdminList" 

	echo "Authorized Administrators already on the system:" >> ~/Desktop/logs/userchangelog.log
	for item in "${authAdmins[@]}"
	do
		echo "$item" >> ~/Desktop/logs/userchangelog.log
	done

	echo "Please enter a list of all authorized users on the machine (as stated on the README) separated by spaces" 
	read authGenUserList 
	IFS=' ' read -r -a authGenUsers <<< "$authGenUserList" 

	echo >> ~/Desktop/logs/userchangelog.log
	echo "Authorized Standard Users already on the system:" >> ~/Desktop/logs/userchangelog.log
	for item in "${authGenUsers[@]}"
	do
		echo "$item" >> ~/Desktop/logs/userchangelog.log
	done

	authUserList=("${authAdminList}${authGenUserList}")
	authUsers=("${authAdmins[@]}" "${authGenUsers[@]}")

	currentUserList=$(awk -F':' '$2 ~ "\$" {print $1}' /etc/shadow | tr '\n' ' ')
	IFS=' ' read -r -a currentUsers <<< "$currentUserList" 

	echo >> ~/Desktop/logs/userchangelog.log
	echo "Current users on the system:" >> ~/Desktop/logs/userchangelog.log
	for item in "${currentUsers[@]}" 
	do 
		echo "$item" >> ~/Desktop/logs/userchangelog.log
	done 

	echo >> ~/Desktop/logs/userchangelog.log
	echo "Users deleted off the system:" >> ~/Desktop/logs/userchangelog.log
	for item in "${currentUsers[@]}"
	do 
		if [[ "$authUserList" != *"$item"* ]]
		then
			echo "${item}" >> ~/Desktop/logs/userchangelog.log
			deluser --remove-home ${item}
		fi
	done 

	echo >> ~/Desktop/logs/userchangelog.log
	echo "Users added to the system:" >> ~/Desktop/logs/userchangelog.log
	for item in "${authUsers[@]}"
	do
		if [[ "$currentUserList" != *"$item"* ]]
		then
			echo "${item}" >> ~/Desktop/logs/userchangelog.log
			adduser ${item}
		fi
	done

	echo >> ~/Desktop/logs/userchangelog.log
	echo "Authorized admins given sudo permissions:" >> ~/Desktop/logs/userchangelog.log
	for item in "${authAdmins[@]}"
	do
		if [[ "$(groups ${item})" != *"sudo"* ]]
		then
			echo "${item}" >> ~/Desktop/logs/userchangelog.log
			usermod -aG sudo ${item}
		fi
	done

	echo >> ~/Desktop/logs/userchangelog.log
	echo "Authorized standard users stripped of sudo permissions:" >> ~/Desktop/logs/userchangelog.log
	for item in "${authGenUsers[@]}"
	do
		if [[ "$(groups ${item})" == *"sudo"* ]]
		then 
			echo "${item}" >> ~/Desktop/logs/userchangelog.log
			gpasswd -d ${item} sudo
		fi
	done

	echo "- Users auditing completed. Please check inside the 'userchangelog.log' file on your desktop for more information." >> ~/Desktop/logs/changelog.log

	rootUserList=$(grep :0: /etc/passwd | tr '\n' ' ' )
	IFS=' ' read -r -a rootUsers <<< "$rootUserList" 
	echo >> ~/Desktop/logs/userchangelog.log
	echo "All current root users on the machine (should only be 'root')" >> ~/Desktop/logs/userchangelog.log
	for thing in "${rootUsers[@]}"
	do
		echo "${thing%%:*}" >> ~/Desktop/logs/userchangelog.log
	done 

}

second_time_failsafe () {

	failYN=""
	while [ $failYN != "exit" ]
	do
		 
		echo "Which part of the script would you like to redo? (all, packages, firewall, services, hacking_tools, general_config, file_config, user_auditing, media_files) (type exit to leave)"
		read failYN
		if [[ $failYN == "all" ]]
		then
			packages
			firewall
			services
			hacking_tools
			general_config
			user_auditing
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
		elif [[ $failYN == "user_auditing" ]]
		then	
			user_auditing
		elif [[ $failYN == "media_files" ]]
		then
			media_files
		else
			echo "Option not found"
		fi
	done
	exit 0

}		
	
failsafe=~/Desktop/logs/changelog.log
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
			rm ~/Desktop/logs/changelog.log
			rm -r ~/Desktop/logs/backups
			echo "Replacing backup folder and backing up important files"
			mkdir -p ~/Desktop/logs/backups
			chmod 777 ~/Desktop/logs/backups
			cp /etc/group ~/Desktop/logs/backups/
			cp /etc/passwd ~/Desktop/logs/backups/
			touch changelog.log ~/Desktop/logs
			chmod 777 ~/Desktop/logs/changelog.log
			echo "List of changes made by script:" > ~/Desktop/logs/changelog.log
			echo "- Backups folder recreated\n- Important files backed up" >> ~/Desktop/logs/changelog.log
			
			 
			second_time_failsafe
		elif [[ $removeYN == "no" ]]
		then
			  
			echo "Replacing legacy folder and backing up old files"
			mkdir -p ~/Desktop/logs/script_legacy
			mv ~/Desktop/logs/changelog.log ~/Desktop/logs/script_legacy
			mv -r ~/Desktop/logs/backups/ ~/Desktop/logs/script_legacy
			echo "Creating new backups folder and backing up important files"
			mkdir -p ~/Desktop/logs/backups
			chmod 777 ~/Desktop/logs/backups
			cp /etc/group ~/Desktop/logs/backups/
			cp /etc/passwd ~/Desktop/logs/backups/
			touch changelog2.log ~/Desktop/logs
			chmod 777 ~/Desktop/logs/changelog.log
			echo "List of changes made by script:" > ~/Desktop/logs/changelog.log
			echo "- Backups folder recreated\n- Important files backed up" >> ~/Desktop/logs/changelog.log
			
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
	echo "- Check for backdoors (netstat -anp | grep LISTEN | grep -v STREAM)"
	echo "- Check for malicious packages that might still be installed (dpkg -l | grep <keyword> (i.e. crack))"
	echo "- Make sure updates are checked for daily and update Ubuntu according to the ReadMe"
}

if [[ "$(date)" == *"Sat Jan  23"* ]]
then
	echo "Happy Competition Day!"
fi

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
user_auditing
media_files

#reload certain services/packages and clean up machine
iptables -P INPUT DROP
rkhunter --propupd
service ssh restart
apt-get update
apt-get upgrade
apt-get autoremove -y -qq  
apt-get autoclean -y -qq  
apt-get clean -y -qq  

#run rkhunter
rkhunter --check --vl --sk
cp /var/log/rkhunter.log ~/Desktop/logs
chmod 777 ~/Desktop/logs/rkhunter.log

#run lynis
lynis audit system
cp /var/log/lynis.log ~/Desktop/logs
chmod 777 ~/Desktop/logs/lynis.log

echo "Installing PortSentry because it can cause false negatives with rkhunter"
echo "PortSentry (Network manager)"
apt-get install portsentry -y -qq 

echo 
echo "Bash Vulnerability Test"
env i='() { :;}; echo Your system is Bash vulnerable' bash -c "echo Bash vulnerability test"
echo "Is Bash vulnerable?"
read bashvulnYN
if [[ $bashvulnYN == "yes" ]]; then
	apt-get update && apt-get install --only-upgrade bash
fi

end

echo "Script done! Good luck :D"

clamtk

update-manager
