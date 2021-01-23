#!/bin/bash
 
echo "MCS Debian Script v2.0 Updated 1/22/2021 at 9:36pm EST"
echo "Created by Massimo Marino"

if [[ "$(whoami)" != root ]]
then
	echo "This script can only be run as root"
	exit 1
fi

first_time_initialize() {
	\unalias -a
	echo "What is the username of the main user on this computer?"
	read -r mainUser
	echo "Creating backup folder and backing up important files + boot files + home files"
	dump 0zf backup.boot /boot
	mkdir -p /home/"$mainUser"/Desktop/logs
	chmod 777 /home/"$mainUser"/Desktop/logs
	mkdir -p /home/"$mainUser"/Desktop/logs/backups
	chmod 777 /home/"$mainUser"/Desktop/logs/backups
	cp /etc/group /home/"$mainUser"/Desktop/logs/backups/
	cp /etc/passwd /home/"$mainUser"/Desktop/logs/backups/
	cp /etc/shadow /home/"$mainUser"/Desktop/logs/backups/
	touch /home/"$mainUser"/Desktop/logs/changelog.log
	chmod 777 /home/"$mainUser"/Desktop/logs/changelog.log
	echo "List of changes made by script:" >/home/"$mainUser"/Desktop/logs/changelog.log
	echo "- Backups folder created" >>/home/"$mainUser"/Desktop/logs/changelog.log
	echo "- Important files backed up" >>/home/"$mainUser"/Desktop/logs/changelog.log
	echo "Is MySQL a critical service on this machine (LAMP or otherwise)?"
	read -r sqlYN
	if [[ "$sqlYN" == "yes" ]]; then
		#install + config mysql
		apt-get install mysql-server -y -qq
		mv /etc/mysql/my.cnf /etc/mysql/my.cnf.bak
		mv /etc/mysql/debian.cnf /etc/mysql/debian.cnf.bak
		chown -R mysql:mysql /var/lib/mysql
		dpkg --configure -a
		ln -s /etc/mysql/mysql.conf.d /etc/mysql/conf.d
		mysqld --initialize --explicit_defaults_for_timestamp
		mysql_secure_installation
	elif [[ "$sqlYN" == "no" ]]; then
		ufw deny ms-sql-s
		ufw deny ms-sql-m
		ufw deny mysql
		ufw deny mysql-proxy
		apt-get purge mysql-server -y -qq
	fi
}

packages () { 
	echo "Updating apt"
	apt-get update --force-yes -qq 
	apt-get upgrade --force-yes -qq
	apt-get dist-upgrade --force-yes -qq 
	echo "- Package installer 'apt' updated (update, upgrade, dist-upgrade)" >>  /home/"$mainUser"/Desktop/changelog.log

	echo "#########Installing useful packages#########"
	echo "#########Firefox (Browser)#########"
	apt-get install firefox-esr --force-yes -qq 
	echo "#########RKHunter (AntiRootkit/antivirus)#########"
	apt-get install rkhunter --force-yes -qq
	echo "#########AppArmor (Kernel enhancer)#########"
	apt-get install apparmor --force-yes -qq
	apt-get install apparmor-profiles --force-yes -qq
	apt-get install apparmor-profiles-extra --force-yes -qq
	echo "#########IPTables (Network manager/Firewall)#########"
	apt-get install iptables --force-yes -qq
	echo "#########Lynis (system auditer)#########"
	apt-get install lynis --force-yes -qq
	echo "#########UFW (Firewall)#########"
	apt-get install ufw --force-yes -qq
	apt-get install gufw --force-yes -qq
	echo "#########ClamAV (Antivirus)#########"
	apt-get install libcanberra-gtk-module --force-yes -qq
	apt-get install clamav-daemon --force-yes -qq
	apt-get install clamav --force-yes -qq
	apt-get install clamtk --force-yes -qq
	echo "#########Libpam (password complexity enforcers)#########"
	apt-get install libpam-cracklib --force-yes -qq
	apt-get install libpam-tmpdir --force-yes -qq
	echo "#########Auditd (auditer)#########"
	apt-get install auditd --force-yes -qq
	echo "#########Tree (view all files on machine)#########"
	apt-get install tree --force-yes -qq
	echo "#########APT (APT package installer enchancements)#########"
	apt-get install apt-listchanges --force-yes -qq
	apt-get install apt-show-versions --force-yes -qq
	echo "#########Debian-Goodies (package assistant)#########"
	apt-get install debian-goodies --force-yes -qq
	echo "#########Debsecan (package vulnerability reporter)#########"
	apt-get install debsecan --force-yes -qq
	echo "#########Debsums (package verifier)#########"
	apt-get install debsums --force-yes -qq
	echo "#########Fail2Ban (Firewall)#########"
	apt-get install fail2ban --force-yes -qq
	echo "#########AIDE (file integrity checker)#########"
	apt-get install aide --force-yes -qq
	echo "#########Arpwatch (ethernet monitor)#########"
	apt-get install arpwatch --force-yes -qq
	echo "#########Unzip and zip (zip file manager)#########"
	apt-get install unzip --force-yes -qq
	apt-get install zip --force-yes -qq
	zip -r myzipbackup.zip ./* --exclude=access_log --exclude=tmp
	echo "#########dos2unix (Text file converter)#########"
	apt-get install dos2unix --force-yes -qq
	echo "#########unattended upgrades (linux updater)#########"
	apt-get install unattended-upgrades --force-yes -qq
	echo "#########LogWatch (Log watcher)#########"
	apt-get install logwatch --force-yes -qq
	apt-get install libdate-manip-perl --force-yes -qq
	echo "#########HardInfo (system info and benchmarks)#########"
	apt-get install hardinfo --force-yes -qq
	echo "#########nmap (network scanner and security monitor)#########"
	apt-get install nmap --force-yes -qq
	echo "*********Install VM tools?*********"
	read -r vmtoolsYN
	if [[ $vmtoolsYN == "yes" ]]; then
		apt-get install open-vm-tools --force-yes -qq
		echo "- Package open-vm-tools installed" >>/home/"$mainUser"/Desktop/logs/changelog.log
	elif [[ $vmtoolsYN == "exit" ]]; then
		exit 1
	fi
	apt-get install --reinstall coreutils --force-yes -qq
	echo "- Packages firefox, aide, arpwatch, unzip, zip, dos2unix, unattended-upgrades, debsecan, debsums, fail2ban, libpam-tmpdir, apt-get-listchanges, apt-get-show-versions, debian-goodies, apparmor, rkhunter, chkrootkit, iptables, portsentry, lynis, ufw, gufw, libpam-cracklib, auditd, tree, clamav, and clamtk installed; coreutils reinstalled" >>/home/"$mainUser"/Desktop/logs/changelog.log
	echo "Type anything to continue"
	read -r timeCheck
}

firewall() {
	echo "#########Configuring firewall (UFW)#########"
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
	ufw default deny
	ufw logging on
	ufw logging high
	echo "- Firewall configured (Firewall enabled, Ports 1337, 23, 2049, 515, 135, 137, 138, 139, 445, 69, 514, 161, 162, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, and 111 denied, Logging on and high)" >>/home/"$mainUser"/Desktop/logs/changelog.log
	echo "Type anything to continue"
	read -r timeCheck
}

services() {

	echo "*********Is this machine a LAMP server? (Linux Apache2 MySQL PHP)*********"
	read -r lampYN
	if [[ $lampYN == "yes" ]]; then
		apt-get purge nginx --force-yes -qq
		apt-get purge nginx-common --force-yes -qq
		apt-get purge nginx-core --force-yes -qq
		echo "- NGINX removed from the machine" >>/home/"$mainUser"/Desktop/logs/changelog.log
		echo "Type anything to continue (NGINX removed)"
		read -r timeCheck
		apt-get install apache2 --force-yes -qq
		apt-get install apache2-utils --force-yes -qq
		apt-get install libapache2-mod-evasive --force-yes -qq
		apt-get install libapache2-mod-security2 --force-yes -qq
		ufw allow in "Apache Full"
		ufw allow http
		ufw allow https
		systemctl restart apache2
		echo "####Configuring ufw for web servers####"
		cp /etc/ufw/before.rules /home/"$mainUser"/Desktop/logs/backups/
		sed -i '12s/$/\n/' /etc/ufw/before.rules
		sed -i '13s/.*/:ufw-http - [0:0]\n/' /etc/ufw/before.rules
		sed -i '14s/.*/:ufw-http-logdrop - [0:0]/' /etc/ufw/before.rules
		sed -i '76s/$/\n/' /etc/ufw/before.rules
		sed -i '77s/.*/### Start HTTP ###\n/' /etc/ufw/before.rules
		sed -i '78s/.*/\n/' /etc/ufw/before.rules
		sed -i '79s/.*/# Enter rule\n/' /etc/ufw/before.rules
		sed -i '80s/.*/-A ufw-before-input -p tcp --dport 80 -j ufw-http\n/' /etc/ufw/before.rules
		sed -i '81s/.*/-A ufw-before-input -p tcp --dport 443 -j ufw-http\n/' /etc/ufw/before.rules
		sed -i '82s/.*/\n/' /etc/ufw/before.rules
		sed -i '83s/.*/# Limit connections per Class C\n/' /etc/ufw/before.rules
		sed -i '84s/.*/-A ufw-http -p tcp --syn -m connlimit --connlimit-above 50 --connlimit-mask 24 -j ufw-http-logdrop\n/' /etc/ufw/before.rules
		sed -i '85s/.*/\n/' /etc/ufw/before.rules
		sed -i '86s/.*/# Limit connections per IP\n/' /etc/ufw/before.rules
		sed -i '87s/.*/-A ufw-http -m state --state NEW -m recent --name conn_per_ip --set\n/' /etc/ufw/before.rules
		sed -i '88s/.*/-A ufw-http -m state --state NEW -m recent --name conn_per_ip --update --seconds 10 --hitcount 20 -j ufw-http-logdrop\n/' /etc/ufw/before.rules
		sed -i '89s/.*/\n/' /etc/ufw/before.rules
		sed -i '90s/.*/# Limit packets per IP\n/' /etc/ufw/before.rules
		sed -i '91s/.*/-A ufw-http -m recent --name pack_per_ip --set\n/' /etc/ufw/before.rules
		sed -i '92s/.*/-A ufw-http -m recent --name pack_per_ip --update --seconds 1 --hitcount 20 -j ufw-http-logdrop\n/' /etc/ufw/before.rules
		sed -i '93s/.*/\n/' /etc/ufw/before.rules
		sed -i '94s/.*/# Finally accept\n/' /etc/ufw/before.rules
		sed -i '95s/.*/-A ufw-http -j ACCEPT\n/' /etc/ufw/before.rules
		sed -i '96s/.*/\n/' /etc/ufw/before.rules
		sed -i '97s/.*/# Log\n/' /etc/ufw/before.rules
		sed -i '98s/.*/-A ufw-http-logdrop -m limit --limit 3\/min --limit-burst 10 -j LOG --log-prefix \"[UFW HTTP DROP] \"\n/' /etc/ufw/before.rules
		sed -i '99s/.*/-A ufw-http-logdrop -j DROP\n/' /etc/ufw/before.rules
		sed -i '100s/.*/\n/' /etc/ufw/before.rules
		sed -i '101s/.*/### End HTTP ###\n/' /etc/ufw/before.rules
		sed -i '102s/.*/\n/' /etc/ufw/before.rules
		sed -i '103s/.*/-A INPUT -p icmp -m limit --limit 6\/s --limit-burst 1 -j ACCEPT\n/' /etc/ufw/before.rules
		sed -i '104s/.*/-A INPUT -p icmp -j DROP/' /etc/ufw/before.rules
		service apache2 restart
		echo "- UFW configured for use on a web server" >>/home/"$mainUser"/Desktop/logs/changelog.log
		echo "Type anything to continue"
		read -r timeCheck

		echo "####Configuring Apache2 config file####"
		sed -i '92s/.*/Timeout 100/' /etc/apache2/apache2.conf
		sed -i '98s/.*/KeepAlive On/' /etc/apache2/apache2.conf
		sed -i '126s/.*/HostnameLookups On/' /etc/apache2/apache2.conf
		sed -i '105s/.*/MaxKeepAliveRequests 75/' /etc/apache2/apache2.conf
		{
			echo "<IfModule mod_headers.c>"
			echo "Header always append X-Frame-Options SAMEORIGIN"
			echo "</IfModule>"
			echo "FileETag None"
			echo "TraceEnable off"
		} >>/etc/apache2/apache2.conf
		chown -R 755 /etc/apache2/bin /etc/apache2/conf
		chmod 511 /usr/sbin/apache2
		chmod 755 /var/log/apache2/
		chmod 755 /etc/apache2/conf/
		chmod 640 /etc/apache2/conf/*
		chgrp -R "$mainUser" /etc/apache2/conf
		chmod -R 755 /var/www
		/etc/init.d/apache2 restart
		echo "Type anything to continue"
		read -r timeCheck
		echo "- Apache2 installed, configured, and http(s) allowed" >>/home/"$mainUser"/Desktop/logs/changelog.log
		echo "Type anything to continue"
		read -r timeCheck
		echo "####Installing PHP####"
		apt-get install php --force-yes -qq
		apt-get install libapache2-mod-php --force-yes -qq
		apt-get install php-mysql --force-yes -qq
		sed -i '2s/.*/\o011DirectoryIndex index.php index.html index.cgi index.pl index.xhtml index.htm/' /etc/apache2/mods-enabled/dir.conf
		systemctl restart apache2
		echo "###Configuring php.ini####"
		cp /etc/php/7.0/apache2/php.ini /home/"$mainUser"/Desktop/logs/backups/
		{
			echo "safe_mode = On"
			echo "safe_mode_gid = On"
			echo "sql.safe_mode=On"
			echo "register_globals = Off"
		} >>/etc/php/7.0/apache2/php.ini
		sed -i '517s/.*/track_errors = Off/' /etc/php/7.0/apache2/php.ini
		sed -i '534s/.*/html_errors = Off/' /etc/php/7.0/apache2/php.ini
		sed -i '299s/.*/disable_functions = php_uname, getmyuid, getmypid, passthru, leak, listen, diskfreespace, tmpfile, link, ignore_user_abord, shell_exec, dl, set_time_limit, exec, system, highlight_file, source, show_source, fpaththru, virtual, posix_ctermid, posix_getcwd, posix_getegid, posix_geteuid, posix_getgid, posix_getgrgid, posix_getgrnam, posix_getgroups, posix_getlogin, posix_getpgid, posix_getpgrp, posix_getpid, posix, _getppid, posix_getpwnam, posix_getpwuid, posix_getrlimit, posix_getsid, posix_getuid, posix_isatty, posix_kill, posix_mkfifo, posix_setegid, posix_seteuid, posix_setgid, posix_setpgid, posix_setsid, posix_setuid, posix_times, posix_ttyname, posix_uname, proc_open, proc_close, proc_get_status, proc_nice, proc_terminate, phpinfo/' /etc/php/7.0/apache2/php.ini
		sed -i '820s/.*/allow_url_fopen = Off/' /etc/php/7.0/apache2/php.ini
		sed -i '824s/.*/allow_url_include = Off/' /etc/php/7.0/apache2/php.ini
		sed -i '805s/.*/upload_tmp_dir = \/var\/php_tmp/' /etc/php/7.0/apache2/php.ini
		sed -i '368s/.*/max_execution_time = 10/' /etc/php/7.0/apache2/php.ini
		sed -i '378s/.*/max_input_time = 30/' /etc/php/7.0/apache2/php.ini
		sed -i '389s/.*/memory_limit = 40M/' /etc/php/7.0/apache2/php.ini
		sed -i '656s/.*/post_max_size=1K/' /etc/php/7.0/apache2/php.ini
		sed -i '1397s/.*/session.cookie_httponly = 1/' /etc/php/7.0/apache2/php.ini
		echo "Type anything to continue"
		read -r  timeCheck
		service apache2 restart
		echo "- Configured PHP 7.0 for use on a web server" >>/home/"$mainUser"/Desktop/logs/changelog.log

		echo "*********Is openssh-server a critical service on this machine?*********"
		read -r sshYN
		if [[ $sshYN == "yes" ]]; then
			apt-get install ssh --force-yes -qq
			apt-get install openssh-server --force-yes -qq
			apt-get upgrade openssl libssl-dev --force-yes -qq
			apt-get-cache policy openssl libssl-dev
			echo "- Packages ssh and openssh-server installed and heartbleed bug fixed" >>/home/"$mainUser"/Desktop/logs/changelog.log

			echo "####Editing /etc/sshd/sshd_config####"
			cp /etc/ssh/sshd_config /home/"$mainUser"/Desktop/logs/backups/
			sed -i '13s/.*/Port 2222/' /etc/ssh/sshd_config
			sed -i '18s/.*/HostKey /etc/ssh/ssh_host_ed25519_key/' /etc/ssh/sshd_config
			sed -i '19s/.*/HostKey /etc/ssh/ssh_host_rsa_key/' /etc/ssh/sshd_config
			sed -i '20s/.*/#/' /etc/ssh/sshd_config
			sed -i '32s/.*/PermitRootLogin no/' /etc/ssh/sshd_config
			sed -i '87s/.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
			sed -i '100s/.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
			sed -i '101s/.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
			sed -i '99s/.*/Compression DELAYED/' /etc/ssh/sshd_config
			sed -i '27s/.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
			sed -i '34s/.*/MaxAuthTries 2/' /etc/ssh/sshd_config
			sed -i '35s/.*/MaxSessions 2/' /etc/ssh/sshd_config
			sed -i '95s/.*/TCPKeepAlive no/' /etc/ssh/sshd_config
			sed -i '89s/.*/X11Forwarding no/' /etc/ssh/sshd_config
			sed -i '86s/.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
			sed -i '94s/.*/PrintLastLog yes/' /etc/ssh/sshd_config
			sed -i '98s/.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
			sed -i '56s/.*/PasswordAuthentication no/' /etc/ssh/sshd_config
			sed -i '57s/.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
			sed -i '53s/.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
			sed -i '48s/.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
			sed -i '31s/.*/LoginGraceTime 120/' /etc/ssh/sshd_config
			sed -i '104s/.*/MaxStartups 2/' /etc/ssh/sshd_config
			sed -i '105s/.*/PermitTunnel no/' /etc/ssh/sshd_config
			sed -i '33s/.*/StrictModes yes/' /etc/ssh/sshd_config
			sed -i '61s/.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
			sed -i '64s/.*/KerberosAuthentication no/' /etc/ssh/sshd_config
			sed -i '70s/.*/GSSAPIAuthentication no/' /etc/ssh/sshd_config
			echo "- Configured /etc/ssh/sshd_config" >>/home/"$mainUser"/Desktop/logs/changelog.log

			echo "####Securing SSH keys####"
			mkdir -p /home/"$mainUser"/.ssh/
			chmod 700 /home/"$mainUser"/.ssh
			touch /home/"$mainUser"/.ssh/authorized_keys
			chmod 600 /home/"$mainUser"/.ssh/authorized_keys
			cd /home/"$mainUser"/.ssh || exit
			ssh-keygen -t rsa
			cd || exit
			echo "- Secured SSH keys" >>/home/"$mainUser"/Desktop/logs/changelog.log

			echo "####SSH port can accept SSH connections####"
			iptables -A INPUT -p tcp --dport ssh -j ACCEPT
			iptables -I INPUT -p tcp --dport 2222 -i eth0 -m state --state NEW -m recent --set
			iptables -I INPUT -p tcp --dport 2222 -i eth0 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP

			echo "#########Configuring fail2ban#########"
			cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
			touch /etc/fail2ban/jail.d/ssh.conf
			{
				echo "[sshd]"
				echo
				echo "enabled = true"
				echo "port = 22"
				echo "filter = sshd"
				echo "logpath = /var/log/auth.log"
				echo "maxretry = 3"
			} >>/etc/fail2ban/jail.d/ssh.conf
			service fail2ban restart

			service ssh restart
			echo "- SSH configured" >>/home/"$mainUser"/Desktop/logs/changelog.log
			echo "Type anything to continue"
			read -r timeCheck
		elif [[ $sshYN == "no" ]]; then
			apt-get purge openssh-server
			ufw deny ssh
			echo "Type anything to continue"
			read -r timeCheck
		elif [[ $sshYN == "exit" ]]; then
			exit 1
		fi

		echo "*********Is Samba a critical service on this machine?*********"
		read -r sambaYN
		if [[ $sambaYN == "yes" ]]; then
			ufw allow microsoft-ds
			ufw allow 137/udp
			ufw allow 138/udp
			ufw allow 139/tcp
			ufw allow 445/tcp
			apt-get install samba --force-yes -qq
			apt-get install system-config-samba --force-yes -qq
			apt-get install libpam-winbind --force-yes -qq
			sed -i '221s/.*/;   guest ok = no/' /etc/samba/smb.conf
			systemctl restart smbd.service nmbd.service
			echo "Type anything to continue"
			read -r timeCheck
			echo "- Samba installed and allowed" >>/home/"$mainUser"/Desktop/logs/changelog.log
		elif [[ $sambaYN == "no" ]]; then
			ufw deny netbios-ns
			ufw deny netbios-dgm
			ufw deny netbios-ssn
			ufw deny microsoft-ds
			apt-get purge samba --force-yes -qq
			echo "Type anything to continue"
			read -r timeCheck
			echo "- Samba uninstalled and blocked" >>/home/"$mainUser"/Desktop/logs/changelog.log
		fi

		echo "#########Is FTP a critical service on this machine?#########"
		read -r ftpYN
		if [[ $ftpYN == "yes" ]]; then
			apt-get install vsftpd
			cp /etc/vsftpd.conf /etc/vsftpd.conf_default
			cp /etc/vsftpd.conf /home/"$mainUser"/Desktop/logs/backups/
			service vsftpd enable
			service vsftpd start
			sed -i '25s/.*/anonymous_enable=NO/' /etc/vsftpd.conf
			sed -i '28s/.*/local_enable=YES/' /etc/vsftpd.conf
			sed -i '31s/.*/write_enable=YES/' /etc/vsftpd.conf
			sed -i '35s/.*/local_umask=022/' /etc/vsftpd.conf
			sed -i '40s/.*/anon_upload_enable=NO/' /etc/vsftpd.conf
			sed -i '44s/.*/anon_mkdir_write_enable=NO/' /etc/vsftpd.conf
			sed -i '48s/.*/dirmessage_enable=YES/' /etc/vsftpd.conf
			openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem
			sed -i '151s/.*/ssl_enable=YES' /etc/vsftpd.conf
			sed -i '114s/.*/chroot_local_user=YES/' /etc/vsftpd.conf
			sed -i '125s/.*/chroot_list_file=/etc/vsftpd.chroot_list/' /etc/vsftpd.conf
			{
				echo "rsa_cert_file=/etc/ssl/private/vsftpd.pem"
				echo "rsa_private_key_file=/etc/ssl/private/vsftpd.pem"
				echo "allow_anon_ssl=NO"
				echo "force_local_data_ssl=YES"
				echo "force_local_logins_ssl=YES"
				echo "ssl_tlsv1=YES"
				echo "ssl_sslv2=NO"
				echo "ssl_sslv3=NO"
				echo "require_ssl_reuse=NO"
				echo "ssl_ciphers=HIGH"
				echo "pasv_min_port=40000"
				echo "pasv_max_port=50000"
			} >>/etc/vsftpd.conf
			mkdir /srv/ftp/new_location
			usermod –d /srv/ftp/new_location ftp
			systemctl restart vsftpd.service
			ufw allow 20/tcp
			ufw allow 21/tcp
			ufw allow 40000:50000/tcp
			ufw allow 990/tcp
			ufw allow ftp
			ufw allow sftp
			ufw allow saft
			ufw allow ftps-data
			ufw allow ftps
			service vsftpd restart
			echo "- FTP installed and allowed" >>/home/"$mainUser"/Desktop/logs/changelog.log
			echo "Type anything to continue"
			read -r timeCheck
		elif [[ $ftpYN == "no" ]]; then
			service vsftpd stop
			ufw deny ftp
			ufw deny sftp
			ufw deny saft
			ufw deny ftps-data
			ufw deny ftps
			apt-get purge vsftpd --force-yes -qq
			echo "- FTP uninstalled and blocked" >>/home/"$mainUser"/Desktop/logs/changelog.log
			echo "Type anything to continue"
			read -r timeCheck
		fi

		echo "#########Is Telnet a critical service on this machine?#########"
		read -r telnetYN
		if [[ $telnetYN == "yes" ]]; then
			ufw allow telnet
			ufw allow rtelnet
			ufw allow telnets
			echo "- Telnet allowed" >>/home/"$mainUser"/Desktop/logs/changelog.log
		elif [[ $telnetYN == "no" ]]; then
			service telnet stop
			ufw deny telnet
			ufw deny rtelnet
			ufw deny telnets
			apt-get purge telnet --force-yes -qq
			apt-get purge telnetd --force-yes -qq
			apt-get purge inetutils-telnetd --force-yes -qq
			apt-get purge telnetd-ssl --force-yes -qq
			apt-get purge vsftpd --force-yes -qq
			echo "- Telnet uninstalled and blocked" >>/home/"$mainUser"/Desktop/logs/changelog.log
			echo "Type anything to continue"
			read -r timeCheck
		fi

		echo "#########Is this machine a web server?#########"
		read -r webYN
		if [[ $webYN == "yes" ]]; then
			echo "*********Apache2 or NGINX? (If unsure, choose Apache2) (Case sensitive)*********"
			read -r webserviceYN
			if [[ $webserviceYN == "NGINX" ]]; then
				apt-get purge apache2 --force-yes -qq
				apt-get purge apache2-bin --force-yes -qq
				apt-get purge apache2-utils --force-yes -qq
				apt-get purge libapache2-mod-evasive --force-yes -qq
				apt-get purge libapache2-mod-security2 --force-yes -qq
				echo "- Apache2 removed" >>/home/"$mainUser"/Desktop/logs/changelog.log
				apt-get install nginx --force-yes -qq
				ufw allow http
				ufw allow https
				echo "- NGINX installed" >>/home/"$mainUser"/Desktop/logs/changelog.log
				echo "Type anything to continue"
				read -r timeCheck
			elif [[ $webserviceYN == "Apache2" ]]; then
				apt-get purge nginx --force-yes -qq
				apt-get purge nginx-common --force-yes -qq
				apt-get purge nginx-core --force-yes -qq
				echo "- NGINX removed from the machine" >>/home/"$mainUser"/Desktop/logs/changelog.log
				apt-get install apache2 --force-yes -qq
				apt-get install apache2-utils --force-yes -qq
				apt-get install libapache2-mod-evasive --force-yes -qq
				apt-get install libapache2-mod-security2 --force-yes -qq
				echo "Type anything to continue"
				read -r timeCheck
				echo "*********Is PHP used on this web server?*********"
				read -r phpYN
				if [[ $phpYN == "yes" ]]; then
					echo "####Installing PHP 7.2####"
					apt-get install php7.2 --force-yes -qq
					echo "###Configuring php.ini####"
					cp /etc/php/7.2/apache2/php.ini /home/"$mainUser"/Desktop/logs/backups/
					{
						echo "safe_mode = On"
						"safe_mode_gid = On"
						"sql.safe_mode=On"
						"register_globals = Off"
					} >>/etc/php/7.2/apache2/php.ini
					sed -i '517s/.*/track_errors = Off/' /etc/php/7.0/apache2/php.ini
					sed -i '534s/.*/html_errors = Off/' /etc/php/7.0/apache2/php.ini
					sed -i '299s/.*/disable_functions = php_uname, getmyuid, getmypid, passthru, leak, listen, diskfreespace, tmpfile, link, ignore_user_abord, shell_exec, dl, set_time_limit, exec, system, highlight_file, source, show_source, fpaththru, virtual, posix_ctermid, posix_getcwd, posix_getegid, posix_geteuid, posix_getgid, posix_getgrgid, posix_getgrnam, posix_getgroups, posix_getlogin, posix_getpgid, posix_getpgrp, posix_getpid, posix, _getppid, posix_getpwnam, posix_getpwuid, posix_getrlimit, posix_getsid, posix_getuid, posix_isatty, posix_kill, posix_mkfifo, posix_setegid, posix_seteuid, posix_setgid, posix_setpgid, posix_setsid, posix_setuid, posix_times, posix_ttyname, posix_uname, proc_open, proc_close, proc_get_status, proc_nice, proc_terminate, phpinfo/' /etc/php/7.0/apache2/php.ini
					sed -i '820s/.*/allow_url_fopen = Off/' /etc/php/7.0/apache2/php.ini
					sed -i '824s/.*/allow_url_include = Off/' /etc/php/7.0/apache2/php.ini
					sed -i '805s/.*/upload_tmp_dir = \/var\/php_tmp/' /etc/php/7.0/apache2/php.ini
					sed -i '368s/.*/max_execution_time = 10/' /etc/php/7.0/apache2/php.ini
					sed -i '378s/.*/max_input_time = 30/' /etc/php/7.0/apache2/php.ini
					sed -i '389s/.*/memory_limit = 40M/' /etc/php/7.0/apache2/php.ini
					sed -i '656s/.*/post_max_size=1K/' /etc/php/7.0/apache2/php.ini
					sed -i '1397s/.*/session.cookie_httponly = 1/' /etc/php/7.0/apache2/php.ini
					service apache2 restart
					echo "- Configured PHP 7.2 for use on a web server" >>/home/"$mainUser"/Desktop/logs/changelog.log
					echo "Type anything to continue"
					read -r timeCheck
				fi

				ufw allow http
				ufw allow https
				systemctl restart apache2
				echo "####Configuring ufw for web servers####"
				cp /etc/ufw/before.rules /home/"$mainUser"/Desktop/logs/backups/
				sed -i '12s/$/\n/' /etc/ufw/before.rules
				sed -i '13s/.*/:ufw-http - [0:0]\n/' /etc/ufw/before.rules
				sed -i '14s/.*/:ufw-http-logdrop - [0:0]/' /etc/ufw/before.rules
				sed -i '76s/$/\n/' /etc/ufw/before.rules
				sed -i '77s/.*/### Start HTTP ###\n/' /etc/ufw/before.rules
				sed -i '78s/.*/\n/' /etc/ufw/before.rules
				sed -i '79s/.*/# Enter rule\n/' /etc/ufw/before.rules
				sed -i '80s/.*/-A ufw-before-input -p tcp --dport 80 -j ufw-http\n/' /etc/ufw/before.rules
				sed -i '81s/.*/-A ufw-before-input -p tcp --dport 443 -j ufw-http\n/' /etc/ufw/before.rules
				sed -i '82s/.*/\n/' /etc/ufw/before.rules
				sed -i '83s/.*/# Limit connections per Class C\n/' /etc/ufw/before.rules
				sed -i '84s/.*/-A ufw-http -p tcp --syn -m connlimit --connlimit-above 50 --connlimit-mask 24 -j ufw-http-logdrop\n/' /etc/ufw/before.rules
				sed -i '85s/.*/\n/' /etc/ufw/before.rules
				sed -i '86s/.*/# Limit connections per IP\n/' /etc/ufw/before.rules
				sed -i '87s/.*/-A ufw-http -m state --state NEW -m recent --name conn_per_ip --set\n/' /etc/ufw/before.rules
				sed -i '88s/.*/-A ufw-http -m state --state NEW -m recent --name conn_per_ip --update --seconds 10 --hitcount 20 -j ufw-http-logdrop\n/' /etc/ufw/before.rules
				sed -i '89s/.*/\n/' /etc/ufw/before.rules
				sed -i '90s/.*/# Limit packets per IP\n/' /etc/ufw/before.rules
				sed -i '91s/.*/-A ufw-http -m recent --name pack_per_ip --set\n/' /etc/ufw/before.rules
				sed -i '92s/.*/-A ufw-http -m recent --name pack_per_ip --update --seconds 1 --hitcount 20 -j ufw-http-logdrop\n/' /etc/ufw/before.rules
				sed -i '93s/.*/\n/' /etc/ufw/before.rules
				sed -i '94s/.*/# Finally accept\n/' /etc/ufw/before.rules
				sed -i '95s/.*/-A ufw-http -j ACCEPT\n/' /etc/ufw/before.rules
				sed -i '96s/.*/\n/' /etc/ufw/before.rules
				sed -i '97s/.*/# Log\n/' /etc/ufw/before.rules
				sed -i '98s/.*/-A ufw-http-logdrop -m limit --limit 3\/min --limit-burst 10 -j LOG --log-prefix \"[UFW HTTP DROP] \"\n/' /etc/ufw/before.rules
				sed -i '99s/.*/-A ufw-http-logdrop -j DROP\n/' /etc/ufw/before.rules
				sed -i '100s/.*/\n/' /etc/ufw/before.rules
				sed -i '101s/.*/### End HTTP ###\n/' /etc/ufw/before.rules
				sed -i '102s/.*/\n/' /etc/ufw/before.rules
				sed -i '103s/.*/-A INPUT -p icmp -m limit --limit 6\/s --limit-burst 1 -j ACCEPT\n/' /etc/ufw/before.rules
				sed -i '104s/.*/-A INPUT -p icmp -j DROP/' /etc/ufw/before.rules
				service apache2 restart
				echo "- UFW configured for use on a web server" >>/home/"$mainUser"/Desktop/logs/changelog.log
				echo "Type anything to continue"
				read -r timeCheck
				echo "####Configuring Apache2 config file####"
				sed -i '92s/.*/Timeout 100/' /etc/apache2/apache2.conf
				sed -i '98s/.*/KeepAlive On/' /etc/apache2/apache2.conf
				sed -i '126s/.*/HostnameLookups On/' /etc/apache2/apache2.conf
				sed -i '105s/.*/MaxKeepAliveRequests 75/' /etc/apache2/apache2.conf
				{
					echo "<IfModule mod_headers.c>"
					"Header always append X-Frame-Options SAMEORIGIN"
					"</IfModule>"
					"FileETag None"
					"TraceEnable off"
				} >>/etc/apache2/apache2.conf
				chown -R 750 /etc/apache2/bin /etc/apache2/conf
				chmod 511 /usr/sbin/apache2
				chmod 750 /var/log/apache2/
				chmod 750 /etc/apache2/conf/
				chmod 640 /etc/apache2/conf/*
				chgrp -R "$mainUser" /etc/apache2/conf
				chmod -R 444 /var/www
				/etc/init.d/apache2 restart
				echo "- Apache2 installed, configured, and http(s) allowed" >>/home/"$mainUser"/Desktop/logs/changelog.log
				echo "Type anything to continue"
				read -r timeCheck
			fi
		elif [[ $webYN == "no" ]]; then
			apt-get purge nginx --force-yes -qq
			apt-get purge nginx-common --force-yes -qq
			apt-get purge nginx-core --force-yes -qq
			echo "- NGINX removed from the machine" >>/home/"$mainUser"/Desktop/logs/changelog.log
			ufw deny http
			ufw deny https
			apt-get purge apache2 --force-yes -qq
			apt-get purge apache2-bin --force-yes -qq
			apt-get purge apache2-utils --force-yes -qq
			apt-get purge libapache2-mod-evasive --force-yes -qq
			apt-get purge libapache2-mod-security2 --force-yes -qq
			rm -r /var/www/*
			echo "- Apache2 removed and http(s) blocked" >>/home/"$mainUser"/Desktop/logs/changelog.log
			echo "Type anything to continue"
			read -r timeCheck
		fi

		echo "*********Is this machine an email server?*********"
		read -r emailYN
		if [[ $emailYN == "yes" ]]; then
			ufw allow smtp
			ufw allow pop2
			ufw allow pop3
			ufw allow imap2
			ufw allow imaps
			ufw allow pop3s
			apt-get install postfix --force-yes -qq
			usermod -aG mail "$mainUser"
			usermod -aG mail "$(whoami)"

			echo "#########Starting Postfix#########"
			cp /usr/share/postfix/main.cf.debian /etc/postfix/main.cf
			postconf -e disable_vrfy_command=yes
			service postfix reload
			chmod 755 /etc/postfix
			chmod 644 /etc/postfix/*.cf
			chmod 755 /etc/postfix/postfix-script*
			chmod 755 /var/spool/postfix
			chown root:root /var/log/mail*
			chmod 600 /var/log/mail*
			service postfix restart
			echo "- Postfix started" >>/home/"$mainUser"/Desktop/logs/changelog.log

			apt-get install mailutils
			service postifx restart
			echo "Type anything to continue"
			read -r timeCheck
		elif [[ $emailYN == "no" ]]; then
			ufw deny smtp
			ufw deny pop2
			ufw deny pop3
			ufw deny imap2
			ufw deny imaps
			ufw deny pop3s
			apt-get purge postfix --force-yes -qq
			apt-get purge dovecot-* --force-yes -qq
			echo "Type anything to continue"
			read -r timeCheck
		fi

		echo "*********Is this machine a DNS server?*********"
		read -r DNSYN
		if [[ $DNSYN == "yes" ]]; then
			apt-get install bind9
			named-checkzone test.com. /var/cache/bind/db.test
			{
				echo "zone \"test.com.\" {"
				echo "\o011type master;"
				echo "\o011file \"db.test\";"
				echo "};"
			} >>/etc/bind/named.conf.default-zones
			systemctl restart bind9
			echo "Type anything to continue"
			read -r timeCheck
		fi
	fi
}


general_config() {

	echo "*********Should root user be locked?*********"
	read -r lockRootYN
	if [[ $lockRootYN == yes ]]; then
		passwd -l root
		echo "- Root account locked. Use 'usermod -U root' to unlock it"
	fi

	echo "#########Denying outside packets#########"
	iptables -A INPUT -p all -s localhost -i eth0 -j DROP
	echo "- Denied outside packets" >>/home/"$mainUser"/Desktop/logs/changelog.log

	echo "#########Enabling auditing#########"
	auditctl -e 1
	echo "- Auditing enabled with auditd (can be configured in /etc/audit/auditd.conf)" >>/home/"$mainUser"/Desktop/logs/changelog.log

	echo "#########Disabling reboot with Ctrl-Alt-Del#########"
	systemctl mask ctrl-alt-del.target
	systemctl daemon-reload
	echo "- Disabled reboot with Ctrl-Alt " >>/home/"$mainUser"/Desktop/logs/changelog.log

	echo "#########Securing important files with chmod#########"
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
	echo "- /var/log, /etc/passwd/, /etc/shadow, /etc/groups/, /etc/cups*, /etc/rc*, /etc/init.d*, /etc/profile, /etc/hosts.allow, /etc/sysctl.conf, /bin/su, /bin/ping, /sbin/ifconfig, /usr/bin/w, /usr/bin/who, /usr/bin/locate, and /usr/bin/whereis permissions set" >>/home/"$mainUser"/Desktop/logs/changelog.log

	#echo "Configuring AIDE"
	#aideinit
	#cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
	#update-aide.conf
	#cp /var/lib/aide/aide.conf.autogenerated /etc/aide/aide.conf

	echo "#########Starting arpwatch#########"
	/etc/init.d/arpwatch start
	arpwatch
	echo "- Arpwatch started" >>/home/"$mainUser"/Desktop/logs/changelog.log

	echo "#########Backing up and clearing crontab#########"
	touch /home/"$mainUser"/Desktop/logs/backups/crontab-backup
	crontab -l >/home/"$mainUser"/Desktop/logs/backups/crontab-backup
	crontab -r
	echo "- Crontab backed up and cleared" >>/home/"$mainUser"/Desktop/logs/changelog.log

	echo "#########Enabling unattended upgrades#########"
	dpkg-reconfigure -plow unattended-upgrades

	echo "#########Configuring swapfile#########"
	swapon -s
	echo "*********Is there a swap file present?*********"
	read -r swapYN
	if [[ $swapYN == "yes" ]]; then
		echo 0 | tee /proc/sys/vm/swappiness
		echo vm.swappiness = 0 | tee -a /etc/sysctl.conf
		chown root:root /swapfile
		chmod 0600 /swapfile
	elif [[ $swapYN == "no" ]]; then
		fallocate -l 4G /swapfile
		chown root:root /swapfile
		chmod 0600 /swapfile
		mkswap /swapfile
		swapon /swapfile
		swapon -s
	fi
	echo "Type anything to continue"
	read -r timeCheck
}

hacking_tools () {
	
	echo "Updating packages"
	apt-get update  
	
	echo "Removing netcat"
	apt-get purge netcat --force-yes -qq  
	apt-get purge netcat-openbsd --force-yes -qq  
	apt-get purge netcat-traditional --force-yes -qq  
	apt-get purge socat --force-yes -qq    
	apt-get purge socket --force-yes -qq  
	apt-get purge sbd --force-yes -qq  
	rm /usr/bin/nc

	echo "Removing John the Ripper"
	apt-get purge john --force-yes -qq  
	apt-get purge john-data --force-yes -qq  
 
	echo "Removing Hydra"
	apt-get purge hydra --force-yes -qq  
	apt-get purge hydra-gtk --force-yes -qq  
 
	echo "Removing Aircrack-NG"
	apt-get purge aircrack-ng --force-yes -qq  

	echo "Removing FCrackZIP"
	apt-get purge fcrackzip --force-yes -qq  

	echo "Removing LCrack"
	apt-get purge lcrack --force-yes -qq  

	echo "Removing OphCrack"
	apt-get purge ophcrack --force-yes -qq  
	apt-get purge ophcrack-cli --force-yes -qq  

	echo "Removing Pyrit"
	apt-get purge pyrit --force-yes -qq  

	echo "Removing RARCrack"
	apt-get purge rarcrack --force-yes -qq  

	echo "Removing SipCrack"
	apt-get purge sipcrack --force-yes -qq  

	echo "Removing Zeitgeist"
	apt-get purge zeitgeist-core --force-yes -qq  
	apt-get purge zeitgeist-datahub --force-yes -qq  
	apt-get purge python-zeitgeist --force-yes -qq  
	apt-get purge zeitgeist --force-yes -qq  

	echo "Removing NFS"
	apt-get purge nfs-kernel-server --force-yes -qq  
	apt-get purge nfs-common --force-yes -qq  
	apt-get purge portmap --force-yes -qq  
	apt-get purge rpcbind --force-yes -qq  
	apt-get purge autofs --force-yes -qq  

	echo "Removing VNC"
	apt-get purge vnc4server --force-yes -qq  
	apt-get purge vncsnapshot --force-yes -qq  
 
	echo "Removing Wireshark"
	apt-get purge wireshark --force-yes -qq  

	echo "Removing Hashcat"
	apt-get purge hashcat --force-yes -qq  
	apt-get purge hashcat-data --force-yes -qq  
 
	echo "Removing CeWl"
	apt-get purge cewl --force-yes -qq  

	echo "Removing Medusa"
	apt-get purge medusa --force-yes -qq  

	echo "Removing Wfuzz"
	apt-get purge wfuzz --force-yes -qq  

	echo "Removing nmap"
	apt-get purge nmap --force-yes -qq  

	echo "Removing SQLMap"
	apt-get purge sqlmap  

	echo "Removing packages that can potentially contribute to backdoors"
	apt-get purge backdoor-factory --force-yes -qq  
	apt-get purge shellinabox --force-yes -qq  

	echo "Cleaning up Packages"
	apt-get autoremove --force-yes -qq  
	apt-get autoclean --force-yes -qq  
	apt-get clean --force-yes -qq  
	echo "- Removed netcat, CeWl, nmap, Medusa, Wfuzz, Hashcat, John the Ripper, Hydra, Aircrack-NG, FCrackZIP, LCrack, OphCrack, Pyrit, rarcrack, SipCrack, Zeitgeist, NFS, VNC, and cleaned up packages" >>  /home/"$mainUser"/Desktop/changelog.log

}

file_config () {

	echo "Securing /etc/rc.local"
	echo > /etc/rc.local
	echo "exit 0" > /etc/rc.local
	echo "- /etc/rc.local secured" >>  /home/"$mainUser"/Desktop/changelog.log

	echo "Editing /etc/login.defs"
	cp /etc/login.defs  /home/"$mainUser"/Desktop/backups/
	sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
	sed -i '161s/.*/PASS_MIN_DAYS\o0117/' /etc/login.defs
	sed -i '162s/.*/PASS_WARN_AGE\o01114/' /etc/login.defs
	sed -i '151s/.*/UMASK\o011\o011027/' /etc/login.defs
	echo "- /etc/login.defs configured (Min days 7, Max days 30, Warn age 14, umask higher perms)" >>  /home/"$mainUser"/Desktop/changelog.log

	echo "Editing /etc/pam.d/common-password"
	cp /etc/pam.d/common-password  /home/"$mainUser"/Desktop/backups/
	sed -i '26s/.*/password\o011[success=1 default=ignore]\o011pam_unix.so obscure pam_unix.so obscure use_authtok try_first_pass remember=5 minlen=8/' /etc/pam.d/common-password
	sed -i '25s/.*/password\o011requisite\o011\o011\o011pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
	echo "- /etc/pam.d/common-password edited (remember=5, minlen=8, complexity requirements)" >>  /home/"$mainUser"/Desktop/changelog.log

	echo "Setting account lockout policy"
	cp /etc/pam.d/common-auth  /home/"$mainUser"/Desktop/backups/
	sed -i '16s/.*/# here are the per-package modules (the "Primary" block)\n/' /etc/pam.d/common-auth
	sed -i '17s/.*/auth\o011required\o011\o011\o011pam_tally2.so onerr=fail deny=5 unlock_time=1800 audit/' /etc/pam.d/common-auth
	echo "- Account lockout policy set in /etc/pam.d/common-auth" >>  /home/"$mainUser"/Desktop/changelog.log

	echo "Securing Shared Memory"
	cp /etc/fstab  /home/"$mainUser"/Desktop/backups/
	mount -o remount,noexec,nosuid /dev/shm
	echo "- Shared memory secured in  /etc/fstab" >>  /home/"$mainUser"/Desktop/changelog.log

	echo "Configuring rkhunter to allow checking for updates"
	cp /etc/rkhunter.conf  /home/"$mainUser"/Desktop/backups
	sed -i '104s/.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
	sed -i '118s/.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
	sed -i '1108s/.*/WEB_CMD=""/' /etc/rkhunter.conf
	echo "- Configured /etc/rkhunter.conf to allow for checking for updates" >>  /home/"$mainUser"/Desktop/changelog.log
	
	echo "Configuring /etc/sysctl.conf"
	cp /etc/sysctl.conf  /home/"$mainUser"/Desktop/backups/
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
	echo "- /etc/sysctl.conf configured (basic)" >>  /home/"$mainUser"/Desktop/changelog.log

}

media_files() {

	echo "#########Logging the fire directories of media files on the machine#########"
	touch /home/"$mainUser"/Desktop/logs/media_files.log
	chmod 777 /home/"$mainUser"/Desktop/logs/media_files.log
	{
		echo "Most common types of media files:"
		find / -name "*.midi"
		find / -name "*.mid"
		find / -name "*.mp3"
		find / -name "*.ogg" ! -path '*/snap/*' ! -path '*/usr/share/*'
		find / -name "*.wav" ! -path '*/usr/share/*' ! -path '*/usr/lib/*'
		find / -name "*.mov"
		find / -name "*.wmv"
		find / -name "*.mp4"
		find / -name "*.avi"
		find / -name "*.swf"
		find / -name "*.ico" ! -path '*/usr/share/*'
		find / -name "*.svg" ! -path '*/var/lib/*' ! -path '*/etc/alternatives/*' ! -path '*/snap/*' ! -path '*/usr/lib/*' ! -path '*/usr/share/*'
		find / -name "*.gif" ! -path '*/usr/lib/*' ! -path '*/usr/share/*'
		find / -name "*.jpeg"
		find / -name "*.jpg" ! -path '*/usr/share/*' ! -path '*/snap/*' ! -path '*/usr/lib/*' ! -path "*/home/$mainUser/.cache/*"
		find / -name "*.png" ! -path '*/etc/alternatives/*' ! -path '*/snap/*' ! -path '*/usr/lib/*' ! -path '*/usr/share/*' ! -path '*/var/lib/*' ! -path "*/home/$mainUser/.cache/*"

		echo
		echo "PHP files:"
		find / -name "*.php" ! -path '*/var/cache/*'
		find / -name "*.php3"
		find / -name "*.php4"
		find / -name "*.phtml"
		find / -name "*.phps"
		find / -name "*.phpt"
		find / -name "*.php5"

		echo
		echo "Script files:"
		find / -name "*.sh" ! -path '*/usr/libreoffice/*' ! -path '*/snap/*' ! -path '*/usr/bin/*' ! -path '*/usr/lib/*' ! -path '*/usr/share/*' ! -path '*/usr/src/*' ! -path '*/lib/*' ! -path '*/boot/*' ! -path '*/etc/profile.d/*' ! -path '*/etc/gdm3/*' ! -path '*/etc/acpi/*' ! -path '*/etc/wpa_supplicant/*' ! -path '*/etc/init.d/*' ! -path '*/etc/console-setup/*'
		find / -name "*.bash" ! -path '*/usr/share/*'
		find / -name "*.bsh"
		find / -name "*.csh" ! -path '*/usr/share/*' ! -path '*/snap/*' ! -path '*/usr/lib/*'
		find / -name "*.bash_profile"
		find / -name "*.profile" ! -path '*/snap/*' ! -path '*/usr/share/*' ! -path '*/usr/src/*'
		find / -name "*.bashrc" ! -path '*/snap/*' ! -path '*/usr/share/*'
		find / -name "*.zsh"
		find / -name "*.ksh"
		find / -name "*.cc" ! -path '*/usr/src/*'
		find / -name "*.startx"
		find / -name "*.bat" ! -path '*/usr/share/*'
		find / -name "*.cmd" ! -path '*/usr/src/*'
		find / -name "*.nt"
		find / -name "*.asp" ! -path '*/usr/lib/*'
		find / -name "*.vb"
		find / -name "*.vbs"
		find / -name "*.tab" ! -path '*/snap/*' ! -path '*/usr/share/*' ! -path '*/run/*'
		find / -name "*.spf"
		find / -name "*.rc" ! -path '*/snap/*' ! -path '*/usr/share/*'
		find / -name "*.reg"
		find / -name "*.py" ! -path '*/snap/*' ! -path '*/usr/lib/*' ! -path '*/usr/share/*' ! -path '*/usr/src/*'
		find / -name "*.ps1"
		find / -name "*.psm1"

		echo
		echo "Audio:"
		find / -name "*.mod" ! -path '*/usr/share/*' ! -path '*/usr/lib/*' ! -path '*/boot/*'
		find / -name "*.mp2"
		find / -name "*.mpa"
		find / -name "*.abs"
		find / -name "*.mpega"
		find / -name "*.au"
		find / -name "*.snd"
		find / -name "*.aiff"
		find / -name "*.aif"
		find / -name "*.sid"
		find / -name "*.flac"

		echo
		echo "Video:"
		find / -name "*.mpeg"
		find / -name "*.mpg" ! -path '*/lib/*'
		find / -name "*.mpe"
		find / -name "*.dl"
		find / -name "*.movie"
		find / -name "*.movi"
		find / -name "*.mv"
		find / -name "*.iff"
		find / -name "*.anim5"
		find / -name "*.anim3"
		find / -name "*.anim7"
		find / -name "*.vfw"
		find / -name "*.avx"
		find / -name "*.fli"
		find / -name "*.flc"
		find / -name "*.qt"
		find / -name "*.spl"
		find / -name "*.swf"
		find / -name "*.dcr"
		find / -name "*.dir" ! -path '*/snap/*' ! -path '*/usr/share/*'
		find / -name "*.dxr"
		find / -name "*.rpm"
		find / -name "*.rm"
		find / -name "*.smi"
		find / -name "*.ra"
		find / -name "*.ram"
		find / -name "*.rv"
		find / -name "*.asf"
		find / -name "*.asx"
		find / -name "*.wma"
		find / -name "*.wax"
		find / -name "*.wmx"
		find / -name "*.3gp"
		find / -name "*.flv"
		find / -name "*.m4v"

		echo
		echo "Images:"
		find / -name "*.tiff"
		find / -name "*.tif"
		find / -name "*.rs"
		find / -name "*.rgb"
		find / -name "*.xwd"
		find / -name "*.xpm" ! -path '*/snap/*' ! -path '*/usr/share/*'
		find / -name "*.ppm" ! -path '*/usr/share/*'
		find / -name "*.pbm"
		find / -name "*.pgm"
		find / -name "*.pcx"
		find / -name "*.svgz" ! -path '*/usr/share/*'
		find / -name "*.im1"
		find / -name "*.jpe"

	} >>/home/"$mainUser"/Desktop/logs/media_files.log
	echo "Type anything to continue"
	read -r timeCheck
}

user_auditing() {
	touch /home/"$mainUser"/Desktop/logs/userchangelog.log
	chmod 777 /home/"$mainUser"/Desktop/logs/userchangelog.log

	echo "*********Please enter a list of all authorized *administrators* on the machine (as stated on the README) separated by spaces*********"
	read -r authAdminList
	IFS=' ' read -r -a authAdmins <<<"$authAdminList"

	echo "Authorized Administrators supposed to be on the system:" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	for item in "${authAdmins[@]}"; do
		echo "$item" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	done

	echo "*********Please enter a list of all authorized users on the machine (as stated on the README) separated by spaces*********"
	read -r authGenUserList
	IFS=' ' read -r -a authGenUsers <<<"$authGenUserList"

	echo >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	echo "Authorized Standard Users supposed to be on the system:" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	for item in "${authGenUsers[@]}"; do
		echo "$item" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	done

	authUserList="${authAdminList} ${authGenUserList}"
	authUsers=("${authAdmins[@]}" "${authGenUsers[@]}")

	currentUserList=$(eval getent passwd "{$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)}" | cut -d: -f1 | tr '\n' ' ')
	IFS=' ' read -r -a currentUsers <<<"$currentUserList"

	echo >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	echo "Users without passwords given passwords:" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	for item in "${currentUsers[@]}"; do
		if [[ $(grep "${item}" /etc/shadow) != *":$"* ]]; then
			echo "####Setting a new password for ${item}####"
			passwd "$item"
			echo "$item" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
		fi
	done

	echo >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	echo "Current users on the system:" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	for item in "${currentUsers[@]}"; do
		echo "$item" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	done

	echo >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	echo "Users deleted off the system:" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	for item in "${currentUsers[@]}"; do
		if [[ "$authUserList" != *"$item"* ]]; then
			echo "${item}" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
			echo "####Removing user ${item} from system####"
			deluser --remove-home "${item}"
		fi
	done

	echo >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	echo "Users added to the system:" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	for item in "${authUsers[@]}"; do
		if [[ "$currentUserList" != *"$item"* ]]; then
			echo "${item}" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
			echo "####Adding user ${item}####"
			adduser "${item}"
		fi
	done

	echo >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	echo "Authorized admins given sudo permissions:" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	for item in "${authAdmins[@]}"; do
		if [[ "$(groups "${item}")" != *"sudo"* ]]; then
			echo "${item}" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
			usermod -aG sudo "${item}"
		fi
	done

	echo >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	echo "Authorized standard users stripped of sudo permissions:" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	for item in "${authGenUsers[@]}"; do
		if [[ "$(groups "${item}")" == *"sudo"* ]]; then
			echo "${item}" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
			gpasswd -d "${item}" sudo
		fi
	done

	for item in "${authGenUsers[@]}"; do
		usermod --shell /usr/sbin/nologin "${item}"
	done
	echo "All standard users are now in the 'NoLogin' Shell" >>/home/"$mainUser"/Desktop/logs/userchangelog.log

	echo "- Users auditing completed. Please check inside the 'userchangelog.log' file on your desktop for more information." >>/home/"$mainUser"/Desktop/logs/changelog.log

	rootUserList=$(grep :0: /etc/passwd | tr '\n' ' ')
	IFS=' ' read -r -a rootUsers <<<"$rootUserList"
	echo >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	echo "All current root users on the machine (should only be 'root')" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	for thing in "${rootUsers[@]}"; do
		echo "${thing%%:*}" >>/home/"$mainUser"/Desktop/logs/userchangelog.log
	done

	for item in "${authUsers[@]}"; do
		touch /home/"$mainUser"/Desktop/logs/backups/crontab-backup
		crontab -u "$item" -l >home/"$mainUser"/Desktop/logs/backups/crontab-backup
		crontab -u "$item" -r
	done
	echo "- Cleared crontab for all users" >>/home/"$mainUser"/Desktop/logs/changelog.log
	echo "Type anything to continue"
	read -r timeCheck

}

second_time_failsafe() {

	failYN=""
	while [ "$failYN" != "exit" ]; do

		echo "*********Which part of the script would you like to redo? (all, packages, firewall, services, hacking_tools, general_config, file_config, user_auditing, media_files) (type exit to leave)*********"
		read -r failYN
		if [[ $failYN == "all" ]]; then
			packages
			firewall
			services
			hacking_tools
			general_config
			user_auditing
			file_config
			media_files
		elif [[ $failYN == "packages" ]]; then
			packages
		elif [[ $failYN == "firewall" ]]; then
			firewall
		elif [[ $failYN == "services" ]]; then
			services
		elif [[ $failYN == "hacking_tools" ]]; then
			hacking_tools
		elif [[ $failYN == "general_config" ]]; then
			general_config
		elif [[ $failYN == "file_config" ]]; then
			file_config
		elif [[ $failYN == "user_auditing" ]]; then
			user_auditing
		elif [[ $failYN == "media_files" ]]; then
			media_files
		else
			echo "####Option not found (or exiting)####"
		fi
	done
	exit 0

}

failsafe=/home/"$mainUser"/Desktop/logs/changelog.log
if [[ -f "$failsafe" ]]; then
	echo "This script is detected as being run for more than one time"
	echo "This has been known to cause a wide variety of problems, including potential loss of internet, which in worst case scenario, can necessitate a restart of the image."
	echo "Luckily, a system has been implemented to avoid this problem"
	echo "Would you like to continue with choosing which parts of the script to redo?"
	read -r restartYN
	if [[ $restartYN == "yes" ]]; then
		echo "Would you like to remove and replace the current installments of the changelog and backups? (other option is creating new files)"
		read -r removeYN
		if [[ $removeYN == "yes" ]]; then
			rm -r /home/"$mainUser"/Desktop/logs
			first_time_initialize
			second_time_failsafe
		elif [[ $removeYN == "no" ]]; then

			echo "Replacing legacy folder and backing up old files"
			mkdir -p /home/"$mainUser"/Desktop/logs_legacy
			mv -r /home/"$mainUser"/Desktop/logs /home/"$mainUser"/Desktop/logs_legacy
			mv /home/"$mainUser"/Desktop/logs/changelog.log /home/"$mainUser"/Desktop/logs_legacy
			mv -r /home/"$mainUser"/Desktop/logs/backups/ /home/"$mainUser"/Desktop/logs_legacy
			first_time_initialize
			second_time_failsafe
		else
			echo "Option not recognized"
			exit 1
		fi
	elif [[ $restartYN == "no" ]]; then
		echo "Exiting script"
		exit 0
	else
		echo "Option not recognized"
		exit 1
	fi
fi

end() {
	touch /home/"$mainUser"/Desktop/to-do.txt
	chmod 777 /home/"$mainUser"/Desktop/to-do.txt
	{
		echo "Manual changes:"
		echo "- Check for backdoors (netstat -anp | grep LISTEN | grep -v STREAM)"
		echo "- Check for malicious packages that might still be installed (dpkg -l | grep <keyword> (i.e. crack))"
		echo "- Make sure updates are checked for daily and update Ubuntu according to the ReadMe"
		echo "- 'sudo nmap -v -sS localhost' to check open ports"
	} >>/home/"$mainUser"/Desktop/to-do.txt
}

if [[ "$(date)" == *"Sat Jan  23"* ]]; then
	echo "Happy Competition Day :D! Good luck and don't mess up!"
fi

echo "Type 'safe' to enter safe mode and anything else to continue"
read -r safecheck
if [[ $safecheck == "safe" ]]; then
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
sysctl -p
service ssh restart
service auditd restart
apt-get update
apt-get upgrade
apt-get autoremove -y -qq
apt-get autoclean -y -qq
apt-get clean -y -qq
echo "Type anything to continue"
read -r timeCheck

#run rkhunter
rkhunter --check --vl --sk
cp /var/log/rkhunter.log /home/"$mainUser"/Desktop/logs
chmod 777 /home/"$mainUser"/Desktop/logs/rkhunter.log

#run lynis
lynis audit system
cp /var/log/lynis.log /home/"$mainUser"/Desktop/logs
chmod 777 /home/"$mainUser"/Desktop/logs/lynis.log

echo "#########Installing other packages#########"
echo "####PortSentry (Network manager)####"
apt-get install portsentry -y -qq
echo "####needrestart (check if a restart is needed)####"
apt-get install needrestart -y -qq

echo
echo "#########Bash Vulnerability Test#########"
env i='() { :;}; echo Your system is Bash vulnerable' bash -c "echo Bash vulnerability test"
echo "*********Is Bash vulnerable? (Will say 'Your system is bash vulnerable')*********"
read -r bashvulnYN
if [[ $bashvulnYN == "yes" ]]; then
	apt-get update && apt-get install --only-upgrade bash
fi

echo "#########Creating symbolic link to /var/log/ in logs folder on Desktop#########"
ln -s /var/log/ /home/"$mainUser"/Desktop/logs/servicelogs
touch /home/"$mainUser"/Desktop/logs/logs_to_check.txt
chmod 777 /home/"$mainUser"/Desktop/logs/logs_to_check.txt
{
	echo "Logs to check often:"
	echo "/var/log/messages - The main system logs or current activity logs are available."
	echo "/var/log/auth.log - Authentication logs"
	echo "/var/log/kern.log - Kernel logs"
	echo "/var/log/cron.log - Crond logs (cron job)"
	echo "/var/log/maillog - Mail server logs"
	echo "/var/log/boot.log - System boot log"
	echo "/var/log/mysqld.log - MySQL database server log file"
	echo "/var/log/secure - Authentication log"
	echo "/var/log/ufw.log - Firewall log"
	echo "/var/log/utmp or /var/log/wtmp - Login records file."
	echo "Execute 'sudo logwatch | less' to see an overview of all important log files"
} >>/home/"$mainUser"/Desktop/logs/logs_to_check.txt

echo "- Created symbolic link to \/var\/log\/ in logs folder on Desktop" >>/home/"$mainUser"/Desktop/logs/changelog.log

echo "$timeCheck"
ufw reload

end

echo "Script done! Good luck :D"

clamtk

needrestart

update-manager