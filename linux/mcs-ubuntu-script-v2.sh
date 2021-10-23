#!/bin/bash

echo "MCS Ubuntu Script v2.0.0 Updated 8/15/2021 at 6:47 EST"

if [[ "$(whoami)" != root ]]; then
	echo "This script can only be run as root"
	exit 1
fi

declare -a services
islamp="no"
homeDir="/home/$username"

init() {
	\unalias -a
	echo "Please enter the username of the main user on this machine."
	read -r username
	logsDir="/home/$username/Desktop/logs"
	mkdir -p ${logsDir}
	mkdir -p ${logsDir}/backups
	cp /etc/group ${logsDir}/backups/
	cp /etc/passwd ${logsDir}/backups/
	cp /etc/shadow ${logsDir}/backups/
	touch ${logsDir}/changelog.log
	chmod -R 777 ${logsDir}
}

packages() {
	apt-get update -y
	apt-get upgrade -y
	apt-get dist-upgrade -y
	apt-get install firefox -y
	apt-get install rkhunter -y
	apt-get install lynis -y -qq
	apt-get install ufw -y -qq
	apt-get install libpam-cracklib -y -qq
	apt-get install libpam-tmpdir -y -qq
	apt-get install libpam-pkcs11 -y -qq
	apt-get install unattended-upgrades -y -qq
	apt-get install logwatch -y -qq
	apt-get install nmap -y -qq
	apt-get install python3-pip -y
	pip3 install bs4
	echo "Type anything to continue"
	read -r timeCheck
	if [[ $timeCheck == "exit" ]]; then
		exit 1
	fi
}

firewall() {
	ufw deny 1337 # trojan port
	ufw deny 23 # telnet
	ufw deny 515 # spooler
	ufw deny 111 # sun remote thing
	ufw deny 135 # ms rpc
	ufw deny 137, 138, 139 # netbios
	ufw deny 69 # tftp
	ufw default deny incoming
	ufw default deny routed
	ufw logging on
	ufw logging high
	ufw enable
}

services() {

	if [[ ${services[*]} =~ 'apache' && ${services[*]} =~ 'mysql' ]]; then
		apt-get purge nginx -y -qq
		apt-get purge nginx-common -y -qq
		apt-get purge nginx-core -y -qq
		echo "- NGINX removed from the machine" >>${homeDir}/Desktop/logs/changelog.log
		apt-get install apache2 -y -qq
		apt-get install apache2-utils -y -qq
		apt-get install libapache2-mod-evasive -y -qq
		apt-get install libapache2-mod-security2 -y -qq
		ufw allow in "Apache Full"
		ufw allow http
		ufw allow https
		systemctl restart apache2
		service apache2 restart

		echo "####Configuring Apache2 config file####"
		cp /etc/apache2/apache2.conf ${homeDir}/Desktop/logs/backups
		cp ${homeDir}/Desktop/linux/apache2.conf /etc/apache2/apache2.conf
		chmod 511 /usr/sbin/apache2
		chmod -R 755 /var/log/apache2/
		chmod -R 755 /var/www
		/etc/init.d/apache2 restart

		echo "####Installing PHP####"
		apt-get install php -y -qq
		apt-get install libapache2-mod-php -y -qq
		apt-get install php-mysql -y -qq
		cp /etc/apache2/mods-enabled/dir.conf ${homeDir}/Desktop/logs/backups
		rm /etc/apache2/mods-enabled/dir.conf
		cp ${homeDir}/Desktop/linux/dir.conf /etc/apache2/mods-enabled
		systemctl restart apache2
		echo "###Configuring php.ini####"
		cp /etc/php/7.2/apache2/php.ini ${homeDir}/Desktop/logs/backups/
		cp ${homeDir}/Desktop/linux/php.ini /etc/php/7.2/apache2/php.ini
		service apache2 restart

		#install + config mysql
		ufw allow ms-sql-s
		ufw allow ms-sql-m
		ufw allow mysql
		ufw allow mysql-proxy
		apt-get install mysql-server -y -qq
		chown -R mysql:mysql /var/lib/mysql
		dpkg --configure -a
		ln -s /etc/mysql/mysql.conf.d /etc/mysql/conf.d
		mysqld --initialize --explicit_defaults_for_timestamp
		mysql_secure_installation

    islamp='yes'
	fi

	if [[ ${services[*]} =~ 'ssh' ]]; then
		apt-get install ssh -y -qq
		apt-get install openssh-server -y -qq
		apt-get upgrade openssl libssl-dev -y -qq
		apt-cache policy openssl libssl-dev
		echo "- Packages ssh and openssh-server installed and heartbleed bug fixed" >>${homeDir}/Desktop/logs/changelog.log

		echo "####Editing /etc/sshd/sshd_config####"
		cp /etc/ssh/sshd_config ${homeDir}/Desktop/logs/backups/
		rm /etc/ssh/sshd_config
		cp ${homeDir}/Desktop/linux/sshd_config /etc/ssh
		chown root:root /etc/ssh/sshd_config
		chmod og-rwx /etc/ssh/sshd_config
		find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
		find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;
		find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;
		find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
		echo "- Configured /etc/ssh/sshd_config" >>${homeDir}/Desktop/logs/changelog.log

		echo "####Securing SSH keys####"
		mkdir -p ${homeDir}/.ssh/
		chmod 700 ${homeDir}/.ssh
		chmod 600 ${homeDir}/.ssh/authorized_keys
		ssh-keygen -t rsa
    chmod 600 ${homeDir}/.ssh/id_rsa
		echo "- Secured SSH keys" >>${homeDir}/Desktop/logs/changelog.log

		echo "####SSH port can accept SSH connections####"
		ufw allow 22

		service ssh restart
		echo "- SSH configured" >>${homeDir}/Desktop/logs/changelog.log
	else
		apt-get purge openssh-server
		ufw deny ssh
	fi

	if [[ ${services[*]} =~ 'smb' || ${services[*]} =~ 'samba' ]]; then
		ufw allow microsoft-ds
		ufw allow 137/udp
		ufw allow 138/udp
		ufw allow 139/tcp
		ufw allow 445/tcp
		apt-get install samba -y -qq
		apt-get install system-config-samba -y -qq
		apt-get install libpam-winbind -y -qq
		systemctl restart smbd.service nmbd.service
		echo "- Samba installed and allowed" >>${homeDir}/Desktop/logs/changelog.log
	else
		ufw deny netbios-ns
		ufw deny netbios-dgm
		ufw deny netbios-ssn
		ufw deny microsoft-ds
		apt-get purge samba -y -qq
		echo "- Samba uninstalled and blocked" >>${homeDir}/Desktop/logs/changelog.log
	fi

	if [[ ${services[*]} =~ 'vsftpd' ]]; then
		apt-get install vsftpd
		cp /etc/vsftpd.conf /etc/vsftpd.conf_default
		cp /etc/vsftpd.conf ${homeDir}/Desktop/logs/backups/
		service vsftpd start
		service vsftpd enable
		openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem
		rm /etc/vsftpd.conf
		cp ${homeDir}/Desktop/linux/vsftpd.conf /etc
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
		echo "- FTP installed and allowed" >>${homeDir}/Desktop/logs/changelog.log
	else
		service vsftpd stop
		ufw deny ftp
		ufw deny sftp
		ufw deny saft
		ufw deny ftps-data
		ufw deny ftps
		apt-get purge vsftpd -y -qq
		echo "- FTP uninstalled and blocked" >>${homeDir}/Desktop/logs/changelog.log
	fi

	service telnet stop
	ufw deny telnet
	ufw deny rtelnet
	ufw deny telnets
	apt-get purge telnet -y -qq
	apt-get purge telnetd -y -qq
	apt-get purge inetutils-telnetd -y -qq
	apt-get purge telnetd-ssl -y -qq

	if [[ ${services[*]} =~ 'apache' && $islamp == 'no' || ${services[*]} =~ 'nginx' && $islamp == 'no' ]]; then
		if [[ ${services[*]} =~ 'nginx' ]]; then
			apt-get purge apache2 -y -qq
			apt-get purge apache2-bin -y -qq
			apt-get purge apache2-utils -y -qq
			apt-get purge libapache2-mod-evasive -y -qq
			apt-get purge libapache2-mod-security2 -y -qq
			echo "- Apache2 removed" >>${homeDir}/Desktop/logs/changelog.log
			apt-get install nginx -y -qq
			ufw allow http
			ufw allow https
			echo "- NGINX installed" >>${homeDir}/Desktop/logs/changelog.log
		elif [[ ${services[*]} =~ 'apache' ]]; then
			apt-get purge nginx -y -qq
			apt-get purge nginx-common -y -qq
			apt-get purge nginx-core -y -qq
			echo "- NGINX removed from the machine" >>${homeDir}/Desktop/logs/changelog.log
			apt-get install apache2 -y -qq
			apt-get install apache2-utils -y -qq
			apt-get install libapache2-mod-evasive -y -qq
			apt-get install libapache2-mod-security2 -y -qq
			ufw allow http
			ufw allow https
			systemctl restart apache2
			echo "####Configuring ufw for web servers####"
			chmod 511 /usr/sbin/apache2
			chmod -R 750 /var/log/apache2/
			chmod -R 444 /var/www
			/etc/init.d/apache2 restart
			echo "- Apache2 installed, configured, and http(s) allowed" >>${homeDir}/Desktop/logs/changelog.log
		fi
	elif [[ $islamp == 'no' ]]; then
		apt-get purge nginx -y -qq
		apt-get purge nginx-common -y -qq
		apt-get purge nginx-core -y -qq
		echo "- NGINX removed from the machine" >>${homeDir}/Desktop/logs/changelog.log
		ufw deny http
		ufw deny https
		apt-get purge apache2 -y -qq
		apt-get purge apache2-bin -y -qq
		apt-get purge apache2-utils -y -qq
		apt-get purge libapache2-mod-evasive -y -qq
		apt-get purge libapache2-mod-security2 -y -qq
		rm -r /var/www/*
		echo "- Apache2 removed and http(s) blocked" >>${homeDir}/Desktop/logs/changelog.log
	fi

	ufw deny smtp
	ufw deny pop3
	ufw deny imap2
	ufw deny imaps
	ufw deny pop3s
	apt-get purge dovecot-* -y -qq

	if [[ ${services[*]} =~ 'bind9' || ${services[*]} =~ 'dns' ]]; then
		apt-get install bind9 -y -qq
		named-checkzone test.com. /var/cache/bind/db.test
		{
			echo "zone \"test.com.\" {"
			echo "\o011type master;"
			echo "\o011file \"db.test\";"
			echo "};"
		} >>/etc/bind/named.conf.default-zones
		systemctl restart bind9
	else
		systemctl stop bind9
		apt-get purge bind9 -y -qq
	fi

	if [[ ${services[*]} =~ 'mysql' && $islamp == 'no' ]]; then
		ufw allow ms-sql-s
		ufw allow ms-sql-m
		ufw allow mysql
		ufw allow mysql-proxy
		apt-get install mysql-server -y -qq
		mv /etc/mysql/my.cnf /etc/mysql/my.cnf.bak
		mv /etc/mysql/debian.cnf /etc/mysql/debian.cnf.bak
		chown -R mysql:mysql /var/lib/mysql
		dpkg --configure -a
		ln -s /etc/mysql/mysql.conf.d /etc/mysql/conf.d
		mysqld --initialize --explicit_defaults_for_timestamp
		mysql_secure_installation
		echo "#########Checking if MySQL config file exists#########"
		cnfCheck=/etc/mysql/my.cnf
		if [[ -f "$cnfCheck" ]]; then
			echo "MySQL config file exists"
		else
			touch /etc/mysql/my.cnf
			echo "MySQL config file created" >>${homeDir}/Desktop/logs/changelog.log
		fi
		echo "#########Configuring my.cnf#########"
		{
			echo "[mysqld]"
			echo "max_connections = 400"
			echo "key_buffer = 16M"
			echo "myisam_sort_buffer_size = 32M"
			echo "join_buffer_size = 1M"
			echo "read_buffer_size = 1M"
			echo "sort_buffer_size = 2M"
			echo "table_cache = 1024"
			echo "thread_cache_size = 286"
			echo "interactive_timeout = 25"
			echo "wait_timeout = 1000"
			echo "connect_timeout = 10"
			echo "max_allowed_packet = 16M"
			echo "max_connect_errors = 10"
			echo "query_cache_limit = 1M"
			echo "query_cache_size = 16M"
			echo "query_cache_type = 1"
			echo "tmp_table_size = 16M"
			echo "skip-innodb"
			echo "local-infile=0"
			echo "bind-address=127.0.0.1"
			echo "skip-show-database"

			echo "[mysqld_safe]"
			echo "open_files_limit = 8192"

			echo "[mysqldump]"
			echo "quick"
			echo "max_allowed_packet = 16M"

			echo "[myisamchk]"
			echo "key_buffer = 32M"
			echo "sort_buffer = 32M"
			echo "read_buffer = 16M"
			echo "write_buffer = 16M"
		} >>/etc/mysql/my.cnf
		chown -R root:root /etc/mysql/
		chmod 644 /etc/mysql/my.cnf
    elif [[ $islamp == 'no' ]]; then
		ufw deny ms-sql-s
		ufw deny ms-sql-m
		ufw deny mysql
		ufw deny mysql-proxy
		apt-get purge mysql-server -y -qq
		apt-get purge mysql-client -y -qq
	fi

	apt-get purge cups -y -qq

}

general_config() {
	passwd -l root

	systemctl mask ctrl-alt-del.target
	systemctl daemon-reload

	systemctl start systemd-timesyncd.service
	timedatectl set-ntp true

	echo "ALL: ALL" >>/etc/hosts.deny
	chown root:root /etc/hosts.allow
	chmod 644 /etc/hosts.allow
	chown root:root /etc/hosts.deny
	chmod 644 /etc/hosts.deny

	echo "#########Disabling Uncommon Network protocols and file system configurations#########"
	touch /etc/modprobe.d/dccp.conf
	chmod 644 /etc/modprobe.d/dccp.conf
	echo "install dccp /bin/true" >/etc/modprobe.d/dccp.conf
	touch /etc/modprobe.d/sctp.conf
	chmod 644 /etc/modprobe.d/sctp.conf
	echo "install sctp /bin/true" >/etc/modprobe.d/sctp.conf
	touch /etc/modprobe.d/rds.conf
	chmod 644 /etc/modprobe.d/rds.conf
	echo "install rds /bin/true" >/etc/modprobe.d/rds.conf
	touch /etc/modprobe.d/tipc.conf
	chmod 644 /etc/modprobe.d/tipc.conf
	echo "install tipc /bin/true" >/etc/modprobe.d/tipc.conf
	touch /etc/modprobe.d/cramfs.conf
	chmod 644 /etc/modprobe.d/cramfs.conf
	echo "install cramfs /bin/true" >/etc/modprobe.d/cramfs.conf
	rmmod cramfs
	touch /etc/modprobe.d/freevxfs.conf
	chmod 644 /etc/modprobe.d/freevxfs.conf
	echo "install freevxfs /bin/true" >/etc/modprobe.d/freevxfs.conf
	rmmod freevxfs
	touch /etc/modprobe.d/jffs2.conf
	chmod 644 /etc/modprobe.d/jffs2.conf
	echo "install jffs2 /bin/true" >/etc/modprobe.d/jffs2.conf
	rmmod jffs2
	touch /etc/modprobe.d/hfs.conf
	chmod 644 /etc/modprobe.d/hfs.conf
	echo "install hfs /bin/true" >/etc/modprobe.d/hfs.conf
	rmmod hfs
	touch /etc/modprobe.d/hfsplus.conf
	chmod 644 /etc/modprobe.d/hfsplus.conf
	echo "install hfsplus /bin/true" >/etc/modprobe.d/hfsplus.conf
	rmmod hfsplus
	touch /etc/modprobe.d/squashfs.conf
	chmod 644 /etc/modprobe.d/squashfs.conf
	echo "install squashfs /bin/true" >/etc/modprobe.d/squashfs.conf
	rmmod squashfs
	touch /etc/modprobe.d/udf.conf
	chmod 644 /etc/modprobe.d/udf.conf
	echo "install udf /bin/true" >/etc/modprobe.d/udf.conf
	rmmod udf
	touch /etc/modprobe.d/vfat.conf
	chmod 644 /etc/modprobe.d/vfat.conf
	echo "install vfat /bin/true" >/etc/modprobe.d/vfat.conf
	rmmod vfat
	touch /etc/modprobe.d/usb-storage.conf
	chmod 644 /etc/modprobe.d/usb-storage.conf
	echo "install usb-storage /bin/true" >/etc/modprobe.d/usb-storage.conf
	rmmod usb-storage

	echo "ENABLED=\"0\"" >>/etc/default/irqbalance

	if [[ -f "/etc/lightdm/lightdm.conf" ]]; then
		echo "allow-guest=false" >>/etc/lightdm/lightdm.conf
	fi
	
	echo >/etc/rc.local
	echo "exit 0" >/etc/rc.local

	cp /etc/login.defs ${homeDir}/Desktop/logs/backups/
	cp ${homeDir}/Desktop/linux/login.defs /etc/login.defs

	cp /etc/pam.d/common-password ${homeDir}/Desktop/logs/backups/
	cp ${homeDir}/Desktop/linux/common-password /etc/pam.d/common-password

	cp /etc/pam.d/common-auth ${homeDir}/Desktop/logs/backups/
	cp ${homeDir}/Desktop/linux/common-auth /etc/pam.d/common-auth

	# account even worse
	# cp /etc/pam.d/common-account ${homeDir}/Desktop/logs/backups/
	# cp ${homeDir}/Desktop/linux/common-account /etc/pam.d/common-account

	cp /etc/sysctl.conf ${homeDir}/Desktop/logs/backups/
	cp ${homeDir}/Desktop/linux/sysctl.conf /etc/sysctl.conf

	cp /etc/fstab ${homeDir}/Desktop/logs/backups/
	echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >>/etc/fstab

	chown root:root /etc/securetty
	chmod 0600 /etc/securetty

	cp ${homeDir}/Desktop/linux/pam_pkcs11.conf /etc/pam_pkcs11/pam_pkcs11.conf

	echo "Authorized users only. All activity may be monitored and reported." >/etc/issue
	echo "Authorized users only. All activity may be monitored and reported." >/etc/issue.net

	sed -i '45s/.*/*\o011\o011 hard\o011 core\o011\o011 0/' /etc/security/limits.conf

}

hacking_tools() {
	apt-get purge nmap* -y -qq
	apt-get purge netcat -y -qq
	apt-get purge netcat-openbsd -y -qq
	apt-get purge netcat-traditional -y -qq
	apt-get purge socket -y -qq
	apt-get purge sbd -y -qq
	apt-get purge john -y -qq
	apt-get purge hashcat -y -qq
	apt-get purge hydra -y -qq
	apt-get purge hydra-gtk -y -qq
	apt-get purge aircrack-ng -y -qq
	apt-get purge fcrackzip -y -qq
	apt-get purge lcrack -y -qq
	apt-get purge ophcrack -y -qq
	apt-get purge ophcrack-cli -y -qq
	apt-get purge pyrit -y -qq
	apt-get purge rarcrack -y -qq
	apt-get purge sipcrack -y -qq
	apt-get purge nfs-kernel-server -y -qq
	apt-get purge nfs-common -y -qq
	apt-get purge portmap -y -qq
	apt-get purge rpcbind -y -qq
	apt-get purge autofs -y -qq
	apt-get purge vnc4server -y -qq
	apt-get purge vncsnapshot -y -qq
	apt-get purge vtgrab -y -qq
	apt-get purge wireshark -y -qq
	apt-get purge cewl -y -qq
	apt-get purge medusa -y -qq
	apt-get purge wfuzz -y -qq
	apt-get purge sqlmap -y -qq
	apt-get purge snmp -y -qq
	apt-get purge crack -y -qq
	apt-get purge rsh-server -y -qq
	apt-get purge nis -y -qq
	apt-get purge prelink -y -qq
	apt-get purge backdoor-factory -y -qq
	apt-get purge shellinabox -y -qq
	apt-get purge at -y -qq
	apt-get purge xinetd -y -qq
	apt-get purge openbsd-inetd -y -qq
	apt-get purge talk -y -qq
	systemctl --now disable avahi-daemon
	systemctl --now disable isc-dhcp-server
	systemctl --now disable isc-dhcp-server6
	systemctl --now disable slapd
	apt-get purge ldap-utils -y -qq
	apt-get purge slapd -y -qq
	systemctl --now disable nfs-server
	apt-get purge nfs-server -y -qq
	systemctl --now disable rpcbind
	apt-get purge rpcbind -y -qq
	systemctl --now disable rsync
	apt-get purge rsync -y -qq
	apt-get autoremove -y -qq
	apt-get autoclean -y -qq
	apt-get clean -y -qq
}

media_files() {

	echo "#########Logging the file directories of media files on the machine#########"
	touch ${homeDir}/Desktop/logs/media_files.log
	chmod 777 ${homeDir}/Desktop/logs/media_files.log
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

	} >> ${homeDir}/Desktop/logs/media_files.log
}

parse_readme() {
	touch ${homeDir}/Desktop/logs/userchangelog.log
	chmod 777 ${homeDir}/Desktop/logs/userchangelog.log
	echo "Please enter the link to the README"
	read -r link
	adminsList=$(python3 scraper.py $link admins)
	IFS=';' read -r -a admins <<< "$adminsList"
	usersList=$(python3 scraper.py $link users)
	IFS=';' read -r -a users <<< "$usersList"
	servicesList=$(python3 scraper.py $link services)
	IFS=';' read -r -a services <<< "$servicesList"
	echo "Authorized Administrators supposed to be on the system:" >>${homeDir}/Desktop/logs/userchangelog.log
	for item in "${admins[@]}"; do
		echo "$item" >>${homeDir}/Desktop/logs/userchangelog.log
	done
	echo "Authorized Standard Users supposed to be on the system:" >>${homeDir}/Desktop/logs/userchangelog.log
	for item in "${users[@]}"; do
		echo "$item" >>${homeDir}/Desktop/logs/userchangelog.log
	done
	echo "Services:"
	for item in "${services[@]}"; do
		echo "$item"
	done

	currentUserList=$(eval getent passwd "{$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)}" | cut -d: -f1 | tr '\n' ' ')
	IFS=' ' read -r -a currentUsers <<<"$currentUserList"
	authUserList="${adminsList} ${usersList}"
	authUsers=("${admins[@]}" "${users[@]}")

	echo >>${homeDir}/Desktop/logs/userchangelog.log
	echo "Users without passwords given passwords:" >>${homeDir}/Desktop/logs/userchangelog.log
	for item in "${currentUsers[@]}"; do
		if [[ $(grep "${item}" /etc/shadow) != *":$"* ]]; then
			echo "####Setting a new password for ${item}####"
			passwd "$item"
			echo "$item" >>${homeDir}/Desktop/logs/userchangelog.log
		fi
	done

	echo >>${homeDir}/Desktop/logs/userchangelog.log
	echo "Users deleted off the system:" >>${homeDir}/Desktop/logs/userchangelog.log
	for item in "${currentUsers[@]}"; do
		if [[ "$authUserList" != *"$item"* ]]; then
			echo "${item}" >>${homeDir}/Desktop/logs/userchangelog.log
			echo "####Removing user ${item} from system####"
			deluser "${item}"
		fi
	done

	echo >>${homeDir}/Desktop/logs/userchangelog.log
	echo "Users added to the system:" >>${homeDir}/Desktop/logs/userchangelog.log
	for item in "${users[@]}"; do
		if [[ "$currentUserList" != *"$item"* ]]; then
			echo "${item}" >>${homeDir}/Desktop/logs/userchangelog.log
			echo "####Adding user ${item}####"
			adduser --gecos "${item}"
		fi
	done

	echo >>${homeDir}/Desktop/logs/userchangelog.log
	echo "Authorized admins given sudo permissions:" >>${homeDir}/Desktop/logs/userchangelog.log
	for item in "${admins[@]}"; do
		if [[ "$(groups "${item}")" != *"sudo"* ]]; then
			echo "${item}" >>${homeDir}/Desktop/logs/userchangelog.log
			usermod -aG sudo "${item}"
		fi
	done

	echo >>${homeDir}/Desktop/logs/userchangelog.log
	echo "Authorized standard users stripped of sudo permissions:" >>${homeDir}/Desktop/logs/userchangelog.log
	for item in "${users[@]}"; do
		if [[ "$(groups "${item}")" == *"sudo"* ]]; then
			echo "${item}" >>${homeDir}/Desktop/logs/userchangelog.log
			gpasswd -d "${item}" sudo
		fi
	done

	for item in "${authGenUsers[@]}"; do
		usermod --shell /usr/sbin/nologin "${item}"
	done
	echo "All standard users are now in the 'NoLogin' Shell" >>${homeDir}/Desktop/logs/userchangelog.log

	rootUserList=$(grep :0: /etc/passwd | tr '\n' ' ')
	IFS=' ' read -r -a rootUsers <<<"$rootUserList"
	echo >>${homeDir}/Desktop/logs/userchangelog.log
	echo "All current root users on the machine (should only be 'root')" >>${homeDir}/Desktop/logs/userchangelog.log
	for thing in "${rootUsers[@]}"; do
		echo "${thing%%:*}" >>${homeDir}/Desktop/logs/userchangelog.log
	done

	allUserList=$(cut -d ':' -f1 /etc/passwd | tr '\n' ' ')
	IFS=' ' read -r -a allUsers <<<"$allUserList"
	echo >>${homeDir}/Desktop/logs/userchangelog.log
	echo "All current users on the machine (make sure all users that look like normal users are authorized)" >>${homeDir}/Desktop/logs/userchangelog.log
	for thing in "${allUsers[@]}"; do
		echo "$thing" >>${homeDir}/Desktop/logs/userchangelog.log
	done

	for item in "${authUsers[@]}"; do
		crontab -u "$item" -r
	done
	echo "- Cleared crontab for all users" >>${homeDir}/Desktop/logs/changelog.log

	useradd -D -f 30
	for item in "${authUsers[@]}"; do
		chage --inactive 30 "$item"
	done
	echo "- Account inactivity policy set" >>${homeDir}/Desktop/logs/changelog.log
}

second_time_failsafe() {

	failYN=""
	while [ "$failYN" != "exit" ]; do

		echo "*********Which part of the script would you like to redo? (all, packages, firewall, services, hacking_tools, general_config, file_config, user_auditing, media_files) (type exit to leave)*********"
		read -r failYN
		if [[ $failYN == "all" ]]; then
			init
			packages
			parse_readme
			hacking_tools
			general_config
			services
			file_config
			firewall
			media_files
			clean
			audit
			end
			clamtk
		elif [[ $failYN == "packages" ]]; then
			packages
		elif [[ $failYN == "user_auditing" ]]; then
			parse_readme
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
		elif [[ $failYN == "parse_readme" ]]; then
			parse_readme
		elif [[ $failYN == "media_files" ]]; then
			media_files
		else
			echo "####Option not found (or exiting)####"
		fi
	done
	exit 0

}

clean() {
	rkhunter --propupd
	sysctl -p
	ufw reload
	apt-get update
	apt-get upgrade
	apt-get autoremove -y -qq
	apt-get autoclean -y -qq
	apt-get clean -y -qq
}

audit() {
	#run rkhunter
	rkhunter --check --vl --sk
	cp /var/log/rkhunter.log ${homeDir}/Desktop/logs
	chmod 777 ${homeDir}/Desktop/logs/rkhunter.log

	#run lynis
	lynis audit system --quick
	cp /var/log/lynis.log ${homeDir}/Desktop/logs
	chmod 777 ${homeDir}/Desktop/logs/lynis.log
}

end() {
	echo "#########Creating symbolic link to /var/log/ in logs folder on Desktop#########"
	ln -s /var/log/ ${homeDir}/Desktop/logs/servicelogs
	cp ${homeDir}/Desktop/linux/logs-to-check.txt ${homeDir}/Desktop/logs/logs-to-check.txt
	echo "- Created symbolic link to \/var\/log\/ in logs folder on Desktop" >>${homeDir}/Desktop/logs/changelog.log

	echo "$timeCheck"
	echo "Script done! Good luck :D"
}

failsafe=${homeDir}/Desktop/logs/changelog.log
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
			rm -r ${homeDir}/Desktop/logs
			first_time_initialize
			second_time_failsafe
		elif [[ $removeYN == "no" ]]; then

			echo "Replacing legacy folder and backing up old files"
			mkdir -p ${homeDir}/Desktop/logs_legacy
			mv -r ${homeDir}/Desktop/logs ${homeDir}/Desktop/logs_legacy
			mv ${homeDir}/Desktop/logs/changelog.log ${homeDir}/Desktop/logs_legacy
			mv -r ${homeDir}/Desktop/logs/backups/ ${homeDir}/Desktop/logs_legacy
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

echo "Type 'safe' to enter safe mode and anything else to continue"
read -r safecheck
if [[ $safecheck == "safe" ]]; then
	echo "Entering safe mode ..."
	echo "In safe mode, you can choose to only run certain parts of the script"
	second_time_failsafe
fi

#Calls for functions to run through individual portions of the script
init
parse_readme
packages
hacking_tools
general_config
services
file_config
firewall
media_files
clean
audit
end
