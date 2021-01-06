# MCS Ubuntu Script v3.0 release
Ubuntu Script for MCS to secure an Ubuntu machine

List of security features:
- Installs useful packages at the start (firewall, antivirus/rootkit, auditd + others)
- Enables automatic auditing with auditd
- Automatically configures the firewall (Blocks insecure ports and enables logging)
- Automatic service auditing for specific services with user input
- Option to lock root account
- Unalias support
- Automatically removes common hacking tools/remote access tools
- Denies outside packets with iptables
- Disables reboot with Ctrl+Alt+Del
- Disallows guest account
- Removes all startup scripts from the machine
- SSH secure configuration
- SSH key security
- Configures password longevity
- Configures password complexity requirements
- Configures account lockout policy
- Secures Shared Memory
- Configured /etc/sysctl.conf

Other features:
- Creates file 'changelog.log' on the desktop and logs all actions performed by the script
- Creates directory 'backups' which automatically backs up important files or files that are edited by the script
- Will abort the script if not run as root to avoid errors
- If script is run twice, 'changelog.log' and 'backups' are automatically removed and replaced

Known issues/to-do list:
- Running the script twice sometimes cuts internet access to the machine
- Script must be run using the bash command rather than the sh command
- Want to add a method of quarantining media files
- Want to add support for more service auditing and more hacking tool removals
- Want to further expand /etc/sysctl.conf editing
