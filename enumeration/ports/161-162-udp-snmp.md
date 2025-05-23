# 161, 162 (UDP) - SNMP

{% embed url="https://medium.com/@minimalist.ascent/enumerating-snmp-servers-with-nmap-89aaf33bce28" %}

SNMP is based on UDP, a simple, stateless protocol, and is thereforesusceptible to IP spoofing and replay attacks. Additionally, thecommonly used SNMP protocols 1, 2, and 2c offer no traffic encryption,meaning that SNMP information and credentials can be easilyintercepted over a local network. Until SNMPv3 good encryption did not come.

| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports  |

{% hint style="danger" %}
Be careful since onesixtyone and hydra only try v1, for more versions research other tools such as [https://github.com/SECFORCE/SNMP-Brute](https://github.com/SECFORCE/SNMP-Brute)

```
python snmpbrute.py -t $IP -f /usr/share/seclists/Discovery/SNMP/snmp.txt
```
{% endhint %}

<pre class="language-bash" data-overflow="wrap" data-full-width="true"><code class="lang-bash"># Identify internal ports with snmp-netstat and running processes with snmp-processes
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes 10.11.1.111
nmap 10.11.1.111 -Pn -sU -p 161 --script=snmp*
<strong>
</strong><strong># Enum running processes, grep for the SNMP process OID, grep for PID and find also arguments
</strong><strong>
</strong><strong># START BY BRUTEFORCING COMMUNITY STRINGS WITH A BIG WORDLIST
</strong>onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $IP
# If some info found, we will see the community string between brackets on the output , e.g. $IP [private] ...
# Once we know valid community strings
sudo apt install snmpcheck
snmp-check $IP (-p 161) -c $COMM_STRING
snmpbulkwalk -c $COMM_STRING -v2c $IP .
<strong>
</strong><strong># MANDATORY TO TRY THE FIRST 3 COMMANDS FIRST, THEY PROVIDE MORE INFO THAN OTHERS
</strong>snmpbulkwalk -c public -v2c $IP . # try also v1 and v3
snmpbulkwalk (-Cr1000) -c public -v2c $IP > snmp_enum.txt #this tool is much faster
snmpwalk -v X -c public $IP NET-SNMP-EXTEND-MIB::nsExtendOutputFull
snmpwalk -c public -v1 -t 10 $IP -Oa
snmpwalk -c public -v1 $IP 1.3.6.1.4.1.77.1.2.25 #enum users
# ENUMERATING THE ENTIRE MIB TREE
snmpwalk -c public -v1 -t 10 10.11.1.14
# ENUM WINDOWS USERS
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25
# ENUM RUNNING WINDOWS PROCESSES
snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2
# ENUM OPEN TCP PORTS
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3
# ENUM INSTALLED SOFTWARE
snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2
snmpcheck 10.11.1.111 -c public|private|community
snmp-check $IP
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 172.21.0.X
# Impacket
python3 samdump.py SNMP 172.21.0.0 
echo public > community
echo private >> community
echo manager >> community
onesixtyone -c community $IP
onesixtyone -c community -i $IP_LIST_FILE

# MSF aux modules
 auxiliary/scanner/misc/oki_scanner                                    
 auxiliary/scanner/snmp/aix_version                                   
 auxiliary/scanner/snmp/arris_dg950                                   
 auxiliary/scanner/snmp/brocade_enumhash                               
 auxiliary/scanner/snmp/cisco_config_tftp                               
 auxiliary/scanner/snmp/cisco_upload_file                              
 auxiliary/scanner/snmp/cnpilot_r_snmp_loot                             
 auxiliary/scanner/snmp/epmp1000_snmp_loot                             
 auxiliary/scanner/snmp/netopia_enum                                    
 auxiliary/scanner/snmp/sbg6580_enum                                 
 auxiliary/scanner/snmp/snmp_enum                                 
 auxiliary/scanner/snmp/snmp_enum_hp_laserjet                           
 auxiliary/scanner/snmp/snmp_enumshares                                
 auxiliary/scanner/snmp/snmp_enumusers                                 
 auxiliary/scanner/snmp/snmp_login
</code></pre>
