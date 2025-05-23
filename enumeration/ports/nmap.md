# Nmap

| [https://www.stationx.net/nmap-cheat-sheet/](https://www.stationx.net/nmap-cheat-sheet/) |
| ---------------------------------------------------------------------------------------- |

{% content-ref url="../active-information-gathering.md" %}
[active-information-gathering.md](../active-information-gathering.md)
{% endcontent-ref %}

## Intro

{% hint style="warning" %}
Be careful with fast scans as they can miss ports; try to reassure the port scan doing

```bash
nmap -p- -n -Pn -vvv $IP
```

also do different scans with less ports.
{% endhint %}

```bash
# BEST WAY, FAST SCAN AND THEN ENUM VERSIONS AND SCRIPTS FOR SPECIFIC PORTS
sudo nmap -p- -sS --min-rate 5000 -n -Pn --open 10.10.10.0 -oG allPorts
nmap $host -sC -sV -p $PORTS -v -n -oN targeted #ports separated by commas
# -sS SYN TCP scan, it does not complete the ACK phase, faster

# SPEED UP SCANS
https://redsiege.com/blog/2022/07/beyondt4/#by_Alex_Norman_Senior_Security_Consultant

# ALTERNATIVES: REDUCE SPEED AND EXCLUDE --open or other parameters
nmap -p- -sS --min-rate 2000 -n -Pn $IP -oG allPorts
sudo nmap -p- $IP
nmap $host -p- --open -T5 -v -n -oG allPorts
# -n no DNS resolution
# -oG export with grepable output
```

## UDP port scan

<pre><code><strong># Try
</strong><strong>sudo nmap -sU --min-rate 10000 --reason
</strong>but also w/o --min-rate since it is not 100 % reliable
</code></pre>

Mostly SNMP and TFTP ports on the UDP side, but on some targets this might be the foothold and the only way in.

```bash
sudo nmap -sU --top-ports 100 --open -T5 -v -n $IP
sudo nmap -sUCV -p$PORT $IP
sudo nmap -sU $box   # -sU scans the top 1000 UDP ports. 
```

## Vuln scan

```bash
cd /usr/share/nmap/scripts/
git clone https://github.com/vulnersCom/nmap-vulners.git
nmap --script nmap-vulners -sV 11.22.33.44
nmap -Pn --script vuln 192.168.1.105
nmap -Pn --script vuln* 192.168.1.105
```

## Fuzzing

```sh
# Enumerate inside a resource
nmap --script http-enum -p $PORT --script-args http-enum.basepath='/mypath' $IP
```

## Proxychains

[#proxychains](../../post-exploitation/port-redirection-and-tunneling.md#proxychains "mention")

```bash
proxychains nmap --top-ports=20 -sT -Pn --open 10.1.1.0 -oG allPorts
proxychains nmap -sC -sV -p $PORTS -sT -Pn $IP -oN targeted
```

## NSE scripts

{% code overflow="wrap" fullWidth="true" %}
```bash
locate .nse | xargs grep "categories" | grep -oP '".*?"' | sort -u
"auth"
"broadcast"
"brute"
"default"
"discovery"
"dos"
"exploit"
"external"
"fuzzer"
"intrusive"
"malware"
"safe"
"version"
"vuln"

nmap -p22,80 --script "vuln and safe" 10.10.166.213

nmap --script http-enum -p$PORT $IP -oN webScan	

# ADD .NSE SCRIPTS MANUALLY
# Google one like https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve-2021-41773.nse
# Download it and save it following the format /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
sudo nmap --script-updatedb
sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124

/usr/share/nmap/scripts/
grep for "exploits" or specific platforms/technologies
--script-help

# CVEs pf services
# We can also set a minimum score
# https://github.com/vulnersCom/nmap-vulners
nmap --script=vulners --script-args min-cvss=7.0 $IP
```
{% endcode %}

## Host discovery

```bash
nmap -sn 10.11.1.1-254
```

## Extract ports

```bash
# FUNCTION IN ~/.bashrc

function extractPorts(){
	echo -e "\n[*] Extracting information...\n"
	ip_address=$(cat allPorts | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u) #IP has 3 digits + . + ...	
	echo -e "\t[*] IP Address: $ip_address"
	open_ports=$(cat allPorts | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',') #xargs to have only one line
	echo -e "\t[*] Open ports: $open_ports"

	echo $open_ports | tr -d '\n' | xclip -sel clip # xclip -sel clip to copy the selected text into the clipboard

	echo -e "[*] Ports have been copied to clipboard!\n"
}
```
