# Packet sniffing

## Spoofing

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"># Spoofing
sudo responder -I tun0
# To get previous hashes go to responder.db, open with sqlite3 and select the appropiate table
<strong>
</strong><strong># Metasploit (alternative)
</strong>msf > auxiliary/server/capture/http_ntlm
set JOHNPWFILE
set SRVHOST
set SRVPORT
set URIPATH
</code></pre>

## tcpdump

{% hint style="danger" %}
IF WE ARE ROOT OR WE CAN USE IT ON THE TARGET, sniff all ports and try to generate traffic on all ports, not only on the one we are using to capture packets.
{% endhint %}

{% hint style="info" %}
For Linux privesc, first check if our user belongs to a tcpdump group or we will not be able to use the binary.
{% endhint %}

In case there is a connection (FTP, SSH, whatever) on the target and we don't have any more clues for privesc, try to sniff the traffic of that port and interface we need either **`tcpdump`** or **`tshark`** installed on the victim machine.

{% code overflow="wrap" fullWidth="true" %}
```bash
tcpdump -i any -w capture.pcap -v -s0
# IF ANY FAILS, choose a specific interface or try 2-3 of them
###### NOTE: The -s ﬂag ensures that the packets are stored completely

tcpdump -D # list interfaces
tcpdump -v -i $INTERFACE port $PORT -w $FILE_TO_SAVE_THE_TRAFFIC
sudo tcpdump -nvvvXi tun0 tcp port 8000 # capture traffic from tun0 interface on port 8000
# Start a tcpdump listener on your local machine using: 
sudo tcpdump ip proto \\icmp -i tun0
# This starts a tcpdump listener, specifically listening for ICMP traffic, which pings operate on.
 
# Read a capture file
sudo tcpdump -r password_cracking_filtered.pcap 
# Count destination IP appearances
sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F" " '{print $5}' | sort | uniq -c | head
# tcpdump filters
sudo tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap
sudo tcpdump -n dst host 172.16.40.10 -r password_cracking_filtered.pcap
sudo tcpdump -n port 81 -r password_cracking_filtered.pcap
# read the packet capture in hex/ascii output
sudo tcpdump -nX -r password_cracking_filtered.pcap
# Advanced filtering to only show data packets 'tcp[13] = 24'
sudo tcpdump -A -n 'tcp[13] = 24' -r password_cracking_filtered.pcap
```
{% endcode %}

## tshark

{% code overflow="wrap" fullWidth="true" %}
```bash
tcpdump -i tun0 -w capture.cap -v
tshark -r capture.cap -Tjson -Tfields -e tcp.payload
tshark -r Captura.cap -Y "http" -Tfields -e tcp.payload 2>/dev/null | xxd -ps -r | grep "GET" | awk '{print $2}' | sort -u | wc -l
# tcp.payload is the field in hex so use xxd -ps -r
# Other fields: ip.src, ip.dst and so on
```
{% endcode %}

## TCPView - SysInternal

To sniff traffic from Windows processes/services.

## Shodan

To check IPs, ports, services, grab banners about versions all over the world...

## Wireshark

{% code overflow="wrap" fullWidth="true" %}
```bash
https://www.wireshark.org/docs/
https://wiki.wireshark.org/SampleCaptures
https://dfirmadness.com/case-001-pcap-analysis/
http://wiki.wireshark.org/CaptureFilters
http://wiki.wireshark.org/DisplayFilters

###### Look at Statistics > Endpoints to find a summary of which are the most relevant IPs, ports...

# capture filters -> any packets that do not match the filter criteria will be dropped and the remaining data is passed on to the capture engine

# The capture engine then dissects the incoming packets, analyzes them, and finally applies any additional display filters before displaying the output.
Capture filter > net 192.168.1.0/24
Display filters > tcp.port == 80
Follow TCP Stream
```
{% endcode %}

### Find strings in packets

Go to Find in packets and select BYTES option for strings in order to locate strings within packets correctly.

```bash
# An easy way to look for strings
strings file.pcap | grep -i password
```
