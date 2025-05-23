# Ports

{% embed url="https://kashz.gitbook.io/kashz-jewels" %}

{% hint style="info" %}
/proc/net/tcp and from hex to dec
{% endhint %}

## Port Scanning

### Linux

```bash
nc -nvv -w 1 -z 192.168.50.152 3388-3390

#!/bin/bash
# ./portScan.sh <ip-address>
if [ $1 ]; then # if an argument was supplied
	ip_address=$1
	for port in $(seq 1 65535); do
		timeout .1 bash -c "echo '' > /dev/tcp/$ip_address/$port" 2>/dev/null && echo "[*] Port $port - OPEN" & # & for multithreading
	done; wait # until it's not finished all ports, wait
else
	echo -e "\n[*] Usage: ./portScan.sh <ip-address>\n"
	exit 1
fi
```

### Windows

{% code overflow="wrap" fullWidth="true" %}
```powershell
Test-NetConnection -Port 445 192.168.50.151
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.0.10", $)) "TCP port $ is open"} 2>$null

$ipAddress = "127.0.0.1"; Get-Content "ports.txt" | ForEach-Object {if ((New-Object System.Net.Sockets.TcpClient).Connect($ipAddress, $_)) { "Port $_ is open." } else { "Port $_ is closed." }}

Invoke-Portscan -Hosts 172.16.0.10 -TopPorts 50
```
{% endcode %}

## Host Discovery

### Linux

<pre class="language-bash" data-overflow="wrap" data-full-width="true"><code class="lang-bash">fscan -h 10.10.110.0/24
<strong>
</strong><strong>#!/bin/bash
</strong>
for i in $(seq 2 254);do
	timeout 0.5 bash -c "ping -c 1 10.11.25.$i >/dev/null 2>&#x26;1" &#x26;&#x26; echo "Host 10.11.25.$i - ACTIVE" &#x26;
done
</code></pre>

### Windows

{% code overflow="wrap" fullWidth="true" %}
```c
C:\>for /L %i in (1,1,255) do @ping -n 1 -w 200 10.10.10.%i > nul && echo 10.10.10.%i is up.
```
{% endcode %}
