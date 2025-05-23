# Anti-forensics

{% code overflow="wrap" fullWidth="true" %}
```sh
sdelete64.exe SysInternals
Timestomper.exe
To detect this -> analyze and parse MFT
Clear logs wevtutil cl $WINDOWS_LOGS
Windows Security Event log ID 1102  and Windows System Event log ID 104 indicate the audit log(s) has attempted to be cleared
ADS:  type HTB-ADS-STEALTH.exe > InnocentFile.txt:HTB-HIDDEN-ADS.exe
to execute it start InnocentFile.txt:HTB-HIDDEN-ADS.exe
Detection -> MFT or Get-Item -Path innocentfile.txt -Stream *
Log tampering -> utmpdump /var/log/wtmp see logins 
Take out our IPs as attacker utmpdump /var/log/wtmp | grep -v “72.255.51.37” > HTB-log-tampering.txt
Then tamper the file with our modified info // utmpdump -r < HTB-log-tampering.txt > /var/log/wtmp
Detection -> check timestamps, if they differ for some minutes then the file was tampered
```
{% endcode %}
