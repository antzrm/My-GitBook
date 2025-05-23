# 21 - FTP

{% code overflow="wrap" fullWidth="true" %}
```bash
# As an option to troubleshoot and for list/transferring files, set the FTPsession as active and enable binary encoding.
passive off
binary
https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ftp-binary

# If hangs saying 
229 Entering Extended Passive Mode
https://youtu.be/i5furEJlySY
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> binary
200 Type set to I.
ftp> ls -la
200 EPRT command successful.
150 Opening ASCII mode data connection.
425 Cannot open data connection.
ftp> dir
200 EPRT command successful.
150 Opening ASCII mode data connection.

# ANONYMOUS MODE AND COMMON CREDS
anonymous:anonymous
admin:admin
admin:password
guest:guest
# BRUTE FORCE WITH HYDRA --> better if we know the username, we might use also rockyou

# NetExec allows file listing and also download and upload files with --get and --put
nxc ftp 127.0.0.1 -u 'anonymous' -p '' --put ~/Desktop/user_list.txt ./user_list.txt
nxc ftp 127.0.0.1 -u 'anonymous' -p '' --ls
nxc ftp 127.0.0.1 -u 'anonymous' -p '' --get user_list.txt


# TRY LFTP IF FTP FAILS OR WE NEED SECURE CONNECTION
# If we see this error on ftp binary
550 SSL/TLS required on the control channel
# Then try lftp
lftp user@$IP
lftp > set ssl:verify-certificate false # might be needed if SSL is disabled
lftp user@host:~> set ssl:verify-certificate no
lftp > dir


# ProFTPd exploit
https://www.exploit-db.com/exploits/367421

# FTP common root directories
/home/ftp
/var/ftp
/var/www/ftp
# vsftpd
/etc/vsftpd.conf # check here anon_root or local_root to know the root FTP share folder
anon_root=/srv # if it is this, all anonymous FTP shares are under /srv
/srv/ftp/file.txt # if there is a folder called ftp on the share, this would be the way to reach it

# Mount FTP (useful if FTP has too many folders to enumerate)
mkdir /mnt/ftp
curlftpfs ftp://10.10.10.10 /mnt/ftp
unmount /mnt/ftp # once we're done

# Download FTP share recursively
wget -m ftp://USER:PASS@$TARGET_IP
wget -r -m --no-passive ftp://user:pass@server.com/
# If special characters
wget -r -m --no-passive --user="user@login" --password="Pa$$wo|^D" ftp://server.com/
```
{% endcode %}

## FileZilla 0.9.41 beta

For privesc, needs access to port `TCP/14147`

[`https://github.com/NeoTheCapt/FilezillaExploit?ref=benheater.com`](https://github.com/NeoTheCapt/FilezillaExploit?ref=benheater.com)
