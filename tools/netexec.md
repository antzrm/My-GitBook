# NetExec

```bash
# GENERATE HOSTS FILE
netexec smb $IP --generate-hosts-file /etc/hosts

# LIST MODULES
nxc mssql dc.domain.com -u user -p password -L

# What do you do if you have compromised a server administrator? Hunt for domain admins
nxc ... -M presence
nxc ... --dpapi

```
