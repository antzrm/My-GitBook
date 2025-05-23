# 135 - MSRPC

```bash
rpcdump.py $IP -p 135

# RID bruteforce - with creds we can enumerate more users
lookupsid.py user:pass@HOST
cme smb IP -u user -p pass --rid-brute
```

## net rpc

```bash
# Net command
net
net rpc
# Change a user's password
net rpc password $USERNAME_TO_CHANGE_PWD -U '$LOGIN_USER' -S $IP
```
