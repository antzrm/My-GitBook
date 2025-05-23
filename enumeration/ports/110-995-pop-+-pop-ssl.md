# 110, 995 - POP + POP (SSL)

```bash
# POP SSL CONNECTION ON PORT 995
openssl s_client -connect $IP:995

# POP commands:
  USER uid           Log in as "uid"
  PASS password      Substitue "password" for your actual password
  STAT               List number of messages, total mailbox size
  LIST               List messages and sizes
  RETR n             Show message n
  DELE n             Mark message n for deletion
  RSET               Undo any changes
  QUIT               Logout (expunges messages if no RSET)
  TOP msg n          Show first n lines of message number msg
  CAPA               Get capabilities
  
root@kali:~# nc -nvC 10.12.11.22 110
(UNKNOWN) [10.12.11.22] 110 (pop3) open
+OK beta POP3 server (JAMES POP3 Server 2.3.2) ready 
USER root
+OK
PASS alphabeta
-ERR Authentication failed.
USER beta
+OK
PASS mail
-ERR Authentication failed.
```
