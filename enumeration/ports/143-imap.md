# 143 - IMAP

```bash
nc -nv <IP> 143
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```

## Syntax

{% code overflow="wrap" fullWidth="true" %}
```bash
# Login
    A1 LOGIN username password
Values can be quoted to enclose spaces and special characters. A " must then be escape with a \
    A1 LOGIN "username" "password"

tag LIST "" "*"
tag SELECT INBOX
tag STATUS INBOX (MESSAGES)
tag fetch 1 (BODY[1])
tag fetch 2:5 BODY[HEADER] BODY[1]

# List Folders/Mailboxes
    A1 LIST "" *
    A1 LIST INBOX *
    A1 LIST "Archive" *

# Create new Folder/Mailbox
    A1 CREATE INBOX.Archive.2012
    A1 CREATE "To Read"

# Delete Folder/Mailbox
    A1 DELETE INBOX.Archive.2012
    A1 DELETE "To Read"

# Rename Folder/Mailbox
    A1 RENAME "INBOX.One" "INBOX.Two"

# List Subscribed Mailboxes
    A1 LSUB "" *

# Status of Mailbox (There are more flags than the ones listed)
    A1 STATUS INBOX (MESSAGES UNSEEN RECENT)

# Select a mailbox
    A1 SELECT INBOX

# List messages
    A1 FETCH 1:* (FLAGS)
    A1 UID FETCH 1:* (FLAGS)

# Retrieve Message Content
    A1 FETCH 2 body[text]
    A1 FETCH 2 all
    A1 UID FETCH 102 (UID RFC822.SIZE BODY.PEEK[])

# Close Mailbox
    A1 CLOSE

# Logout
    A1 LOGOUT
```
{% endcode %}
