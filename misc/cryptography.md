# Cryptography

{% hint style="danger" %}
If we have a base64 encode that outputs gibberish after decode, it is most likely encrypted.
{% endhint %}

## RSA

{% code overflow="wrap" fullWidth="true" %}
```python
Prime numbers -> p, q
If we get p q we can 
f = open("/root/.ssh/id_rsa")
key = RSA.importKey(f.read())
key # p q only available if private key


# PYTHON SCRIPT
from Crypto.PublicKey import RSA

p = 
q = 
n = p*q
e = 65537
m = n-(p+q-1)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
        
d = modinv(e, m)

key = RSA.construct(n, e, d, p, q)
print(key.exportKey())

We already have private.pem
openssl rsa -in private.pem -pubout # now we have private and public key
# Cypher message.txt
openssl pkeyutl -encrypt -inkey public.pem -pubin -in message.txt

##### Python decrypt script
from Crypto.PublicKey import RSA
f = open("public.pem")
key = RSA.importKey(f.read())

# Website factordb.com factorizes p,q from n
n = key.n
p = # value found 
q = # value found
e = 65537
...
# Part of the script we saw before



# Factorize n into p,q
from sympy.ntheory import factorint
factorint($n)
# Another option to factorize:
https://sagecell.sagemath.org/
n = ....
factor(n)
# Tool
https://github.com/RsaCtfTool/RsaCtfTool
python RsaCtfTool.py --private -n ...
python RsaCtfTool.py --createpub -n ...


########################################################################

└─$ cat rsa.py                      
import math

def find_factors(n):
    # Start with 2 and check for divisibility up to the square root of n
    for i in range(2, math.isqrt(n) + 1):
        if n % i == 0:
            p = i
            q = n // i
            return p, q
    return None  # In case no factors are found (n is prime)

# Example usage
n = 148850198159038150435668136595790479899500260139999323253838008250558541325709310780669825450205537293838513838572476075322448214337566888625882555747192879754285324762834221764209408942441503910742882028226616072659338878605288072813773852723842396297735201327436314188068695317133522061791222239167471912518199817  # Replace with your value of n
p, q = find_factors(n)

if p and q:
    print(f"The prime factors of n are p = {p} and q = {q}")
else:
    print("No factors found, n might be prime or too large.")



└─$ cat signature.py
#!/usr/bin/python3

from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sympy
import jwt
from datetime import *

# Generate RSA key pair
q = 1041853
n = 148850198159038150435668136595790479899500260139999323253838008250558541325709310780669825450205537293838513838572476075322448214337566888625882555747192879754285324762834221764209408942441503910742882028226616072659338878605288072813773852723842396297735201327436314188068695317133522061791222239167471912518199817 #sympy.randprime(2**1023, 2**1024) * q
e = 65537
p = 142870633533750107199065642269869626424745391278807397256463251774058856024515273057398524984048169265566748705021222835968652213256156951725322627805643291092203338439140859376715725675734968283186670315511512730355759285240132794946862803796545574373481864838356576396160202367448691957302251122919905123389
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)
key_data = {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}
key = RSA.construct((key_data['n'], key_data['e'], key_data['d'], key_data['p'], key_data['q']))
private_key_bytes = key.export_key()

private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()

payload = {
                        'email': 'test@test.com',
                        'role': 'administrator',
                        'iat': datetime.now(timezone.utc),
                        'exp': datetime.now(timezone.utc) + timedelta(seconds=3600),
                        'jwk':{'kty': 'RSA',"n": n,"e": 65537}
                    }

encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

print(encoded_jwt)
```
{% endcode %}

## AES

{% hint style="info" %}
We need at least **Key** (usually is in hex and seems MD5 hash) and the **input** (usually base64 encoded)
{% endhint %}

{% code overflow="wrap" %}
```python
# On Cyberchef we put From Base64 and AES Decrypt, place input, place key on AES Decrypt, choose mode ECB or try others, and the Input choose Raw 

pip3 install pyaes

# Script
import pyaes 
from base64 import b64decode 
key = b"" 
iv = b"" 
aes = pyaes.AESModeOfOperationCBC(key, iv = iv) 
decrypted = aes.decrypt(b64decode('')) print(decrypted.decode())

python3 decrypt.py

https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.ciphermode?view=netcore-3.1
```
{% endcode %}

## OpenSSL

```sh
https://github.com/thosearetheguise/decrypt-openssl-bruteforce
apt install bruteforce-salted-openssl
Alternative: openssl2john  
```

## ECC attacks (eliptic curves)

[https://github.com/elikaski/ECC\_Attacks?tab=readme-ov-file#ECC-Attacks](https://github.com/elikaski/ECC_Attacks?tab=readme-ov-file#ECC-Attacks)

## EFS - Windows

```bash
https://en.wikipedia.org/wiki/Encrypting_File_System
cipher /c [file] # to see if the file is encrypted and who can decrypt it
# To use cipher command, we need to migrate to a console process (session=1)
```

