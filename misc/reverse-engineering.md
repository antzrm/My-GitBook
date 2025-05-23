# Reverse Engineering



{% embed url="https://github.com/mandiant/flare-floss" %}

{% embed url="https://x64dbg.com/" %}

```bash
└─$ strings heedv1\ Setup\ 1.0.0.exe -n 12 | sort -u | grep 'http'

# List .exe on Linux
7z l file.exe
#Decompress .exe on Linux
7z e file.exe
```

## Windows binaries

{% code overflow="wrap" %}
```bash
strings file.exe -e l

# dotPeek
https://www.jetbrains.com/decompiler/

# Password Decryption. To decipher a password, we usually need:
- IV (Initialization Vector)
- Key
- Password (encrypted)
- Kind of cipher (AES for example)
# To achieve this, try to get those variables
strings file.exe -e l
strings file.dll -e l
# Once we get it, we can use Cyberchef, select Decrypt module, type Key and IV with UTF8 format and then Input/Output Raw if that is the format
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (73).png" alt=""><figcaption></figcaption></figure>

## Linux binaries

### strings

{% code overflow="wrap" %}
```bash
# There are other "strings" that are not visible directly with the common strings binary
strings -h
...
  -e --encoding={s,S,b,l,B,L} Select character size and endianness:                   
                            s = 7-bit, S = 8-bit, {b,l} = 16-bit, {B,L} = 32-bit  
                            
...
# Try these and some more in case there is more hidden text
strings -e l ./binary
strings -e L ./binary
```
{% endcode %}

### xxd

```bash
# Inspect all 
xxd file
# Searching for specific strings
└─$ xxd password-manager | grep -i password -C 5 
00001fd0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001fe0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00001ff0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00002000: 0100 0200 0000 0000 0000 0000 0000 0000  ................
00002010: 5765 6c63 6f6d 6520 746f 204a 6f73 6820  Welcome !.......
00002040: 6e74 6572 2079 6f75 7220 6d61 7374 6572  nter your master
00002050: 2070 6173 7377 6f72 643a 2000 0053 0061   password: ..S.a
00002060: 006d 0070 006c 0065 0000 0000 0000 0000  .m.p.l.e........
00002070: 4163 6365 7373 2067 7261 6e74 6564 2120  Access granted! 
00002080: 4865 7265 2069 7320 6372 6564 7320 2100  Here is creds !.
```

### gHidra

```
File > New Project
File > Import file
Drag the binary to the dragon icon
Analyze the binary > Yes > Analyze
Then go to Functions > main > Look for Listing and Decompile windows
To search for strings > Search > Program Text > Selected Fields or All Fields

Right click > References... or Tools > Function call graph
```

## Wireshark

Sniff traffic while we run/try .exe

## dnSpy

{% code overflow="wrap" fullWidth="true" %}
```sh
https://github.com/dnSpy/dnSpy

Has the ability to allow editing code and save it on the same .exe so that is useful to alter the executable behaviour, decrypt stuff moving functions, print messages, etc.
Edit C# > then Compile > then we can run .exe as the edited executable
We can use this to delete optional/disturbing code or to write variable values such as 
Console.WriteLine("The password is:")
Console.WriteLine(function.Password)
```
{% endcode %}

### on Linux using Wine

```
sudo apt install wine64 -y 
https://github.com/0xd4d/dnSpy/releases
unzip dnSpy-netcore-win64.zip 
cd dnSpy-netcore-win64 
wine dnSpy.exe
```

## SYSCALL

If we Dissasemble the code and find syscall, we have to check which register is pushed following this guide. By doing so, we will know which instructions are used: [https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86\_64-64\_bit](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit)

## Windows

### Outlook - pffexport OST, PAB, PST

```
https://manpages.ubuntu.com/manpages/jammy/man1/pffexport.1.html
     pffexport — exports items stored in a Personal Folder File (OST, PAB and PST)
```

## electron

```bash
# asar electron files
sudo apt install nodejs npm
└─$ sudo npm install -g asar       
asar file.asar
asar ef file.asar $FILE_TO_EXTRACT
```
