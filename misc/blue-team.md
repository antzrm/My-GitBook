# Blue Team

{% code overflow="wrap" %}
```bash
# MITRE
https://medium.com/mitre-engenuity/introducing-the-all-new-adversary-emulation-plan-library-234b1d543f6b

# YARA
https://cuckoosandbox.org/
```
{% endcode %}

## Malware

{% tabs %}
{% tab title="First steps" %}
```bash
Check MD5 hash with Virustotal

Check obfuscation/packing of executables with PEiD
Whilst this tool has a huge database, it doesn't have every packer out there! 
Especially say if an Author has written their own - PeID will have no way 
of identifying the packer used. In cases like this, it's more about what
 PeID doesn't tell us - rather than what it does.
 
 If it's packed, open it with IDA Freeware
 Only few imports -- it's obfuscated
 
 Use Ghidra for static analysis
 
 # PACKING & ENTROPY -- DETECT IF AN EXECUTABLE WAS PACKED
 Not too many imports
 High entropy
 Use PEiD
```
{% endtab %}

{% tab title="REMnux" %}
{% code overflow="wrap" %}
```bash
https://remnux.org/
https://docs.remnux.org/

## PDF
# Inspection
peepdf demo_notsuspicious.pdf
# Script creation
echo 'extract js > javascript-from-demo_notsuspicious.pdf' > extracted_javascript.txt
# Javascript extraction
peepdf -s extracted_javascript.txt demo_notsuspicious.pdf

## MICROSOFT OFFICE MACROS
vmonkey DefinitelyALegitInvoice.doc
```
{% endcode %}
{% endtab %}
{% endtabs %}

## GPO

GPOs are distributed to the network via a network share called `SYSVOL`, which is stored in the DC. All users in a domain should typically have access to this share over the network to sync their GPOs periodically. The SYSVOL share points by default to the `C:\Windows\SYSVOL\sysvol\` directory on each of the DCs in our network.

{% code overflow="wrap" %}
```powershell
GPO > Default Domain Policy > New > User Configuration > Administrative Templates > Control Panel > Prohibit Control Panel # may be applied for some users
# Sync/Update GPOs changes immediately
PS C:\> gpupdate /force
```
{% endcode %}

## PDF

[https://www.kali.org/tools/pdfid/](https://www.kali.org/tools/pdfid/)

## osquery

{% code overflow="wrap" %}
```bash
# TABLE LIST
https://osquery.io/schema/4.7.0/

https://osquery.readthedocs.io/en/stable/deployment/yara/

# LINUX
yara /var/osquery/yara/scanner.yara /home/charlie/
SELECT * FROM yara WHERE path LIKE '/home/tryhackme/%' and sigfile='/var/osquery/yara/scanner.yara';

# WINDOWS
https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide
https://github.com/polylogyx/osq-ext-bin/blob/master/README.md
osqueryi --allow-unsafe --extension "C:\Program Files\osquery\extensions\osq-ext-bin\plgx_win_extension.ext.exe"
# Wait for the command prompt to reflect the phrase Done StartDriver. This will indicate that the extension is fully loaded into the session.
select * from win_event_log_channels where source like '%Sysmon%';
select eventid from win_event_log_data where source='Microsoft-Windows-Sysmon/Operational' order by datetime limit 1;
```
{% endcode %}

## DNS Poisoning

```bash
Check C:\Windows\System32\drivers\etc\hosts
```

## Windows Event Logs

```bash
Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="System"'

Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=15'

#Hunting for Common Back Connect Ports with PowerShell
Get-WinEvent  -Path <Path to Log> -FilterXPath '*/System/EventID=3 and  */EventData/Data[@Name="DestinationPort"] and  */EventData/Data=<Port>'

# Detecting LSASS Behavior with PowerShell
Get-WinEvent  -Path <Path to Log> -FilterXPath '*/System/EventID=10 and  */EventData/Data[@Name="TargetImage"] and  */EventData/Data="C:\Windows\system32\lsass.exe"'

# Hunting for open ports
Get-WinEvent  -Path <Path to Log> -FilterXPath '*/System/EventID=3 and  */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
```

## Volatility

At the time of writing, there are two versions of Volatility: [Volatility 2](https://github.com/volatilityfoundation/volatility), which is built using Python 2, and [Volatility 3](https://github.com/volatilityfoundation/volatility3), which uses Python 3. There are different use cases for each version, and depending on this, you might choose either one over the other. For example, Volatility 2 has been around for longer, so in some cases, it will have modules and plugins that have yet to be adapted to Volatility 3. For the purposes of this task, we're using Volatility 2.

{% code overflow="wrap" fullWidth="true" %}
```bash
https://downloads.volatilityfoundation.org/releases/2.4/CheatSheet_v2.4.pdf

######### VOLATILITY 2 WAS USED FOR THESE EXAMPLES
# Profiles (Linux profiles have to be manually created from the same device the memory dump is from)
vol.py --info
# To use a Linux profile, we have to copy it where Volatility stores the various profiles for Linux (~/.local/lib/python2.7/site-packages/volatility/plugins/overlays/linux/
https://beguier.eu/nicolas/articles/security-tips-3-volatility-linux-profiles.html

# Memory Analysis
vol.py -f memorydump.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" -h

############ PLUGINS
# History file
vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_bash
# Running processes
vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_pslist
# Process Extraction (extract binary process by specifing its PID)
mkdir extracted
vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_procdump -D extracted -p PID
# File Extraction (in this case looking for cron files)
vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_enumerate_files | grep -i cron 
# Extract specific file by indicating its inode value 0x...
vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_find_file -i $INODE -O extracted/elfie


python2 /opt/Hacking/TOOLS/volatility/vol.py -f memdump.elf --profile="Win7SP1x64" -h
# Check files included on the memory damp
python2 /opt/Hacking/TOOLS/volatility/vol.py -f memdump.elf --profile="Win7SP1x64" filescan
# Grep if a specific file is found (hex value id of every file is shown)
python2 /opt/Hacking/TOOLS/volatility/vol.py -f memdump.elf --profile="Win2008R2SP1x64_23418" filescan | grep -i FILE
# Dump a specific file by its hex id, we can rename it and dump it on the current directory)
python2 /opt/Hacking/TOOLS/volatility/vol.py -f memdump.elf --profile="Win7SP0x64" dumpfiles -Q 0x000000001c7e8500 --name file2 -D .


# List possible profiles
volatility -f MEMORY_FILE.raw imageinfo

# Test different profiles to find the good one / View active processes
volatility -f MEMORY_FILE.raw --profile=PROFILE pslist

# View active network connections 
volatility -f MEMORY_FILE.raw --profile=PROFILE netscan

# View intentionally hidden processes
... psxview

# Three columns will appear here in the middle, InLoad, InInit, InMem. If any of these are false, that module has likely been injected which is a really bad thing. 
... ldrmodules

# View unexpected patches in the standard system DLLs
# If we see an instance where Hooking module: <unknown> that's really bad.
... apihooks

# Check code injection and extract it. We can upload them to Virustotal to see the malware (for example, Trojan/Win32.CRIDEX where Cridex is the malware)
... malfind -D $DEST_PATH

# list all of the DLLs in memory
... dlllist

# See/Pull DLLs out of the abnormal process (process PID, optional destination)
volatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump (-D <Dest. Dir.>)

#####################
https://github.com/volatilityfoundation/volatility
https://github.com/volatilityfoundation/volatility3 # Faster but fewer plugins
# Installing Volatility 2
git clone <https://github.com/volatilityfoundation/volatility.git> # If Python 2 isn't installed sudo apt install python2 # To Install Pip 2 curl <https://bootstrap.pypa.io/pip/2.7/get-pip.py> -o get-pip.py python2 get-pip.py # Installing distorm 3 and pycryptdome pip2 install distorm3 pycryptodome
# Installing volatility 3
git clone <https://github.com/volatilityfoundation/volatility3> # Installing pycryptodome pip3 install pycryptodome
# Memory dump samples
https://github.com/pinesol93/MemoryForensicSamples
# Virtual Machine Files meaning
https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.vm_admin.doc/GUID-CEFF6D89-8C19-4143-8C26-4B6D6734D2CB.html
# VOLATILITY PLUGINS
vol3 banners # symbols, know OS and kernel versions
linux_bash # bash history
netscan / linux_netstat # ports
imageinfo # identify the profile (Win7SP1x64, Win2008R2SP0x64...)
pstree # running processes
strings file.vmem | grep # find some specific strings in memory dump
editbox # which popped up for getting user credentials
filescan # find files from the memory dump
dumpfiles -u -r pst$ -D pst_files # dump all files that end on pst to a directory called pst_files, -r for regex purposes -u unsafe
```
{% endcode %}

## Powershell - Hash files, strings, streams, hide connectors

{% code overflow="wrap" fullWidth="true" %}
```
# Obtain the hash of a file
Get-FileHash -Algorithm MD5 file.txt

\Tools\strings64.exe -accepteula file.exe
# n the output, you should notice a command related to ADS. You know this by the end of the Powershell command -Stream.

# View ADS
Get-Item -Path file.exe -Stream *

# We can use a built-in Windows tool, Windows Management Instrumentation, to launch the hidden file.
wmic process call create $(Resolve-Path file.exe:streamname)
```
{% endcode %}

Alternate Data Streams (ADS) is a file attribute specific to Windows NTFS (New Technology File System). Every file has at least one data stream ($DATA) and ADS allows files to contain more than one stream of data. Natively Window Explorer doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, but Powershell gives you the ability to view ADS for files.

Malware writers have used ADS to hide data in an endpoint, but not all its uses are malicious. When you download a file from the Internet unto an endpoint there are identifiers written to ADS to identify that it was downloaded from the Internet.

## Ransomware and Shadow Copy

Ransomware is a real threat that enterprise defenders and casual computer users need to defend & prepare against. According to Wikipedia, ransomware is a type of malware that threatens to publish the victim's data or perpetually block access to it unless a ransom is paid. It can be a frightening experience to log into a machine only to realize that malware has encrypted all of your important documents.

There are numerous security products that can be implemented in the security stack to catch this type of malware. If ransomware infects an endpoint, depending on the actual malware, there might be a decryptor made available by a security vendor. If not then you must rely on backups in order to restore your machines to the last working state, along with its files. Windows has a built-in feature that can assist with that.

The Volume Shadow Copy Service (VSS) coordinates the actions that are required to create a consistent shadow copy (also known as a snapshot or a point-in-time copy) of the data that is to be backed up.  (official definition)

Malware writers know of this Windows feature and write code in their malware to look for these files and delete them. Doing so makes it impossible to recover from a ransomware attack unless you have an offline/off-site backup. Not all malware deletes the volume shadow copies though.

Before diving into VSS on the endpoint let's talk briefly regarding the Task Scheduler.

The Task Scheduler enables you to automatically perform routine tasks on a chosen computer. Task Scheduler does this by monitoring whatever criteria you choose (referred to as triggers) and then executing the tasks when those criteria are met. (official definition)

Malware writers might have the malware create a scheduled task in order for the malware to run at a specific desired day/time or trigger. The Task Scheduler utility has been conveniently been placed in the taskbar for you. To view, the scheduled tasks click on Task Scheduler Library.  You should see 2 scheduled tasks of interest: 1 with a weird name and the other related to VSS. Click on any of the scheduled tasks to populate more information about it, such as Triggers and Actions.

At this point you should realize that VSS is enabled and thanks to the scheduled task you know the ID of the volume.

The command to interact with VSS is `vssadmin`. Running the command alone will display brief information on how to run the utility with additional commands. Two commands of particular interest are `List Volumes` and `List Shadows`.

![](https://assets.tryhackme.com/additional/sam-aoc2020/vssadmin1.png)

If you run `vssadmin list volumes` you will see that the C:\ drive has a different volume name/id. There must be another volume on the endpoint.

![](https://assets.tryhackme.com/additional/sam-aoc2020/vssadmin2.png)

You can use Disk Management to check into that. Disk Management is a system utility in Windows that enables you to perform advanced storage tasks. (official definition) As with the other utilities, Disk Management has been placed in the taskbar for your convenience.

As you can see there is another volume but you're unable to view it within Windows Explorer. Right-click the partition to view its properties. Now, look at the `Security` tab. Confirm that the volume name/id from the Task Scheduler and vssadmin output is similar to the `object name` of this partition.  Also, notice there is a tab titled `Shadow Copies`. Review the information and close the Properties window.

In order to see this partition within Windows Explorer, you must assign it a drive letter. Right-click the partition and select `Change Drive Letter and Paths`.  Click `Add`.  In the dropdown choose a letter, such as Z, and click OK.  At the top, in the Volume column, you should now see that the partition has a letter assigned to it. Open Windows Explorer to navigate to the partition.

In a previous challenge, you managed to view hidden content in folders via the command-line. You can do the same within Windows Explorer. In the menu, select `View`, and checkmark  `Hidden Items`. You should now see any hidden content right within Windows Explorer.

Back to VSS, to restore files to a previous version, simply right-click the folder and select `Properties` then select the `Previous Versions` tab.  Select which shadow copy you would like to restore and click the `Restore`button. Accept the confirmation to restore the shadow copy. Close the Properties window and drill into the folder to find the restore file(s).

