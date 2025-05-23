# Forensics / Incident Response

* Static acquisition: A bit-by-bit image of the disk is created while the device is turned off.
* Live acquisition: A bit-by-bit image of the disk is created while the device is turned on.
* Logical acquisition: A select list of files is copied from the seized device.
* Sparse acquisition: Select fragments of unallocated data are copied. The unallocated areas of the disk might contain deleted data; however, this approach is limited compared to static and live acquisition because it doesn’t cover the whole disk.

Computer that's switched off

We use a write blocker, a hardware device that makes it possible to clone a disk without any risk of modifying the original data.

We rely on our forensic imaging software to get the raw image or equivalent. This would create a bit-by-bit copy of the disk.

Finally, we need a suitable storage device to save the image.

Computer that's switched on -> Acquire live data + RAM

## Smartphone

First put the phone in a Faraday bag. A Faraday bag prevents the phone from receiving any wireless signal, meaning nobody can’t wipe its data remotely.

Tools: adb, [https://www.autopsy.com/](https://www.autopsy.com/)

Unlock the phone and

{% code fullWidth="true" %}
```bash
# Logical image -f backup_file, but not all apps can be backed up 
adb backup -all -f android_backup.ab
# Once we root the phone
adb shell
generic_x86:/ # whoami
root
generic_x86:/ # mount | grep data    
[...]
/dev/block/dm-0 on /data type ext4 (rw,seclabel,nosuid,nodev,noatime,errors=panic,data=ordered)
[...]
adb pull /dev/block/dm-0 Android-McGreedy.img
# Now create a case on Autopsy and import the file as Image Disk
```
{% endcode %}

## Malicious executables

{% code overflow="wrap" fullWidth="true" %}
```bash
/windows/prefetch/malware.exe -> inside prefetch marks first time a executable was run on the system
dcontrol.exe
dllhost.exe -> injecting dll
/quarantine 
```
{% endcode %}
