# Stego

{% embed url="https://book.hacktricks.xyz/stego/stego-tricks" %}

{% embed url="https://0xrick.github.io/lists/stego" %}

{% embed url="https://github.com/RickdeJager/stegseek" %}

## Excel to txt

Rename as .zip, unzip it and open SharedStrings.xml. If it does not exist, there is not text on the file.

## PDF to text (pdf2text)

```
https://github.com/jalan/pdftotext
https://github.com/spatie/pdf-to-text

└─$ for i in $(ls); do pdftotext $i; done

└─$ grep -ri password .                             

└─$ cat file.txt
```

{% code overflow="wrap" %}
```bash
file $file

# exiftool
# Sometimes important stuff is hidden in the metadata of the image or the file, exiftool can be very helpful to view the metadata of the files. 
exiftool file # shows the metadata of the given file

pngcheck

zsteg # for PNG and BMP
# Zsteg is a Ruby tool that detects hidden data in PNG and BMP images. 
gem install zsteg 
zsteg -a file # Runs all the methods on the given file 
zsteg -E file # Extracts data from the given payload 
# (example : zsteg -E b4,bgr,msb,xy name.png)
```
{% endcode %}

stegnow [http://manpages.ubuntu.com/manpages/bionic/man1/stegsnow.1.html](http://manpages.ubuntu.com/manpages/bionic/man1/stegsnow.1.html)

## Steghide

Hides data in various kinds of image and audio files , only supports these file formats : JPEG, BMP, WAV and AU. but it’s also useful for extracting embedded and encrypted data from other files.&#x20;

```
steghide info file
steghide extract -sf file
```

## Stegsolve

Sometimes there is a message or a text hidden in the image itself and in order to view it you need to apply some color filters or play with the color levels. [https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)

## Stegcracker

[https://github.com/Paradoxis/StegCracker](https://github.com/Paradoxis/StegCracker) A tool that bruteforces passwords using steghide

## Strings

It is a linux tool that displays printable strings in a file. That simple tool can be very helpful when solving stego challenges. Usually the embedded data is password protected or encrypted and sometimes the password is actaully in the file itself and can be easily viewed by using strings

## foremost

Foremost is a program that recovers files based on their headers , footers and internal data structures , I find it useful when dealing with png images.&#x20;

```bash
foremost -i file # extracts data from the given file.
```

## Binwalk

Searching binary files like images and audio files for embedded files and data. [https://github.com/ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)&#x20;

```bash
binwalk file # Displays the embedded data in the given file 
binwalk -e file # Displays and extracts the data from the given file
```

## Wavsteg

Python3 tool that can hide data and files in wav files and can also extract data from wav files. [https://github.com/ragibson/Steganography#WavSteg](https://github.com/ragibson/Steganography#WavSteg)&#x20;

```bash
# extracts data from a wav sound file and outputs the data into a new file
python3 WavSteg.py -r -s soundfile -o outputfile 
```

## WAV to Morse Decoder

[https://morsecode.world/international/decoder/audio-decoder-adaptive.html](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)

## Sonic visualizer

Viewing and analyzing the contents of audio files, however it can be helpful when dealing with audio steganography. You can reveal hidden shapes in audio files. [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

## Steganography text decoder

[https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder) A web tool for unicode steganography , it can encode and decode text.

[https://www.bertnase.de/npiet/npiet-execute.php](https://www.bertnase.de/npiet/npiet-execute.php) an online interpreter for piet. piet is an esoteric language , programs in piet are images. read more about piet

## Dcode

[https://www.dcode.fr/](https://www.dcode.fr/) Sometimes when solving steganography challenges you will need to decode some text. dcode.fr has many decoders for a lot of ciphers and can be really helpful.

## Fcrackzip

Sometimes the extracted data is a password protected zip , this tool bruteforces zip archives. It can be installed with apt fcrackzip -u -D -p wordlist.txt file.zip : bruteforces the given zip file with passwords from the given wordlist

Hex editor flags code morse code What kind of encoding uses dashes and dots? // MORSE DECODER

Link for compare cats pictures Convert to hex ---> xxd .jpg > .hex diff to see changes --> diff file1.hex file2.hex (se puede usar después | cut como complemento)

## xdg-open

It will use the default program to open a file on Linux
