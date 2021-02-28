hcxtools
==============

Small set of tools convert packets from captures (h = hash, c = capture, convert and
calculate candidates, x = different hashtypes) for the use with latest hashcat
or John the Ripper. The tools are 100% compatible to hashcat and John the Ripper
and recommended by hashcat. This branch is pretty closely synced to hashcat git branch
(that means: latest hcxtools matching on latest hashcat beta) and John the Ripper
git branch ("bleeding-jumbo").

Support for hashcat hash-modes: 4800, 5500, 2200x, 16100, 250x (deprecated), 1680x (deprecated)
  
Support for John the Ripper hash-modes: WPAPSK-PMK, PBKDF2-HMAC-SHA1, chap, netntlm, tacacs-plus

After capturing, upload the "uncleaned" cap here (https://wpa-sec.stanev.org/?submit)
to see if your ap or the client is vulnerable by using common wordlists.
Convert the dump file to WPA-PBKDF2-PMKID+EAPOL hash file and check if wlan-key
or plainmasterkey was transmitted unencrypted.


Brief description
--------------

Multiple stand-alone binaries - designed to run on  Arch Linux.

All of these utils are designed to execute only one specific function.

hcxdumptool moved to: https://github.com/ZerBea/hcxdumptool

Read this post: hcxtools - solution for capturing wlan traffic and conversion to hashcat formats (https://hashcat.net/forum/thread-6661.html)

Read this post: New attack on WPA/WPA2 using PMKID (https://hashcat.net/forum/thread-7717.html)


Detailed description
--------------

| Tool           | Description                                                                                                            |
| -------------- | ---------------------------------------------------------------------------------------------------------------------- |
| hcxpcapngtool  | Provide new hashcat format 22000                                                                                       |
| hcxhashtool    | Provide various filter operations on new PMKID/EAPOL hash line                                                         |
| hcxpsktool     | Calculates candidates for hashcat and john based on based on hcxpcapngtool output or commandline input                 |
| hcxpmktool     | Calculate and verify a PSK and/or a PMK                                                                                |
| hcxeiutool     | Prepare -E -I -U output of hcxpcapngtool for use by hashcat + rule or JtR + rule                                       |
| hcxwltool      | Calculates candidates for hashcat and john based on mixed wordlists                                                    |
| hcxhash2cap    | Converts hash file (PMKID&EAPOL, PMKID, EAPOL-hccapx, EAPOL-hccap, WPAPSK-john) to cap                                 |
| wlancap2wpasec | Upload multiple (gzip compressed) pcapng, pcap and cap files to https://wpa-sec.stanev.org                             |
| whoismac       | Show vendor information and/or download oui reference list                                                             |


| deprecated     | obsolete and - no longer under maintenance - will be removed, when OpenSSL switching to version 3.0.0                  |
| -------------- | ---------------------------------------------------------------------------------------------------------------------- |
| hcxmactool     | Various MAC based filter operations on HCCAPX and PMKID files - convert hccapx and/or PMKID to new hashline format     |
| hcxpmkidtool   | CPU based tools to verify a PMKID                                                                                      |
| hcxessidtool   | Various ESSID based filter operations on HCCAPX and PMKID files                                                        |
| hcxhashcattool | Convert old hashcat (<= 5.1.0) separate potfile (2500 and/or 16800) to new potfile format                              |


Get source
--------------
```
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools
```

Compile
--------------
```
make
make install (as super user)
```

Or install via packet manager of your distribution
--------------

### Arch Linux
[Arch Linux](https://www.archlinux.org/) 
`pacman -S hcxtools`

### Arch Linux ARM
[Arch Linux ARM ](https://archlinuxarm.org/) 
`pacman -S hcxtools`

### Black Arch
[Black Arch](https://blackarch.org/) is an Arch Linux-based penetration testing distribution for penetration testers and security researchers  
`pacman -S hcxtools`

### Kali Linux
`apt install hcxtools`


### macOS
[Homebrew](https://brew.sh/) is 3-rd party package manager for macOS  
`brew install hcxtools`


Requirements
--------------

* Linux (recommended Arch Linux, but other distros should work, too (no support for other distributions).

* gcc 10 recommended (deprecated versions are not supported: https://gcc.gnu.org/)

* libopenssl and openssl-dev installed

* librt and librt-dev installed (should be installed by default)

* zlib and zlib-dev installed (for gzip compressed cap/pcap/pcapng files)

* libcurl and curl-dev installed (used by whoismac and wlancap2wpasec)

* libpthread and pthread-dev installed (used by hcxhashcattool)

* pkg-config installed

To install requirements on Kali use the following 'apt-get install pkg-config libcurl4-openssl-dev libssl-dev zlib1g-dev'


Useful scripts
--------------

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| piwritecard  | Example script to restore SD-Card                        |
| piwreadcard  | Example script to backup SD-Card                         |
| hcxgrep.py   | Extract records from hccapx/pmkid file based on regexp   |


Notice
--------------

Most output files will be appended to existing files (with the exception of pcapng, pcap, cap files).

It is recommended to use hash mode 22000 (22001) instead of deprecated hash modes 2500 (2501) and 16800 (16801)


Bitmask message pair field (hcxpcapngtool)
--------------

bit 0-2

000 = M1+M2, EAPOL from M2 (challenge)

001 = M1+M4, EAPOL from M4 if not zeroed (authorized)

010 = M2+M3, EAPOL from M2 (authorized)

011 = M2+M3, EAPOL from M3 (authorized) - unused"

100 = M3+M4, EAPOL from M3 (authorized) - unused"

101 = M3+M4, EAPOL from M4 if not zeroed (authorized)"

3: reserved

4: ap-less attack (set to 1) - no nonce-error-corrections necessary

5: LE router detected (set to 1) - nonce-error-corrections only for LE necessary

6: BE router detected (set to 1) - nonce-error-corrections only for BE necessary

7: not replaycount checked (set to 1) - replaycount not checked, nonce-error-corrections definitely necessary

