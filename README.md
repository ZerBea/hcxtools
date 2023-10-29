hcxtools
==============

Small set of tools convert packets from captures (h = hash, c = capture, convert and calculate candidates, x = different hashtypes) for the use with latest hashcat or John the Ripper. 
The tools are 100% compatible to hashcat and John the Ripper and recommended by hashcat.


Brief description
--------------

Main purpose is to detect weak points within own WiFi networks by analyzing the hashes.
Therefore convert the dump file to WPA-PBKDF2-PMKID+EAPOL hash file and check if wlan-key or plainmasterkey was transmitted unencrypted.
Or upload the "uncleaned" dump file (pcapng, pcap, cap) here https://wpa-sec.stanev.org/?submit to find out if your ap or the client is vulnerable by using common wordlists or a weak password generation algorithm.

This branch is pretty closely synced to hashcat git and John the Ripper git.

Support of hashcat hash-modes: 4800, 5500, 2200x, 16100, 250x (deprecated), 1680x (deprecated)
  
Support of John the Ripper hash-modes: WPAPSK-PMK, PBKDF2-HMAC-SHA1, chap, netntlm, tacacs-plus

Support of gzip (.gz) single file compression.

Unsupported: Windows OS, macOS, Android, emulators or wrappers!

Read this post: hcxtools - solution for capturing wlan traffic and conversion to hashcat formats (https://hashcat.net/forum/thread-6661.html)

Read this post: New attack on WPA/WPA2 using PMKID (https://hashcat.net/forum/thread-7717.html)

Read this post: Hash mode 22000 explained (https://hashcat.net/forum/thread-10253.html)

Read this wiki: https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2


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


Workflow
--------------

hcxdumptool -> hcxpcapngtool -> hcxhashtool (additional hcxpsktool/hcxeiutool) -> hashcat or JtR

hcxdumptool: attack and capture everything (depending on options)

hcxpcapngtool: convert everything

hcxhashtool: filter hashes

hcxpsktool: get weak PSK candidates

hcxeiutool: calculate wordlists from ESSID
 
hashcat or JtR: get PSK from hash


Get source
--------------
```
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools
```

Compile & install
--------------
```
make
```

install to `/usr/bin`:
```
make install (as super user)
```

or install to `/usr/local/bin`:
```
make install PREFIX=/usr/local (as super user)
```

Or install via package manager of your distribution
--------------

### Arch Linux
[Arch Linux](https://www.archlinux.org/) 
`pacman -S hcxtools`

### Arch Linux ARM
[Arch Linux ARM ](https://archlinuxarm.org/) 
`pacman -S hcxtools`

### BlackArch
[Black Arch](https://blackarch.org/) is an Arch Linux-based penetration testing distribution for penetration testers and security researchers  
`pacman -S hcxtools`

### Fedora/CentOS
`dnf install hcxtools`

### Kali Linux
`apt install hcxtools`

### OpenWRT
`opkg install hcxtools`

### macOS
[Homebrew](https://brew.sh/) is 3-rd party package manager for macOS  
`brew install hcxtools`


Requirements
--------------

* knowledge of radio technology
* knowledge of electromagnetic-wave engineering
* detailed knowledge of 802.11 protocol
* detailed knowledge of key derivation functions
* detailed knowledge of Linux
* operating system: Linux (strict)
* distribution: recommended Arch Linux, but other distros should work, too (no support for other distributions).
* gcc >= 13 recommended (deprecated versions are not supported: https://gcc.gnu.org/)
* libopenssl (>= 3.0) and openssl-dev installed
* librt and librt-dev installed (should be installed by default)
* zlib and zlib-dev installed (for gzip compressed cap/pcap/pcapng files)
* libcurl (>= 7.56) and curl-dev installed (used by whoismac and wlancap2wpasec)
* pkg-config installed

Debian (e.g. Kali, Ubuntu) release requirements >= bookworm (testing/Debian 12)  
To install use the following:  
`apt-get install pkg-config libcurl4-openssl-dev libssl-dev zlib1g-dev make gcc`

If you decide to compile latest git head, make sure that your distribution is updated on latest version.

Useful scripts
--------------

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| piwritecard  | Example script to restore SD-Card                        |
| piwreadcard  | Example script to backup SD-Card                         |
| hcxgrep.py   | Extract records from m22000 hashline/hccapx/pmkid file based on regexp   |


Notice
--------------

Most output files will be appended to existing files (with the exception of pcapng, pcap, cap files).

It is recommended to use hash mode 22000 (22001) instead of deprecated hash modes 2500 (2501) and 16800 (16801)

hcxtools are designed to be analysis tools. This means that everything is converted by default and unwanted information must be filtered out! 

Warning: do not merge (pcapng) dump files, because this destroys hash values, assigned by custom blocks.


Bitmask message pair field (hcxpcapngtool)
--------------

bit 0-2

000 = M1+M2, EAPOL from M2 (challenge)

001 = M1+M4, EAPOL from M4 if not zeroed (authorized)

010 = M2+M3, EAPOL from M2 (authorized)

011 = M2+M3, EAPOL from M3 (authorized) - unused

100 = M3+M4, EAPOL from M3 (authorized) - unused

101 = M3+M4, EAPOL from M4 if not zeroed (authorized)

3: reserved

4: ap-less attack (set to 1) - no nonce-error-corrections necessary

5: LE router detected (set to 1) - nonce-error-corrections only for LE necessary

6: BE router detected (set to 1) - nonce-error-corrections only for BE necessary

7: not replaycount checked (set to 1) - replaycount not checked, nonce-error-corrections definitely necessary


Important notice:
--------------
tools do not do NONCE ERROR CORRECTIONS
in case of a packet loss, you get a wrong PTK


Warning:
--------------

You might expect me to recommend that everyone should be using hcxdumptool/hcxtools. But the fact of the matter is, however, that hcxdumptool/hcxtools is NOT recommended to be used by unexperienced users or newbees.
If you are not familiar with Linux generally or if you do not have at least a basic level of knowledge as mentioned in section "Requirements", hcxdumptool/hcxtools is probably not what you are looking for.
However, if you have that knowledge there’s no better toolkit than hcxdumtool/hcxtools.

The entire toolkit (hcxdumptool and hcxtools) is designed to be an analysis toolkit. 
