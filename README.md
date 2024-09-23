hcxtools
=========

A small set of tools to convert packets from capture files to hash files for use with Hashcat or John the Ripper. 

These tools are 100% compatible with Hashcat and John the Ripper and are endorsed by Hashcat.

Brief Description
------------------

The main purpose of hcxtools is to detect weak points within one's own WiFi network by analyzing the hashes.
Therefore, the conversion of the dump file to WPA-PBKDF2-PMKID+EAPOL hash file allows the user to check if the WLAN-KEY or PMK was transmitted unencrypted.
Or upload the "uncleaned" dump file (pcapng, pcap, cap) [here](https://wpa-sec.stanev.org/?submit) to find out if your AP or the CLIENT is vulnerable by using common wordlists or a weak password generation algorithm.

* Support for Hashcat hash-modes: 4800, 5500, 2200x, 16100, 250x (deprecated), and 1680x (deprecated).
  
* Support for John the Ripper hash-modes: WPAPSK-PMK, PBKDF2-HMAC-SHA1, chap, netntlm, and tacacs-plus.

* Support for gzip (.gz) single file compression.

An overview of Hashcat mode 22000. - (https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)

Old but still applicable write-up by **atom** of the Hashcat forums covering a new attack on WPA/WPA2 using PMKID. - (https://hashcat.net/forum/thread-7717.html)

Hashcat mode 22000 write-up by **atom** of the Hashcat forums. - (https://hashcat.net/forum/thread-10253.html)

**Unsupported:** Windows OS, macOS, Android, emulators or wrappers!

What Don't hcxtools Do?
------------------------

* They do not crack WPA PSK related hashes. (Use Hashcat or JtR to recover the PSK.)

* They do not crack WEP. (Use the aircrack-ng suite instead.)

* They do not crack WPS. (Use Reaver or Bully instead.)

* They do not decrypt encrypted traffic. (Use tshark or Wireshark to do so.)

Detailed Description
---------------------

| Tool           | Description                                                                                                            |
| -------------- | ---------------------------------------------------------------------------------------------------------------------- |
| hcxpcapngtool  | Tool to convert raw capture files to Hashcat and JtR readable formats.                                                 |
| hcxhashtool    | Tool to filter hashes from HC22000 files based on user input.                                                          |
| hcxpsktool     | Tool to get weak PSK candidates from hash files or user input.                                                         |
| hcxpmktool     | Tool to calculate and verify a PSK and/or a PMK.                                                                       |
| hcxeiutool     | Tool to prepare -E -I -U output of hcxpcapngtool for use by Hashcat + rule or JtR + rule.                              |
| hcxwltool      | Tool to calculate candidates for Hashcat and JtR based on mixed wordlists.                                             |
| hcxhash2cap    | Tool to convert hash files (PMKID&EAPOL, PMKID, EAPOL-hccapx, EAPOL-hccap, WPAPSK-john) to cap.                        |
| wlancap2wpasec | Tool to upload multiple (gzip compressed) pcapng, pcap and cap files to https://wpa-sec.stanev.org                     |
| whoismac       | Tool to show vendor information and/or download oui reference list.                                                    |

Workflow
---------

hcxdumptool -> hcxpcapngtool -> hcxhashtool (additional hcxpsktool/hcxeiutool) -> hashcat or JtR

Install Guide
--------------

On most distributions hcxtools are available through the package manager.

If you decide to compile latest git head, make sure that your distribution is updated to it's latest version and make sure that all header files and dependencies have been installed!

### Clone Repository
---------------------

```
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools
```

### Compile & Install
----------------------

```
make -j $(nproc)
```

Install to `/usr/bin`:
```
make install (as super user)
```

Or install to `/usr/local/bin`:
```
make install PREFIX=/usr/local (as super user)
```

Requirements
--------------

* Knowledge of radio technology.
* Knowledge of electromagnetic-wave engineering.
* Detailed knowledge of 802.11 protocol.
* Detailed knowledge of key derivation functions.
* Detailed knowledge of Linux
* Operating system: Linux (recommended: kernel >= 6.4, mandatory: kernel >= 5.10)
* Recommendation: Arch Linux (notebooks and desktop systems), OpenWRT (small systems like Raspberry Pi, WiFi router)
* gcc >= 13 recommended (deprecated versions are not supported: https://gcc.gnu.org/)
* libopenssl (>= 3.0) and openssl-dev installed
* librt and librt-dev installed. (Should be installed by default.)
* zlib and zlib-dev installed. (For gzip compressed cap/pcap/pcapng files.)
* libcurl (>= 7.56) and curl-dev installed. (Used by whoismac and wlancap2wpasec.)
* pkg-config installed.
* Make sure that the version of hcxpcapngtool always fits to the version of hcxdumptool 

**If you decide to compile latest git head, make sure that your distribution is updated to it's latest version!**

Useful Scripts
---------------

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| piwritecard  | Example script to restore SD-Card                        |
| piwreadcard  | Example script to backup SD-Card                         |
| hcxgrep.py   | Extract records from m22000 hashline/hccapx/pmkid file based on regexp   |

Notice
-------

* Most output files will be appended to existing files (with the exception of pcapng, pcap, cap files).

* It is recommended to use hash mode 22000 (22001) instead of deprecated hash modes 2500 (2501) and 16800 (16801).

* hcxtools are designed to be analysis tools. This means that everything is converted by default and unwanted information must be filtered out! 

**Warning:** Do not merge dump files! This WILL destroy hash values assigned by custom blocks!

* Tools do not perform NONCE ERROR CORRECTIONS! In case of a packet loss, you'll get a wrong PTK.

* This branch is pretty closely synced to the Hashcat and John the Ripper repositories.

Bitmask Message Pair Field (hcxpcapngtool)
-------------------------------------------

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

Warning
--------

You might expect me to recommend that everyone should be using hcxdumptool/hcxtools. But the fact of the matter is, hcxdumptool/hcxtools is NOT recommended to be used by inexperienced users or newbies.

If you are not familiar with Linux in general or you do not have at least a basic level of knowledge as mentioned in section "Requirements", hcxdumptool/hcxtools is probably not what you are looking for.
However, if you have that knowledge hcxdumptool/hcxtools can do magic for you.

The entire toolkit (hcxdumptool and hcxtools) is designed to be an analysis toolkit. 

Useful Links
--------------

https://pcapng.com/

https://www.kernel.org/doc/html/latest/

https://www.kernel.org/doc/html/latest/bpf/index.html

https://www.freecodecamp.org/news/the-linux-commands-handbook/

https://en.wikipedia.org/wiki/Wpa2

https://en.wikipedia.org/wiki/802.11_Frame_Types

https://en.wikipedia.org/wiki/IEEE_802.11i-2004
