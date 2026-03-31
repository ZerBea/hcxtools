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
| hcxpmktool     | Tool to calculate and verify a PSK and/or a PMK.                                                                       |
| hcxpottool     | Tool to to handle ASCII format and several UTF formats of hashcat's pot file.                                          |
| hcxpsktool     | Tool to get weak PSK candidates from hash files or user input.                                                         |
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

You might expect me to recommend that everyone should be using hcxdumptool/hcxtools. But the fact of the matter is, however, that hcxdumptool/hcxtools is NOT recommended to be used by unexperienced users or newbies.
If you are not familiar with Linux generally or if you do not have at least a basic level of knowledge as mentioned in section "Requirements", hcxdumptool/hcxtools is probably not what you are looking for.
However, if you have that knowledge this tools can do magic.

* Knowledge of radio technology.
* Knowledge of electromagnetic-wave engineering.
* Detailed knowledge of 802.11 protocol.
* Detailed knowledge of key derivation functions.
* Detailed knowledge of NMEA 0183 protocol.
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
| pireadcard   | Example script to backup SD-Card                         |
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

Each EAPOL hash in the `WPA*02*` hash line is built from two handshake
messages. One message provides the EAPOL frame (which contains the MIC
to verify against and one nonce already embedded at byte offset 17). The
other message provides the second nonce that is not present in the frame.
Together they give hashcat everything it needs: ANonce + SNonce + MIC +
EAPOL frame.

### Why 12 theoretical combos become 6 message pairs with 3 unique hashes

There are three independent choices when building a hash from a complete
4-way handshake:

- **ANonce source**: M1 or M3 (2 choices)
- **SNonce source**: M2 or M4 (2 choices)
- **EAPOL/MIC source**: M2, M3, or M4 (3 choices, M1 has no MIC)

That gives 2 x 2 x 3 = **12 theoretical combinations**.

But the EAPOL frame already contains one nonce embedded at byte offset
17 (SNonce in M2/M4, ANonce in M3). Hashcat extracts that automatically.
It only needs the *other* nonce supplied externally. So the real model
is: 3 EAPOL sources x 2 external nonce sources = **6 message pairs**.

Within one handshake session, M1 and M3 carry the same ANonce value, and
M2 and M4 carry the same SNonce value. Swapping which message the
external nonce came from doesn't change the nonce itself. So each pair
of message pairs that share the same EAPOL source produces an identical
hash. 6 pairs collapse to **3 unique hashes**, one per EAPOL source.

### Bits 0-2: Message Pair Type

Rows are grouped by EAPOL source (Hash 1/2/3). Pairs within the same
group produce identical crackable hashes.

| ID   | Bits | Hex  | Messages | EAPOL from        | External Nonce | Unique Hash | Status |
|------|------|------|----------|-------------------|----------------|-------------|--------|
| N1E2 | 000  | 0x00 | M1+M2    | M2 (MIC + SNonce) | M1 (ANonce)    | Hash 1      | challenge, default |
| N3E2 | 010  | 0x02 | M2+M3    | M2 (MIC + SNonce) | M3 (ANonce)    | Hash 1      | authorized, default |
| N2E3 | 011  | 0x03 | M2+M3    | M3 (MIC + ANonce) | M2 (SNonce)    | Hash 2      | authorized, --all |
| N4E3 | 100  | 0x04 | M3+M4    | M3 (MIC + ANonce) | M4 (SNonce)    | Hash 2      | authorized, --all (requires non-zero M4 nonce) |
| N1E4 | 001  | 0x01 | M1+M4    | M4 (MIC + SNonce) | M1 (ANonce)    | Hash 3      | authorized, --all (requires non-zero M4 nonce) |
| N3E4 | 101  | 0x05 | M3+M4    | M4 (MIC + SNonce) | M3 (ANonce)    | Hash 3      | authorized, --all (requires non-zero M4 nonce) |

The **ID** column uses the format N{nonce source}E{eapol source}. For
example, N1E2 means the external nonce comes from M1 and the EAPOL frame
comes from M2.

"Challenge" means only M1 and M2 were needed. The AP has not yet
confirmed the password was correct (M3 was not required). "Authorized"
means M3 or M4 were involved, which only exist after both sides verified
the MIC. The password was both sent and validated.

M4's Key Nonce shall be 0 per IEEE 802.11i-2004 Section 8.5.3.4. Most
implementations conform to the spec and zero it. Some reuse the SNonce
from M2 instead. When zeroed, message pairs 0x01 and 0x05 are unusable
because hashcat cannot reconstruct both nonces. In practice, most
captures yield only Hash 1 and Hash 2.

### Bits 3-7: Flags

| Bit | Hex  | Meaning |
|-----|------|---------|
| 3   | 0x08 | Reserved |
| 4   | 0x10 | AP-less attack (no nonce-error-corrections necessary) |
| 5   | 0x20 | LE router detected (nonce-error-corrections only for LE necessary) |
| 6   | 0x40 | BE router detected (nonce-error-corrections only for BE necessary) |
| 7   | 0x80 | Replaycount not checked (nonce-error-corrections definitely necessary) |

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
