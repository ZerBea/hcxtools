hcxtools
==============

Small set of tools convert packets from captures (h = hash, c = capture, convert and
calculate candidates, x = different hashtypes) for the use with latest hashcat
or John the Ripper. The tools are 100% compatible to hashcat and John the Ripper
and recommended by hashcat. This branch is pretty closely synced to hashcat git branch
(that means: latest hcxtools matching on latest hashcat beta) and John the Ripper
git branch ("bleeding-jumbo").

Support for hashcat hash-modes: 2500, 2501, 4800, 5500, 12000, 16100, 16800, 16801, 22000
 
Support for John the Ripper hash-modes: WPAPSK-PMK, PBKDF2-HMAC-SHA1, chap, netntlm, tacacs-plus

After capturing, upload the "uncleaned" cap here (https://wpa-sec.stanev.org/?submit)
to see if your ap or the client is vulnerable by using common wordlists.
Convert the cap to hccapx and/or to WPA-PMKID-PBKDF2 hashline (16800) and check if wlan-key
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

| Tool           | Description                                                                                                          |
| -------------- | -------------------------------------------------------------------------------------------------------------------- |
| hcxpcapngtool  | Provide new hashcat format 22000 - highly experimental - format may change until final release (see changelog)       |
| hcxpsktool     | Calculates candidates for hashcat and john based on based on hcxpcaptool output (-c -o, -z- -U) or commandline input |
| hcxhashtool    | Provide various filter operations on new PMKID/EAPOL hash line - highly experimental - only limited functions        |
| hcxwltool      | Calculates candidates for hashcat and john based on hcxpcaptool output (-E, -I- -U)                                  |
| wlancap2wpasec | Upload multiple (gzip compressed) pcapng, pcap and cap files to https://wpa-sec.stanev.org                           |
| -------------- | -------------------------------------------------------------------------------------------------------------------- |
| deprecated     | obsolete when hashcat and JtR moved to new PMKID/EAPOL hash line - no longer under maintenance                       |
| -------------- | -------------------------------------------------------------------------------------------------------------------- |
| whoismac       | Show vendor information and/or download oui reference list                                                           |
| hcxmactool     | Various MAC based filter operations on HCCAPX and PMKID files - convert hccapx and/or PMKID to new hashline format   |
| hcxhash2cap    | Converts hash file (PMKID, EAPOL-hccapx, EAPOL-hccap, WPAPSK-john) to cap                                            |
| hcxpcaptool    | Shows info of pcap/pcapng file and convert it to other hashformats accepted by hashcat and John the Ripper           |
| hcxpmkidtool   | CPU based tools to verfiy a PMKID                                                                                    |
| hcxessidtool   | Various ESSID based filter operations on HCCAPX and PMKID files                                                      |
| hcxhashcattool | Convert old hashcat (<= 5.1.0) separate potfile (2500 and/or 16800) to new potfile format                            |
| wlanhc2hcx     | Converts hccap to hccapx                                                                                             |
| wlanwkp2hcx    | Converts wpk (ELMCOMSOFT EWSA projectfile) to hccapx                                                                 |
| wlanhcx2ssid   | Strips BSSID, ESSID, OUI                                                                                             |
| wlanhcxinfo    | Shows detailed info from contents of hccapxfile                                                                      |
| wlanhcxcat     | Simple password recovery tool for WPA/WPA2/WPA2 SHA256 AES-128-CMAC (hash-modes 2500, 2501)                          |
| wlanpmk2hcx    | Converts plainmasterkey and ESSID for use with hashcat hash-mode 12000 or john PBKDF2-HMAC-SHA1                      |
| wlanjohn2hcx   | Converts john wpapsk hashfiles for use with hashcat hash-modes 2500, 2501                                            |
| wlancow2hcxpmk | Converts pre-computed cowpatty hashfiles for use with hashcat hash-mode 2501                                         |
| wlanhcx2john   | Converts hccapx to format expected by John the Ripper                                                                |


Compile
--------------

Simply run:

```
make
make install (as super user)
```


Requirements
--------------

* Linux (recommended Arch Linux, but other distros should work, too (no support for other distributions).

* libopenssl and openssl-dev installed

* librt and librt-dev installed (should be installed by default)

* zlib and zlib-dev installed (for gzip compressed cap/pcap/pcapng files)

* libcurl and curl-dev installed (used by whoismac and wlancap2wpasec)

* libpthread and pthread-dev installed (used by hcxhashcattool)

To install requirements on Kali use the following 'apt-get install libcurl4-openssl-dev libssl-dev zlib1g-dev'


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


Bitmask message pair field (hcxpcaptool)
--------------

0: MP info (https://hashcat.net/wiki/doku.php?id=hccapx#message_pair_table)

1: MP info (https://hashcat.net/wiki/doku.php?id=hccapx#message_pair_table)

2: MP info (https://hashcat.net/wiki/doku.php?id=hccapx#message_pair_table)

3: x unused

4: ap-less attack (set to 1) - no nonce-error-corrections neccessary

5: LE router detected (set to 1) - nonce-error-corrections only for LE neccessary

6: BE router detected (set to 1) - nonce-error-corrections only for BE neccessary

7: not replaycount checked (set to 1) - replaycount not checked, nonce-error-corrections definitely neccessary

