hcxtools
==============

Small set of tools to capture and convert packets from wlan devices
for the use with latest hashcat. The tools are 100% compatible to hashcat
and recommended by hashcat (that means hcxtools 3.6.0 working with
hashcat 3.6.0). Support for hashcat hash-modes (2500, 2501, 4800, 5500).
After capturing, upload the "uncleaned" cap here
(http://wpa-sec.stanev.org/?submit) to see if your ap is vulnerable
by using common wordlists. Convert the cap to hccapx and check if wlan-key
or plainmasterkey was transmitted unencrypted.

Brief description
--------------

Multiple stand-alone binaries.

All of these utils are designed to execute only one specific function.


Detailed description
--------------

| Tool           | Description                                                                                          |
| -------------- | ---------------------------------------------------------------------------------------------------- |
| wlandump-ng    | Small, fast and powerfull deauthentication/authentication/response tool                              |
| wlanresponse   | Extreme fast deauthentication/authentication/response tool (unattended use on Raspberry Pi's)        |
| wlanrcascan    | Small, fast and simple passive WLAN channel assignment scanner (status output)                       |
| pioff          | Turns Raspberry Pi off via GPIO switch                                                               |
| wlancapinfo    | Shows info of pcap file                                                                              |
| wlancap2hcx    | Converts cap to hccapx and other formats (recommended for use with wlandump-ng and wlanresponse)     |
| wlanhcx2cap    | Converts hccapx to cap                                                                               |
| wlanhc2hcx     | Converts hccap to hccapx                                                                             |
| wlanhcx2essid  | Merges hccapx containing the same ESSID                                                              |
| wlanhcx2ssid   | Strips BSSID, ESSID, OUI                                                                             |
| wlanhcx2john   | Converts hccapx to format expected by John the Ripper                                                |
| wlanhcxinfo    | Shows detailed info from contents of hccapxfile                                                      |
| wlanhcxmnc     | Manually do nonce correction on byte number xx of a nonce                                            |
| wlanhashhcx    | Generate hashlist from hccapx hashfile (md5_64 hash:mac_ap:mac_sta:essid)                            |
| wlancow2hcxpmk | Converts pre-computed cowpatty hashfiles for use with hashcat hash-mode 2501                         |
| wlancap2wpasec | Upload multiple caps to http://wpa-sec.stanev.org                                                    |
| whoismac       | Show vendor information                                                                              |


Compile
--------------

Simply run:

```
make
make install (as super user)
```

or (with GPIO support - hardware mods required)

```
make GPIOSUPPORT=on
make GPIOSUPPORT=on install (as super user)
```


Requirements
--------------

* Linux (recommended Arch, but other distros should work, too). Don't use Kernel 4.4 (rt2x00 driver regression)

* libpcap and pcap-dev installed

* libopenssl and openssl-dev installed

* librt and librt-dev installed (should be installed by default)

* libcurl and curl-dev installed (used by whoismac and wlancap2wpasec)

* Raspberry Pi: additionally libwiringpi and wiringpi dev installed (Raspberry Pi GPIO support)

* Chipset must be able to run in monitor mode. Recommended: RALINK chipset (good receiver sensitivity), rt2x00 driver (stable and fast)

* Raspberry Pi (Recommended: A+ = very low power consumption or B+)


Useful scripts
--------------

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| bash_profile | Autostart for Raspberry Pi (copy to /root/.bash_profile) |
| pireadcard   | Back up a Pi SD card                                     |
| piwritecard  | Restore a Pi SD card                                     |
| makemonnb    | Example script to activate monitor mode                  |
| killmonnb    | Example script to deactivate monitor mode                |


Notice
--------------

Most output files will be appended to existing files (with the exception of .cap files).


Warning
--------------

You must use wlandump-ng and wlanresponse only on networks you have permission to do this, because

* wlandump-ng/wlanresponse are able to prevent complete wlan traffic

* wlandump-ng/wlanresponse are able to capture handshakes from not connected clients

* wlandump-ng/wlanresponse are able to capture handshakes from 5GHz clients on 2.4GHz

* wlandump-ng/wlanresponse are able to capture extended EAPOL (RADIUS, GSM-SIM, WPS)

* wlandump-ng/wlanresponse are able to capture passwords from the wlan traffic

* wlandump-ng/wlanresponse are able to capture plainmasterkeys from the wlan traffic

* wlandump-ng/wlanresponse are able to capture usernames and identities from the wlan traffic
