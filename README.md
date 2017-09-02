hcxtools
==============

Small set of tools to capture and convert packets from wlan devices
for the use with latest hashcat. The tools are 100% compatible to hashcat
and recommended by hashcat. This branch is pretty closely synced to
hashcat git branch (that means: latest hcxtools matching on latest hashcat beta)
Support for hashcat hash-modes (2500, 2501, 4800, 5500, 12000, 15800).
After capturing, upload the "uncleaned" cap here
(http://wpa-sec.stanev.org/?submit) to see if your ap is vulnerable
by using common wordlists. Convert the cap to hccapx and check if wlan-key
or plainmasterkey was transmitted unencrypted.


Brief description
--------------

Multiple stand-alone binaries - designed to run on Raspberry Pi's.

All of these utils are designed to execute only one specific function.

Read this post: hcxtools - solution for capturing wlan traffic and conversion to hashcat formats (https://hashcat.net/forum/thread-6661.html)


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
| wlanwkp2hcx    | Converts wpk (ELMCOMSOFT EWSA projectfile) to hccapx                                                 |
| wlanhcx2essid  | Merges hccapx containing the same ESSID                                                              |
| wlanhcx2ssid   | Strips BSSID, ESSID, OUI                                                                             |
| wlanhcxinfo    | Shows detailed info from contents of hccapxfile                                                      |
| wlanhcxmnc     | Manually do nonce correction on byte number xx of a nonce                                            |
| wlanhashhcx    | Generate hashlist from hccapx hashfile (md5_64 hash:mac_ap:mac_sta:essid)                            |
| wlanhcxcat     | Simple password recovery tool (hash-modes 2500, 2501 and 15800)                                      |
| wlanpmk2hcx    | Converts plainmasterkey and ESSID for use with hashcat hash-mode 12000                               |
| wlancow2hcxpmk | Converts pre-computed cowpatty hashfiles for use with hashcat hash-mode 2501                         |
| wlanhcx2john   | Converts hccapx to format expected by John the Ripper                                                |
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


Hardware mod (wlandump-ng/wlanresponse)
--------------

LED flashes 5 times if wlandump-ng/wlanresponse successfully started

LED flashes every 5 seconds if everything is fine

Press push button at least > 5 seconds until LED turns on (LED turns on if wlandump-ng/wlanresponse terminates)

Green ACT LED flashes 10 times

Raspberry Pi turned off and can be disconnected from power supply

Do not use wlandump-ng, wlanresponse or pioff together!


Hardware mod (pioff)
--------------

LED flashes every 30 seconds 2 times if pioff successfully started

Press push button at least > 5 seconds until LED turns on (pioff will shut down Raspberry Pi safely)

Green ACT LED flashes 10 times

Raspberry Pi turned off and can be disconnected from power supply

Do not use wlandump-ng, wlanresponse or pioff together!


Berkeley Packet Filter BPF (example)
--------------

wlan host = filter all hosts using this mac

wlan dst = filter all destinations using this mac

wlan src = filter all sources using this mac

wlan ta = filter all transmitter addresses using this mac

wlan ta = filter all receiver addresses using this mac

write all filter entries into one single line !(filterenty1 || filterenty2  || filterenty2)

use ! (not) to filter entries out

!(wlan host 00:00:00:00:00:00 || wlan dst 00:00:00:00:00:00 || wlan src 00:00:00:00:00:00 || wlan ta 00:00:00:00:00:00 || wlan ra 00:00:00:00:00:00)

or allow only this entries

(wlan host 00:00:00:00:00:00 || wlan dst 00:00:00:00:00:00 || wlan src 00:00:00:00:00:00 || wlan ta 00:00:00:00:00:00 || wlan ra 00:00:00:00:00:00)


Warning
--------------

You must use wlandump-ng and wlanresponse only on networks you have permission to do this, because

* wlandump-ng/wlanresponse are able to prevent complete wlan traffic

* wlandump-ng/wlanresponse are able to capture handshakes from not connected clients (only one single M2 from the client is required)

* wlandump-ng/wlanresponse are able to capture handshakes from 5GHz clients on 2.4GHz (only one single M2 from the client is required)

* wlandump-ng/wlanresponse are able to capture extended EAPOL (RADIUS, GSM-SIM, WPS)

* wlandump-ng/wlanresponse are able to capture passwords from the wlan traffic

* wlandump-ng/wlanresponse are able to capture plainmasterkeys from the wlan traffic

* wlandump-ng/wlanresponse are able to capture usernames and identities from the wlan traffic
