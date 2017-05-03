hcxtools
==============

Small set of tools to capture and convert packets from WLAN devices
for the use with hashcat. The tools are 100% compatible with hashcat
because new WPA functions were developed together.

Brief description
--------------

Multiple stand-alone binaries.

All of these utils are designed to execute only one specific function.


Detailed description
--------------

| Tool          | Description                                                                                         |
| ------------- | --------------------------------------------------------------------------------------------------- |
| wlandump      | Small, fast and simple active WLAN scanner (no status output)                                       |
| wlanscan      | Small, fast and simple passive WLAN scanner (status output)                                         |
| pioff         | Turns Raspberry Pi off via GPIO switch                                                              |
| wlancap2hcx   | Converts cap to hccapx (recommended for use with wlandump - like cap2hccapx, but different options) |
| wlanhcx2cap   | Converts hccapx to cap                                                                              |
| wlanhc2hcx    | Converts hccap to hccapx                                                                            |
| wlanhcx2essid | Merges hccapx containing the same ESSID                                                             |
| wlanhcx2ssid  | Strips BSSID, ESSID, OUI                                                                            |
| wlanhcx2john  | Converts hccapx to format expected by John the Ripper                                               |
| wlanhcxinfo   | Shows detailed info from contents of hccapxfile                                                     |
| wlanhcxmnc    | Manually do nonce correction on byte number xx of a nonce                                           |
| whoismac      | Show vendor information                                                                             |


Compile
--------------

Simply run:

```
make
make install
```

Use Makefile.pi to compile (wlandump) on Raspberry Pi

Use Makefile.pi.gpio to compile (wlandump and pioff) on Raspberry Pi (needs hardware mods (gpiowait.odg))


Requirements
--------------

* Linux (recommended Arch, but other distros should work, too. Kernel > 4.4 because 4.4 has a driver regression)

* libpcap and pcap-dev installed

* libopenssl and openssl-dev installed

* libcurl and curl-dev installed (used by whoismac)

* Raspberry Pi: additionally libwiringpi and wiringpi dev installed (Raspberry Pi GPIO support)

* Chipset must be able to run in monitor mode. Recommended: RALINK chipset (good receiver sensitivity), rt2x00 driver (very fast)


Useful scripts
--------------

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| bash_profile | Autostart for Raspberry Pi (copy to /root/.bash_profile) |
| pireadcard   | Back up a Pi SD card                                     |
| piwritecard  | Restore a Pi SD card                                     |


Notice
--------------

Most output files will be appended to existing files (with the exception of .cap files).

