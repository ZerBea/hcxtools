hcxtools
==============

Small set of utilites to capture and convert packets from wlan devices
for the use with hashcat

Brief description
--------------

Multiple stand-alone binaries.

All of these utils are designed to execute only one specific function.


Detailed description
--------------

wlandump      captures packets from wlan device

wlancap2hcx   converts cap to hccapx

wlanhcx2cap   converts hccapx to cap

wlanhc2hcx    converts hccap to hccapx

wlanhcx2essid merges hccapx containing the same essid

wlanhcx2ssid  strips by bssid, essid

wlanhcx2john  converts hccapx to john

wlanhcxinfo   shows detailed info from content of hccapxfile


Compile
--------------

Simply

run make

run make install

use Makefile.pi to compile on raspberry pi
(needs hardware mods (gpiowait.odg))


Requirements
--------------

LINUX (‎recommended ARCH)

libpcap and libpcap dev installed

chipset must able to run in monitor mode

