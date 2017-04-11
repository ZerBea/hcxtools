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

wlanhcx2ssid  strips by bssid, essid, oui

wlanhcx2john  converts hccapx to john

wlanhcxinfo   shows detailed info from content of hccapxfile

wlanhcxmnc    manually do nonce correction on byte number xx of a nonce 

whoismac      show vendor information


Compile
--------------

Simply

run make

run make install

use Makefile.pi to compile on raspberry pi

use Makefile.pi.gpio to compile on raspberry pi (needs hardware mods (gpiowait.odg))


Requirements
--------------

LINUX (‎recommended ARCH, but other distro's should work, too)

lib pcap and pcap dev installed

lib openssl and openssl dev installed

lib curl and curl dev installed

raspberry pi: lib wiringpi and wiringpi dev installed (raspberry pi gpio support)

chipset must able to run in monitor mode

