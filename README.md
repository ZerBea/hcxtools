hcxtools
==============

Small set of tools to capture and convert packets from wlan devices
for the use with hashcat. The tools are 100% compatible to hashcat
because new wpa functions were developed together.

Brief description
--------------

Multiple stand-alone binaries.

All of these utils are designed to execute only one specific function.


Detailed description
--------------

wlandump      small, fast and simple active wlan scanner (no status output)

wlanscan      small, fast and simple passive wlan scanner (status output)

pioff         turns raspberry pi off by gpio switch

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

use Makefile.pi to compile (wlandump) on raspberry pi

use Makefile.pi.gpio to compile (wlandump and pioff) on raspberry pi (needs hardware mods (gpiowait.odg))


Requirements
--------------

LINUX (‎recommended ARCH, but other distro's should work, too. Kernel > 4.4 because 4.4 has a driver regression)

lib pcap and pcap dev installed

lib openssl and openssl dev installed

lib curl and curl dev installed (used by whoismac)

raspberry pi: additionally lib wiringpi and wiringpi dev installed (raspberry pi gpio support)

chipset must able to run in monitor mode. Recommended: RALINK chipset (good receiver sensitivity), rt2x00 driver (very fast)

