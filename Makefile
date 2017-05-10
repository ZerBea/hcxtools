INSTALLDIR	= /usr/local/bin

GPIOSUPPORT=off

CC	= gcc
CFLAGS	= -O3 -Wall -Wextra

all: build

build:
ifeq ($(GPIOSUPPORT), on)
	$(CC) $(CFLAGS) -DDOGPIOSUPPORT -o wlandump wlandump.c -lpcap -lcrypt -lwiringPi -lwiringPiDev
	$(CC) $(CFLAGS) -DDOGPIOSUPPORT -o pioff pioff.c -lcrypt -lwiringPi -lwiringPiDev
else
	$(CC) $(CFLAGS) -o wlandump wlandump.c -lpcap
endif
	$(CC) $(CFLAGS) -o wlanscan wlanscan.c -lpcap
	$(CC) $(CFLAGS) -o wlancapinfo wlancapinfo.c -lpcap
	$(CC) $(CFLAGS) -o wlancap2hcx wlancap2hcx.c -lpcap
	$(CC) $(CFLAGS) -o wlanhcx2cap wlanhcx2cap.c -lpcap
	$(CC) $(CFLAGS) -o wlanhc2hcx wlanhc2hcx.c
	$(CC) $(CFLAGS) -o wlanhcx2essid wlanhcx2essid.c
	$(CC) $(CFLAGS) -o wlanhcx2ssid wlanhcx2ssid.c
	$(CC) $(CFLAGS) -o wlanhcx2john wlanhcx2john.c
	$(CC) $(CFLAGS) -o wlanhcx2key wlanhcx2key.c -lcrypto
	$(CC) $(CFLAGS) -o wlanhcxinfo wlanhcxinfo.c
	$(CC) $(CFLAGS) -o wlanhcxmnc wlanhcxmnc.c
	$(CC) $(CFLAGS) -o whoismac whoismac.c -lcurl
	$(CC) $(CFLAGS) -o pwhash pwhash.c -lcrypto


install: build
ifeq ($(GPIOSUPPORT), on)
	install -D -m 0755 pioff $(INSTALLDIR)/pioff
endif
	install -D -m 0755 wlandump $(INSTALLDIR)/wlandump
	install -D -m 0755 wlanscan $(INSTALLDIR)/wlanscan
	install -D -m 0755 wlancapinfo $(INSTALLDIR)/wlancapinfo
	install -D -m 0755 wlancap2hcx $(INSTALLDIR)/wlancap2hcx
	install -D -m 0755 wlanhcx2cap $(INSTALLDIR)/wlanhcx2cap
	install -D -m 0755 wlanhc2hcx $(INSTALLDIR)/wlanhc2hcx
	install -D -m 0755 wlanhcx2essid $(INSTALLDIR)/wlanhcx2essid
	install -D -m 0755 wlanhcx2ssid $(INSTALLDIR)/wlanhcx2ssid
	install -D -m 0755 wlanhcx2john $(INSTALLDIR)/wlanhcx2john
	install -D -m 0755 wlanhcx2key $(INSTALLDIR)/wlanhcx2key
	install -D -m 0755 wlanhcxinfo $(INSTALLDIR)/wlanhcxinfo
	install -D -m 0755 wlanhcxmnc $(INSTALLDIR)/wlanhcxmnc
	install -D -m 0755 whoismac $(INSTALLDIR)/whoismac
	install -D -m 0755 pwhash $(INSTALLDIR)/pwhash

ifeq ($(GPIOSUPPORT), on)
	rm -f pioff
endif
	rm -f wlandump
	rm -f wlanscan
	rm -f wlancapinfo
	rm -f wlancap2hcx
	rm -f wlanhcx2cap
	rm -f wlanhc2hcx
	rm -f wlanhcx2essid
	rm -f wlanhcx2ssid
	rm -f wlanhcx2john
	rm -f wlanhcx2key
	rm -f wlanhcxinfo
	rm -f wlanhcxmnc
	rm -f whoismac
	rm -f pwhash
	rm -f *.o *~


clean:
ifeq ($(GPIOSUPPORT), on)
	rm -f pioff
endif
	rm -f wlandump
	rm -f wlanscan
	rm -f wlancapinfo
	rm -f wlancap2hcx
	rm -f wlanhcx2cap
	rm -f wlanhc2hcx
	rm -f wlanhcx2essid
	rm -f wlanhcx2ssid
	rm -f wlanhcx2john
	rm -f wlanhcx2key
	rm -f wlanhcxinfo
	rm -f wlanhcxmnc
	rm -f whoismac
	rm -f pwhash
	rm -f *.o *~


uninstall:
ifeq ($(GPIOSUPPORT), on)
	rm -f $(INSTALLDIR)/pioff
endif
	rm -f $(INSTALLDIR)/wlandump
	rm -f $(INSTALLDIR)/wlanscan
	rm -f $(INSTALLDIR)/wlancapinfo
	rm -f $(INSTALLDIR)/wlancap2hcx
	rm -f $(INSTALLDIR)/wlanhcx2cap
	rm -f $(INSTALLDIR)/wlanhc2hcx
	rm -f $(INSTALLDIR)/wlanhcx2essid
	rm -f $(INSTALLDIR)/wlanhcx2ssid
	rm -f $(INSTALLDIR)/wlanhcx2john
	rm -f $(INSTALLDIR)/wlanhcx2key
	rm -f $(INSTALLDIR)/wlanhcxinfo
	rm -f $(INSTALLDIR)/wlanhcxmnc
	rm -f $(INSTALLDIR)/whoismac
	rm -f $(INSTALLDIR)/pwhash
