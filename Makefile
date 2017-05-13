INSTALLDIR	= /usr/local/bin

GPIOSUPPORT=off
DOACTIVE=on
DOSTATUS=on

CC	= gcc
CFLAGS	= -O3 -Wall -Wextra

ifeq ($(GPIOSUPPORT), on)
CFLAGS	+= -DDOGPIOSUPPORT
LFLAGS	= -lcrypt -lwiringPi -lwiringPiDev
endif


all: build

build:
ifeq ($(GPIOSUPPORT), on)
	$(CC) $(CFLAGS) -DDOGPIOSUPPORT -o pioff pioff.c $(LFLAGS)
endif

ifeq ($(DOACTIVE), on)
	$(CC) $(CFLAGS) -DDOACTIVE -o wlandump wlandump.c -lpcap $(LFLAGS)
endif

ifeq ($(DOSTATUS), on)
	$(CC) $(CFLAGS) -DDOSTATUS -DDOACTIVE -o wlandump-sts wlandump.c -lpcap $(LFLAGS)
	$(CC) $(CFLAGS) -DDOSTATUS -o wlanscan-sts wlandump.c -lpcap $(LFLAGS)
endif
	$(CC) $(CFLAGS) -o wlanscan wlandump.c -lpcap $(LFLAGS)
	$(CC) $(CFLAGS) -o wlancapinfo wlancapinfo.c -lpcap
	$(CC) $(CFLAGS) -o wlancap2hcx wlancap2hcx.c -lpcap
	$(CC) $(CFLAGS) -o wlanhcx2cap wlanhcx2cap.c -lpcap
	$(CC) $(CFLAGS) -o wlanrcascan wlanrcascan.c -lpcap
	$(CC) $(CFLAGS) -o wlanhc2hcx wlanhc2hcx.c
	$(CC) $(CFLAGS) -o wlanhcx2essid wlanhcx2essid.c
	$(CC) $(CFLAGS) -o wlanhcx2ssid wlanhcx2ssid.c
	$(CC) $(CFLAGS) -o wlanhcx2john wlanhcx2john.c
	$(CC) $(CFLAGS) -o wlanhcxinfo wlanhcxinfo.c
	$(CC) $(CFLAGS) -o wlanhcxmnc wlanhcxmnc.c
	$(CC) $(CFLAGS) -o whoismac whoismac.c -lcurl
	$(CC) $(CFLAGS) -o pwhash pwhash.c -lcrypto


install: build
ifeq ($(GPIOSUPPORT), on)
	install -D -m 0755 pioff $(INSTALLDIR)/pioff
endif

ifeq ($(DOACTIVE), on)
	install -D -m 0755 wlandump $(INSTALLDIR)/wlandump
endif

ifeq ($(DOSTATUS), on)
	install -D -m 0755 wlandump-sts $(INSTALLDIR)/wlandump-sts
	install -D -m 0755 wlanscan-sts $(INSTALLDIR)/wlanscan-sts
endif
	install -D -m 0755 wlanscan $(INSTALLDIR)/wlanscan
	install -D -m 0755 wlanrcascan $(INSTALLDIR)/wlanrcascan
	install -D -m 0755 wlancapinfo $(INSTALLDIR)/wlancapinfo
	install -D -m 0755 wlancap2hcx $(INSTALLDIR)/wlancap2hcx
	install -D -m 0755 wlanhcx2cap $(INSTALLDIR)/wlanhcx2cap
	install -D -m 0755 wlanhc2hcx $(INSTALLDIR)/wlanhc2hcx
	install -D -m 0755 wlanhcx2essid $(INSTALLDIR)/wlanhcx2essid
	install -D -m 0755 wlanhcx2ssid $(INSTALLDIR)/wlanhcx2ssid
	install -D -m 0755 wlanhcx2john $(INSTALLDIR)/wlanhcx2john
	install -D -m 0755 wlanhcxinfo $(INSTALLDIR)/wlanhcxinfo
	install -D -m 0755 wlanhcxmnc $(INSTALLDIR)/wlanhcxmnc
	install -D -m 0755 whoismac $(INSTALLDIR)/whoismac
	install -D -m 0755 pwhash $(INSTALLDIR)/pwhash

ifeq ($(GPIOSUPPORT), on)
	rm -f pioff
endif
	rm -f wlandump
	rm -f wlandump-sts
	rm -f wlanscan
	rm -f wlanscan-sts
	rm -f wlanrcascan
	rm -f wlancapinfo
	rm -f wlancap2hcx
	rm -f wlanhcx2cap
	rm -f wlanhc2hcx
	rm -f wlanhcx2essid
	rm -f wlanhcx2ssid
	rm -f wlanhcx2john
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
	rm -f wlandump-sts
	rm -f wlanscan
	rm -f wlanscan-sts
	rm -f wlanrcascan
	rm -f wlancapinfo
	rm -f wlancap2hcx
	rm -f wlanhcx2cap
	rm -f wlanhc2hcx
	rm -f wlanhcx2essid
	rm -f wlanhcx2ssid
	rm -f wlanhcx2john
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
	rm -f $(INSTALLDIR)/wlandump-sts
	rm -f $(INSTALLDIR)/wlanscan
	rm -f $(INSTALLDIR)/wlanscan-sts
	rm -f $(INSTALLDIR)/wlanrcascan
	rm -f $(INSTALLDIR)/wlancapinfo
	rm -f $(INSTALLDIR)/wlancap2hcx
	rm -f $(INSTALLDIR)/wlanhcx2cap
	rm -f $(INSTALLDIR)/wlanhc2hcx
	rm -f $(INSTALLDIR)/wlanhcx2essid
	rm -f $(INSTALLDIR)/wlanhcx2ssid
	rm -f $(INSTALLDIR)/wlanhcx2john
	rm -f $(INSTALLDIR)/wlanhcxinfo
	rm -f $(INSTALLDIR)/wlanhcxmnc
	rm -f $(INSTALLDIR)/whoismac
	rm -f $(INSTALLDIR)/pwhash
