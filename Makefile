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
	$(CC) $(CFLAGS) -o wlandump-ng wlandump-ng.c -lpcap -lrt $(LFLAGS)
	$(CC) $(CFLAGS) -o wlanresponse wlanresponse.c -lpcap -lrt $(LFLAGS)
	$(CC) $(CFLAGS) -o wlanrcascan wlanrcascan.c -lpcap
	$(CC) $(CFLAGS) -o wlancapinfo wlancapinfo.c -lpcap
	$(CC) $(CFLAGS) -o wlancap2hcx wlancap2hcx.c -lpcap -lcrypto
	$(CC) $(CFLAGS) -o wlanhcx2cap wlanhcx2cap.c -lpcap
	$(CC) $(CFLAGS) -o wlanhc2hcx wlanhc2hcx.c
	$(CC) $(CFLAGS) -o wlanhcx2essid wlanhcx2essid.c
	$(CC) $(CFLAGS) -o wlanhcx2ssid wlanhcx2ssid.c
	$(CC) $(CFLAGS) -o wlanhcx2john wlanhcx2john.c
	$(CC) $(CFLAGS) -o wlanhcxinfo wlanhcxinfo.c
	$(CC) $(CFLAGS) -o wlanhcxmnc wlanhcxmnc.c
	$(CC) $(CFLAGS) -o wlanhashhcx wlanhashhcx.c
	$(CC) $(CFLAGS) -o wlangenpmk wlangenpmk.c -lcrypto
	$(CC) $(CFLAGS) -o wlancow2hcxpmk wlancow2hcxpmk.c
	$(CC) $(CFLAGS) -o whoismac whoismac.c -lcurl
	$(CC) $(CFLAGS) -o pwhash pwhash.c -lcrypto
	$(CC) $(CFLAGS) -o wlancap2wpasec wlancap2wpasec.c -lcurl


install: build
ifeq ($(GPIOSUPPORT), on)
	install -D -m 0755 pioff $(INSTALLDIR)/pioff
endif
	install -D -m 0755 wlandump-ng $(INSTALLDIR)/wlandump-ng
	install -D -m 0755 wlanresponse $(INSTALLDIR)/wlanresponse
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
	install -D -m 0755 wlanhashhcx $(INSTALLDIR)/wlanhashhcx
	install -D -m 0755 wlangenpmk $(INSTALLDIR)/wlangenpmk
	install -D -m 0755 wlancow2hcxpmk $(INSTALLDIR)/wlancow2hcxpmk
	install -D -m 0755 whoismac $(INSTALLDIR)/whoismac
	install -D -m 0755 pwhash $(INSTALLDIR)/pwhash
	install -D -m 0755 wlancap2wpasec $(INSTALLDIR)/wlancap2wpasec

ifeq ($(GPIOSUPPORT), on)
	rm -f pioff
endif
	rm -f wlandump-ng
	rm -f wlanresponse
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
	rm -f wlanhashhcx
	rm -f wlangenpmk
	rm -f wlancow2hcxpmk
	rm -f whoismac
	rm -f pwhash
	rm -f wlancap2wpasec
	rm -f *.o *~


clean:
ifeq ($(GPIOSUPPORT), on)
	rm -f pioff
endif
	rm -f wlandump-ng
	rm -f wlanresponse
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
	rm -f wlanhashhcx
	rm -f wlangenpmk
	rm -f wlancow2hcxpmk
	rm -f whoismac
	rm -f pwhash
	rm -f wlancap2wpasec
	rm -f *.o *~


uninstall:
ifeq ($(GPIOSUPPORT), on)
	rm -f $(INSTALLDIR)/pioff
endif
	rm -f $(INSTALLDIR)/wlandump-ng
	rm -f $(INSTALLDIR)/wlanresponse
	rm -f $(INSTALLDIR)/wlanrcascan
	rm -f $(INSTALLDIR)/wlandumpfix
	rm -f $(INSTALLDIR)/wlancapinfo
	rm -f $(INSTALLDIR)/wlancap2hcx
	rm -f $(INSTALLDIR)/wlanhcx2cap
	rm -f $(INSTALLDIR)/wlanhc2hcx
	rm -f $(INSTALLDIR)/wlanhcx2essid
	rm -f $(INSTALLDIR)/wlanhcx2ssid
	rm -f $(INSTALLDIR)/wlanhcx2john
	rm -f $(INSTALLDIR)/wlanhcxinfo
	rm -f $(INSTALLDIR)/wlanhcxmnc
	rm -f $(INSTALLDIR)/wlanhashhcx
	rm -f $(INSTALLDIR)/wlangenpmk
	rm -f $(INSTALLDIR)/wlancow2hcxpmk
	rm -f $(INSTALLDIR)/whoismac
	rm -f $(INSTALLDIR)/pwhash
	rm -f $(INSTALLDIR)/wlancap2wpasec
