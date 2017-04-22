INSTALLDIR	= /usr/local/bin

CC	= gcc
CFLAGS	= -O3 -Wall -Wextra
CFLAGS1	= -funsafe-math-optimizations -fPIC -fwrapv -msse2 -mpclmul

all: build

build:
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlandump wlandump.c -lpcap
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlanscan wlanscan.c -lpcap
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlancap2hcx wlancap2hcx.c -lpcap
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlanhcx2cap wlanhcx2cap.c -lpcap
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlanhc2hcx wlanhc2hcx.c
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlanhcx2essid wlanhcx2essid.c
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlanhcx2ssid wlanhcx2ssid.c
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlanhcx2john wlanhcx2john.c
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlanhcxinfo wlanhcxinfo.c
	$(CC) $(CFLAGS) $(CFLAGS1) -o wlanhcxmnc wlanhcxmnc.c
	$(CC) $(CFLAGS) $(CFLAGS1) -o whoismac whoismac.c -lcurl


install: build
	install -D -m 0755 wlandump $(INSTALLDIR)/wlandump
	install -D -m 0755 wlanscan $(INSTALLDIR)/wlanscan
	install -D -m 0755 wlancap2hcx $(INSTALLDIR)/wlancap2hcx
	install -D -m 0755 wlanhcx2cap $(INSTALLDIR)/wlanhcx2cap
	install -D -m 0755 wlanhc2hcx $(INSTALLDIR)/wlanhc2hcx
	install -D -m 0755 wlanhcx2essid $(INSTALLDIR)/wlanhcx2essid
	install -D -m 0755 wlanhcx2ssid $(INSTALLDIR)/wlanhcx2ssid
	install -D -m 0755 wlanhcx2john $(INSTALLDIR)/wlanhcx2john
	install -D -m 0755 wlanhcxinfo $(INSTALLDIR)/wlanhcxinfo
	install -D -m 0755 wlanhcxmnc $(INSTALLDIR)/wlanhcxmnc
	install -D -m 0755 whoismac $(INSTALLDIR)/whoismac

	rm -f wlandump
	rm -f wlanscan
	rm -f wlancap2hcx
	rm -f wlanhcx2cap
	rm -f wlanhc2hcx
	rm -f wlanhcx2essid
	rm -f wlanhcx2ssid
	rm -f wlanhcx2john
	rm -f wlanhcxinfo
	rm -f wlanhcxmnc
	rm -f whoismac
	rm -f *.o *~

clean:
	rm -f wlandump
	rm -f wlanscan
	rm -f wlancap2hcx
	rm -f wlanhcx2cap
	rm -f wlanhc2hcx
	rm -f wlanhcx2essid
	rm -f wlanhcx2ssid
	rm -f wlanhcx2john
	rm -f wlanhcxinfo
	rm -f wlanhcxmnc
	rm -f whoismac
	rm -f *.o *~

uninstall:
	rm -f $(INSTALLDIR)/wlandump
	rm -f $(INSTALLDIR)/wlanscan
	rm -f $(INSTALLDIR)/wlancap2hcx
	rm -f $(INSTALLDIR)/wlanhcx2cap
	rm -f $(INSTALLDIR)/wlanhc2hcx
	rm -f $(INSTALLDIR)/wlanhcx2essid
	rm -f $(INSTALLDIR)/wlanhcx2ssid
	rm -f $(INSTALLDIR)/wlanhcx2john
	rm -f $(INSTALLDIR)/wlanhcxinfo
	rm -f $(INSTALLDIR)/wlanhcxmnc
	rm -f $(INSTALLDIR)/whoismac
