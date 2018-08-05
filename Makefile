PREFIX?=/usr/local
INSTALLDIR      = $(DESTDIR)$(PREFIX)/bin

HOSTOS := $(shell uname -s)

CC ?= gcc
CFLAGS = -std=gnu99 -O3 -Wall -Wextra
INSTFLAGS = -m 0755

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

ifeq ($(HOSTOS), Darwin)
CFLAGS += -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include
endif


all: build

build:
        $(CC) $(CFLAGS) -o hcxpcaptool hcxpcaptool.c -lz -lcrypto $(LDFLAGS)
        $(CC) $(CFLAGS) -o hcxhashcattool hcxhashcattool.c -lcrypto -lpthread  $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhc2hcx wlanhc2hcx.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanwkp2hcx wlanwkp2hcx.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhcxinfo wlanhcxinfo.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhcx2cap wlanhcx2cap.c -lpcap $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhcx2essid wlanhcx2essid.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhcx2ssid wlanhcx2ssid.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhcxmnc wlanhcxmnc.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhashhcx wlanhashhcx.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhcxcat wlanhcxcat.c -lcrypto $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanpmk2hcx wlanpmk2hcx.c -lcrypto $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanjohn2hcx wlanjohn2hcx.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlancow2hcxpmk wlancow2hcxpmk.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o whoismac whoismac.c -lcurl $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhcx2john wlanhcx2john.c $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlanhcx2psk wlanhcx2psk.c -lcrypto $(LDFLAGS)
        $(CC) $(CFLAGS) -o wlancap2wpasec wlancap2wpasec.c -lcurl $(LDFLAGS)


install: build
        install $(INSTFLAGS) hcxpcaptool $(INSTALLDIR)/hcxpcaptool
        install $(INSTFLAGS) hcxhashcattool $(INSTALLDIR)/hcxhashcattool
        install $(INSTFLAGS) wlanhc2hcx $(INSTALLDIR)/wlanhc2hcx
        install $(INSTFLAGS) wlanwkp2hcx $(INSTALLDIR)/wlanwkp2hcx
        install $(INSTFLAGS) wlanhcxinfo $(INSTALLDIR)/wlanhcxinfo
        install $(INSTFLAGS) wlanhcx2cap $(INSTALLDIR)/wlanhcx2cap
        install $(INSTFLAGS) wlanhcx2essid $(INSTALLDIR)/wlanhcx2essid
        install $(INSTFLAGS) wlanhcx2ssid $(INSTALLDIR)/wlanhcx2ssid
        install $(INSTFLAGS) wlanhcxmnc $(INSTALLDIR)/wlanhcxmnc
        install $(INSTFLAGS) wlanhashhcx $(INSTALLDIR)/wlanhashhcx
        install $(INSTFLAGS) wlanhcxcat $(INSTALLDIR)/wlanhcxcat
        install $(INSTFLAGS) wlanpmk2hcx $(INSTALLDIR)/wlanpmk2hcx
        install $(INSTFLAGS) wlanjohn2hcx $(INSTALLDIR)/wlanjohn2hcx
        install $(INSTFLAGS) wlancow2hcxpmk $(INSTALLDIR)/wlancow2hcxpmk
        install $(INSTFLAGS) whoismac $(INSTALLDIR)/whoismac
        install $(INSTFLAGS) wlanhcx2john $(INSTALLDIR)/wlanhcx2john
        install $(INSTFLAGS) wlanhcx2psk $(INSTALLDIR)/wlanhcx2psk
        install $(INSTFLAGS) wlancap2wpasec $(INSTALLDIR)/wlancap2wpasec

        rm -f hcxpcaptool
        rm -f hcxhashcattool
        rm -f wlanhc2hcx
        rm -f wlanwkp2hcx
        rm -f wlanhcxinfo
        rm -f wlanhcx2cap
        rm -f wlanhcx2essid
        rm -f wlanhcx2ssid
        rm -f wlanhcx2john
        rm -f wlanhcxmnc
        rm -f wlanhashhcx
        rm -f wlanhcxcat
        rm -f wlanpmk2hcx
        rm -f wlanjohn2hcx
        rm -f wlancow2hcxpmk
        rm -f whoismac
        rm -f wlanhcx2john
        rm -f wlanhcx2psk
        rm -f wlancap2wpasec
        rm -f *.o *~


clean:
        rm -f hcxpcaptool
        rm -f hcxhashcattool
        rm -f wlanhc2hcx
        rm -f wlanwkp2hcx
        rm -f wlanhcxinfo
        rm -f wlanhcx2cap
        rm -f wlanhcx2essid
        rm -f wlanhcx2ssid
        rm -f wlanhcx2john
        rm -f wlanhcxmnc
        rm -f wlanhashhcx
        rm -f wlanhcxcat
        rm -f wlanpmk2hcx
        rm -f wlanjohn2hcx
        rm -f wlancow2hcxpmk
        rm -f whoismac
        rm -f wlanhcx2john
        rm -f wlanhcx2psk
        rm -f wlancap2wpasec
        rm -f *.o *~


uninstall:
        rm -f $(INSTALLDIR)/hcxpcaptool
        rm -f $(INSTALLDIR)/hcxhashcattool
        rm -f $(INSTALLDIR)/wlanhc2hcx
        rm -f $(INSTALLDIR)/wlanwkp2hcx
        rm -f $(INSTALLDIR)/wlanhcx2cap
        rm -f $(INSTALLDIR)/wlanhcx2essid
        rm -f $(INSTALLDIR)/wlanhcx2ssid
        rm -f $(INSTALLDIR)/wlanhcxinfo
        rm -f $(INSTALLDIR)/wlanhcxmnc
        rm -f $(INSTALLDIR)/wlanhashhcx
        rm -f $(INSTALLDIR)/wlanhcxcat
        rm -f $(INSTALLDIR)/wlanpmk2hcx
        rm -f $(INSTALLDIR)/wlanjohn2hcx
        rm -f $(INSTALLDIR)/wlancow2hcxpmk
        rm -f $(INSTALLDIR)/whoismac
        rm -f $(INSTALLDIR)/wlanhcx2john
        rm -f $(INSTALLDIR)/wlanhcx2psk
        rm -f $(INSTALLDIR)/wlancap2wpasec
