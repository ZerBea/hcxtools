PRODUCTION		:= 1
PRODUCTION_VERSION	:= 6.0.3
PRODUCTION_YEAR		:= 2020

ifeq ($(PRODUCTION),1)
VERSION_TAG		:= $(PRODUCTION_VERSION)
else
VERSION_TAG		:= $(shell git describe --tags || echo $(PRODUCTION_VERSION))
endif
VERSION_YEAR		:= $(shell echo $(PRODUCTION_YEAR))

PREFIX		?= /usr/local
BINDIR		= $(DESTDIR)$(PREFIX)/bin
MANDIR		= $(DESTDIR)$(PREFIX)/share/man

HOSTOS		:= $(shell uname -s)

CC		?= gcc
CFLAGS		?= -O3 -Wall -Wextra
CFLAGS		+= -std=gnu99
DEFS		= -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_YEAR=\"$(VERSION_YEAR)\"

INSTALL		?= install
INSTFLAGS	=

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

ifeq ($(HOSTOS), Darwin)
CFLAGS += -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include
endif

TOOLS=
TOOLS+=hcxpcapngtool
hcxpcapngtool_libs=-lz -lcrypto -lssl
TOOLS+=hcxhashtool
hcxhashtool_libs=-lcrypto -lssl -lcurl
TOOLS+=hcxpsktool
hcxpsktool_libs=-lcrypto -lssl
TOOLS+=hcxwltool
TOOLS+=hcxhash2cap
TOOLS+=wlancap2wpasec
wlancap2wpasec_libs=-lcrypto -lssl -lcurl
TOOLS+=whoismac
whoismac_libs=-lcrypto -lssl -lcurl

TOOLS+=hcxpmkidtool
TOOLS+=wlanhcx2john
TOOLS+=hcxpcaptool
hcxpcaptool_libs=-lz -lcrypto -lssl
TOOLS+=hcxhashcattool
hcxhashcattool_libs=-lcrypto -lssl -lpthread
hcxpmkidtool_libs=-lcrypto -lssl -lpthread
TOOLS+=hcxmactool
TOOLS+=hcxessidtool
TOOLS+=wlanwkp2hcx
TOOLS+=wlanhcxinfo
TOOLS+=wlanhcx2ssid
TOOLS+=wlanhcxcat
wlanhcxcat_libs=-lcrypto -lssl
TOOLS+=wlanpmk2hcx
wlanpmk2hcx_libs=-lcrypto -lssl
TOOLS+=wlanjohn2hcx

.PHONY: all build install clean uninstall

all: build

build: $(TOOLS)

.deps:
	mkdir -p .deps

# $1: tool name
define tool-build
$(1)_src ?= $(1).c
$(1)_libs ?=

$(1): $$($(1)_src) | .deps
	$$(CC) $$(CFLAGS) $$(CPPFLAGS) -MMD -MF .deps/$$@.d -o $$@ $$($(1)_src) $$($(1)_libs) $$(LDFLAGS) $$(DEFS)

.deps/$(1).d: $(1)

.PHONY: $(1).install
$(1).install: $(1)
	$$(INSTALL) $$(INSTFLAGS) -m 0755 $(1) $$(BINDIR)/$(1)

.PHONY: $(1).clean
$(1).clean:
	rm -f .deps/$(1).d
	rm -f $(1)

.PHONY: $(1).uninstall
$(1).uninstall:
	rm -rf $$(BINDIR)/$(1)

ifneq ($(wildcard manpages/$(1).1),)
.PHONY: $(1).man-install
$(1).install: $(1).man-install
$(1).man-install:
	$$(INSTALL) $$(INSTFLAGS) -m 0644 manpages/$(1).1 $$(MANDIR)/man1/$(1).1

.PHONY: $(1).man-uninstall
$(1).uninstall: $(1).man-uninstall
$(1).man-uninstall:
	rm -rf $$(MANDIR)/man1/$(1).1
endif

endef

$(foreach tool,$(TOOLS),$(eval $(call tool-build,$(tool))))

install: $(patsubst %,%.install,$(TOOLS))

clean: $(patsubst %,%.clean,$(TOOLS))
	rm -rf .deps
	rm -f *.o *~

uninstall: $(patsubst %,%.uninstall,$(TOOLS))

-include .deps/*.d
