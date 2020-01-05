PREFIX		?=/usr/local
INSTALLDIR	= $(DESTDIR)$(PREFIX)/bin

HOSTOS := $(shell uname -s)

CC		?= gcc
CFLAGS		?= -O3 -Wall -Wextra
CFLAGS		+= -std=gnu99
#CFLAGS		+= -ggdb -fsanitize=address
INSTFLAGS	= -m 0755

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

ifeq ($(HOSTOS), Darwin)
CFLAGS += -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include
endif


TOOLS=
TOOLS+=hcxpcapngtool
hcxpcapngtool_libs=-lz -lcrypto
TOOLS+=hcxhashtool
hcxhashtool_libs=-lcrypto -lcurl
TOOLS+=hcxpsktool
hcxpsktool_libs=-lcrypto
TOOLS+=hcxwltool
TOOLS+=wlancap2wpasec
wlancap2wpasec_libs=-lcurl

TOOLS+=whoismac
whoismac_libs=-lcurl
TOOLS+=hcxpmkidtool
TOOLS+=wlanhcx2john
TOOLS+=hcxpcaptool
hcxpcaptool_libs=-lz -lcrypto
TOOLS+=hcxhashcattool
hcxhashcattool_libs=-lcrypto -lpthread
hcxpmkidtool_libs=-lcrypto -lpthread
TOOLS+=hcxmactool
TOOLS+=hcxessidtool
TOOLS+=hcxhash2cap
TOOLS+=wlanhc2hcx
TOOLS+=wlanwkp2hcx
TOOLS+=wlanhcxinfo
TOOLS+=wlanhcx2ssid
TOOLS+=wlanhcxcat
wlanhcxcat_libs=-lcrypto
TOOLS+=wlanpmk2hcx
wlanpmk2hcx_libs=-lcrypto
TOOLS+=wlanjohn2hcx
TOOLS+=wlancow2hcxpmk

.PHONY: build
build: $(TOOLS)

.deps:
	mkdir -p .deps

# $1: tool name
define tool-build
$(1)_src ?= $(1).c
$(1)_libs ?=

$(1): $$($(1)_src) | .deps
	$$(CC) $$(CFLAGS) $$(CPPFLAGS) -MMD -MF .deps/$$@.d -o $$@ $$($(1)_src) $$($(1)_libs) $$(LDFLAGS)

.deps/$(1).d: $(1)

.PHONY: $(1).install
$(1).install: $(1)
	install $$(INSTFLAGS) $(1) $$(INSTALLDIR)/$(1)

.PHONY: $(1).clean
$(1).clean:
	rm -f .deps/$(1).d
	rm -f $(1)

.PHONY: $(1).uninstall
$(1).uninstall:
	rm -rf $$(INSTALLDIR)/$(1)

endef

$(foreach tool,$(TOOLS),$(eval $(call tool-build,$(tool))))

.PHONY: install
install: $(patsubst %,%.install,$(TOOLS))

.PHONY: clean
clean: $(patsubst %,%.clean,$(TOOLS))
	rm -rf .deps

.PHONY: uninstall
uninstall: $(patsubst %,%.uninstall,$(TOOLS))

-include .deps/*.d
