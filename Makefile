PRODUCTION		:= 0
PRODUCTION_VERSION	:= 6.3.5
PRODUCTION_YEAR		:= 2024

ifeq ($(PRODUCTION),1)
VERSION_TAG		:= $(PRODUCTION_VERSION)
else
VERSION_TAG		:= $(shell git describe --tags || echo $(PRODUCTION_VERSION))
endif
VERSION_YEAR		:= $(shell echo $(PRODUCTION_YEAR))

PREFIX		?= /usr
BINDIR		= $(DESTDIR)$(PREFIX)/bin

HOSTOS		:= $(shell uname -s)

CC		?= gcc
CFLAGS		?= -O3 -Wall -Wextra -Wpedantic
CFLAGS		+= -std=gnu99
DEFS		= -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_YEAR=\"$(VERSION_YEAR)\"
DEFS		+= -DWANTZLIB

INSTALL		?= install
INSTFLAGS	=
PKG_CONFIG ?= pkg-config

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

OPENSSL_LIBS=$(shell $(PKG_CONFIG) --libs openssl)
OPENSSL_CFLAGS=$(shell $(PKG_CONFIG) --cflags openssl)
CURL_LIBS=$(shell $(PKG_CONFIG) --libs libcurl)
CURL_CFLAGS=$(shell $(PKG_CONFIG) --cflags libcurl)
Z_LIBS=$(shell $(PKG_CONFIG) --libs zlib)
Z_CFLAGS=$(shell $(PKG_CONFIG) --cflags zlib)

TOOLS=
TOOLS+=hcxpcapngtool
hcxpcapngtool_libs=$(OPENSSL_LIBS) $(Z_LIBS)
hcxpcapngtool_cflags=$(OPENSSL_CFLAGS) $(Z_CFLAGS)
TOOLS+=hcxhashtool
hcxhashtool_libs=$(OPENSSL_LIBS) $(CURL_LIBS)
hcxhashtool_cflags=$(OPENSSL_CFLAGS) $(CURL_CFLAGS)
TOOLS+=hcxpsktool
hcxpsktool_libs=$(OPENSSL_LIBS)
hcxpsktool_cflags=$(OPENSSL_CFLAGS)
TOOLS+=hcxpmktool
hcxpmktool_libs=$(OPENSSL_LIBS)
hcxpmktool_cflags=$(OPENSSL_CFLAGS)
TOOLS+=hcxeiutool
TOOLS+=hcxwltool
TOOLS+=hcxhash2cap
TOOLS+=wlancap2wpasec
wlancap2wpasec_libs=$(OPENSSL_LIBS) $(CURL_LIBS)
wlancap2wpasec_cflags=$(OPENSSL_CFLAGS) $(CURL_CFLAGS)
TOOLS+=whoismac
whoismac_libs=$(OPENSSL_LIBS) $(CURL_LIBS)
whoismac_cflags=$(OPENSSL_CFLAGS) $(CURL_CFLAGS)

.PHONY: all build install clean uninstall

all: build

build: $(TOOLS)

.deps:
	mkdir -p .deps

# $1: tool name
define tool-build
$(1)_src ?= $(1).c
$(1)_libs ?=
$(1)_cflags ?=

$(1): $$($(1)_src) | .deps
	$$(CC) $$(CFLAGS) $$($(1)_cflags) $$(CPPFLAGS) -MMD -MF .deps/$$@.d -o $$@ $$($(1)_src) $$($(1)_libs) $$(LDFLAGS) $$(DEFS)

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

endef

$(foreach tool,$(TOOLS),$(eval $(call tool-build,$(tool))))

install: $(patsubst %,%.install,$(TOOLS))

clean: $(patsubst %,%.clean,$(TOOLS))
	rm -rf .deps
	rm -f *.o *~

uninstall: $(patsubst %,%.uninstall,$(TOOLS))

-include .deps/*.d
