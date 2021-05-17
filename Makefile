PRODUCTION		:= 0
PRODUCTION_VERSION	:= 6.2.0
PRODUCTION_YEAR		:= 2021

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

OPENSSL_LIBS=$(shell pkg-config --libs openssl)
OPENSSL_CFLAGS=$(shell pkg-config --cflags openssl)
CURL_LIBS=$(shell pkg-config --libs libcurl)
CURL_CFLAGS=$(shell pkg-config --cflags libcurl)
Z_LIBS=$(shell pkg-config --libs zlib)
Z_CFLAGS=$(shell pkg-config --cflags zlib)

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

TOOLS+=hcxpmkidtool
TOOLS+=hcxhashcattool
hcxhashcattool_libs=-lpthread $(OPENSSL_LIBS)
hcxhashcattool_cflags=$(OPENSSL_CFLAGS)
hcxpmkidtool_libs=-lpthread $(OPENSSL_LIBS)
hcxpmkidtool_cflags=$(OPENSSL_CFLAGS)
TOOLS+=hcxmactool
TOOLS+=hcxessidtool

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
