PKGDIR ?= ../../../
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_defaultprov.a $(PKGNAME)_defaultprov.p.a
SRC_C  = defaultprov.c
PC_FILENAME = $(PKGNAME)_defaultprov
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_cipher
DEPENDS_LIBS = $(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk

