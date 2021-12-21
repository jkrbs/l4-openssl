PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_provider.a $(PKGNAME)_provider.p.a
SRC_C  = provider_child.c provider_conf.c provider_core.c provider_predefined.c
PC_FILENAME = $(PKGNAME)_provider
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_nullprov libossl_baseprov libossl_defaultprov
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


