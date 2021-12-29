PKGDIR ?= ../../../
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_fips.a $(PKGNAME)_fips.p.a
SRC_C  = fips_entry.c self_test.c self_test_kats.c
PC_FILENAME = $(PKGNAME)_fips
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_evp libossl_self_test
DEPENDS_LIBS = $(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk

