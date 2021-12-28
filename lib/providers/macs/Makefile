PKGDIR ?= ../../../
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_macs.a $(PKGNAME)_macs.p.a
SRC_C  = blake2b_mac.c blake2s_mac.c cmac_prov.c gmac_prov.c hmac_prov.c kmac_prov.c poly1305_prov.c siphash_prov.c
PC_FILENAME = $(PKGNAME)_macs
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS =  libossl_sm3 libossl_siphash libossl_poly1305 libossl_prov_common libossl_hmac libossl_ssl libossl_cmac
DEPENDS_LIBS = $(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk

