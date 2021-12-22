PKGDIR ?= ../../../
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_digests.a $(PKGNAME)_digests.p.a
SRC_C  = blake2b_prov.c blake2_prov.c blake2s_prov.c digestcommon.c md2_prov.c md4_prov.c md5_prov.c md5_sha1_prov.c mdc2_prov.c null_prov.c ripemd_prov.c sha2_prov.c sha3_prov.c sm3_prov.c wp_prov.c 
PC_FILENAME = $(PKGNAME)_digests
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS =  libossl_sm3
DEPENDS_LIBS = $(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk

