PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_sha.a $(PKGNAME)_sha.p.a
SRC_C  = keccak1600.c sha1dgst.c sha1_one.c sha256.c sha3.c sha512.c sha_ppc.c

PC_FILENAME = $(PKGNAME)_sha
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


