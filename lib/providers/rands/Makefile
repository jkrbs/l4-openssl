PKGDIR ?= ../../../
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_rands_impl.a $(PKGNAME)_rands_impl.p.a
SRC_C  = crngt.c  drbg.c  drbg_ctr.c  drbg_hash.c  drbg_hmac.c  seeding_l4.c  seed_src.c  test_rng.c 
PC_FILENAME = $(PKGNAME)_rands_impl
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_evp
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


