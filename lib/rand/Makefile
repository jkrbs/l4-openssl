PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_rand.a $(PKGNAME)_rand.p.a
SRC_C  = prov_seed.c  rand_deprecated.c  rand_egd.c  rand_err.c  randfile.c  rand_lib.c  rand_meth.c  rand_pool.c
PC_FILENAME = $(PKGNAME)_rand
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_threads libossl_cryptlib libossl_rands_impl
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


