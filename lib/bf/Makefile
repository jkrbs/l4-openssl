PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_bf.a $(PKGNAME)_bf.p.a
SRC_C  = bf_cfb64.c  bf_ecb.c  bf_enc.c  bf_ofb64.c  bf_skey.c
PC_FILENAME = $(PKGNAME)_bf
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


