PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_cast.a $(PKGNAME)_err.p.a
SRC_C  = c_cfb64.c  c_ecb.c  c_enc.c  c_ofb64.c  c_skey.c
PC_FILENAME = $(PKGNAME)_cast
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


