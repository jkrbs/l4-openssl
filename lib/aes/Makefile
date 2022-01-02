PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_aes.a $(PKGNAME)_aes.p.a
SRC_C  = aes_cbc.c aes_cfb.c aes_core.c aes_ecb.c aes_ige.c aes_misc.c aes_ofb.c aes_wrap.c

PC_FILENAME = $(PKGNAME)_aes
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


