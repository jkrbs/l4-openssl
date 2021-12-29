PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_rc2.a $(PKGNAME)_rc2.p.a
SRC_C  = rc2_cbc.c rc2cfb64.c rc2_ecb.c rc2ofb64.c rc2_skey.c
PC_FILENAME = $(PKGNAME)_rc2
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


