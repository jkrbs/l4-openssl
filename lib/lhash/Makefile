PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_lhash.a $(PKGNAME)_objects.p.a
SRC_C  = lhash.c  lh_stats.c
PC_FILENAME = $(PKGNAME)_lhash
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_ctype
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


