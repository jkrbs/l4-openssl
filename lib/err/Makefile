PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_err.a $(PKGNAME)_err.p.a
SRC_C  = err_all.c err_all_legacy.c err_blocks.c err.c err_prn.c
PC_FILENAME = $(PKGNAME)_err
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_threads libossl_fips
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


