PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_ex_data.a $(PKGNAME)_ex_data.p.a
SRC_C  = ex_data.c
PC_FILENAME = $(PKGNAME)_ex_data
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_stack
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


