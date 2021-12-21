PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_stack.a $(PKGNAME)_stack.p.a
SRC_C  = stack.c
PC_FILENAME = $(PKGNAME)_stack
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_bsearch
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


