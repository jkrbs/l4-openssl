PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_mem_clr.a $(PKGNAME)_mem_clr.p.a
SRC_C  = mem_clr.c
PC_FILENAME = $(PKGNAME)_mem_clr
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_stack
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


