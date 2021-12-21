PKGDIR ?= ../../../
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_nullprov.a $(PKGNAME)_nullprov.p.a
SRC_C  = nullprov.c
PC_FILENAME = $(PKGNAME)_nullprov
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = 
#DEPENDS_LIBS = $(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk

