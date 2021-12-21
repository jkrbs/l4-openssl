PKGDIR ?= ../../../
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_baseprov.a $(PKGNAME)_baseprov.p.a
SRC_C  = baseprov.c
PC_FILENAME = $(PKGNAME)_baseprov
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = 
#DEPENDS_LIBS = $(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk

