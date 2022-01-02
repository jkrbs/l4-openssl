PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_getenv.a $(PKGNAME)_getenv.p.a
SRC_C  = getenv.c
PC_FILENAME = $(PKGNAME)_getenv
CFLAGS += -I$(PKGDIR)/include/

DEFINES += -D_L4=1

REQUIRES_LIBS = libossl_uid
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


