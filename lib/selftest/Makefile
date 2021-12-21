PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_self_test.a $(PKGNAME)_self_test.p.a
SRC_C  = self_test_core.c
PC_FILENAME = $(PKGNAME)_self_test
CFLAGS += -I$(PKGDIR)/include/
REQUIRES_LIBS = libossl_context
DEPENDS_LIBS=$(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk

