PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_threads.a $(PKGNAME)_threads.p.a
SRC_C  = threads_lib.c threads_none.c initthread.c
PC_FILENAME = $(PKGNAME)_threads
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_cryptlib
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk
