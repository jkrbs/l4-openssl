PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_core.a $(PKGNAME)_core.p.a
SRC_C  = core_algorithm.c core_fetch.c core_namemap.c init.c
PC_FILENAME = $(PKGNAME)_core
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS += libossl_async libossl_comp libossl_store libossl_mem libossl_cmp libossl_trace
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk

