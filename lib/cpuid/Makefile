PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_cpuid.a $(PKGNAME)_cpuid.p.a
SRC_C  = cpuid.c
PC_FILENAME = $(PKGNAME)_cpuid
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_stack
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


