PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_modes.a $(PKGNAME)_modes.p.a
SRC_C  = cbc128.c  ccm128.c  cfb128.c  ctr128.c  cts128.c  gcm128.c  ocb128.c  ofb128.c  siv128.c  wrap128.c  xts128.c

#SRC_S  = asm/aes-gcm.S

PC_FILENAME = $(PKGNAME)_modes
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_cpuid libossl_mem_clr libossl_params libossl_o_str libossl_bn libossl_rand
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


