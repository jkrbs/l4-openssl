PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_param_build_set.a $(PKGNAME)_param_build_set.p.a
SRC_C  = param_build_set.c param_build.c params_dup.c
PC_FILENAME = $(PKGNAME)_param_build_set
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


