PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_store.a $(PKGNAME)_store.p.a
SRC_C  = store_err.c store_init.c  store_lib.c store_meth.c store_register.c store_result.c store_strings.c

PC_FILENAME = $(PKGNAME)_store
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


