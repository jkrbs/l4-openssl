PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_async.a $(PKGNAME)_async.p.a
SRC_C  = async.c async_err.c async_wait.c arch/async_null.c
PC_FILENAME = $(PKGNAME)_async
CFLAGS += -I$(PKGDIR)/include/
#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


