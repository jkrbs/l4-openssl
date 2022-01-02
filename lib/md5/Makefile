PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_md5.a $(PKGNAME)_md5.p.a
SRC_C  = md5_dgst.c  md5_one.c  md5_sha1.c
PC_FILENAME = $(PKGNAME)_md5
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_sha
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


