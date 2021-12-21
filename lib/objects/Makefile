PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_objects.a $(PKGNAME)_objects.p.a
SRC_C  = obj_dat.c  obj_err.c  obj_lib.c  obj_xref.c  o_names.c
PC_FILENAME = $(PKGNAME)_objects
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_lhash libossl_bio libossl_bn libossl_asn1
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


