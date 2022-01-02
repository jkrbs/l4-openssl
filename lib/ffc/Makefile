PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_ffc.a $(PKGNAME)_ffc.p.a
SRC_C = ffc_backend.c  ffc_dh.c  ffc_key_generate.c  ffc_key_validate.c  ffc_params.c  ffc_params_generate.c  ffc_params_validate.c
PC_FILENAME = $(PKGNAME)_ffc
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_bn libossl_param_build_set libossl_asn1
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


