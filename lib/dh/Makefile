PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_dh.a $(PKGNAME)_dh.p.a
SRC_C  = dh_ameth.c dh_asn1.c dh_backend.c dh_check.c dh_depr.c dh_err.c dh_gen.c dh_group_params.c dh_kdf.c dh_key.c dh_lib.c dh_meth.c dh_pmeth.c dh_prn.c dh_rfc5114.c
PC_FILENAME = $(PKGNAME)_dh
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_bn libossl_ffc libossl_evp libossl_rsa
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


