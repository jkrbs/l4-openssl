PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_dsa.a $(PKGNAME)_dsa.p.a
SRC_C = dsa_ameth.c dsa_backend.c dsa_depr.c dsa_gen.c dsa_lib.c  dsa_ossl.c  dsa_prn.c  dsa_vrf.c dsa_asn1.c  dsa_check.c  dsa_err.c  dsa_key.c dsa_meth.c dsa_pmeth.c dsa_sign.c asn1_dsa.c
PC_FILENAME = $(PKGNAME)_dsa
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_packet libossl_ffc libossl_evp
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


