PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_rsa.a $(PKGNAME)_rsa.p.a
SRC_C  = rsa_ameth.c rsa_asn1.c rsa_backend.c rsa_chk.c rsa_crpt.c rsa_depr.c rsa_err.c rsa_gen.c rsa_lib.c rsa_meth.c rsa_mp.c rsa_mp_names.c rsa_none.c rsa_oaep.c rsa_ossl.c rsa_pk1.c rsa_pmeth.c rsa_prn.c rsa_pss.c rsa_saos.c rsa_schemes.c rsa_sign.c rsa_sp800_56b_check.c rsa_sp800_56b_gen.c rsa_x931.c rsa_x931g.c 
PC_FILENAME = $(PKGNAME)_rsa
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_asn1 libossl_bn libossl_x509 
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


