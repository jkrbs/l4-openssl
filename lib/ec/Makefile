PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_ec.a $(PKGNAME)_ec.p.a
SRC_C  = curve25519.c ec2_oct.c ec2_smpl.c ec_ameth.c ec_asn1.c ec_backend.c ec_check.c ec_curve.c ec_cvt.c ec_deprecated.c ecdh_kdf.c ecdh_ossl.c ecdsa_ossl.c ecdsa_sign.c ecdsa_vrf.c ec_err.c ec_key.c ec_kmeth.c eck_prn.c ec_lib.c ec_mult.c ec_oct.c ec_pmeth.c ecp_mont.c ecp_nist.c ecp_nistp224.c ecp_nistp256.c ecp_nistp521.c ecp_nistputil.c ecp_nistz256.c ecp_nistz256_table.c ecp_oct.c ecp_ppc.c ec_print.c ecp_s390x_nistp.c ecp_smpl.c ecx_backend.c ecx_key.c ecx_meth.c ecx_s390x.c
PC_FILENAME = $(PKGNAME)_ec
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS= libossl_bn libossl_curve448 libossl_asn1

include $(L4DIR)/mk/lib.mk


