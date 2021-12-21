PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_asn1.a $(PKGNAME)_asn1.p.a
SRC_C  = a_bitstr.c  a_gentm.c   ameth_lib.c  a_sign.c          asn1_lib.c    asn_mstbl.c  a_time.c   a_verify.c   d2i_pr.c    f_string.c  p5_pbe.c     tasn_dec.c  tasn_prn.c  t_bitst.c  x_bignum.c  x_pkey.c \
a_d2i_fp.c  a_i2d_fp.c  a_object.c   asn1_err.c        asn1_parse.c  asn_pack.c   a_type.c   bio_asn1.c   d2i_pu.c    i2d_evp.c   p5_pbev2.c   tasn_enc.c  tasn_scn.c  t_pkey.c   x_info.c    x_sig.c \
a_digest.c  a_int.c     a_octet.c    asn1_gen.c        asn_mime.c    a_strex.c    a_utctm.c  bio_ndef.c   evp_asn1.c  n_pkey.c    p5_scrypt.c  tasn_fre.c  tasn_typ.c  t_spki.c   x_int64.c   x_spki.c \
a_dup.c     a_mbstr.c   a_print.c    asn1_item_list.c  asn_moid.c    a_strnid.c   a_utf8.c   d2i_param.c  f_int.c     nsseq.c     p8_pkey.c    tasn_new.c  tasn_utl.c  x_algor.c  x_long.c    x_val.c

PC_FILENAME = $(PKGNAME)_asn1
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_threads libossl_fips libossl_date libossl_evp
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


