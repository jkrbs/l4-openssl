PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_evp.a $(PKGNAME)_evp.p.a
SRC_C  = e_rc4_hmac_md5.c keymgmt_lib.c e_aes_cbc_hmac_sha1.c legacy_ripemd.c p_enc.c e_xcbc_d.c digest.c pmeth_gn.c p5_crpt.c e_des.c evp_cnf.c kem.c e_old.c evp_err.c bio_ok.c e_camellia.c p_legacy.c c_alld.c e_null.c legacy_md2.c e_sm4.c e_aes.c bio_enc.c dh_support.c e_rc2.c e_rc4.c dsa_ctrl.c names.c exchange.c bio_md.c ec_support.c evp_utils.c kdf_meth.c evp_pkey.c evp_fetch.c kdf_lib.c e_idea.c keymgmt_meth.c ec_ctrl.c evp_key.c m_null.c pmeth_check.c p_verify.c pbe_scrypt.c signature.c ctrl_params_translate.c p5_crpt2.c e_bf.c e_cast.c e_aes_cbc_hmac_sha256.c mac_meth.c legacy_mdc2.c mac_lib.c legacy_wp.c legacy_sha.c p_dec.c c_allc.c m_sigver.c bio_b64.c asymcipher.c legacy_md5_sha1.c p_seal.c legacy_md5.c e_seed.c evp_rand.c legacy_blake2.c cmeth_lib.c e_chacha20_poly1305.c e_rc5.c evp_lib.c pmeth_lib.c p_lib.c dh_ctrl.c e_des3.c evp_enc.c evp_pbe.c e_aria.c p_open.c legacy_md4.c p_sign.c encode.c
PC_FILENAME = $(PKGNAME)_evp
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_cast libossl_bf libossl_objects
DEPENDS_LIBS = $(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk
