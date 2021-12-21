PKGDIR ?= ../../../
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_cipher.a $(PKGNAME)_cipher.p.a
SRC_C  = cipher_aes.c cipher_aria_ccm.c ciphercommon_ccm_hw.c cipher_aes_cbc_hmac_sha1_hw.c cipher_aria_ccm_hw.c ciphercommon_gcm.c cipher_aes_cbc_hmac_sha256_hw.c cipher_aria_gcm.c ciphercommon_gcm_hw.c cipher_seed.c cipher_aes_cbc_hmac_sha.c cipher_aria_gcm_hw.c ciphercommon_hw.c cipher_seed_hw.c cipher_aes_ccm.c cipher_aria_hw.c cipher_cts.c cipher_sm4.c cipher_aes_ccm_hw.c cipher_blowfish.c cipher_des.c cipher_sm4_ccm.c cipher_aes_gcm.c cipher_blowfish_hw.c cipher_des_hw.c cipher_sm4_ccm_hw.c cipher_aes_gcm_hw.c cipher_camellia.c cipher_desx.c cipher_sm4_gcm.c cipher_aes_hw.c cipher_camellia_hw.c cipher_desx_hw.c cipher_sm4_gcm_hw.c cipher_aes_ocb.c cipher_cast5.c cipher_idea.c cipher_sm4_hw.c cipher_aes_ocb_hw.c cipher_cast5_hw.c cipher_idea_hw.c cipher_tdes.c cipher_aes_siv.c cipher_chacha20.c cipher_null.c cipher_tdes_common.c cipher_aes_siv_hw.c cipher_chacha20_hw.c cipher_rc2.c cipher_tdes_default.c cipher_aes_wrp.c cipher_chacha20_poly1305.c cipher_rc2_hw.c cipher_tdes_default_hw.c cipher_aes_xts.c cipher_chacha20_poly1305_hw.c cipher_rc4.c cipher_tdes_hw.c cipher_aes_xts_fips.c ciphercommon_block.c cipher_rc4_hmac_md5.c cipher_tdes_wrap.c cipher_aes_xts_hw.c ciphercommon.c cipher_rc4_hmac_md5_hw.c cipher_tdes_wrap_hw.c cipher_aria.c ciphercommon_ccm.c cipher_rc4_hw.c

PC_FILENAME = $(PKGNAME)_cipher
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_aria libossl_modes
DEPENDS_LIBS = $(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk

