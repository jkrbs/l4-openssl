PKGDIR ?= ..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME).a $(PKGNAME).p.a

DEFINES += -DOPENSSL_NO_SOCK=1 -DOPENSSL_NO_DGRAM=1  -DDSO_NONE=1 -DOPENSSL_NO_SECURE_MEMORY=1 -DOPENSSL_SYS_L4=1 -DOPENSSL_NO_UI_CONSOLE=1

SRC_C  = ./poly1305/poly1305_base2_44.c\
crmf/crmf_pbm.c crmf/crmf_err.c crmf/crmf_asn.c crmf/crmf_lib.c\
params_from_text/params_from_text.c\
providers/storemgmgt/file_store_any2obj.c  providers/storemgmgt/file_store.c\
property/defn_cache.c  property/property.c  property/property_err.c  property/property_parse.c	property/property_query.c  property/property_string.c\
ess/ess_asn1.c	ess/ess_err.c  ess/ess_lib.c\
ct/ct_b64.c  ct/ct_err.c  ct/ct_log.c  ct/ct_oct.c  ct/ct_policy.c  ct/ct_prn.c  ct/ct_sct.c  ct/ct_sct_ctx.c  ct/ct_vfy.c  ct/ct_x509v3.c\
mdc2/mdc2dgst.c  mdc2/mdc2_one.c\
sm2/sm2_crypt.c  sm2/sm2_err.c	sm2/sm2_key.c  sm2/sm2_sign.c\
providers/asymciphers/rsa_enc.c  providers/asymciphers/sm2_enc.c\
whirlpool/wp_block.c  whirlpool/wp_dgst.c\
seed/seed.c  seed/seed_cbc.c  seed/seed_cfb.c  seed/seed_ecb.c	seed/seed_ofb.c\
chacha/chacha_enc.c  chacha/chacha_ppc.c\
md4/md4_dgst.c	md4/md4_one.c\
passphrase/passphrase.c\
punycode/punycode.c\
der_writer/der_writer.c\
providers/signatures/dsa_sig.c	 providers/signatures/eddsa_sig.c	providers/signatures/rsa_sig.c\
providers/signatures/ecdsa_sig.c  providers/signatures/mac_legacy_sig.c  providers/signatures/sm2_sig.c\
ripemd/rmd_dgst.c  ripemd/rmd_one.c\
camellia/camellia.c  camellia/cmll_cbc.c  camellia/cmll_cfb.c  camellia/cmll_ctr.c  camellia/cmll_ecb.c  camellia/cmll_misc.c  camellia/cmll_ofb.c\
idea/i_cbc.c  idea/i_cfb64.c  idea/i_ecb.c  idea/i_ofb64.c  idea/i_skey.c\
kdf/kdf_err.c\
providers/kdfs/hkdf.c	 providers/kdfs/pbkdf1.c	providers/kdfs/pkcs12kdf.c  providers/kdfs/sshkdf.c    providers/kdfs/x942kdf.c\
providers/kdfs/kbkdf.c	 providers/kdfs/pbkdf2.c	providers/kdfs/pvkkdf.c     providers/kdfs/sskdf.c\
providers/kdfs/krb5kdf.c  providers/kdfs/pbkdf2_fips.c	providers/kdfs/scrypt.c     providers/kdfs/tls1_prf.c\
providers/exchange/dh_exch.c  providers/exchange/ecdh_exch.c  providers/exchange/ecx_exch.c  providers/exchange/kdf_exch.c\
providers/kem/rsa_kem.c\
providers/encode_decode/decode_der2key.c     providers/encode_decode/decode_pvk2key.c	    providers/encode_decode/encode_key2ms.c\
providers/encode_decode/decode_epki2pki.c    providers/encode_decode/decode_spki2typespki.c  providers/encode_decode/encode_key2text.c\
providers/encode_decode/decode_msblob2key.c  providers/encode_decode/encode_key2any.c	    providers/encode_decode/endecoder_common.c\
providers/encode_decode/decode_pem2der.c     providers/encode_decode/encode_key2blob.c\
sparse_array/sparse_array.c\
providers/keymgmt/dh_kmgmt.c   providers/keymgmt/ec_kmgmt.c   providers/keymgmt/kdf_legacy_kmgmt.c  providers/keymgmt/rsa_kmgmt.c\
providers/keymgmt/dsa_kmgmt.c  providers/keymgmt/ecx_kmgmt.c  providers/keymgmt/mac_legacy_kmgmt.c\
providers/der/der_digests_gen.c  providers/der/der_ec_gen.c   providers/der/der_ecx_key.c  providers/der/der_sm2_gen.c\
providers/der/der_dsa_gen.c	providers/der/der_ec_key.c   providers/der/der_rsa_gen.c  providers/der/der_sm2_key.c\
providers/der/der_dsa_key.c	providers/der/der_ec_sig.c   providers/der/der_rsa_key.c  providers/der/der_sm2_sig.c\
providers/der/der_dsa_sig.c	providers/der/der_ecx_gen.c  providers/der/der_rsa_sig.c  providers/der/der_wrap_gen.c\
./cms/cms_dh.c\
./cms/cms_asn1.c\
./cms/cms_smime.c\
./cms/cms_lib.c\
./cms/cms_enc.c\
./cms/cms_env.c\
./cms/cms_rsa.c\
./cms/cms_ec.c\
./cms/cms_cd.c\
./cms/cms_ess.c\
./cms/cms_io.c\
./cms/cms_err.c\
./cms/cms_dd.c\
./cms/cms_sd.c\
./cms/cms_att.c\
./cms/cms_pwri.c\
./cms/cms_kari.c\
./ui/ui_err.c\
./ui/ui_openssl.c\
./ui/ui_util.c\
./ui/ui_null.c\
./ui/ui_lib.c\
./http/http_lib.c\
./http/http_err.c\
./http/http_client.c\
./poly1305/poly1305.c \
./conf/conf_mod.c \
./conf/conf_sap.c \
./conf/conf_lib.c \
./conf/conf_ssl.c \
./conf/conf_mall.c \
./conf/conf_api.c \
./conf/conf_def.c \
./conf/conf_err.c \
./rc4/rc4_skey.c \
./rc4/rc4_enc.c \
./modes/cbc128.c \
./modes/wrap128.c \
./modes/ocb128.c \
./modes/ctr128.c \
./modes/cfb128.c \
./modes/xts128.c \
./modes/ofb128.c \
./modes/ccm128.c \
./modes/siv128.c \
./modes/cts128.c \
./modes/gcm128.c \
./md5/md5_dgst.c \
./md5/md5_one.c \
./md5/md5_sha1.c \
./x509/v3_crld.c \
./x509/x509name.c \
./x509/x509_set.c \
./x509/v3_info.c \
./x509/by_dir.c \
./x509/pcy_tree.c \
./x509/v3_sxnet.c \
./x509/v3_extku.c \
./x509/by_store.c \
./x509/pcy_map.c \
./x509/v3_genn.c \
./x509/v3_purp.c \
./x509/x_all.c \
./x509/v3_san.c \
./x509/v3err.c \
./x509/x509_meth.c \
./x509/v3_prn.c \
./x509/v3_akid.c \
./x509/x509_vpm.c \
./x509/x_name.c \
./x509/x509_cmp.c \
./x509/v3_conf.c \
./x509/x509_def.c \
./x509/v3_addr.c \
./x509/x_crl.c \
./x509/v3_ncons.c \
./x509/v3_skid.c \
./x509/x509_att.c \
./x509/v3_ia5.c \
./x509/x509_lu.c \
./x509/v3_int.c \
./x509/x509_r2x.c \
./x509/x_x509a.c \
./x509/v3_akeya.c \
./x509/x509rset.c \
./x509/x509_trust.c \
./x509/x_req.c \
./x509/x509spki.c \
./x509/v3_pcia.c \
./x509/v3_utf8.c \
./x509/x509_vfy.c \
./x509/v3_pcons.c \
./x509/v3_tlsf.c \
./x509/v3_asid.c \
./x509/x509_req.c \
./x509/v3_lib.c \
./x509/x_attrib.c \
./x509/v3_cpols.c \
./x509/x509_txt.c \
./x509/t_crl.c \
./x509/v3_bcons.c \
./x509/x_x509.c \
./x509/pcy_lib.c \
./x509/pcy_node.c \
./x509/x509_obj.c \
./x509/t_x509.c \
./x509/v3_bitst.c \
./x509/v3_admis.c \
./x509/x509cset.c \
./x509/pcy_data.c \
./x509/v3_pmaps.c \
./x509/x509_d2.c \
./x509/v3_ist.c \
./x509/by_file.c \
./x509/v3_enum.c \
./x509/v3_pci.c \
./x509/x509_ext.c \
./x509/t_req.c \
./x509/pcy_cache.c \
./x509/v3_pku.c \
./x509/x_pubkey.c \
./x509/x509type.c \
./x509/x509_v3.c \
./x509/v3_utl.c \
./x509/x_exten.c \
./x509/x509_err.c \
./bsearch/bsearch.c \
./bn/bn_div.c \
./bn/bn_rsa_fips186_4.c \
./bn/bn_sparc.c \
./bn/bn_conv.c \
./bn/bn_mpi.c \
./bn/bn_print.c \
./bn/bn_word.c \
./bn/bn_depr.c \
./bn/bn_ctx.c \
./bn/rsaz_exp_x2.c \
./bn/bn_srp.c \
./bn/bn_shift.c \
./bn/bn_add.c \
./bn/bn_recp.c \
./bn/bn_nist.c \
./bn/bn_mul.c \
./bn/bn_gf2m.c \
./bn/bn_exp.c \
./bn/bn_x931p.c \
./bn/bn_sqrt.c \
./bn/bn_mont.c \
./bn/bn_rand.c \
./bn/bn_exp2.c \
./bn/bn_lib.c \
./bn/bn_kron.c \
./bn/bn_gcd.c \
./bn/bn_blind.c \
./bn/bn_err.c \
./bn/bn_dh.c \
./bn/bn_sqr.c \
./bn/bn_const.c \
./bn/bn_intern.c \
./bn/bn_prime.c \
./bn/bn_ppc.c \
./bn/rsaz_exp.c \
./bn/bn_asm.c \
./bn/bn_mod.c \
./curve448/arch_32/f_impl32.c \
./curve448/curve448.c \
./curve448/scalar.c \
./curve448/arch_64/f_impl64.c \
./curve448/f_generic.c \
./curve448/eddsa.c \
./curve448/curve448_tables.c \
./ctype/ctype.c \
./sm3/sm3.c \
./sm3/legacy_sm3.c \
./dso/dso_openssl.c \
./dso/dso_dlfcn.c \
./dso/dso_vms.c \
./dso/dso_dl.c \
./dso/dso_lib.c \
./dso/dso_win32.c \
./dso/dso_err.c \
./ssl/statem_srvr.c \
./ssl/ssl_asn1.c \
./ssl/ssl3_buffer.c \
./ssl/ssl_stat.c \
./ssl/d1_srtp.c \
./ssl/s3_lib.c \
./ssl/extensions_clnt.c \
./ssl/rec_layer_s3.c \
./ssl/ssl_conf.c \
./ssl/tls13_enc.c \
./ssl/t1_lib.c \
./ssl/ssl_txt.c \
./ssl/pqueue.c \
./ssl/ssl_rsa_legacy.c \
./ssl/d1_lib.c \
./ssl/ssl3_record.c \
./ssl/ssl_cert.c \
./ssl/tls_pad.c \
./ssl/t1_enc.c \
./ssl/extensions_cust.c \
./ssl/ssl_ciph.c \
./ssl/ssl_init.c \
./ssl/dtls1_bitmap.c \
./ssl/s3_msg.c \
./ssl/s3_enc.c \
./ssl/statem.c \
./ssl/methods.c \
./ssl/s3_cbc.c \
./ssl/ssl_mcnf.c \
./ssl/ssl3_record_tls13.c \
./ssl/ssl_err_legacy.c \
./ssl/tls_depr.c \
./ssl/tls_srp.c \
./ssl/statem_clnt.c \
./ssl/extensions_srvr.c \
./ssl/statem_lib.c \
./ssl/extensions.c \
./ssl/ssl_sess.c \
./ssl/ssl_err.c \
./ssl/ssl_rsa.c \
./ssl/t1_trce.c \
./ssl/ssl_utst.c \
./ssl/rec_layer_d1.c \
./ssl/bio_ssl.c \
./ssl/d1_msg.c \
./ssl/statem_dtls.c \
./ssl/ssl_lib.c \
./param_build_set/param_build_set.c \
./param_build_set/param_build.c \
./param_build_set/params_dup.c \
./cmac/cmac.c \
./rand/randfile.c \
./rand/rand_lib.c \
./rand/rand_meth.c \
./rand/prov_seed.c \
./rand/rand_pool.c \
./rand/rand_err.c \
./rand/rand_deprecated.c \
./rand/rand_egd.c \
./des/qud_cksm.c \
./des/ofb_enc.c \
./des/str2key.c \
./des/cfb64ede.c \
./des/ncbc_enc.c \
./des/des_enc.c \
./des/pcbc_enc.c \
./des/fcrypt_b.c \
./des/fcrypt.c \
./des/ofb64ede.c \
./des/set_key.c \
./des/cfb64enc.c \
./des/ecb_enc.c \
./des/ecb3_enc.c \
./des/xcbc_enc.c \
./des/cbc_enc.c \
./des/cfb_enc.c \
./des/rand_key.c \
./des/cbc_cksm.c \
./des/ofb64enc.c \
./params/params.c \
./dsa/dsa_asn1.c \
./dsa/dsa_prn.c \
./dsa/dsa_check.c \
./dsa/dsa_meth.c \
./dsa/dsa_key.c \
./dsa/dsa_ameth.c \
./dsa/dsa_sign.c \
./dsa/dsa_backend.c \
./dsa/dsa_vrf.c \
./dsa/dsa_ossl.c \
./dsa/asn1_dsa.c \
./dsa/dsa_pmeth.c \
./dsa/dsa_lib.c \
./dsa/dsa_gen.c \
./dsa/dsa_depr.c \
./dsa/dsa_err.c \
./provider/provider_core.c \
./provider/provider_child.c \
./provider/provider_predefined.c \
./provider/provider_conf.c \
./err/err_prn.c \
./err/err_blocks.c \
./err/err.c \
./err/cpt_err.c\
./err/err_all.c \
./err/err_all_legacy.c \
./lhash/lh_stats.c \
./lhash/lhash.c \
./comp/c_zlib.c \
./comp/comp_err.c \
./comp/comp_lib.c \
./threads/threads_lib.c \
./threads/initthread.c \
./threads/threads_none.c \
./siphash/siphash.c \
./cast/c_skey.c \
./cast/c_ofb64.c \
./cast/c_enc.c \
./cast/c_ecb.c \
./cast/c_cfb64.c \
./context/context.c \
./o_str/o_str.c \
./cpuid/cpuid.c \
./ffc/ffc_key_generate.c \
./ffc/ffc_dh.c \
./ffc/ffc_key_validate.c \
./ffc/ffc_backend.c \
./ffc/ffc_params_generate.c \
./ffc/ffc_params.c \
./ffc/ffc_params_validate.c \
./rc2/rc2cfb64.c \
./rc2/rc2_skey.c \
./rc2/rc2ofb64.c \
./rc2/rc2_ecb.c \
./rc2/rc2_cbc.c \
./ocsp/ocsp_vfy.c \
./ocsp/ocsp_cl.c \
./ocsp/ocsp_http.c \
./ocsp/v3_ocsp.c \
./ocsp/ocsp_ext.c \
./ocsp/ocsp_lib.c \
./ocsp/ocsp_srv.c \
./ocsp/ocsp_asn.c \
./ocsp/ocsp_prn.c \
./ocsp/ocsp_err.c \
./dir/o_dir.c \
./mem_clr/mem_clr.c \
./date/o_time.c \
./cryptlib/cryptlib.c \
./pkcs12/p12_decr.c \
./pkcs12/p12_attr.c \
./pkcs12/p12_p8d.c \
./pkcs12/p12_init.c \
./pkcs12/pk12err.c \
./pkcs12/p12_asn.c \
./pkcs12/p12_mutl.c \
./pkcs12/p12_utl.c \
./pkcs12/p12_key.c \
./pkcs12/p12_p8e.c \
./pkcs12/p12_crt.c \
./pkcs12/p12_sbag.c \
./pkcs12/p12_crpt.c \
./pkcs12/p12_npas.c \
./pkcs12/p12_add.c \
./pkcs12/p12_kiss.c \
./evp/e_rc4_hmac_md5.c \
./evp/keymgmt_lib.c \
./evp/e_aes_cbc_hmac_sha1.c \
./evp/legacy_ripemd.c \
./evp/p_enc.c \
./evp/e_xcbc_d.c \
./evp/digest.c \
./evp/pmeth_gn.c \
./evp/p5_crpt.c \
./evp/e_des.c \
./evp/evp_cnf.c \
./evp/kem.c \
./evp/e_old.c \
./evp/evp_err.c \
./evp/bio_ok.c \
./evp/e_camellia.c \
./evp/p_legacy.c \
./evp/c_alld.c \
./evp/e_null.c \
./evp/legacy_md2.c \
./evp/e_sm4.c \
./evp/e_aes.c \
./evp/bio_enc.c \
./evp/dh_support.c \
./evp/e_rc2.c \
./evp/e_rc4.c \
./evp/dsa_ctrl.c \
./evp/names.c \
./evp/exchange.c \
./evp/bio_md.c \
./evp/ec_support.c \
./evp/evp_utils.c \
./evp/kdf_meth.c \
./evp/evp_pkey.c \
./evp/evp_fetch.c \
./evp/kdf_lib.c \
./evp/e_idea.c \
./evp/keymgmt_meth.c \
./evp/ec_ctrl.c \
./evp/evp_key.c \
./evp/m_null.c \
./evp/pmeth_check.c \
./evp/p_verify.c \
./evp/pbe_scrypt.c \
./evp/signature.c \
./evp/ctrl_params_translate.c \
./evp/p5_crpt2.c \
./evp/e_bf.c \
./evp/e_cast.c \
./evp/e_aes_cbc_hmac_sha256.c \
./evp/mac_meth.c \
./evp/legacy_mdc2.c \
./evp/mac_lib.c \
./evp/legacy_wp.c \
./evp/legacy_sha.c \
./evp/p_dec.c \
./evp/c_allc.c \
./evp/m_sigver.c \
./evp/bio_b64.c \
./evp/asymcipher.c \
./evp/legacy_md5_sha1.c \
./evp/p_seal.c \
./evp/legacy_md5.c \
./evp/e_seed.c \
./evp/evp_rand.c \
./evp/legacy_blake2.c \
./evp/cmeth_lib.c \
./evp/e_chacha20_poly1305.c \
./evp/e_rc5.c \
./evp/evp_lib.c \
./evp/pmeth_lib.c \
./evp/p_lib.c \
./evp/dh_ctrl.c \
./evp/e_des3.c \
./evp/evp_enc.c \
./evp/evp_pbe.c \
./evp/e_aria.c \
./evp/p_open.c \
./evp/legacy_md4.c \
./evp/p_sign.c \
./evp/encode.c \
./hmac/hmac.c \
./objects/o_names.c \
./objects/obj_lib.c \
./objects/obj_dat.c \
./objects/obj_err.c \
./objects/obj_xref.c \
./engine/tb_dsa.c \
./engine/eng_fat.c \
./engine/eng_lib.c \
./engine/tb_rsa.c \
./engine/eng_dyn.c \
./engine/tb_cipher.c \
./engine/eng_err.c \
./engine/tb_digest.c \
./engine/eng_list.c \
./engine/tb_rand.c \
./engine/eng_ctrl.c \
./engine/tb_pkmeth.c \
./engine/tb_eckey.c \
./engine/tb_dh.c \
./engine/eng_all.c \
./engine/eng_init.c \
./engine/eng_openssl.c \
./engine/eng_rdrand.c \
./engine/tb_asnmth.c \
./engine/eng_pkey.c \
./engine/eng_cnf.c \
./engine/eng_table.c \
./exdata/ex_data.c \
./rsa/rsa_pss.c \
./rsa/rsa_sp800_56b_gen.c \
./rsa/rsa_mp.c \
./rsa/rsa_sign.c \
./rsa/rsa_meth.c \
./rsa/rsa_ameth.c \
./rsa/rsa_pk1.c \
./rsa/rsa_mp_names.c \
./rsa/rsa_schemes.c \
./rsa/rsa_crpt.c \
./rsa/rsa_x931g.c \
./rsa/rsa_x931.c \
./rsa/rsa_ossl.c \
./rsa/rsa_err.c \
./rsa/rsa_prn.c \
./rsa/rsa_asn1.c \
./rsa/rsa_lib.c \
./rsa/rsa_oaep.c \
./rsa/rsa_pmeth.c \
./rsa/rsa_depr.c \
./rsa/rsa_backend.c \
./rsa/rsa_sp800_56b_check.c \
./rsa/rsa_chk.c \
./rsa/rsa_none.c \
./rsa/rsa_saos.c \
./rsa/rsa_gen.c \
./uid/uid.c \
./fopen/o_fopen.c \
./store/store_lib.c \
./store/store_register.c \
./store/store_result.c \
./store/store_meth.c \
./store/store_init.c \
./store/store_err.c \
./store/store_strings.c \
./getenv/getenv.c \
./pkcs7/pk7_mime.c \
./pkcs7/pk7_lib.c \
./pkcs7/pkcs7err.c \
./pkcs7/pk7_doit.c \
./pkcs7/pk7_asn1.c \
./pkcs7/bio_pk7.c \
./pkcs7/pk7_smime.c \
./pkcs7/pk7_attr.c \
./dh/dh_check.c \
./dh/dh_depr.c \
./dh/dh_meth.c \
./dh/dh_gen.c \
./dh/dh_prn.c \
./dh/dh_backend.c \
./dh/dh_pmeth.c \
./dh/dh_ameth.c \
./dh/dh_kdf.c \
./dh/dh_err.c \
./dh/dh_group_params.c \
./dh/dh_rfc5114.c \
./dh/dh_key.c \
./dh/dh_asn1.c \
./dh/dh_lib.c \
./packet/packet.c \
./mem/mem_sec.c \
./mem/mem.c \
./bf/bf_ofb64.c \
./bf/bf_skey.c \
./bf/bf_enc.c \
./bf/bf_cfb64.c \
./bf/bf_ecb.c \
./buffer/buf_err.c \
./buffer/buffer.c \
./aria/aria.c \
./selftest/self_test_core.c \
./ec/ecp_nistp224.c \
./ec/ec_pmeth.c \
./ec/ec_cvt.c \
./ec/ec_err.c \
./ec/curve25519.c \
./ec/ec_curve.c \
./ec/ecx_backend.c \
./ec/ec_oct.c \
./ec/ecp_nistputil.c \
./ec/ecp_ppc.c \
./ec/ecx_key.c \
./ec/ec_ameth.c \
./ec/ecx_s390x.c \
./ec/ecdsa_ossl.c \
./ec/ec_lib.c \
./ec/ecdsa_vrf.c \
./ec/ecp_nistp256.c \
./ec/ec_kmeth.c \
./ec/ec_check.c \
./ec/ecdh_kdf.c \
./ec/ecdh_ossl.c \
./ec/ec2_oct.c \
./ec/ec_asn1.c \
./ec/ecp_s390x_nistp.c \
./ec/ecp_nistp521.c \
./ec/ec2_smpl.c \
./ec/ec_print.c \
./ec/ecx_meth.c \
./ec/ecp_nistz256_table.c \
./ec/ec_mult.c \
./ec/ecp_smpl.c \
./ec/eck_prn.c \
./ec/ec_deprecated.c \
./ec/ecp_mont.c \
./ec/ecdsa_sign.c \
./ec/ec_key.c \
./ec/ecp_nistz256.c \
./ec/ecp_nist.c \
./ec/ec_backend.c \
./ec/ecp_oct.c \
./bio/bio_sock2.c \
./bio/bf_nbio.c \
./bio/bio_print.c \
./bio/bss_dgram.c \
./bio/bio_addr.c \
./bio/bio_cb.c \
./bio/bss_bio.c \
./bio/bio_meth.c \
./bio/bss_acpt.c \
./bio/bio_lib.c \
./bio/bf_prefix.c \
./bio/bf_null.c \
./bio/bss_sock.c \
./bio/bf_readbuff.c \
./bio/bio_sock.c \
./bio/bss_null.c \
./bio/bio_err.c \
./bio/bss_fd.c \
./bio/bf_buff.c \
./bio/bio_dump.c \
./bio/bss_mem.c \
./bio/bss_file.c \
./bio/bss_core.c \
./bio/bss_log.c \
./bio/bss_conn.c \
./bio/ossl_core_bio.c \
./bio/bf_lbuf.c \
./sha/keccak1600.c \
./sha/sha_ppc.c \
./sha/sha1_one.c \
./sha/sha256.c \
./sha/sha512.c \
./sha/sha1dgst.c \
./sha/sha3.c \
./sm4/sm4.c \
./async/async.c \
./async/async_wait.c \
./async/async_err.c \
./async/arch/async_null.c \
./async/arch/async_posix.c \
./async/arch/async_win.c \
./asn1/x_bignum.c \
./asn1/tasn_new.c \
./asn1/a_object.c \
./asn1/d2i_param.c \
./asn1/a_time.c \
./asn1/asn1_err.c \
./asn1/bio_ndef.c \
./asn1/evp_asn1.c \
./asn1/a_octet.c \
./asn1/asn_mime.c \
./asn1/tasn_prn.c \
./asn1/asn_pack.c \
./asn1/bio_asn1.c \
./asn1/f_string.c \
./asn1/x_int64.c \
./asn1/x_val.c \
./asn1/a_verify.c \
./asn1/a_utctm.c \
./asn1/p5_pbev2.c \
./asn1/t_pkey.c \
./asn1/a_strex.c \
./asn1/a_int.c \
./asn1/x_algor.c \
./asn1/asn_mstbl.c \
./asn1/tasn_typ.c \
./asn1/x_spki.c \
./asn1/x_sig.c \
./asn1/a_sign.c \
./asn1/asn_moid.c \
./asn1/a_dup.c \
./asn1/asn1_item_list.c \
./asn1/a_digest.c \
./asn1/a_print.c \
./asn1/p5_scrypt.c \
./asn1/tasn_fre.c \
./asn1/nsseq.c \
./asn1/d2i_pu.c \
./asn1/t_spki.c \
./asn1/n_pkey.c \
./asn1/i2d_evp.c \
./asn1/x_pkey.c \
./asn1/asn1_parse.c \
./asn1/tasn_enc.c \
./asn1/d2i_pr.c \
./asn1/asn1_gen.c \
./asn1/tasn_scn.c \
./asn1/x_info.c \
./asn1/f_int.c \
./asn1/a_strnid.c \
./asn1/a_i2d_fp.c \
./asn1/t_bitst.c \
./asn1/a_type.c \
./asn1/asn1_lib.c \
./asn1/a_mbstr.c \
./asn1/p8_pkey.c \
./asn1/p5_pbe.c \
./asn1/tasn_dec.c \
./asn1/tasn_utl.c \
./asn1/x_long.c \
./asn1/a_bitstr.c \
./asn1/ameth_lib.c \
./asn1/a_gentm.c \
./asn1/a_utf8.c \
./asn1/a_d2i_fp.c \
./pem/pem_lib.c \
./pem/pem_oth.c \
./pem/pem_sign.c \
./pem/pem_pk8.c \
./pem/pem_pkey.c \
./pem/pem_xaux.c \
./pem/pem_err.c \
./pem/pvkfmt.c \
./pem/pem_all.c \
./pem/pem_info.c \
./pem/pem_x509.c \
./trace/trace.c \
./core/core_fetch.c \
./core/core_namemap.c \
./core/core_algorithm.c \
./core/init.c \
./providers/nullprov/nullprov.c \
./providers/cipher/ciphercommon_hw.c \
./providers/cipher/cipher_sm4_ccm.c \
./providers/cipher/cipher_aes_cbc_hmac_sha.c \
./providers/cipher/cipher_chacha20.c \
./providers/cipher/cipher_sm4.c \
./providers/cipher/cipher_aes_xts_hw.c \
./providers/cipher/cipher_sm4_gcm_hw.c \
./providers/cipher/cipher_aes_ocb_hw.c \
./providers/cipher/cipher_des.c \
./providers/cipher/cipher_idea.c \
./providers/cipher/cipher_tdes_default.c \
./providers/cipher/cipher_rc4_hmac_md5.c \
./providers/cipher/cipher_camellia.c \
./providers/cipher/cipher_blowfish.c \
./providers/cipher/cipher_aes_siv.c \
./providers/cipher/cipher_sm4_hw.c \
./providers/cipher/cipher_rc4_hw.c \
./providers/cipher/cipher_aes_gcm_hw.c \
./providers/cipher/cipher_chacha20_poly1305_hw.c \
./providers/cipher/cipher_tdes_wrap.c \
./providers/cipher/cipher_aes_cbc_hmac_sha256_hw.c \
./providers/cipher/ciphercommon_block.c \
./providers/cipher/ciphercommon.c \
./providers/cipher/cipher_blowfish_hw.c \
./providers/cipher/cipher_cast5_hw.c \
./providers/cipher/cipher_aes_siv_hw.c \
./providers/cipher/cipher_aria.c \
./providers/cipher/cipher_aria_ccm.c \
./providers/cipher/cipher_tdes_wrap_hw.c \
./providers/cipher/cipher_camellia_hw.c \
./providers/cipher/cipher_aes_hw.c \
./providers/cipher/cipher_idea_hw.c \
./providers/cipher/cipher_chacha20_poly1305.c \
./providers/cipher/ciphercommon_gcm.c \
./providers/cipher/cipher_sm4_gcm.c \
./providers/cipher/cipher_null.c \
./providers/cipher/cipher_rc2_hw.c \
./providers/cipher/cipher_des_hw.c \
./providers/cipher/cipher_rc4.c \
./providers/cipher/cipher_aes_xts.c \
./providers/cipher/cipher_aes_xts_fips.c \
./providers/cipher/cipher_aes_cbc_hmac_sha1_hw.c \
./providers/cipher/cipher_aria_ccm_hw.c \
./providers/cipher/cipher_tdes_common.c \
./providers/cipher/cipher_desx.c \
./providers/cipher/ciphercommon_gcm_hw.c \
./providers/cipher/cipher_seed_hw.c \
./providers/cipher/ciphercommon_ccm.c \
./providers/cipher/ciphercommon_ccm_hw.c \
./providers/cipher/cipher_aes.c \
./providers/cipher/cipher_aria_hw.c \
./providers/cipher/cipher_chacha20_hw.c \
./providers/cipher/cipher_sm4_ccm_hw.c \
./providers/cipher/cipher_cast5.c \
./providers/cipher/cipher_desx_hw.c \
./providers/cipher/cipher_aes_gcm.c \
./providers/cipher/cipher_cts.c \
./providers/cipher/cipher_aria_gcm_hw.c \
./providers/cipher/cipher_rc4_hmac_md5_hw.c \
./providers/cipher/cipher_aes_wrp.c \
./providers/cipher/cipher_aes_ccm_hw.c \
./providers/cipher/cipher_rc2.c \
./providers/cipher/cipher_tdes.c \
./providers/cipher/cipher_tdes_hw.c \
./providers/cipher/cipher_tdes_default_hw.c \
./providers/cipher/cipher_aria_gcm.c \
./providers/cipher/cipher_seed.c \
./providers/cipher/cipher_aes_ccm.c \
./providers/cipher/cipher_aes_ocb.c \
./providers/fips/self_test.c \
./providers/fips/fips_entry.c \
./providers/fips/self_test_kats.c \
./providers/rands/test_rng.c \
./providers/rands/drbg.c \
./providers/rands/drbg_hmac.c \
./providers/rands/drbg_ctr.c \
./providers/rands/seed_src.c \
./providers/rands/crngt.c \
./providers/rands/drbg_hash.c \
./providers/rands/seeding_l4.c \
./providers/macs/blake2b_mac.c \
./providers/macs/blake2s_mac.c \
./providers/macs/kmac_prov.c \
./providers/macs/poly1305_prov.c \
./providers/macs/siphash_prov.c \
./providers/macs/cmac_prov.c \
./providers/macs/hmac_prov.c \
./providers/macs/gmac_prov.c \
./providers/defaultprov/defaultprov.c \
./providers/defaultprov/baseprov.c \
./providers/baseprov/baseprov.c \
./providers/digests/md4_prov.c \
./providers/digests/wp_prov.c \
./providers/digests/digestcommon.c \
./providers/digests/blake2_prov.c \
./providers/digests/md2_prov.c \
./providers/digests/ripemd_prov.c \
./providers/digests/sha3_prov.c \
./providers/digests/sha2_prov.c \
./providers/digests/blake2s_prov.c \
./providers/digests/mdc2_prov.c \
./providers/digests/md5_prov.c \
./providers/digests/sm3_prov.c \
./providers/digests/md5_sha1_prov.c \
./providers/digests/blake2b_prov.c \
./providers/digests/null_prov.c \
./providers/common/provider_err.c \
./providers/common/securitycheck_default.c \
./providers/common/provider_seeding.c \
./providers/common/der/der_sm2_key.c \
./providers/common/der/der_dsa_key.c \
./providers/common/der/der_rsa_sig.c \
./providers/common/der/der_dsa_sig.c \
./providers/common/der/der_sm2_sig.c \
./providers/common/der/der_ecx_key.c \
./providers/common/der/der_ec_key.c \
./providers/common/der/der_ec_sig.c \
./providers/common/der/der_rsa_key.c \
./providers/common/digest_to_nid.c \
./providers/common/securitycheck_fips.c \
./providers/common/provider_util.c \
./providers/common/provider_ctx.c \
./providers/common/bio_prov.c \
./providers/common/capabilities.c \
./providers/common/securitycheck.c \
./cmp/cmp_asn.c \
./cmp/cmp_util.c \
./cmp/cmp_msg.c \
./cmp/cmp_ctx.c \
./cmp/cmp_http.c \
./cmp/cmp_vfy.c \
./cmp/cmp_hdr.c \
./cmp/cmp_server.c \
./cmp/cmp_err.c \
./cmp/cmp_client.c \
./cmp/cmp_status.c \
./cmp/cmp_protect.c \
./aes/aes_ige.c \
./aes/aes_misc.c \
./aes/aes_ecb.c \
./aes/aes_ofb.c \
./aes/aes_core.c \
./aes/aes_cbc.c \
./aes/aes_cfb.c \
./aes/aes_wrap.c \
./stack/stack.c\
./encode_decode/decoder_pkey.c\
./encode_decode/encoder_pkey.c\
./encode_decode/decoder_lib.c\
./encode_decode/encoder_lib.c\
./encode_decode/decoder_err.c\
./encode_decode/decoder_meth.c\
./encode_decode/encoder_err.c\
./encode_decode/encoder_meth.c\
./provider/provider.c\
ts/ts_req_print.c\
ts/ts_err.c\
ts/ts_req_utils.c\
ts/ts_asn1.c\
ts/ts_rsp_sign.c\
ts/ts_lib.c\
ts/ts_rsp_utils.c\
ts/ts_rsp_verify.c\
ts/ts_rsp_print.c\
ts/ts_conf.c\
ts/ts_verify_ctx.c
PC_FILENAME = $(PKGNAME)
CFLAGS += -I$(PKGDIR)/include/

include $(L4DIR)/mk/lib.mk


