PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_ssl.a $(PKGNAME)_ssl.p.a
SRC_C  = bio_ssl.c d1_lib.c d1_msg.c d1_srtp.c dtls1_bitmap.c extensions.c extensions_clnt.c extensions_cust.c extensions_srvr.c  methods.c pqueue.c rec_layer_d1.c rec_layer_s3.c s3_cbc.c s3_enc.c s3_lib.c s3_msg.c ssl3_buffer.c ssl3_record.c ssl3_record_tls13.c ssl_asn1.c ssl_cert.c ssl_ciph.c ssl_conf.c ssl_err.c ssl_err_legacy.c ssl_init.c ssl_lib.c ssl_mcnf.c ssl_rsa.c ssl_rsa_legacy.c ssl_sess.c ssl_stat.c ssl_txt.c ssl_utst.c statem.c statem_clnt.c statem_dtls.c statem_lib.c statem_srvr.c t1_enc.c t1_lib.c t1_trce.c tls13_enc.c tls_depr.c tls_pad.c tls_srp.c
PC_FILENAME = $(PKGNAME)_ssl
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


