PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_des.a $(PKGNAME)_des.p.a
SRC_C  = cbc_cksm.c cbc_enc.c cfb64ede.c cfb64enc.c cfb_enc.c des_enc.c ecb3_enc.c ecb_enc.c fcrypt_b.c fcrypt.c ncbc_enc.c ofb64ede.c ofb64enc.c ofb_enc.c pcbc_enc.c qud_cksm.c rand_key.c set_key.c str2key.c xcbc_enc.c 
PC_FILENAME = $(PKGNAME)_des
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


