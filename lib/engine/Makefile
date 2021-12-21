PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_engine.a $(PKGNAME)_engine.p.a
SRC_C  = eng_err.c eng_openssl.c tb_cipher.c tb_pkmeth.c eng_all.c eng_fat.c eng_pkey.c tb_dh.c tb_rand.c eng_cnf.c eng_init.c eng_rdrand.c tb_digest.c tb_rsa.c eng_ctrl.c eng_lib.c eng_table.c tb_dsa.c eng_dyn.c eng_list.c tb_asnmth.c tb_eckey.c
PC_FILENAME = $(PKGNAME)_engine
CFLAGS += -I$(PKGDIR)/include/
include $(L4DIR)/mk/lib.mk

