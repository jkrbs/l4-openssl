PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_bn.a $(PKGNAME)_bn.p.a
PC_FILENAME = $(PKGNAME)_bn
SRC_C  = bn_div.c bn_rsa_fips186_4.c bn_sparc.c bn_conv.c bn_mpi.c  bn_print.c bn_word.c bn_depr.c bn_ctx.c rsaz_exp_x2.c bn_srp.c bn_shift.c bn_add.c bn_recp.c bn_nist.c bn_mul.c bn_gf2m.c bn_exp.c bn_x931p.c bn_sqrt.c bn_mont.c bn_rand.c bn_exp2.c bn_lib.c bn_kron.c bn_gcd.c bn_blind.c bn_err.c bn_dh.c bn_sqr.c bn_const.c bn_intern.c bn_prime.c bn_ppc.c rsaz_exp.c bn_asm.c bn_mod.c

CFLAGS += -I$(PKGDIR)/include/
include $(L4DIR)/mk/lib.mk
