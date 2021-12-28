PKGDIR ?= ../../../
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_prov_common.a $(PKGNAME)_prov_common.p.a
SRC_C  = bio_prov.c      digest_to_nid.c  provider_err.c      provider_util.c  securitycheck_default.c capabilities.c  provider_ctx.c   provider_seeding.c  securitycheck.c  securitycheck_fips.c
PC_FILENAME = $(PKGNAME)_prov_common
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS =  
#DEPENDS_LIBS = $(REQUIRES_LIBS)
include $(L4DIR)/mk/lib.mk

