PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_cmp.a $(PKGNAME)_cmp.p.a
SRC_C  = cmp_asn.c cmp_client.c cmp_ctx.c cmp_err.c cmp_hdr.c cmp_http.c cmp_msg.c cmp_protect.c cmp_server.c cmp_status.c cmp_util.c cmp_vfy.c
PC_FILENAME = $(PKGNAME)_cmp
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


