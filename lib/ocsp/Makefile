PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_ocsp.a $(PKGNAME)_ocsp.p.a
SRC_C  = ocsp_asn.c ocsp_cl.c ocsp_err.c ocsp_ext.c ocsp_http.c ocsp_lib.c ocsp_prn.c ocsp_srv.c ocsp_vfy.c v3_ocsp.c
PC_FILENAME = $(PKGNAME)_ocsp
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


