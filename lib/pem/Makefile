PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_pem.a $(PKGNAME)_pem.p.a
SRC_C  = pem_all.c pem_err.c pem_info.c pem_lib.c pem_oth.c pem_pk8.c pem_pkey.c pem_sign.c pem_x509.c pem_xaux.c pvkfmt.c 
PC_FILENAME = $(PKGNAME)_pem
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


