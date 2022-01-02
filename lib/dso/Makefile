PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_dso.a $(PKGNAME)_dso.p.a
SRC_C  = dso_dl.c dso_dlfcn.c dso_err.c dso_lib.c dso_openssl.c dso_vms.c dso_win32.c

PC_FILENAME = $(PKGNAME)_dso
CFLAGS += -I$(PKGDIR)/include/

DEFINES += -DDSO_NONE=1
#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


