PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_curve448.a $(PKGNAME)_curve448.p.a
SRC_C  = curve448.c curve448_tables.c eddsa.c f_generic.c scalar.c arch_64/f_impl64.c

PC_FILENAME = $(PKGNAME)_curve448
CFLAGS += -I$(PKGDIR)/include/

#REQUIRES_LIBS = libossl_threads libossl_fips
#DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


