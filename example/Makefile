PKGDIR ?= .
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = openssl-example 
CFLAGS += -I$(PKGDIR)/../include
SRC_C = main.c

REQUIRES_LIBS = libossl_conf libossl_evp libossl_core libossl_engine libossl_err libossl_threads
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/prog.mk
