PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_conf.a $(PKGNAME)_conf.p.a
SRC_C  = conf_def.c  conf_lib.c    conf_mod.c conf_sap.c conf_api.c  conf_err.c  conf_mall.c   conf_ssl.c
PC_FILENAME = $(PKGNAME)_conf
CFLAGS += -I$(PKGDIR)/include/
include $(L4DIR)/mk/lib.mk

