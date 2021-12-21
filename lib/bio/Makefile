PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_bio.a $(PKGNAME)_bio.p.a
SRC_C  = bf_buff.c  bf_nbio.c  bf_prefix.c    bio_addr.c  bio_dump.c  bio_lib.c   bio_print.c  bio_sock.c  bss_bio.c   bss_core.c   bss_fd.c    bss_log.c  bss_null.c  ossl_core_bio.c \
bf_lbuf.c  bf_null.c  bf_readbuff.c  bio_cb.c    bio_err.c   bio_meth.c  bio_sock2.c  bss_acpt.c  bss_conn.c  bss_dgram.c  bss_file.c  bss_mem.c  bss_sock.c
PC_FILENAME = $(PKGNAME)_bio
CFLAGS += -I$(PKGDIR)/include/
DEFINES += -DOPENSSL_NO_SOCK=1 -DOPENSSL_NO_DGRAM=1
REQUIRES_LIBS = libossl_buffer libossl_fopen
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


