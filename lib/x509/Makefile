PKGDIR ?= ../..
L4DIR  ?= /home/beleg/l4re/src/l4
O 	   ?= /home/beleg/l4re/obj/l4/arm64
TARGET = $(PKGNAME)_x509.a $(PKGNAME)_x509.p.a
SRC_C = by_dir.c pcy_node.c v3_akeya.c v3_crld.c v3_int.c v3_pku.c v3_tlsf.c x509_def.c x509_r2x.c x509type.c x_exten.c \
by_file.c pcy_tree.c v3_akid.c v3_enum.c v3_ist.c v3_pmaps.c v3_utf8.c x509_err.c x509_req.c x509_v3.c x_name.c \
by_store.c t_crl.c v3_asid.c v3err.c v3_lib.c v3_prn.c v3_utl.c x509_ext.c x509rset.c x509_vfy.c x_pubkey.c \
pcy_cache.c t_req.c v3_bcons.c v3_extku.c v3_ncons.c v3_purp.c x509_att.c x509_lu.c x509_set.c x509_vpm.c x_req.c \
pcy_data.c t_x509.c v3_bitst.c v3_genn.c v3_pcia.c v3_san.c x509_cmp.c x509_meth.c x509spki.c x_all.c x_x509a.c \
pcy_lib.c v3_addr.c v3_conf.c v3_ia5.c v3_pci.c v3_skid.c x509cset.c x509name.c x509_trust.c x_attrib.c x_x509.c \
pcy_map.c v3_admis.c v3_cpols.c v3_info.c v3_pcons.c v3_sxnet.c x509_d2.c x509_obj.c x509_txt.c x_crl.c

PC_FILENAME = $(PKGNAME)_x509
CFLAGS += -I$(PKGDIR)/include/

REQUIRES_LIBS = libossl_threads libossl_fips libossl_asn1
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/lib.mk


