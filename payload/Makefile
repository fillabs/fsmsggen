include Makefile.am.libasncodec

ASN1_SRC := asn1/CAM-PDU-Descriptions.asn \
            asn1/DENM-PDU-Descriptions.asn \
			asn1/VAM-PDU-Descriptions.asn \
            asn1/ETSI-ITS-CDD.asn

ASN1_PDU :=  CAM DENM VAM

PROJECTROOT  = ..

BUILDROOT    = $(PROJECTROOT)/build
CSHAREDDIR   = $(PROJECTROOT)/cshared
PROJECT      = itspayload
DEBUG        = yes
#ASN1CDIR    ?= ../../../../asn1c-fillabs

alibs        = $(PROJECT)

sources       := $(ASN_MODULE_SRCS)

headers       := $(ASN_MODULE_HDRS)

includes      += .

include $(CSHAREDDIR)/common.mk

ifneq (,$(ASN1CDIR))
  ASN1C := $(ASN1CDIR)/asn1c/asn1c -S $(ASN1CDIR)/skeletons
else
  ASN1C := asn1c
endif

Makefile.am.libasncodec: $(ASN1_SRC) 
	$(ASN1C) -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names $(addprefix -pdu=,$(ASN1_PDU)) $(ASN1_SRC)
	touch $@

regen: FORCE
	$(ASN1C) -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names $(addprefix -pdu=,$(ASN1_PDU)) $(ASN1_SRC)

libItsPayload.vcxproj.list: Makefile.am.libasncodec
	rm -f $@
	for n in $(sources); do echo "    <ClCompile Include=\"$$n\" />" >>$@; done
	echo >> $@ 
	for n in $(headers); do echo "    <ClInclude Include=\"$$n\" />" >>$@; done
