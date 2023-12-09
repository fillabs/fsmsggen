include Makefile.am.libasncodec

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

ASN1_SRC := $(addprefix asn1/,CAM-PDU-Descriptions.asn DENM-PDU-Descriptions.asn ITS-Container.asn)

ASN1_PDU :=  CAM DENM


Makefile.am.libasncodec: $(ASN1_SRC) 
	$(ASN1C) -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print $(addprefix -pdu=,$(ASN1_PDU)) $(ASN1_SRC)
	touch $@

regen: FORCE
	$(ASN1C) -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print $(addprefix -pdu=,$(ASN1_PDU)) $(ASN1_SRC)

libItsPayload.vcxproj.list: Makefile.am.libasncodec
	rm -f $@
	for n in $(sources); do echo "    <ClCompile Include=\"$$n\" />" >>$@; done
	echo >> $@ 
	for n in $(headers); do echo "    <ClInclude Include=\"$$n\" />" >>$@; done
