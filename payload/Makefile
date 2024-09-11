include Makefile.am.libasncodec

ASN1_SRC := asn1/CAM-PDU-Descriptions.asn \
            asn1/DENM-PDU-Descriptions.asn \
			asn1/VAM-PDU-Descriptions.asn \
			asn1/CPM-OriginatingStationContainers.asn \
			asn1/CPM-PDU-Descriptions.asn \
			asn1/CPM-PerceivedObjectContainer.asn \
			asn1/CPM-PerceptionRegionContainer.asn \
			asn1/CPM-SensorInformationContainer.asn \
            asn1/ETSI-ITS-CDD.asn

ASN1_PDU :=  CAM DENM VAM CollectivePerceptionMessage

PROJECTROOT  = ..

BUILDROOT    = $(PROJECTROOT)/build
CSHAREDDIR   = $(PROJECTROOT)/cshared
PROJECT      = itspayload
DEBUG        = yes
#ASN1CDIR    ?= ../../../../asn1c-fillabs

ASN1C_OPTS := -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names

alibs        = $(PROJECT)

sources       := $(ASN_MODULE_SRCS)

headers       := $(ASN_MODULE_HDRS)
#defines       := ASN_EMIT_DEBUG=1
includes      += .

include $(CSHAREDDIR)/common.mk

ifneq (,$(ASN1CDIR))
  ASN1C := $(ASN1CDIR)/asn1c/asn1c -S $(ASN1CDIR)/skeletons $(ASN1C_OPTS)
else
  ASN1C := asn1c $(ASN1C_OPTS)
endif

Makefile.am.libasncodec: $(ASN1_SRC) 
	$(ASN1C) $(addprefix -pdu=,$(ASN1_PDU)) $(ASN1_SRC)
	touch $@

regen: FORCE
	$(ASN1C) $(addprefix -pdu=,$(ASN1_PDU)) $(ASN1_SRC)

libItsPayload.vcxproj.list: Makefile.am.libasncodec
	rm -f $@
	for n in $(sources); do echo "    <ClCompile Include=\"$$n\" />" >>$@; done
	echo >> $@ 
	for n in $(headers); do echo "    <ClInclude Include=\"$$n\" />" >>$@; done
