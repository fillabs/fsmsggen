######################################################################
##
##  Created by: Denis Filatov
##
##  Copyleft (c) 2015
##  This code is provided under the CeCill-C license agreement.
######################################################################
PROJECTROOT    = .
BUILDROOT      = $(PROJECTROOT)/build
CSHAREDDIR     = $(PROJECTROOT)/cshared
PROJECT        = fsmsggen
DEBUG          = yes

NPCAP_SDK     := /cygdrive/c/PROGRA~1/Npcap/sdk

bins           = fsmsggen
sources       := fsmsggen.c load_certs.c msggen_cam.c msggen_denm.c msggen_beacon.c utils.c	
packages      += pcap cshared openssl thread
includes      += fitsec2 cshared payload uppertester
deps          += $(outdir)/libfitsec2.a $(outdir)/libuppertester.a $(outdir)/libitspayload.a
libs          += -Wl,--whole-archive $(outdir)/libfitsec2.a -Wl,--no-whole-archive $(outdir)/libuppertester.a $(outdir)/libitspayload.a -lm 
predirs       += payload cshared fitsec2 uppertester

include $(CSHAREDDIR)/common.mk
