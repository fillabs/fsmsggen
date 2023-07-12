PROJECTROOT    = .
BUILDROOT      = $(PROJECTROOT)/build
CSHAREDDIR     = $(PROJECTROOT)/cshared
PROJECT        = fsmsggen
DEBUG          = yes

NPCAP_SDK     := /cygdrive/c/PROGRA~1/Npcap/sdk

ifeq (,$(FITSEC_SRC))
  ifneq (,$(strip $(wildcard fitsec2/Makefile)))
   FITSEC_SRC ?= fitsec2
  else
   FITSEC_SRC ?= fitsec2-rel
  endif
endif

bins           = fsmsggen
sources       := fsmsggen.c load_certs.c msggen_cam.c msggen_denm.c msggen_beacon.c utils.c	
packages      += pcap cshared openssl thread
includes      += $(FITSEC_SRC) fscrypt cshared payload uppertester
deps          += $(outdir)/libfitsec2.a $(outdir)/libfscrypt.a $(outdir)/libuppertester.a $(outdir)/libitspayload.a
libs          += $(outdir)/libfitsec2.a -Wl,--whole-archive $(outdir)/libfscrypt.a -Wl,--no-whole-archive $(outdir)/libuppertester.a $(outdir)/libitspayload.a -lm 
predirs       += payload fscrypt $(FITSEC_SRC) uppertester

include $(CSHAREDDIR)/common.mk
