PROJECTROOT    ?= .
BUILDROOT      ?= $(PROJECTROOT)/build
CSHAREDDIR     ?= $(PROJECTROOT)/cshared
PROJECT        := fsmsggen
DEBUG          ?= yes
FSCRYPTDIR     ?= $(PROJECTROOT)/fscrypt

NPCAP_SDK     := /cygdrive/c/PROGRA~1/Npcap/sdk

ifeq (,$(FITSEC_SRC))
  ifneq (,$(strip $(wildcard fitsec2/Makefile)))
   FITSEC_SRC ?= fitsec2
   FSPKI_SRC  ?= fspki
  else
   FITSEC_SRC ?= fitsec2-rel
  endif
endif

bins           = fsmsggen
sources       := fsmsggen.c load_data.c msggen_cam.c msggen_denm.c msggen_beacon.c msggen_pki.c utils.c	
packages      += pcap cshared openssl thread
includes      += $(FITSEC_SRC) $(FSPKI_SRC) $(FSCRYPTDIR) $(CSHAREDDIR) payload uppertester
deps          += $(outdir)/libfitsec2.a $(outdir)/libfspki.a $(outdir)/libfscrypt.a $(outdir)/libuppertester.a $(outdir)/libitspayload.a
libs          += $(outdir)/libfspki.a $(outdir)/libfitsec2.a -Wl,--whole-archive $(outdir)/libfscrypt.a -Wl,--no-whole-archive $(outdir)/libuppertester.a $(outdir)/libitspayload.a -lm -lcurl
predirs       += payload $(FSCRYPTDIR) $(FITSEC_SRC) $(FSPKI_SRC) uppertester

include $(CSHAREDDIR)/common.mk
