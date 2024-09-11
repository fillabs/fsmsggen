PROJECTROOT    ?= .
BUILDROOT      ?= $(PROJECTROOT)/build
CSHAREDDIR     ?= $(PROJECTROOT)/cshared
PROJECT        := fsmsggen
DEBUG          ?= yes
FSCRYPTDIR     ?= $(PROJECTROOT)/fscrypt

export GPSD_SDK := C:/Users/filatov/Work/ITS/gpsd-3.25/gpsd-3.25

ifeq (,$(FITSEC_SRC))
  ifneq (,$(strip $(wildcard fitsec2/Makefile)))
   FITSEC_SRC ?= fitsec2
   FSPKI_SRC  ?= fspki
  else
   FITSEC_SRC ?= fitsec2-rel
  endif
endif

bins           = fsmsggen
sources       := fsmsggen.c load_data.c msggen_cam.c msggen_denm.c msggen_beacon.c msggen_pki.c msggen_vam.c utils.c fsgpsd.c
packages      += libgps cshared pcap openssl thread curl
includes      += $(FITSEC_SRC) $(FSPKI_SRC) $(FSCRYPTDIR) payload uppertester
deps          += $(outdir)/libfitsec2.a $(outdir)/libfspki.a $(outdir)/libfscrypt.a $(outdir)/libuppertester.a $(outdir)/libitspayload.a
libs          += $(outdir)/libfspki.a $(outdir)/libfitsec2.a -Wl,--whole-archive $(outdir)/libfscrypt.a -Wl,--no-whole-archive $(outdir)/libuppertester.a $(outdir)/libitspayload.a -lm 
predirs       += payload $(FSCRYPTDIR) $(sort $(FITSEC_SRC) $(FSPKI_SRC)) uppertester

include $(CSHAREDDIR)/common.mk
