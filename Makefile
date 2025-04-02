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

bins          := fsmsggen
sources       := fsmsggen.c msggen_cam.c msggen_denm.c msggen_gn.c msggen_vam.c utils.c fsgpsd.c
packages      := libgps cshared pcap thread curl
includes      := $(FITSEC_SRC) $(FSPKI_SRC) $(FSCRYPTDIR) payload uppertester
predirs       := payload uppertester

ifneq ($(SECURITY), no)
 sources  +=  load_data.c msggen_pki.c
 packages += openssl
 deps     = $(outdir)/libuppertester.a $(outdir)/libitspayload.a $(outdir)/libfspki.a $(outdir)/libfitsec2.a $(outdir)/libfscrypt.a $(outdir)/libuppertester.a $(outdir)/libitspayload.a
 libs     = $(outdir)/libuppertester.a $(outdir)/libitspayload.a $(outdir)/libfspki.a $(outdir)/libfitsec2.a -lm -Wl,--whole-archive $(outdir)/libfscrypt.a -Wl,--no-whole-archive $(outdir)/libuppertester.a $(outdir)/libitspayload.a -lm
 predirs  += $(FSCRYPTDIR) $(sort $(FITSEC_SRC) $(FSPKI_SRC))
else
 deps          = $(outdir)/libuppertester.a $(outdir)/libitspayload.a
 libs          = $(outdir)/libuppertester.a $(outdir)/libitspayload.a -lm 
 defines  += NO_SECURITY
endif

include $(CSHAREDDIR)/common.mk
