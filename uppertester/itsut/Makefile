PROJECTROOT  = ../..
CSHAREDDIR   = $(PROJECTROOT)/cshared
PROJECT      = itsut

bins         = $(PROJECT)
includes       = ..
sources       := itsut.c
packages      := cshared
ifeq (no,$(SECURITY))
defines += NO_SECURITY
libs          = $(outdir)/libuppertester-nosec.a
deps          = $(outdir)/libuppertester-nosec.a
else
libs          = $(outdir)/libuppertester.a
deps          = $(outdir)/libuppertester.a
endif


include $(CSHAREDDIR)/common.mk
