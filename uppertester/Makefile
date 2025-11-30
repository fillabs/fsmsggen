PROJECTROOT  = ..
CSHAREDDIR   = $(PROJECTROOT)/cshared
ifeq (no,$(SECURITY))
PROJECT      = uppertester-nosec
defines     += NO_SECURITY
else
PROJECT      = uppertester
endif

alibs        = $(PROJECT)
solibs       = $(PROJECT)

sources       := uppertester.c uppertester_cmd.c
headers       := uppertester.h
packages      := cshared

postdirs      := itsut

include $(CSHAREDDIR)/common.mk
