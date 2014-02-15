#
# this is a gnu makefile

BSD_HEAD ?= /home/luigi/FreeBSD/head
NETMAP_INC ?= ../netmap-release/sys

OBJDIR=objs
OSARCH := $(shell uname)
OSARCH := $(findstring $(OSARCH),FreeBSD Linux Darwin)
ifeq ($(OSARCH),)
    OSARCH := Windows
endif

ifeq ($V,) # no echo
    MSG=@echo
    HIDE=@
else
    MSG=@\#
    HIDE=
endif

# ipfw and kipfw are built in subdirs so the paths for
# headers refer to one directory up
INCDIRS += -I ../$(OBJDIR)/include_e -DEMULATE_SYSCTL
INCDIRS += -I ../sys -I ../extra/sys -I ../extra/sys/contrib/pf
.c.o:
	$(MSG) "   CC $<"
	$(HIDE) $(CC) $(CFLAGS) -c $< -o $@
