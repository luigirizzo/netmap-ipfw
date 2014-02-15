# Makefile to build the userland part of ipfw
# and have it communicate with the kernel part through a socket.
#
# For portability, this Makefile needs gmake
# (the 'Makefile.bsd' is the original one, and extremely simple
# XXX we could reverse the logic, Makefile is the original, Makefile.linux
# is the gmake version)
#
include ../Makefile.inc

VPATH = .:../extra
CFLAGS += -include ../extra/glue.h
CFLAGS += -O2 -Wall -Werror
OBJS = ipfw2.o dummynet.o main.o ipv6.o altq.o

LDFLAGS=
LDFLAGS += -lutil # expand_number and humanize_number

CFLAGS += $(INCDIRS)
CFLAGS += -DUSERSPACE	# communicate through userspace
ifeq ($(OSARCH),Linux)	# XXX untested
    CFLAGS += -D__BSD_VISIBLE
    CFLAGS += -DNEED_STRTONUM -DNEED_SYSCTLBYNAME
    CFLAGS += -Wno-unused-but-set-variable
    OBJS += expand_number.o humanize_number.o
endif
ifeq ($(OSARCH),Darwin)
    CFLAGS += -D__BSD_VISIBLE
    CFLAGS += -DNEED_STRTONUM
    OBJS += expand_number.o humanize_number.o
endif

OBJS += glue.o

ipfw: $(OBJS)
	$(MSG) "   LD  $@"
	$(HIDE)$(CC) $(LDFLAGS) -o $@ $^

../$(OBJDIR)/include_e:
	(cd ../objs; $(MAKE) -f ../Makefile.kipfw include_e)

$(OBJS) : ipfw2.h ../extra/glue.h ../$(OBJDIR)/include_e

clean:
	-rm -f *.o ipfw

diff:
	(diff -ubwr $(BSD_HEAD)/sbin/ipfw .)
