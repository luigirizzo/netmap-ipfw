#
# This is a gnu makefile to build ipfw in userspace.
# Usage:
#
#	make NETMAP_INC=/some/place/with/netmap-release/sys
#
# build with make NETMAP_INC=/place/with/netmap/sys

SUBDIRS= ipfw dummynet
.PHONY:	ipfw kipfw

include Makefile.inc
all: ipfw kipfw

ipfw: $(OBJDIR)
	$(MSG) Building userspace ...
	@(cd ipfw && $(MAKE) $(MAKECMDGOALS) )

$(OBJDIR):
	-@mkdir $(OBJDIR)

kipfw: $(OBJDIR)
	$(MSG) Building datapath ...
	@(cd $(OBJDIR) && $(MAKE) -f ../Makefile.kipfw && cp kipfw ..)

clean:
	-@rm -rf $(OBJDIR) kipfw
	@(cd ipfw && $(MAKE) clean )

tgz:
	@$(MAKE) clean
	(cd ..; tar cvzf /tmp/ipfw-user.tgz --exclude .svn ipfw-user)

# compute diffs wrt FreeBSD head tree in BSD_HEAD
diffs:
	-@diff -urp --exclude Makefile $(BSD_HEAD)/sbin/ipfw ipfw
	-@diff -urp --exclude Makefile $(BSD_HEAD)/sys sys
