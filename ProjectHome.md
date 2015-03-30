This project is a userspace version of FreeBSD's ipfw firewall and [dummynet](http://info.iet.unipi.it/~luigi/dummynet/) link emulator, using the [netmap](http://info.iet.unipi.it/~luigi/netmap/) I/O framework for extremely high speed packet I/O. This version reaches 7-10 Mpps for filtering and over 2.5 Mpps for emulation.

The netmap packet I/O framework is described at http://info.iet.unipi.it/~luigi/netmap/.

Other related repositories of interest (in all cases we track the original repositories and will try to upstream our changes):

  * https://code.google.com/p/netmap/ the latest version of netmap source code (kernel module and examples) for FreeBSD and Linux. Note, FreeBSD distribution include netmap natively.
  * https://code.google.com/p/netmap-libpcap a netmap-enabled version of libpcap from https://github.com/the-tcpdump-group/libpcap.git . With this, basically any pcap client can read/write traffic at 10+ Mpps, with zerocopy reads and (soon) support for zerocopy writes
  * https://code.google.com/p/netmap-click a netmap-enabled version of the Click Modular Router from git://github.com/kohler/click.git . This version matches the current version of netmap, supporting all features (including netmap pipes)