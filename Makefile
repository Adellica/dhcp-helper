PREFIX?=/usr/local
BINDIR = ${PREFIX}/sbin
MANDIR = ${PREFIX}/man
 
CFLAGS?= -O2
version= $(shell ./get-version)

all: dhcp-helper.c
	$(CC) $(CFLAGS) $(RPM_OPT_FLAGS) -DVERSION=\"$(version)\" -Wall -W dhcp-helper.c -o dhcp-helper

clean:
	rm -f *~ *.o core dhcp-helper

install : all
	install -d $(DESTDIR)$(BINDIR) -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 dhcp-helper.8 $(DESTDIR)$(MANDIR)/man8 
	install -m 755 dhcp-helper $(DESTDIR)$(BINDIR)
