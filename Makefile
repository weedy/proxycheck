# Automatically generated from Makefile.in by configure
#
# $Id: Makefile.in,v 1.19 2004/05/29 15:16:29 mjt Exp $
# Makefile for proxycheck.  GPL

CC = gcc
CFLAGS = -Wall -W -O2
DEFS = -D_GNU_SOURCE -D_BSD_SOURCE -DHAVE_CONFIG_H
LD = $(CC)
LDFLAGS = $(CFLAGS)

LIBRESOLV = 
LIBSOCKET = 

USE_CFLAGS = -I. $(CFLAGS) $(DEFS)

SRCS = proxycheck.c pxy.c event.c memmem.c proxylogger.c
HDRS = pxy.h event.h
DIST = $(SRCS) $(HDRS) Makefile.in event.3 proxycheck.1 CHANGES configure
VERSION = 0.49a
VERSION_DATE = 2004-05-29

all: proxycheck

proxycheck_OBJS = proxycheck.o pxy.o event.o memmem.o
proxycheck: $(proxycheck_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(proxycheck_OBJS) $(LIBRESOLV) $(LIBSOCKET)
$(proxycheck_OBJS): config.h

proxylogger_OBJS = proxylogger.o
proxylogger: $(proxylogger_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(proxylogger_OBJS) $(LIBSOCKET)
$(proxylogger_OBJS): config.h

.c.o:
	$(CC) $(USE_CFLAGS) -c $<

proxycheck.o: proxycheck.c
	$(CC) $(USE_CFLAGS) -c -DVERSION_STR='"$(VERSION) $(VERSION_DATE)"' $<

Makefile config.h: Makefile.in configure CHANGES
	./configure
	@echo
	@echo Please rerun make.
	@false

event.3.html: event.3
	groff -Thtml -mandoc event.3 > $@.tmp
	mv $@.tmp $@

b = proxycheck-$(VERSION)
dist: $(b).tar.gz
$(b).tar.gz: $(DIST)
	rm -rf $(b)
	mkdir $(b)
	ln $(DIST) $(b)/
	tar cfz $@ $(b)
	rm -rf $(b)

clean:
	rm -f *~ *.o core config.log config.h conftest*

depend dep deps:
	@echo Generating deps for:
	@echo \ $(SRCS)
	@sed '/^# depend/q' Makefile.in > Makefile.tmp
	@$(CC) $(CFLAGS) -MM $(SRCS) >> Makefile.tmp
	@if cmp Makefile.tmp Makefile.in ; then \
	  echo Makefile.in unchanged; \
	  rm -f Makefile.tmp; \
	else \
	  echo Updating Makfile.in; \
	  mv -f Makefile.tmp Makefile.in ; \
	fi

# depend: anything after this line will be replaced by make depend
proxycheck.o: proxycheck.c event.h pxy.h
pxy.o: pxy.c event.h pxy.h
event.o: event.c event.h
memmem.o: memmem.c
proxylogger.o: proxylogger.c
