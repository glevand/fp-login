## Makefile.am -- Process this file with automake to produce Makefile.in
#
#  Copyright 2008 Geoff Levand
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, Version 2 as
# published by the Free Software Foundation.
#

composed_mans = fp-login.1

man_MANS = $(composed_mans)

AM_CFLAGS = \
	-g \
	-Wall \
	-W \
	-Wunused \
	-Wstrict-prototypes \
	-Wmissing-prototypes \
	-Wmissing-declarations \
	-Wredundant-decls \
	-Winline

bin_PROGRAMS = fp-login

fp_login_SOURCES = fp-login.c platform.h
fp_login_LDADD = -lssl -lcrypto
fp_login_LDFLAGS =

if COND_COREFOUNDATION
 fp_login_SOURCES += darwin.c
 fp_login_LDFLAGS += -framework CoreFoundation -framework SystemConfiguration
else
 fp_login_SOURCES += posix.c
endif

edit = sed \
	-e 's|@PACKAGE_NAME\@|$(PACKAGE_NAME)|g' \
	-e 's|@PACKAGE_VERSION\@|$(PACKAGE_VERSION)|g' \
	-e 's|@PACKAGE_BUGREPORT\@|$(PACKAGE_BUGREPORT)|g' \
	-e 's|@libexecdir\@|$(libexecdir)|g' \
	-e 's|@datadir\@|$(pkgdatadir)|g' \
	-e 's|@prefix\@|$(prefix)|g'

fp-login.1: Makefile $(srcdir)/fp-login.1.in
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/$@.in >$@.tmp
	groff -Cz -man $@.tmp
	mv $@.tmp $@

install-exec-local:
	chmod 4755 $(bindir)/fp-login

composed_files = $(composed_mans)

EXTRA_DIST = bootstrap configure.ac.in $(addsuffix .in, $(composed_mans))

MAINTAINERCLEANFILES = aclocal.m4 config.* configure configure.ac depcomp \
	install-sh ltmain.sh Makefile.in missing $(PACKAGE)-*.gz

CLEANFILES = $(composed_files) $(addsuffix .tmp, $(composed_files))
