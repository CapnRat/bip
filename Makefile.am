bin_PROGRAMS = src/bip src/bipmkpw src/bipcrypt
src_bip_SOURCES = src/conf.y src/lex.l \
	src/bip.c src/bip.h \
	src/connection.c src/connection.h \
	src/defaults.h \
	src/irc.c src/irc.h \
	src/line.c src/line.h \
	src/log.c src/log.h \
	src/md5.c src/md5.h \
	src/moduli.h \
	src/tuple.h \
	src/util.c src/util.h \
	src/crypt.c src/crypt.h
src_bipmkpw_SOURCES = src/bipmkpw.c src/md5.c src/util.c
src_bipcrypt_SOURCES = src/bipcrypt.c src/crypt.h src/crypt.c src/util.h src/util.c
AM_YFLAGS= -d
BUILT_SOURCES = src/conf.c src/conf.h src/lex.c

AM_CFLAGS=-Wall -Wextra

dist_man_MANS = bip.1 bip.conf.5 bipmkpw.1

examplesdir = $(prefix)/share/doc/bip/examples/
dist_examples_DATA = samples/bip.conf samples/bip.vim

EXTRA_DIST = \
	BUGS \
	scripts/bip-release \
	scripts/bipgenconfig
