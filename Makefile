######################################################################
# $Id: Makefile,v 1.12 2004/04/29 21:12:56 xvr Exp $
# Created: 08/16/2002
#
# xvr (c) 2002-2004
# xvr@xvr.net
######################################################################

PROG		= hydan
VERSION		= 0.15-dev

###

CC 		= gcc
DEBUG		= -g #-D_DEBUG
MISC		= -DVARBITS
CFLAGS		= -Wall $(DEBUG) $(MISC)
LDFLAGS		= -lssl -lcrypto -lm -lZydis -lgmp

###

all:   $(PROG) lns
dist:  $(PROG) lns strip

###

OBJS		= hdn_common.o hdn_embed.o\
		  hdn_decode.o hdn_stats.o\
		  hdn_crypto.o\
		  hdn_subst_insns.o  hdn_io.o \
		  hdn_math.o hdn_exe.o    \
		  $(PROG).o

LIBOBJS		= $(filter-out $(PROG).o,$(OBJS))

###

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS) $(LDFLAGS)

lns:
	ln -fs $(PROG) $(PROG)-decode
	ln -fs $(PROG) $(PROG)-stats

strip:
	strip -s $(PROG)

clean:
	rm -f $(OBJS) *~ *.core \#* $(PROG) $(PROG)-decode $(PROG)-stats \
	      tests/*.o tests/test_crypto tests/test_subst \
	      tests/test_embed_logic

###
#
# Tests: standalone C tests + an integration script.  `make test`
# builds and runs everything; no install or root needed.
#

TEST_BINS	= tests/test_crypto tests/test_subst tests/test_embed_logic

test: $(PROG) lns $(TEST_BINS)
	./tests/test_crypto
	./tests/test_subst
	./tests/test_embed_logic
	./tests/test_integration.sh

check: test

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) -I. -c -o $@ $<

tests/test_crypto: tests/test_crypto.o $(LIBOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_subst: tests/test_subst.o $(LIBOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_embed_logic: tests/test_embed_logic.o $(LIBOBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: all dist lns strip clean test check
