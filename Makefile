######################################################################
# $Id: Makefile,v 1.12 2004/04/29 21:12:56 xvr Exp $
# Created: 08/16/2002
#
# xvr (c) 2002-2004
# xvr@xvr.net
######################################################################

PROG		= hydan
VERSION		= 0.13

###

CC 		= gcc
ARCH = -m32
LIBDIS_LOC	= libdisasm-32bit/src/arch/i386/libdisasm
#LIBDIS_LOC	= libdisasm-64bit/libdisasm
DEBUG		= -g #-D_DEBUG
MISC		= -DVARBITS
INCLUDE		= -I$(LIBDIS_LOC)
CFLAGS		= -Wall $(INCLUDE) $(DEBUG) $(MISC) $(ARCH) #-static
LDFLAGS		= -L$(LIBDIS_LOC) -ldisasm -lcrypto -lm #-lelf $(ARCH)

###

all:   libdis $(PROG) lns
dist:  $(PROG) lns strip

###

OBJS		= hdn_common.o hdn_embed.o\
		  hdn_decode.o hdn_stats.o\
		  hdn_crypto.o\
		  hdn_subst_insns.o  hdn_io.o \
		  hdn_math.o hdn_exe.o    \
		  $(PROG).o

###

libdis:
	cd $(LIBDIS_LOC) && make libdisasm

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS) $(LDFLAGS)

lns:
	ln -fs $(PROG) $(PROG)-decode
	ln -fs $(PROG) $(PROG)-stats

strip:
	strip -s $(PROG)

clean:
	rm -f $(OBJS) *~ *.core \#* $(PROG) $(PROG)-decode $(PROG)-stats
	cd $(LIBDIS_LOC) && make clean
