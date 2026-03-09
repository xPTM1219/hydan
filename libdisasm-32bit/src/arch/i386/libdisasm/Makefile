LIB	= libdisasm

INCLUDE = -I.
CFLAGS 	= $(INCLUDE) -O3 -ggdb -m32
LFLAGS 	= $(CFLAGS) -fPIC -shared -Wl,-soname,$(LIB).so
RM	= rm -f
CC	= gcc
AR	= ar
RANLIB	= ranlib

OBJ	= libdis.o\
	  i386_invariant.o\
	  vm.o\
	  bastard.o\
	  i386.o

all: $(LIB) quikdis quikdis_old testdis

$(LIB): $(OBJ)
	# make .a
	$(AR) rc $@.a $(OBJ)
	$(RANLIB) $@.a


# make .so
#$(CC) $(LFLAGS) $(OBJ) -o $@.so

quikdis quikdis_old testdis: $(LIB)
	$(CC) $(CFLAGS) -L. -ldisasm $@.c -o $@

clean:
	@$(RM) quikdis quikdis_old testdis  $(LIB).a $(LIB).so $(OBJ) *~
