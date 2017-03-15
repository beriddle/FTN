#
# This is a Makefile for a R-Track program.
# Typing 'make' or 'make r-track' will create the executable file.
#

# define some Makefile variables for the compiler and compiler flags
# to use Makefile variables later in the Makefile: $()
#
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
#
# for C++ define  CC = g++
CC = gcc
CFLAGS  = -g -Wall -I.
RM = rm -f

# typing 'make' will invoke the first target entry in the file 
# (in this case the default target entry)
# you can name this target entry anything, but "default" or "all"
# are the most commonly used names by convention
#
default: r-track

# To create the executable file count we need the object files
# r-track.o ftn.o:
#
r-track:  r-track.o ftn.o
	$(CC) $(CFLAGS) -o r-track r-track.o ftn.o

# To create the object file ftn.o, we need the source
# files ftn.c and ftn.h:
#
ftn.o:  ftn.c ftn.h
	$(CC) $(CFLAGS) -c ftn.c

# To create the object file r-track.o, we need the source files
# r-track.c and ftn.h:
#
r-track.o:  r-track.c ftn.h
	$(CC) $(CFLAGS) -c r-track.c

# To start over from scratch, type 'make clean'.  This
# removes the executable file, as well as old .o object
# files and *~ backup files:
#
clean: 
	$(RM) r-track *.o *~
