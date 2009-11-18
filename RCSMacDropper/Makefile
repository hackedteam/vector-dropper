CC        = gcc
CFLAGS    = -Wall -gstabs+ #-DDEBUG

BINFILE   = RCSMacInfector

default: all

all: $(BINFILE)

RCSMacInfector: RCSMacInfector.c RCSMacInfectorUtil.c RCSMacDropper.c
	$(CC) $(CFLAGS) RCSMacInfector.c RCSMacInfectorUtil.c RCSMacDropper.c -o $(BINFILE)

clean:
	$(RM) $(BINFILE)
