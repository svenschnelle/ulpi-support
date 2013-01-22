CC=/cygdrive/c/mingw/bin/gcc
CFLAGS=-Wextra -Wall -O2 -Wno-unused -ggdb

all: ULPI.dll

ULPI.dll:	ULPI.c ULPI.h Makefile
		$(CC) $(CFLAGS) -shared -o $@ $<

install:	ULPI.dll ULPI.tla PID.tsf ULPI_T.cop ULPI_std.clk
		mkdir -p /cygdrive/c/Program\ Files/TLA\ 700/Supports/ULPI/
		cp -Rva $^ /cygdrive/c/Program\ Files/TLA\ 700/Supports/ULPI/
clean:

		rm -f ULPI.dll
