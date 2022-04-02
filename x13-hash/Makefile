SHELL = /bin/sh
CC    = gcc
WINCC32 = i686-w64-mingw32
WINCC64 = x86_64-w64-mingw32
FLAGS        = -std=gnu99 -Isrc
WINFLAGS     = -c -DBUILD_DLL
CFLAGS       = -fPIC -shared -pedantic -Wall -Wextra -ggdb3 -fpermissive
CFLAGSWIN    = -shared -o $(WINTARGET) libx13.o -Wl, --out-implib,libx13.a
DEBUGFLAGS   = -O0 -D _DEBUG
RELEASEFLAGS = -O2 -D NDEBUG -fwhole-program

TARGET  = libx13.so
TARGETWIN = libx13.dll
TARGETMAC = libx13.dylib
SOURCES = x13.c $(shell echo sha3/*.c)
HEADERS = x13.h $(shell echo sha3/*.h)
OBJECTS = $(SOURCES:.c=.o)

PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin

all: linux win mac

mac: $(OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(RELEASEFLAGS) -o $(TARGETMAC) $(OBJECTS)

linux: $(OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(RELEASEFLAGS) -o $(TARGET) $(OBJECTS)

win32:
	$(WINCC32)-g++ -c -D_WIN32 -fpermissive $(SOURCES)
	$(WINCC32)-g++ -shared -o $(TARGETWIN)  *.o -Wl,--out-implib,libx13.a
	strip libx13.dll

win64:
	$(WINCC64)-g++ -c -D_WIN32 -fpermissive $(SOURCES)
	$(WINCC64)-g++ -shared -o $(TARGETWIN)  *.o -Wl,--out-implib,libx13.a
	strip libx13.dll

clean:
	rm libx13.so libx13.dll *.o sha3/*.o

install:
	cp libx13.so $PREFIX/libx13.so
