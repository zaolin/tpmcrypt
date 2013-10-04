CPP=g++
PKG=blkid botan-1.10
CPPFLAGS=-O2 -ggdb -Wall -pedantic -Weffc++ -std=c++11 -Wextra \
	 -Wformat -Wformat-security -Werror=format-security \
	 -D_FORTIFY_SOURCE=2 -fstack-protector-all --param ssp-buffer-size=4 \
	 -fpic -pie -I. `pkg-config --cflags $(PKG)`
LD=g++
LDFLAGS=-ltspi -z relro -z now `pkg-config --libs $(PKG)`

bin/tpmcrypt-console: $(patsubst %.cpp,%.o,$(wildcard */*.cpp console.cpp))
	$(LD) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(wildcard */*.h)
	$(CPP) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f $(wildcard */*.o *.o) bin/tpmcrypt-console
