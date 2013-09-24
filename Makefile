CPP=g++
CPPFLAGS=-O2 -ggdb -Wall -pedantic -Weffc++ -std=c++11 -Wextra \
	 -Wformat -Wformat-security -Werror=format-security \
	 -D_FORTIFY_SOURCE=2 -fstack-protector-all --param ssp-buffer-size=4 \
	 -fpic -pie -I.
LD=g++
LDFLAGS=-ltspi -lblkid -z relro -z now

bin/tpmcrypt: $(patsubst %.cpp,%.o,$(wildcard */*.cpp *.cpp))
	$(LD) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(wildcard */*.h)
	$(CPP) $(CPPFLAGS) -c -o $@ $<

clean: 
	rm -f $(wildcard */*.o *.o) bin/tpmcrypt
