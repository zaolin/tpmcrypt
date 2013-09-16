CPP=g++
CPPFLAGS=-ggdb -Wall -pedantic -Weffc++ -std=c++11 \
	 -Wformat -Wformat-security -Werror=format-security \
	 -D_FORTIFY_SOURCE=2 -fstack-protector-all --param ssp-buffer-size=4 \
	 -fPIE -pie
LD=g++
LDFLAGS=-ltspi -lblkid -z relro -z now

tpmcrypt: $(patsubst %.cpp,%.o,$(wildcard *.cpp))
	$(LD) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(wildcard *.h)
	$(CPP) $(CPPFLAGS) -c -o $@ $<

clean: 
	rm -f $(wildcard *.o) tpmcrypt
