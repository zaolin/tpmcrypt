CPP=g++
CPPFLAGS=-ggdb -Wall -pedantic -Weffc++ -std=c++11
LD=g++
LDFLAGS=-ltspi -lblkid

tpmcrypt: $(patsubst %.cpp,%.o,$(wildcard *.cpp))
	$(LD) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(wildcard *.h)
	$(CPP) $(CPPFLAGS) -c -o $@ $<

clean: 
	rm -f $(wildcard *.o) tpmcrypt
