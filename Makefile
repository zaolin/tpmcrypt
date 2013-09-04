CPP=g++
CPPFLAGS=-ggdb -Wall -pedantic
LD=g++
LDFLAGS=-ltspi -lblkid

tpmcrypt: $(patsubst %.cpp,%.o,$(wildcard *.cpp))
	$(LD) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(wildcard *.h)
	$(CPP) $(CPPFLAGS) -c -o $@ $<
