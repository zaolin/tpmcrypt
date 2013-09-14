#include "CryptoBackend.h"
#include <random>

using namespace std;
using namespace crypto;

std::string
CryptoBackend::generateRandomString ( size_t count, bool allAscii ) {
    std::random_device rng;
    std::uniform_int_distribution<int> dist(0, 255);
    std::string stringRandom;
    std::stringstream byteRandom;

    while ( stringRandom.length() < count ) {
        if ( byteRandom.eof() ) {
            byteRandom.clear();
            byteRandom << ( char ) dist(rng);
        }

        uint8_t num = byteRandom.get() % 128;

        if ( allAscii ) {
            if ( isgraph(num) ) {
                stringRandom += ( char ) num;
            }
        } else {
            if ( isalnum(num) ) {
                stringRandom += ( char ) num;
            }
        }
    }

    return stringRandom;
}

SecureString<char>
CryptoBackend::getPassword ( const char *promt ) {
    char *password = getpass(promt);
    SecureString<char> spassword;

    spassword = SecureString<char>(password, strlen(password));

    if ( password != NULL ) {
        free(password);
    }

    return spassword;
}
