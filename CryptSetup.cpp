/*
 *    This file is part of tpmcrypt.
 *
 *    tpmcrypt is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    tpmcrypt is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with tpmcrypt.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "CryptSetup.h"
#include <sstream>
#include <unistd.h>
#include <stdlib.h>
#include <list>
#include <stdexcept>

using namespace tools;
using namespace std;

const static string MapperPath = "/dev/mapper/";
const static string ToolIdentifier = "cryptsetup";

const string CryptSetup::TAG = "LUKS";

CryptSetup::~CryptSetup ( ) {

}

string CryptSetup::openVolume ( string dev, crypto::SecureString<char> password ) {
    int ret = 1;
    list<string> args;
    list<crypto::SecureString<char> > stdout;
    string stdin;

    try {
        if ( !this->isAvailable() ) {
            throw 1;
        }

        if ( !this->isTool(dev) ) {
            throw 1;
        }

        if ( access(dev.c_str(), F_OK) != 0 ) {
            throw 1;
        }

        if ( password.isEmpty() ) {
            throw 1;
        }

        args.push_back("luksOpen");
        args.push_back(dev);
        args.push_back(genUniqueName(dev));

        stdout.push_back(password);

        call(ToolIdentifier, args, stdout, stdin, &ret);

        if ( ret ) {
            throw 1;
        }
    } catch ( exception &e ) {

    }

    return genUniqueName(dev);
}

void CryptSetup::closeVolume ( string dev ) {
    list<string> args;
    string stdin;
    list<crypto::SecureString<char> > stdout;
    int ret = 1;

    if ( !this->isAvailable() ) {
        throw runtime_error("foo");
    }

    if ( !this->isTool(dev) ) {
        throw runtime_error("foo1");
    }

    if ( access(dev.c_str(), F_OK) != 0 ) {
        throw runtime_error("foo2");
    }
    /*
    if (access(genUniqueName(dev).c_str(), F_OK) != 0) {
            throw runtime_error("foo3");
    }
     */
    args.push_back("luksClose");
    args.push_back(genUniqueName(dev));

    call(ToolIdentifier, args, stdout, stdin, &ret);

    if ( ret ) {
        throw 1;
    }
}

void CryptSetup::createVolume ( string dev, crypto::SecureString<char> password, bool force,
                                Cipher c, Mode m, Hash h, KeySize k, Entropy e ) {
    list<string> args;
    stringstream ss;
    string stdin;
    list<crypto::SecureString<char> > stdout;
    int ret = 1;

    if ( !this->isAvailable() ) {
        throw 1;
    }

    if ( this->isTool(dev) && !force ) {
        throw 1;
    }

    if ( access(dev.c_str(), F_OK) != 0 ) {
        throw 1;
    }

    ss << getCipher(c) << "-" << getMode(m);

    args.push_back("-c");
    args.push_back(ss.str());
    args.push_back("-h");
    args.push_back(getHash(h));
    args.push_back("-s");
    args.push_back(getKeySize(k));
    args.push_back(getEntropy(e));
    args.push_back("luksFormat");
    args.push_back(dev);

    stdout.push_back(password);

    call(ToolIdentifier, args, stdout, stdin, &ret);

    if ( ret ) {
        throw 1;
    }
}

void CryptSetup::changeVolume ( string dev, crypto::SecureString<char> password, crypto::SecureString<char> newPassword ) {
    list<string> args;
    list<crypto::SecureString<char> > stdout;
    int ret = 1;
    string stdin;

    if ( !this->isAvailable() ) {
        throw 1;
    }

    if ( !this->isTool(dev) ) {
        throw 1;
    }

    if ( access(dev.c_str(), F_OK) != 0 ) {
        throw 1;
    }

    args.push_back("luksChangeKey");
    args.push_back(dev);

    stdout.push_back(password);
    stdout.push_back(newPassword);

    call(ToolIdentifier, args, stdout, stdin, &ret);

    if ( ret ) {
        throw 1;
    }
}

bool CryptSetup::isTool ( string dev ) {
    list<string> args;
    list<crypto::SecureString<char> > stdout;
    string stdin;
    int ret = 1;

    args.push_back("isLuks");
    args.push_back(dev);

    call(ToolIdentifier, args, stdout, stdin, &ret);

    return ret ? false : true;
}

bool CryptSetup::isAvailable ( ) {
    list<string> args;
    list<crypto::SecureString<char> > stdout;
    string stdin;
    int ret = 1;

    args.push_back(ToolIdentifier);

    call("which", args, stdout, stdin, &ret);

    return ret ? false : true;
}

string CryptSetup::getCipher ( Cipher c ) {
    switch ( c ) {
        case AES: return "aes";
            break;
        case SERPENT: return "serpent";
            break;
        case TWOFISH: return "twofish";
            break;
        case CAST: return "cast";
            break;
        case MARS: return "mars";
            break;
        default: throw 1;
            break;
    }
}

string CryptSetup::getMode ( Mode m ) {
    switch ( m ) {
        case CBC: return "cbc-essiv:sha256";
            break;
        case XTS: return "xts-plain";
            break;
        case XTS64: return "xts-plain64";
            break;
        default: throw 1;
            break;
    }
}

string CryptSetup::getHash ( Hash h ) {
    switch ( h ) {
        case SHA1: return "sha1";
            break;
        case SHA256: return "sha256";
            break;
        case SHA512: return "sha512";
            break;
        case WHIRLPOOL: return "whirlpool";
            break;
        case RIPEMD160: return "ripemd160";
            break;
        default: throw 1;
            break;
    }
}

string CryptSetup::getKeySize ( KeySize k ) {
    switch ( k ) {
        case S128: return "128";
            break;
        case S256: return "256";
            break;
        case S384: return "384";
            break;
        case S512: return "512";
            break;
        default: throw 1;
            break;
    }
}

string CryptSetup::getEntropy ( Entropy e ) {
    switch ( e ) {
        case RANDOM: return "--use-random";
            break;
        case URANDOM: return "--use-urandom";
            break;
        default: throw 1;
            break;
    }
}