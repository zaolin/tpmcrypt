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

#ifndef CRYPTOBACKEND_H
#define	CRYPTOBACKEND_H

#include <iostream>
#include <string.h>
#include <stdexcept>
#include <unistd.h>
#include <sstream>

#include <utils/SecureMem.h>
#include <crypto++/cryptlib.h>

namespace crypto {

    class CryptoBackend {
    public:
        utils::SecureMem<char>
        getPassword(const char *promt);

        utils::SecureMem<char>
        generateRandomString(size_t count, bool allAscii);
        
        //std::vector<std::string> initBlob(utils::SecureMem<char> toEncrypt, utils::SecureMem<char> passphrase);
        //utils::SecureMem<unsigned char>decryptBlob(std::string toDecrypt, utils::SecureMem<char> passphrase, std::string iv, std::string salt);
        //std::string encryptBlob(utils::SecureMem<unsigned char> toEncrypt, utils::SecureMem<char> passphrase, std::string iv, std::string salt);
        
    private:        
        /*byte*
        generateSalt();
        
        byte*
        generateIV();
        
        utils::SecureMem<unsigned char>
        keyDerivation(utils::SecureMem<unsigned char> passphrase, byte *salt);*/
    };
}
#endif
