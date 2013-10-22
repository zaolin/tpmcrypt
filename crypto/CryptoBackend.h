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
    
    /**
     * @name CryptoBackend
     * @brief Class for cryptography based functions.
     * @detail 
     * + Supports Secure Random Number Generator for Passphrases.
     * + Supports Secure Passphrase Input.
     * + Supports Secure Blob Encryption/Decryption. 
     * @author Philipp Deppenwiese
     * @date 22-10-2013
     */
    class CryptoBackend {
    public:
        
        /**
         * @brief Used to retrieve a passphrase of a secure terminal input.
         * @param promt A text for the passphrase input.
         * @return Returns a secure memory object containing the passphrase.
         */
        utils::SecureMem<char>
        getPassword(const char *promt);

        /**
         * @brief Used to retrieve a passphrase of a secure terminal input.
         * @param count Number of characters that should be returned.
         * @param allAscii If true uses all ascii characters on keyboard, if false only uses alphanumeric.
         * @return Returns a secure memory object containing the random string.
         */
        utils::SecureMem<char>
        generateRandomString(size_t count, bool allAscii);
        
        /**
         * @brief Used to initialize a encrypted blob with a passphrase.
         * @param toEncrypt Data that should be encrypted.
         * @param passphrase The passphrase for the key derivation.
         * @return Returns string vector containing:
         * 1) The encrypted blob.
         * 2) Iv string of the encryption process.
         * 3) Salt string of the key derivation.
         */
        std::vector<std::string> initBlob(utils::SecureMem<unsigned char> toEncrypt, utils::SecureMem<unsigned char> passphrase);
        
        /**
         * @brief Used to decrypt a encrypted blob with passphrase.
         * @param toDecrypt Data that should be decrypted.
         * @param passphrase The passphrase for the key derivation.
         * @param iv The Initialization Vector.
         * @param salt The salt of the key derivation.
         * @return Returns a secure memory object containing the decrypted blob.
         */
        utils::SecureMem<unsigned char> decryptBlob(std::string toDecrypt, utils::SecureMem<unsigned char> passphrase, std::string iv, std::string salt);
        
        /**
         * @brief Used to encrypt a blob with passphrase.
         * @param toEncrypt Data that should be encrypted.
         * @param passphrase The passphrase for the key derivation.
         * @param iv The Initialization Vector.
         * @param salt The salt of the key derivation.
         * @return Returns a string containing the encrypted blob.
         */
        std::string encryptBlob(utils::SecureMem<unsigned char> toEncrypt, utils::SecureMem<unsigned char> passphrase, std::string iv, std::string salt);
        
    private:
        /**
         * @brief Used to generate a random salt of 2 byte.
         * @return Returns a unsigned char pointer.
         */
        byte*
        generateSalt();
        
        /**
         * @brief Used to generate a radom iv of 32 byte.
         * @return Returns a unsigned char pointer.
         */
        byte*
        generateIV();
        
        /**
         * @brief Used to generate the cipher key of a passphrase.
         * @detail key size is 256bit with 2000 iterations.
         * @param passphrase The passphrase for the key derivation.
         * @param salt The salt of the key derivation.
         * @return Returns a secure memory object containing the cipher key.
         */
        utils::SecureMem<unsigned char>
        keyDerivation(utils::SecureMem<unsigned char> passphrase, byte *salt);
    };
}
#endif
